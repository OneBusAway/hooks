package tokens

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/onebusaway/hooks/internal/store"
)

// patchOwnerFixture is a minimal admin-+-token-row setup for the PATCH
// /api/tokens/{id} owner-transfer endpoint.
type patchOwnerFixture struct {
	st        *store.SQLite
	srv       *httptest.Server
	admin     IssueResult
	target    store.Token
	otherUser string
}

func newPatchOwnerFixture(t *testing.T) *patchOwnerFixture {
	t.Helper()
	dir := t.TempDir()
	st, err := store.OpenSQLite(filepath.Join(dir, "x.db"), store.SQLiteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	AttachVerifier(st)

	admin, _ := Issue(context.Background(), st.Tokens(), "ops", []string{"admin"})

	// Owner user must exist for the FK on listener_tokens.owner_user_id.
	owner := uuid.NewString()
	if err := st.InsertUser(context.Background(), store.User{
		ID: owner, Email: "u@example.com", Name: "U", Role: store.RoleUser,
		PasswordHash: "x", CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	target := store.Token{
		ID: uuid.NewString(), Name: "target", Scopes: []string{"render"},
		SecretHash: "$argon2id$v=19$m=65536,t=1,p=4$aaaaaaaaaaaaaaaaaaaaaa$bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		CreatedAt:  time.Now().UTC(), OwnerUserID: &owner, Kind: store.TokenKindListener,
	}
	if err := st.Insert(context.Background(), target); err != nil {
		t.Fatal(err)
	}

	api := NewAPI(st.Tokens(), New(st.Tokens()))
	mux := http.NewServeMux()
	api.Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &patchOwnerFixture{st: st, srv: srv, admin: admin, target: target, otherUser: owner}
}

func (f *patchOwnerFixture) patch(t *testing.T, body string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPatch, f.srv.URL+"/api/tokens/"+f.target.ID, bytes.NewReader([]byte(body)))
	req.Header.Set("Authorization", "Bearer "+f.admin.Plaintext)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// Empty PATCH body MUST NOT silently transfer ownership to system. The
// earlier *string-based handler had this bug.
func TestPatchToken_EmptyBody_400(t *testing.T) {
	f := newPatchOwnerFixture(t)
	resp := f.patch(t, `{}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: %d (want 400)", resp.StatusCode)
	}
	got, _ := f.st.GetToken(context.Background(), f.target.ID)
	if got.OwnerUserID == nil {
		t.Error("owner unexpectedly cleared by empty PATCH")
	}
}

func TestPatchToken_NullOwner_TransfersToSystem(t *testing.T) {
	f := newPatchOwnerFixture(t)
	resp := f.patch(t, `{"owner_user_id": null}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	got, _ := f.st.GetToken(context.Background(), f.target.ID)
	if got.OwnerUserID != nil {
		t.Errorf("owner not cleared: %v", *got.OwnerUserID)
	}
}

func TestPatchToken_StringOwner_Reassigns(t *testing.T) {
	f := newPatchOwnerFixture(t)
	newOwner := uuid.NewString()
	if err := f.st.InsertUser(context.Background(), store.User{
		ID: newOwner, Email: "v@example.com", Name: "V", Role: store.RoleUser,
		PasswordHash: "x", CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	resp := f.patch(t, `{"owner_user_id":"`+newOwner+`"}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	got, _ := f.st.GetToken(context.Background(), f.target.ID)
	if got.OwnerUserID == nil || *got.OwnerUserID != newOwner {
		t.Errorf("owner: %v want %s", got.OwnerUserID, newOwner)
	}
}

func TestPatchToken_SystemLiteral_TransfersToSystem(t *testing.T) {
	f := newPatchOwnerFixture(t)
	resp := f.patch(t, `{"owner_user_id":"system"}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	got, _ := f.st.GetToken(context.Background(), f.target.ID)
	if got.OwnerUserID != nil {
		t.Errorf("owner not cleared: %v", *got.OwnerUserID)
	}
}

// A non-string non-null value (number, bool, array, object) must produce
// a clean 400, not a 500 or panic. The handler hands the bytes to
// json.Unmarshal-into-string, so a type mismatch returns
// json.UnmarshalTypeError; resolveOwner forwards it as a 400.
func TestPatchToken_NumericOwner_400(t *testing.T) {
	f := newPatchOwnerFixture(t)
	resp := f.patch(t, `{"owner_user_id": 42}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: %d (want 400)", resp.StatusCode)
	}
	got, _ := f.st.GetToken(context.Background(), f.target.ID)
	if got.OwnerUserID == nil {
		t.Error("owner unexpectedly cleared by malformed PATCH")
	}
}

func TestPatchToken_UnknownID_404(t *testing.T) {
	f := newPatchOwnerFixture(t)
	req, _ := http.NewRequest(http.MethodPatch, f.srv.URL+"/api/tokens/does-not-exist", bytes.NewReader([]byte(`{"owner_user_id":null}`)))
	req.Header.Set("Authorization", "Bearer "+f.admin.Plaintext)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status: %d", resp.StatusCode)
	}
}

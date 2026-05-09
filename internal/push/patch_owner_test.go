package push

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/onebusaway/hooks/internal/pubsub"
	"github.com/onebusaway/hooks/internal/store"
	"github.com/onebusaway/hooks/internal/tokens"
)

type patchSubFixture struct {
	st     *store.SQLite
	srv    *httptest.Server
	admin  tokens.IssueResult
	target store.PushSubscription
}

func newPatchSubFixture(t *testing.T) *patchSubFixture {
	t.Helper()
	dir := t.TempDir()
	st, err := store.OpenSQLite(filepath.Join(dir, "x.db"), store.SQLiteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	tokens.AttachVerifier(st)

	admin, _ := tokens.Issue(context.Background(), st.Tokens(), "ops", []string{"admin"})

	owner := uuid.NewString()
	if err := st.InsertUser(context.Background(), store.User{
		ID: owner, Email: "u@example.com", Name: "U", Role: store.RoleUser,
		PasswordHash: "x", CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	target := store.PushSubscription{
		ID: uuid.NewString(), Source: "render", TargetURL: "https://example.com/hook",
		SigningSecretHash: "x", CreatedAt: time.Now().UTC(), OwnerUserID: &owner,
	}
	if err := st.InsertPush(context.Background(), target); err != nil {
		t.Fatal(err)
	}

	notifier := pubsub.New()
	mgr := New(st.Events(), st.PushSubscriptions(), notifier, slog.New(slog.DiscardHandler))
	api := NewAPI(mgr, st.PushSubscriptions(), tokens.New(st.Tokens()), []string{"render"}, tokens.Hash)
	mux := http.NewServeMux()
	api.Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &patchSubFixture{st: st, srv: srv, admin: admin, target: target}
}

func (f *patchSubFixture) patch(t *testing.T, body string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPatch, f.srv.URL+"/api/push-subscriptions/"+f.target.ID, bytes.NewReader([]byte(body)))
	req.Header.Set("Authorization", "Bearer "+f.admin.Plaintext)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestPatchPushSub_EmptyBody_400(t *testing.T) {
	f := newPatchSubFixture(t)
	resp := f.patch(t, `{}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: %d (want 400)", resp.StatusCode)
	}
	got, _ := f.st.GetPush(context.Background(), f.target.ID)
	if got.OwnerUserID == nil {
		t.Error("owner unexpectedly cleared by empty PATCH")
	}
}

func TestPatchPushSub_NullOwner_TransfersToSystem(t *testing.T) {
	f := newPatchSubFixture(t)
	resp := f.patch(t, `{"owner_user_id":null}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	got, _ := f.st.GetPush(context.Background(), f.target.ID)
	if got.OwnerUserID != nil {
		t.Errorf("owner not cleared: %v", *got.OwnerUserID)
	}
}

// Numeric / bool / array values must produce a 400, not a 500 or panic.
func TestPatchPushSub_NumericOwner_400(t *testing.T) {
	f := newPatchSubFixture(t)
	resp := f.patch(t, `{"owner_user_id":42}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: %d (want 400)", resp.StatusCode)
	}
	got, _ := f.st.GetPush(context.Background(), f.target.ID)
	if got.OwnerUserID == nil {
		t.Error("owner unexpectedly cleared by malformed PATCH")
	}
}

func TestPatchPushSub_SystemLiteral_TransfersToSystem(t *testing.T) {
	f := newPatchSubFixture(t)
	resp := f.patch(t, `{"owner_user_id":"system"}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	got, _ := f.st.GetPush(context.Background(), f.target.ID)
	if got.OwnerUserID != nil {
		t.Errorf("owner not cleared: %v", *got.OwnerUserID)
	}
}

func TestPatchPushSub_UnknownID_404(t *testing.T) {
	f := newPatchSubFixture(t)
	req, _ := http.NewRequest(http.MethodPatch, f.srv.URL+"/api/push-subscriptions/does-not-exist",
		bytes.NewReader([]byte(`{"owner_user_id":null}`)))
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

func TestPatchPushSub_StringOwner_Reassigns(t *testing.T) {
	f := newPatchSubFixture(t)
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
	got, _ := f.st.GetPush(context.Background(), f.target.ID)
	if got.OwnerUserID == nil || *got.OwnerUserID != newOwner {
		t.Errorf("owner: %v want %s", got.OwnerUserID, newOwner)
	}
}

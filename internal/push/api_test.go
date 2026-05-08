package push

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/onebusaway/hooks/internal/pubsub"
	"github.com/onebusaway/hooks/internal/store"
	"github.com/onebusaway/hooks/internal/tokens"
)

func setupAPI(t *testing.T) (*API, *Manager, *store.SQLite, string) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.OpenSQLite(filepath.Join(dir, "x.db"), store.SQLiteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	tokens.AttachVerifier(st)

	res, err := tokens.Issue(context.Background(), st.Tokens(), "ops", []string{"admin"})
	if err != nil {
		t.Fatal(err)
	}

	notifier := pubsub.New()
	m := New(st.Events(), st.PushSubscriptions(), notifier, slog.New(slog.DiscardHandler))
	t.Cleanup(m.Stop)

	api := NewAPI(m, st.PushSubscriptions(), tokens.New(st.Tokens()), []string{"render"}, tokens.Hash)
	return api, m, st, res.Plaintext
}

func TestAPICreateRejectsUnknownSource(t *testing.T) {
	api, _, _, admin := setupAPI(t)
	mux := http.NewServeMux()
	api.Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	body := `{"source":"stripe","target_url":"http://x/y"}`
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/push-subscriptions", bytes.NewReader([]byte(body)))
	req.Header.Set("Authorization", "Bearer "+admin)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func TestAPICreateRejectsMultiSource(t *testing.T) {
	api, _, _, admin := setupAPI(t)
	mux := http.NewServeMux()
	api.Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	body := `{"sources":["render","stripe"],"target_url":"http://x/y"}`
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/push-subscriptions", bytes.NewReader([]byte(body)))
	req.Header.Set("Authorization", "Bearer "+admin)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d", resp.StatusCode)
	}
	bodyB, _ := io.ReadAll(resp.Body)
	if !bytes.Contains(bodyB, []byte("one source")) {
		t.Fatalf("unexpected error message: %s", bodyB)
	}
}

func TestAPICreateLifecycle(t *testing.T) {
	api, m, st, admin := setupAPI(t)
	mux := http.NewServeMux()
	api.Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	// Pre-load some events so cold-start cursor=latest is meaningful.
	for i := 0; i < 5; i++ {
		_, err := st.Append(context.Background(), store.AppendInput{
			Source:            "render",
			DeliveryID:        "d-" + time.Now().Format(time.RFC3339Nano) + "-" + string(rune('a'+i)),
			ProviderTimestamp: time.Now(),
			Headers:           map[string]string{},
			Body:              []byte("x"),
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	body := `{"source":"render","target_url":"http://example.com/hook","name":"staging"}`
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/push-subscriptions", bytes.NewReader([]byte(body)))
	req.Header.Set("Authorization", "Bearer "+admin)
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusCreated {
		bodyB, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d body %s", resp.StatusCode, bodyB)
	}
	var created struct {
		ID            string `json:"id"`
		Cursor        int64  `json:"cursor"`
		SigningSecret string `json:"signing_secret"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&created)
	resp.Body.Close()
	if created.ID == "" {
		t.Fatal("missing id")
	}
	if created.SigningSecret == "" {
		t.Fatal("missing signing_secret")
	}
	if created.Cursor != 5 {
		t.Fatalf("cold-start cursor = %d, want 5", created.Cursor)
	}

	// Ensure plaintext doesn't appear on a list view.
	req, _ = http.NewRequest(http.MethodGet, srv.URL+"/api/push-subscriptions", nil)
	req.Header.Set("Authorization", "Bearer "+admin)
	resp, _ = http.DefaultClient.Do(req)
	bodyB, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if bytes.Contains(bodyB, []byte(created.SigningSecret)) {
		t.Fatalf("list leaked plaintext secret: %s", bodyB)
	}

	// Rotate secret returns new plaintext.
	req, _ = http.NewRequest(http.MethodPost, srv.URL+"/api/push-subscriptions/"+created.ID+"/rotate-secret", nil)
	req.Header.Set("Authorization", "Bearer "+admin)
	resp, _ = http.DefaultClient.Do(req)
	var rot struct {
		SigningSecret string `json:"signing_secret"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&rot)
	resp.Body.Close()
	if rot.SigningSecret == "" || rot.SigningSecret == created.SigningSecret {
		t.Fatalf("rotate returned bad secret: %q -> %q", created.SigningSecret, rot.SigningSecret)
	}

	// Test action calls the manager (target unreachable will 502).
	req, _ = http.NewRequest(http.MethodPost, srv.URL+"/api/push-subscriptions/"+created.ID+"/test", nil)
	req.Header.Set("Authorization", "Bearer "+admin)
	resp, _ = http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("test against unreachable target: %d", resp.StatusCode)
	}

	// Pause / Resume.
	req, _ = http.NewRequest(http.MethodPost, srv.URL+"/api/push-subscriptions/"+created.ID+"/pause", nil)
	req.Header.Set("Authorization", "Bearer "+admin)
	resp, _ = http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("pause: %d", resp.StatusCode)
	}
	req, _ = http.NewRequest(http.MethodPost, srv.URL+"/api/push-subscriptions/"+created.ID+"/resume", nil)
	req.Header.Set("Authorization", "Bearer "+admin)
	resp, _ = http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("resume: %d", resp.StatusCode)
	}

	// Delete.
	req, _ = http.NewRequest(http.MethodDelete, srv.URL+"/api/push-subscriptions/"+created.ID, nil)
	req.Header.Set("Authorization", "Bearer "+admin)
	resp, _ = http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete: %d", resp.StatusCode)
	}
	_, err := st.PushSubscriptions().Get(context.Background(), created.ID)
	if err == nil {
		t.Fatal("subscription still present after delete")
	}
	_ = m
	// pre-existing manager workers don't matter for this assertion; we just
	// ensure HTTP wiring succeeded without holding a hot reference.
	_ = sync.Mutex{}
}

func TestAPIRequiresAdmin(t *testing.T) {
	api, _, st, _ := setupAPI(t)
	mux := http.NewServeMux()
	api.Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	res, _ := tokens.Issue(context.Background(), st.Tokens(), "user", []string{"render"})
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/push-subscriptions", nil)
	req.Header.Set("Authorization", "Bearer "+res.Plaintext)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

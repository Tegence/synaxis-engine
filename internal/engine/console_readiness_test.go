package engine

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// readinessTestStore keeps the real FileStore account-store implementation
// while exposing a deterministic durable-check seam for the public probe.
type readinessTestStore struct {
	*FileStore
	err   error
	calls int
}

func (s *readinessTestStore) CheckReadiness(context.Context) error {
	s.calls++
	return s.err
}

func readinessTestMux(store *readinessTestStore, lifecycle context.Context) *http.ServeMux {
	api := NewConsoleAPI(
		store,
		nil,
		nil,
		"password",
		"secret",
		"https://engine.example",
		"https://console.example",
		"",
		WithReadinessCheck(store.CheckReadiness),
		WithLifecycleContext(lifecycle),
	)
	mux := http.NewServeMux()
	api.Routes(mux)
	return mux
}

func readinessRequest(mux *http.ServeMux, method, path string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	return rec
}

func probePayload(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode probe payload: %v", err)
	}
	return payload
}

func TestConsoleReadinessChecksDurableStoreWithoutChangingLiveness(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store := &readinessTestStore{FileStore: &FileStore{}}
	mux := readinessTestMux(store, ctx)

	ready := readinessRequest(mux, http.MethodGet, "/readyz")
	if ready.Code != http.StatusOK {
		t.Fatalf("healthy readyz = %d, body=%s", ready.Code, ready.Body.String())
	}
	if store.calls != 1 {
		t.Fatalf("readyz durable checks = %d, want 1", store.calls)
	}
	if payload := probePayload(t, ready); payload["ready"] != true || payload["status"] != "ok" {
		t.Fatalf("healthy readyz payload = %v", payload)
	}

	store.err = errors.New("postgres connection refused at db.internal")
	unready := readinessRequest(mux, http.MethodGet, "/readyz")
	if unready.Code != http.StatusServiceUnavailable {
		t.Fatalf("failed-store readyz = %d, body=%s", unready.Code, unready.Body.String())
	}
	if payload := probePayload(t, unready); payload["ready"] != false || payload["status"] != "unavailable" {
		t.Fatalf("failed-store readyz payload = %v", payload)
	}
	if strings.Contains(unready.Body.String(), "db.internal") {
		t.Fatalf("readyz leaked durable-store failure: %s", unready.Body.String())
	}

	live := readinessRequest(mux, http.MethodGet, "/healthz")
	if live.Code != http.StatusOK {
		t.Fatalf("liveness during store outage = %d, body=%s", live.Code, live.Body.String())
	}
	if store.calls != 2 {
		t.Fatalf("healthz unexpectedly queried durable store; calls=%d", store.calls)
	}
}

func TestConsoleReadinessRejectsTrafficDuringShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	store := &readinessTestStore{FileStore: &FileStore{}}
	mux := readinessTestMux(store, ctx)
	cancel()

	ready := readinessRequest(mux, http.MethodGet, "/readyz")
	if ready.Code != http.StatusServiceUnavailable {
		t.Fatalf("draining readyz = %d, body=%s", ready.Code, ready.Body.String())
	}
	if payload := probePayload(t, ready); payload["ready"] != false || payload["status"] != "shutting_down" {
		t.Fatalf("draining readyz payload = %v", payload)
	}
	if store.calls != 0 {
		t.Fatalf("draining readyz called durable store %d times", store.calls)
	}

	live := readinessRequest(mux, http.MethodGet, "/healthz")
	if live.Code != http.StatusOK {
		t.Fatalf("liveness during draining = %d, body=%s", live.Code, live.Body.String())
	}
	if head := readinessRequest(mux, http.MethodHead, "/readyz"); head.Code != http.StatusServiceUnavailable || head.Body.Len() != 0 {
		t.Fatalf("draining HEAD readyz = %d body=%q", head.Code, head.Body.String())
	}
}

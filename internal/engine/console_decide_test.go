package engine

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/server"
)

// doHTML issues a request against mux with no bearer token — the one-time
// decide link is deliberately unauthenticated (see console_decide.go) — and
// returns the raw response.
func doHTML(t *testing.T, mux *http.ServeMux, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func TestOneTimeDecideGetRendersPendingForm(t *testing.T) {
	mux, _, g := newConnectorConsole(t, map[string][]string{"linear": {"save_issue"}})
	seedPending(t, g, "dec1", "eng", "linear", "save_issue")

	rec := doHTML(t, mux, http.MethodGet, "/a/dec1", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /a/dec1 = %d, body %s", rec.Code, rec.Body)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "save_issue") || !strings.Contains(body, "linear") {
		t.Fatalf("decide page missing tool/account context: %s", body)
	}
	if !strings.Contains(body, `action="/a/dec1/approve"`) || !strings.Contains(body, `action="/a/dec1/deny"`) {
		t.Fatalf("decide page missing approve/deny forms: %s", body)
	}

	// The "prk_"-prefixed id (what decide_url actually carries) resolves to
	// the exact same row.
	rec = doHTML(t, mux, http.MethodGet, "/a/prk_dec1", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "save_issue") {
		t.Fatalf("GET /a/prk_dec1 = %d, body %s", rec.Code, rec.Body)
	}
}

func TestOneTimeDecideApproveCommitsAndConfirms(t *testing.T) {
	mux, tok, g := newConnectorConsole(t, map[string][]string{"linear": {"save_issue"}})
	seedPending(t, g, "dec2", "eng", "linear", "save_issue")

	rec := doHTML(t, mux, http.MethodPost, "/a/dec2/approve", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("POST approve = %d, body %s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "Already approved") {
		t.Fatalf("approve confirmation missing: %s", rec.Body)
	}

	// The authenticated console sees the exact same durable decision.
	rec2, _ := doJSON(t, mux, tok, http.MethodGet, "/api/approvals", "")
	if rec2.Code != http.StatusOK || !strings.Contains(rec2.Body.String(), `"status":"approved"`) {
		t.Fatalf("GET /api/approvals after one-time approve = %d, body %s", rec2.Code, rec2.Body)
	}

	// A second click is idempotent — still 200, still "already approved",
	// and does not flip to denied.
	rec = doHTML(t, mux, http.MethodPost, "/a/dec2/approve", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Already approved") {
		t.Fatalf("idempotent re-approve = %d, body %s", rec.Code, rec.Body)
	}

	// A contradictory decision after the fact is reported, not silently
	// applied — the row stays approved.
	rec = doHTML(t, mux, http.MethodPost, "/a/dec2/deny", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Already approved") {
		t.Fatalf("deny-after-approve = %d, body %s, want it to report the existing approval", rec.Code, rec.Body)
	}
}

func TestOneTimeDecideDeny(t *testing.T) {
	mux, _, g := newConnectorConsole(t, map[string][]string{"linear": {"save_issue"}})
	seedPending(t, g, "dec3", "eng", "linear", "save_issue")

	rec := doHTML(t, mux, http.MethodPost, "/a/dec3/deny", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Already denied") {
		t.Fatalf("POST deny = %d, body %s", rec.Code, rec.Body)
	}
}

func TestOneTimeDecideUnknownID(t *testing.T) {
	mux, _, _ := newConnectorConsole(t, map[string][]string{"linear": {"save_issue"}})

	rec := doHTML(t, mux, http.MethodGet, "/a/ghost", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET unknown id = %d, want 404", rec.Code)
	}
	rec = doHTML(t, mux, http.MethodPost, "/a/ghost/approve", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("POST unknown id = %d, want 404", rec.Code)
	}
}

func TestOneTimeDecideWrongMethod(t *testing.T) {
	mux, _, g := newConnectorConsole(t, map[string][]string{"linear": {"save_issue"}})
	seedPending(t, g, "dec4", "eng", "linear", "save_issue")

	if rec := doHTML(t, mux, http.MethodPost, "/a/dec4", ""); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /a/{id} = %d, want 405", rec.Code)
	}
	if rec := doHTML(t, mux, http.MethodGet, "/a/dec4/approve", ""); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET /a/{id}/approve = %d, want 405", rec.Code)
	}
}

// TestOneTimeDecide501WithoutApprovalLog mirrors
// TestApprovalAPI501WithoutApprovalLog for the unauthenticated decide
// actions: a store without the ApprovalLog facet must fail closed, not
// silently 404 (which would be indistinguishable from "no such link").
func TestOneTimeDecide501WithoutApprovalLog(t *testing.T) {
	fs, err := LoadFileStore(filepath.Join(t.TempDir(), "accounts.json"))
	if err != nil {
		t.Fatalf("file store: %v", err)
	}
	g := NewGateway(accountsOnly{fs}, server.NewMCPServer("test", "0.0.0", server.WithToolCapabilities(true)))
	api := NewConsoleAPI(accountsOnly{fs}, g, nil, "pw", "test-secret", "https://engine.example", "http://localhost:3000", "")
	mux := http.NewServeMux()
	api.Routes(mux)

	rec := doHTML(t, mux, http.MethodPost, "/a/x/approve", "")
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("POST /a/x/approve without ApprovalLog = %d, want 501", rec.Code)
	}
}

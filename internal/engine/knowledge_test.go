package engine

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func knowledgeContract(t *testing.T, s KnowledgeStore, source string) {
	t.Helper()
	ctx := context.Background()
	d := KnowledgeDocument{Source: source, ID: "tasks/one", Version: 1, Title: "Quarterly planning", Text: "Private source content"}
	if err := s.PutKnowledge(ctx, d); err != nil {
		t.Fatal(err)
	}
	if err := s.PutKnowledge(ctx, d); err != nil {
		t.Fatal(err)
	}
	changed := d
	changed.Text = "conflicting content"
	if err := s.PutKnowledge(ctx, changed); !errors.Is(err, ErrKnowledgeConflict) {
		t.Fatal(err)
	}
	page, err := searchKnowledge(ctx, s, source, "quarterly", 0)
	if err != nil || len(page.Items) != 1 {
		t.Fatal(page, err)
	}
	raw, _ := json.Marshal(page)
	if strings.Contains(string(raw), "Private") || strings.Contains(string(raw), "planning") {
		t.Fatal("index returned source content")
	}
	other, err := searchKnowledge(ctx, s, source+"-other", "quarterly", 0)
	if err != nil || len(other.Items) != 0 {
		t.Fatal("source leaked", other, err)
	}
	tombstone := KnowledgeDocument{Source: source, ID: d.ID, Version: 2, Deleted: true}
	if err = s.PutKnowledge(ctx, tombstone); err != nil {
		t.Fatal(err)
	}
	if err = s.PutKnowledge(ctx, d); err != nil {
		t.Fatal(err)
	}
	page, err = searchKnowledge(ctx, s, source, "quarterly", 0)
	if err != nil || len(page.Items) != 0 {
		t.Fatal("stale write resurrected tombstone", page, err)
	}
}
func TestKnowledgeFilePersistenceAndVersioning(t *testing.T) {
	path := filepath.Join(t.TempDir(), "engine.json")
	s, err := LoadFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	knowledgeContract(t, s, "source")
	again, err := LoadFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = again.PutKnowledge(context.Background(), KnowledgeDocument{Source: "source", ID: "tasks/one", Version: 1, Title: "Quarterly planning"}); err != nil {
		t.Fatal(err)
	}
	page, err := searchKnowledge(context.Background(), again, "source", "quarterly", 0)
	if err != nil || len(page.Items) != 0 {
		t.Fatal("restart lost tombstone")
	}
}
func TestKnowledgeSourceCredentialBoundary(t *testing.T) {
	s, _ := LoadFileStore(filepath.Join(t.TempDir(), "engine.json"))
	c := NewConsoleAPI(s, nil, nil, "", "secret", "http://localhost", "", "", WithAdminToken("engine-admin"))
	mux := http.NewServeMux()
	c.Routes(mux)
	token := knowledgeToken(knowledgeSigningKey("engine-admin"), "praxis.one")
	call := func(source, bearer, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/knowledge/v1/sources/"+source+"/search", strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+bearer)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}
	for _, token := range []string{"", "engine-admin", knowledgeToken(knowledgeSigningKey("other-engine"), "praxis.one")} {
		if w := call("praxis.one", token, `{"query":"test"}`); w.Code != 401 {
			t.Fatal(w.Code)
		}
	}
	if w := call("praxis.two", token, `{"query":"test"}`); w.Code != 401 {
		t.Fatal("cross-source credential accepted")
	}
	if w := call("praxis.one", token, `{"query":"test"}`); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := call("praxis.one", token, `{"query":"test"} {}`); w.Code != 400 {
		t.Fatal("trailing JSON accepted")
	}
	r := httptest.NewRequest("GET", "/control/v1/meta", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatal("source credential became admin", w.Code)
	}
}
func TestKnowledgePostgresContract(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL required")
	}
	s, err := NewPgStore(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.SetCipher(testCipher(t, 42))
	source := "knowledge-test"
	defer s.pool.Exec(context.Background(), `DELETE FROM synaxis_knowledge_documents WHERE source=$1`, source)
	_, err = s.pool.Exec(context.Background(), `DELETE FROM synaxis_knowledge_documents WHERE source=$1`, source)
	if err != nil {
		t.Fatal(err)
	}
	secret := KnowledgeDocument{Source: source, ID: "private", Version: 1, Text: "confidential source text"}
	if err = s.PutKnowledge(context.Background(), secret); err != nil {
		t.Fatal(err)
	}
	var raw string
	if err = s.pool.QueryRow(context.Background(), `SELECT payload FROM synaxis_knowledge_documents WHERE source=$1 AND id='private'`, source).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(raw, "confidential") || !strings.HasPrefix(raw, encPrefix) {
		t.Fatal("knowledge payload not encrypted")
	}
	knowledgeContract(t, s, source)
}

func TestKnowledgeHostedCredentialRequiresServiceActor(t *testing.T) {
	mux, _, key, now, _ := newHostedControlConsole(t)
	path := "/control/v1/knowledge/sources/praxis.example/credential"
	for _, role := range []string{"viewer", "operator", "admin", "owner"} {
		response := controlRequest(t, mux, key, now, "usr_one", role, http.MethodPost, path, "")
		if response.Code != http.StatusForbidden {
			t.Fatal("human actor minted index credential", role, response.Code, response.Body.String())
		}
	}
	response := controlRequest(t, mux, key, now, platformServiceActorID, "service", http.MethodPost, path, "")
	if response.Code != http.StatusOK {
		t.Fatal("service credential failed", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Header().Get("Cache-Control"), "no-store") {
		t.Fatal("credential response cacheable")
	}
}

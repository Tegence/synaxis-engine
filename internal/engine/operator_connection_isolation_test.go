package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"testing"
)

func TestFileOperatorPersonalFolderLifecycle(t *testing.T) {
	testOperatorPersonalFolderLifecycle(t, newLibraryFileStore(t))
}

func TestPgOperatorPersonalFolderLifecycle(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL required")
	}
	s, err := NewPgStore(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	testOperatorPersonalFolderLifecycle(t, s)
}

func testOperatorPersonalFolderLifecycle(t *testing.T, store governedConnectionStore) {
	t.Helper()
	verifier, key, now := newActorVerifier(t)
	api := NewConsoleAPI(store, NewGateway(store, nil), nil, "", "local-secret", "https://engine.example", "https://app.example", "",
		WithAdminToken("machine-token"), WithLocalAdminAuth(false), WithPlatformActorVerifier(verifier))
	mux := http.NewServeMux()
	api.Routes(mux)
	owner := "usr_folder_owner_" + newEpoch()
	other := "usr_folder_other_" + newEpoch()
	request := func(user, role, method, path, body string, want int) []byte {
		t.Helper()
		response := hostedNamespaceRequest(t, mux, key, now, user, role, method, path, body)
		if response.Code != want {
			t.Fatalf("%s %s as %s = %d: %s; want %d", method, path, role, response.Code, response.Body, want)
		}
		return response.Body.Bytes()
	}
	var folder connectionNamespaceDTO
	if err := json.Unmarshal(request(owner, "operator", http.MethodPost, "/api/connection-namespaces", `{"label":"My research"}`, http.StatusCreated), &folder); err != nil {
		t.Fatal(err)
	}
	if pg, ok := store.(*PgStore); ok {
		t.Cleanup(func() {
			if _, err := pg.pool.Exec(context.Background(), `DELETE FROM narthex_connection_namespaces WHERE id=$1`, folder.ID); err != nil {
				t.Errorf("cleanup folder: %v", err)
			}
		})
	}
	path := "/api/connection-namespaces/" + folder.ID
	if folder.OwnerSubject != owner || !folder.CanManage || !folder.CanDelete || folder.CanManageMembership {
		t.Fatalf("wrong personal folder permissions: %+v", folder)
	}
	for _, attempt := range []struct{ method, body string }{
		{http.MethodGet, ""},
		{http.MethodPatch, fmt.Sprintf(`{"label":"Stolen","revision":%d}`, folder.Revision)},
		{http.MethodDelete, fmt.Sprintf(`{"revision":%d}`, folder.Revision)},
	} {
		request(other, "operator", attempt.method, path, attempt.body, http.StatusNotFound)
	}
	request(owner, "operator", http.MethodGet, path, "", http.StatusOK)
	request("usr_admin", "admin", http.MethodGet, path, "", http.StatusOK)
	// Private ownership permits ordinary folder management, never delegation.
	for _, suffix := range []string{"/managers", "/managers/" + other} {
		request("usr_admin", "admin", http.MethodPut, path+suffix,
			fmt.Sprintf(`{"revision":%d,"managers":[%q]}`, folder.Revision, other), http.StatusForbidden)
	}
	raw := request(owner, "operator", http.MethodPatch, path,
		fmt.Sprintf(`{"label":"My renamed research","revision":%d}`, folder.Revision), http.StatusOK)
	var renamed connectionNamespaceDTO
	if err := json.Unmarshal(raw, &renamed); err != nil {
		t.Fatal(err)
	}
	if renamed.Label != "My renamed research" || renamed.OwnerSubject != owner || renamed.ID != folder.ID || renamed.Slug != folder.Slug {
		t.Fatalf("rename changed identity or ownership: %+v", renamed)
	}
	request(owner, "operator", http.MethodPatch, path, fmt.Sprintf(`{"label":"Stale","revision":%d}`, folder.Revision), http.StatusConflict)
	request(owner, "operator", http.MethodDelete, path, fmt.Sprintf(`{"revision":%d}`, renamed.Revision), http.StatusNoContent)
	request(owner, "operator", http.MethodGet, path, "", http.StatusNotFound)
}

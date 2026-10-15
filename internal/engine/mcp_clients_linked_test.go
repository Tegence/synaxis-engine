package engine

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func exerciseLinkedWorkload(t *testing.T, store MCPClientStore) []string {
	t.Helper()
	ctx := context.Background()
	source, err := store.CreateMCPClient(ctx, MCPClient{Name: "Linked Codex", Subject: "usr_linked"})
	if err != nil {
		t.Fatal(err)
	}
	source, err = store.BindMCPClientOAuthClient(ctx, source.ID, "mcp-linked-"+source.ID, MCPClientPrecondition{ID: source.ID, Revision: source.Revision}, PlatformActor{UserID: source.Subject, Role: "operator"})
	if err != nil {
		t.Fatal(err)
	}
	input := MCPClient{Name: "Linked jobs", Subject: "agt_linked", Kind: MCPClientKindWorkload, InteractiveClientID: source.ID, SourceRevision: source.Revision}
	stale := input
	stale.SourceRevision--
	if _, err := store.CreateMCPClient(ctx, stale); !errors.Is(err, ErrMCPClientRevision) {
		t.Fatalf("stale source revision: %v", err)
	}
	invalid := input
	invalid.Kind = MCPClientKindInteractive
	if _, err := store.CreateMCPClient(ctx, invalid); !errors.Is(err, ErrInvalidMCPClient) {
		t.Fatalf("interactive cannot link: %v", err)
	}
	child, err := store.CreateMCPClient(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	if child.InteractiveClientID != source.ID || child.Subject == source.Subject || child.OAuthClientID != "" || len(child.ConnectionNamespaceIDs)+len(child.ConnectionIDs) != 0 {
		t.Fatalf("link changed authority: %+v", child)
	}
	current, _ := store.MCPClient(ctx, source.ID)
	if current.OAuthClientID != source.OAuthClientID || current.Slug != source.Slug || current.Epoch != source.Epoch || current.Revision != source.Revision {
		t.Fatal("link mutated existing OAuth identity")
	}
	if _, err := store.CreateMCPClient(ctx, input); !errors.Is(err, ErrMCPClientExists) {
		t.Fatalf("duplicate child: %v", err)
	}
	invalid = input
	invalid.InteractiveClientID = child.ID
	invalid.SourceRevision = child.Revision
	if _, err := store.CreateMCPClient(ctx, invalid); !errors.Is(err, ErrMCPClientKind) {
		t.Fatalf("cannot chain workload: %v", err)
	}
	child, err = store.BindMCPClientWorkloadIdentity(ctx, child.ID)
	if err != nil {
		t.Fatal(err)
	}
	if child.OAuthClientID != workloadOAuthClientID(child.ID) {
		t.Fatal("wrong workload identity")
	}
	if _, ok := store.ActiveMCPClient(ctx, child.ID); !ok {
		t.Fatal("child not active")
	}
	updated := child
	updated.InteractiveClientID = "other_source"
	if _, err := store.UpdateMCPClient(ctx, updated, MCPClientPrecondition{ID: child.ID, Revision: child.Revision}); !errors.Is(err, ErrInvalidMCPClient) {
		t.Fatalf("mutable source link: %v", err)
	}
	if _, err := store.RevokeMCPClient(ctx, source.ID, source.Subject, MCPClientPrecondition{ID: source.ID, Revision: source.Revision}); err != nil {
		t.Fatal(err)
	}
	after, found := store.MCPClient(ctx, child.ID)
	if !found || after.Status != MCPClientStatusRevoked || after.Epoch == child.Epoch || after.Revision <= child.Revision {
		t.Fatal("source revocation did not cascade")
	}
	if _, ok := store.ActiveMCPClient(ctx, child.ID); ok {
		t.Fatal("revoked child served")
	}
	if _, ok := store.ActiveMCPClientByOAuthClientID(ctx, child.OAuthClientID); ok {
		t.Fatal("revoked child OAuth served")
	}
	if _, err := store.BindMCPClientWorkloadIdentity(ctx, child.ID); !errors.Is(err, ErrMCPClientRevoked) {
		t.Fatalf("revoked token bind: %v", err)
	}
	if _, err := store.CreateMCPClient(ctx, input); !errors.Is(err, ErrMCPClientRevoked) {
		t.Fatalf("revoked source accepted: %v", err)
	}
	return []string{source.ID, child.ID}
}

func TestFileStoreLinkedWorkloadPreservesOAuthAndCascadesRevocation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "linked.json")
	store, err := LoadFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	ids := exerciseLinkedWorkload(t, store)
	reloaded, err := LoadFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	child, ok := reloaded.MCPClient(context.Background(), ids[1])
	if !ok || child.InteractiveClientID != ids[0] || child.Status != MCPClientStatusRevoked {
		t.Fatal("link did not survive reload")
	}
}

func TestPgStoreLinkedWorkloadPreservesOAuthAndCascadesRevocation(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL required")
	}
	store, err := NewPgStore(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ids := exerciseLinkedWorkload(t, store)
	defer func() {
		_, _ = store.pool.Exec(context.Background(), `DELETE FROM narthex_library_skill_bindings WHERE scope_id=ANY($1)`, ids)
		_, _ = store.pool.Exec(context.Background(), `DELETE FROM narthex_mcp_clients WHERE id=ANY($1)`, ids)
	}()
	child, ok := store.MCPClient(context.Background(), ids[1])
	if !ok || child.InteractiveClientID != ids[0] {
		t.Fatal("link not persisted")
	}
}

func TestLinkedWorkloadRequiresExplicitWorkspaceScopes(t *testing.T) {
	ctx := context.Background()
	store, err := LoadFileStore(filepath.Join(t.TempDir(), "scopes.json"))
	if err != nil {
		t.Fatal(err)
	}
	folder, err := store.CreateConnectionNamespace(ctx, ConnectionNamespace{Label: "Job connections", CreatedBy: "usr_owner"})
	if err != nil {
		t.Fatal(err)
	}
	shared := Account{Name: "shared_job", URL: "https://example.test/mcp", AuthMode: "token", BearerToken: "test", ConnectionNamespaceID: folder.ID}
	if err := store.Create(ctx, shared); err != nil {
		t.Fatal(err)
	}
	personal := shared
	personal.Name = "personal_job"
	personal.ConnectionScope = ConnectionScopePersonal
	personal.OwnerSubject = "agt_linked"
	if err := store.Create(ctx, personal); err != nil {
		t.Fatal(err)
	}
	source, err := store.CreateMCPClient(ctx, MCPClient{Name: "Codex", Subject: "usr_owner"})
	if err != nil {
		t.Fatal(err)
	}
	input := MCPClient{Name: "Jobs", Subject: "agt_linked", Kind: MCPClientKindWorkload, InteractiveClientID: source.ID, SourceRevision: source.Revision, ConnectionIDs: []string{personal.Name}}
	if _, err := store.CreateMCPClient(ctx, input); !errors.Is(err, ErrMCPClientNamespaceSubject) {
		t.Fatalf("personal exact grant admitted: %v", err)
	}
	input.ConnectionIDs = nil
	input.ConnectionNamespaceIDs = []string{folder.ID}
	if _, err := store.CreateMCPClient(ctx, input); !errors.Is(err, ErrMCPClientNamespaceSubject) {
		t.Fatalf("personal folder admitted: %v", err)
	}
	input.ConnectionNamespaceIDs = nil
	input.ConnectionIDs = []string{shared.Name}
	client, err := store.CreateMCPClient(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	account, _ := store.Account(shared.Name)
	if !mcpClientDeliversAccount(client, account) {
		t.Fatal("reviewed workspace connection unavailable")
	}
	unchanged, _ := store.MCPClient(ctx, source.ID)
	if len(unchanged.ConnectionIDs)+len(unchanged.ConnectionNamespaceIDs) != 0 {
		t.Fatal("job grant widened external app scope")
	}
}

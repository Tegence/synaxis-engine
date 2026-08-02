package engine

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

type tokenGenerationStoreContract interface {
	LoadOrCreateTokenGeneration(context.Context, string) (string, error)
	CurrentTokenGeneration(context.Context) (string, error)
	RotateTokenGeneration(context.Context, string, string) (string, error)
}

// Both stores must satisfy ConnectorStore and ApprovalLog.
var (
	_ AccountStore                 = (*FileStore)(nil)
	_ AccountStore                 = (*PgStore)(nil)
	_ PortableAccountConfigStore   = (*FileStore)(nil)
	_ PortableAccountConfigStore   = (*PgStore)(nil)
	_ ConnectorStore               = (*FileStore)(nil)
	_ ConnectorStore               = (*PgStore)(nil)
	_ ConnectionNamespaceStore     = (*FileStore)(nil)
	_ ConnectionNamespaceStore     = (*PgStore)(nil)
	_ ApprovalLog                  = (*FileStore)(nil)
	_ ApprovalLog                  = (*PgStore)(nil)
	_ tokenGenerationStoreContract = (*FileStore)(nil)
	_ tokenGenerationStoreContract = (*PgStore)(nil)
)

func TestFileStoreSetMetaIsLabelOnlyAndRejectsStaleGroupOwnership(t *testing.T) {
	ctx := context.Background()
	store, err := LoadFileStore(filepath.Join(t.TempDir(), "accounts.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Create(ctx, Account{
		Name: "notion", Label: "Notion", Group: "Source", URL: "https://notion.example/mcp", AuthMode: "token", BearerToken: "secret",
	}); err != nil {
		t.Fatal(err)
	}
	before, ok := store.Account("notion")
	if !ok {
		t.Fatal("account missing")
	}
	if err := store.SetMeta(ctx, before.Name, "Stale label", "Old group"); !errors.Is(err, ErrConnectionNamespaceRevision) {
		t.Fatalf("SetMeta group reassignment = %v, want ErrConnectionNamespaceRevision", err)
	}
	afterRejected, ok := store.Account(before.Name)
	if !ok || afterRejected.Label != before.Label || afterRejected.Group != before.Group ||
		afterRejected.ConnectionNamespaceID != before.ConnectionNamespaceID || afterRejected.Revision != before.Revision {
		t.Fatalf("rejected SetMeta changed ownership or label: before=%+v after=%+v", before, afterRejected)
	}
	if err := store.SetMeta(ctx, before.Name, "Renamed Notion", before.Group); err != nil {
		t.Fatalf("label-only SetMeta: %v", err)
	}
	afterRename, _ := store.Account(before.Name)
	if afterRename.Label != "Renamed Notion" || afterRename.Group != before.Group ||
		afterRename.ConnectionNamespaceID != before.ConnectionNamespaceID || afterRename.Revision != before.Revision+1 {
		t.Fatalf("label-only SetMeta = %+v; before=%+v", afterRename, before)
	}
}

func TestFileStorePortableConfigUpdateCannotUndoMovedOwnership(t *testing.T) {
	ctx := context.Background()
	store, err := LoadFileStore(filepath.Join(t.TempDir(), "accounts.json"))
	if err != nil {
		t.Fatal(err)
	}
	source, err := store.CreateConnectionNamespace(ctx, ConnectionNamespace{Label: "Source"})
	if err != nil {
		t.Fatal(err)
	}
	target, err := store.CreateConnectionNamespace(ctx, ConnectionNamespace{Label: "Target"})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Create(ctx, Account{
		Name: "notion", Label: "Before import", Group: source.Label,
		ConnectionNamespaceID: source.ID, ConnectionScope: ConnectionScopeShared,
		URL: "https://notion.example/mcp", AuthMode: "token", BearerToken: "secret",
	}); err != nil {
		t.Fatal(err)
	}
	staleSnapshot, ok := store.Account("notion")
	if !ok {
		t.Fatal("account missing before move")
	}
	if _, err := store.MoveAccountToConnectionNamespace(ctx, staleSnapshot.Name, staleSnapshot.IncarnationID, AccountConnectionAssignment{
		ConnectionNamespaceID: target.ID, Scope: ConnectionScopeShared,
	}, staleSnapshot.Revision); err != nil {
		t.Fatalf("move after export snapshot: %v", err)
	}
	// A portable import may still hold staleSnapshot's old Group and namespace.
	// The metadata-only update intentionally accepts only its safe fields.
	updated, err := store.UpdatePortableAccountConfig(ctx, staleSnapshot.Name, PortableAccountConfig{
		Label: "Imported label", URL: staleSnapshot.URL, ReadOnly: true,
		DisabledTools: []string{"write"}, ToolOverrides: map[string]ToolOverride{"search": {Alias: "find"}},
	})
	if err != nil {
		t.Fatalf("apply stale portable metadata: %v", err)
	}
	if updated.ConnectionNamespaceID != target.ID || updated.ConnectionScope != ConnectionScopeShared || updated.Group != target.Label ||
		updated.Label != "Imported label" || !updated.ReadOnly || updated.ToolOverrides["search"].Alias != "find" {
		t.Fatalf("portable metadata update restored stale ownership: %+v", updated)
	}
}

func TestFileStoreCreateRejectsExistingAccountAndUpsertStillUpdates(t *testing.T) {
	ctx := context.Background()
	s, err := LoadFileStore(filepath.Join(t.TempDir(), "accounts.json"))
	if err != nil {
		t.Fatalf("LoadFileStore: %v", err)
	}
	original := Account{Name: "acme", Label: "Acme", URL: "https://original.example/mcp", AuthMode: "token", BearerToken: "original"}
	if err := s.Create(ctx, original); err != nil {
		t.Fatalf("Create original: %v", err)
	}

	replacement := Account{Name: "acme", Label: "Replacement", URL: "https://replacement.example/mcp", AuthMode: "token", BearerToken: "replacement"}
	if err := s.Create(ctx, replacement); !errors.Is(err, ErrAccountExists) {
		t.Fatalf("Create duplicate = %v; want ErrAccountExists", err)
	}
	got, _ := s.Account("acme")
	if got.Label != original.Label || got.URL != original.URL || got.BearerToken != original.BearerToken {
		t.Fatalf("Create duplicate mutated original: %+v", got)
	}

	if err := s.Upsert(ctx, replacement); err != nil {
		t.Fatalf("explicit Upsert replacement: %v", err)
	}
	got, _ = s.Account("acme")
	if got.Label != replacement.Label || got.URL != replacement.URL || got.BearerToken != replacement.BearerToken {
		t.Fatalf("Upsert did not update original: %+v", got)
	}
}

func TestFileStoreAccountIncarnationIsStoreOwnedImmutableAndNeverReused(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "accounts.json")
	store, err := LoadFileStore(path)
	if err != nil {
		t.Fatalf("LoadFileStore: %v", err)
	}

	if err := store.Create(ctx, Account{
		Name: "notion", URL: "https://notion.example/mcp", AuthMode: "token",
		BearerToken: "first", IncarnationID: "caller-controlled",
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	first, _ := store.Account("notion")
	if first.IncarnationID == "" || first.IncarnationID == "caller-controlled" {
		t.Fatalf("Create accepted caller incarnation %q", first.IncarnationID)
	}

	updated := first
	updated.Label = "Notion updated"
	updated.IncarnationID = "replacement-attempt"
	if err := store.Upsert(ctx, updated); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	afterUpdate, _ := store.Account("notion")
	if afterUpdate.IncarnationID != first.IncarnationID {
		t.Fatalf("Upsert changed incarnation from %q to %q", first.IncarnationID, afterUpdate.IncarnationID)
	}

	if err := store.Delete(ctx, "notion", afterUpdate.IncarnationID, afterUpdate.Revision); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := store.Create(ctx, Account{
		Name: "notion", URL: first.URL, AuthMode: "token", BearerToken: "second",
		IncarnationID: first.IncarnationID,
	}); err != nil {
		t.Fatalf("recreate: %v", err)
	}
	recreated, _ := store.Account("notion")
	if recreated.IncarnationID == "" || recreated.IncarnationID == first.IncarnationID {
		t.Fatalf("recreated account reused incarnation %q", recreated.IncarnationID)
	}
	if err := store.UpdateTokens(ctx, recreated.Name, first.IncarnationID, "stale-access", "stale-refresh"); !errors.Is(err, ErrAccountIncarnation) {
		t.Fatalf("stale UpdateTokens = %v, want ErrAccountIncarnation", err)
	}
	if err := store.Delete(ctx, recreated.Name, first.IncarnationID, first.Revision); !errors.Is(err, ErrAccountIncarnation) {
		t.Fatalf("stale Delete = %v, want ErrAccountIncarnation", err)
	}
	if _, err := store.SetBearerToken(ctx, recreated.Name, first.IncarnationID, "stale-bearer", first.Revision); !errors.Is(err, ErrAccountIncarnation) {
		t.Fatalf("stale SetBearerToken = %v, want ErrAccountIncarnation", err)
	}
	target, err := store.CreateConnectionNamespace(ctx, ConnectionNamespace{Label: "Replacement target"})
	if err != nil {
		t.Fatalf("create target namespace: %v", err)
	}
	if _, err := store.MoveAccountToConnectionNamespace(ctx, recreated.Name, first.IncarnationID, AccountConnectionAssignment{
		ConnectionNamespaceID: target.ID, Scope: ConnectionScopeShared,
	}, first.Revision); !errors.Is(err, ErrAccountIncarnation) {
		t.Fatalf("stale MoveAccountToConnectionNamespace = %v, want ErrAccountIncarnation", err)
	}
	unchanged, ok := store.Account(recreated.Name)
	if !ok || unchanged.IncarnationID != recreated.IncarnationID || unchanged.BearerToken != "second" || unchanged.AccessToken != "" {
		t.Fatalf("stale writes changed replacement account: %+v, ok=%v", unchanged, ok)
	}

	reopened, err := LoadFileStore(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	persisted, _ := reopened.Account("notion")
	if persisted.IncarnationID != recreated.IncarnationID {
		t.Fatalf("incarnation did not persist: got %q, want %q", persisted.IncarnationID, recreated.IncarnationID)
	}
}

func TestFileStoreTokenGenerationPersistsAndRotatesAcrossRestarts(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "accounts.json")
	first, err := LoadFileStore(path)
	if err != nil {
		t.Fatalf("LoadFileStore: %v", err)
	}
	generation, err := first.LoadOrCreateTokenGeneration(ctx, "generation-one")
	if err != nil {
		t.Fatalf("LoadOrCreateTokenGeneration: %v", err)
	}
	if generation != "generation-one" {
		t.Fatalf("initial generation = %q, want generation-one", generation)
	}

	second, err := LoadFileStore(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	generation, err = second.LoadOrCreateTokenGeneration(ctx, "must-not-replace")
	if err != nil {
		t.Fatalf("LoadOrCreateTokenGeneration after restart: %v", err)
	}
	if generation != "generation-one" {
		t.Fatalf("restart replaced generation with %q", generation)
	}
	current, err := second.CurrentTokenGeneration(ctx)
	if err != nil {
		t.Fatalf("CurrentTokenGeneration after restart: %v", err)
	}
	if current != "generation-one" {
		t.Fatalf("current generation = %q, want generation-one", current)
	}
	generation, err = second.RotateTokenGeneration(ctx, "generation-one", "generation-two")
	if err != nil {
		t.Fatalf("RotateTokenGeneration: %v", err)
	}
	if generation != "generation-two" {
		t.Fatalf("rotated generation = %q, want generation-two", generation)
	}

	third, err := LoadFileStore(path)
	if err != nil {
		t.Fatalf("reload after rotation: %v", err)
	}
	generation, err = third.LoadOrCreateTokenGeneration(ctx, "must-not-resurrect")
	if err != nil {
		t.Fatalf("LoadOrCreateTokenGeneration after rotation: %v", err)
	}
	if generation != "generation-two" {
		t.Fatalf("rotated generation did not persist: %q", generation)
	}
	generation, err = third.RotateTokenGeneration(ctx, "generation-one", "stale-replacement")
	if err != nil {
		t.Fatalf("stale RotateTokenGeneration: %v", err)
	}
	if generation != "generation-two" {
		t.Fatalf("stale rotation overwrote current generation with %q", generation)
	}
}

// TestFileStoreConnectorCRUD proves connector round-trips through the JSON
// file: upsert, get, list, update, delete — and that everything survives a
// reload from disk (the property that matters across engine restarts).
func TestFileStoreConnectorCRUD(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "accounts.json")
	s, err := LoadFileStore(path)
	if err != nil {
		t.Fatalf("LoadFileStore: %v", err)
	}

	// Accounts and connectors coexist in the same file.
	if err := s.Upsert(ctx, Account{Name: "acct1", URL: "https://x/mcp", AuthMode: "token", BearerToken: "T"}); err != nil {
		t.Fatalf("Upsert account: %v", err)
	}

	vc := VirtualConnector{
		Slug:  "eng",
		Label: "Engineering",
		Tools: map[string][]string{"acct1": {"list_issues", "get_issue"}, "acct2": {}},
	}
	if err := s.UpsertConnector(ctx, vc); err != nil {
		t.Fatalf("UpsertConnector: %v", err)
	}

	got, ok := s.VirtualConnector(ctx, "eng")
	if !ok {
		t.Fatal("VirtualConnector: not found after upsert")
	}
	if got.Label != "Engineering" || len(got.Tools["acct1"]) != 2 || got.Tools["acct1"][0] != "list_issues" {
		t.Fatalf("round-trip mismatch: %+v", got)
	}

	// Returned value is a copy — mutating it must not touch store state.
	got.Tools["acct1"][0] = "mutated"
	again, _ := s.VirtualConnector(ctx, "eng")
	if again.Tools["acct1"][0] != "list_issues" {
		t.Fatal("VirtualConnector leaked internal state (mutation visible)")
	}

	// Upsert with same slug updates in place.
	vc.Label = "Eng v2"
	if err := s.UpsertConnector(ctx, vc); err != nil {
		t.Fatalf("UpsertConnector (update): %v", err)
	}
	list, err := s.Connectors(ctx)
	if err != nil {
		t.Fatalf("Connectors: %v", err)
	}
	if len(list) != 1 || list[0].Label != "Eng v2" {
		t.Fatalf("update should replace, not append: %+v", list)
	}

	// Reload from disk: accounts AND connectors persist.
	s2, err := LoadFileStore(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if _, ok := s2.Account("acct1"); !ok {
		t.Fatal("account lost after reload")
	}
	got2, ok := s2.VirtualConnector(ctx, "eng")
	if !ok {
		t.Fatal("connector lost after reload")
	}
	if got2.Label != "Eng v2" || len(got2.Tools["acct1"]) != 2 {
		t.Fatalf("reloaded connector mismatch: %+v", got2)
	}

	// Delete is generation-bound and a second stale delete fails closed.
	if err := s2.DeleteConnector(ctx, "eng", got2.Epoch); err != nil {
		t.Fatalf("DeleteConnector: %v", err)
	}
	if _, ok := s2.VirtualConnector(ctx, "eng"); ok {
		t.Fatal("connector still present after delete")
	}
	if err := s2.DeleteConnector(ctx, "eng", got2.Epoch); !errors.Is(err, ErrConnectorNotFound) {
		t.Fatalf("DeleteConnector after removal = %v, want ErrConnectorNotFound", err)
	}
	s3, err := LoadFileStore(path)
	if err != nil {
		t.Fatalf("reload after delete: %v", err)
	}
	if list, _ := s3.Connectors(ctx); len(list) != 0 {
		t.Fatalf("delete did not persist: %+v", list)
	}
	if _, ok := s3.Account("acct1"); !ok {
		t.Fatal("account lost by connector delete")
	}
}

func TestFileStoreAccountDeletePrunesConnectorReferencesAtomically(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "accounts.json")
	store, err := LoadFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, account := range []Account{
		{Name: "doomed", URL: "https://doomed.example/mcp", AuthMode: "token", BearerToken: "secret"},
		{Name: "kept", URL: "https://kept.example/mcp", AuthMode: "token", BearerToken: "kept"},
	} {
		if err := store.Upsert(ctx, account); err != nil {
			t.Fatalf("upsert %s: %v", account.Name, err)
		}
	}
	if err := store.UpsertConnector(ctx, VirtualConnector{
		Slug: "work",
		Tools: map[string][]string{
			"doomed": {"search", "write"},
			"kept":   {"search"},
		},
		Approval: map[string][]string{
			"doomed": {"write"},
			"kept":   {"search"},
		},
	}); err != nil {
		t.Fatalf("upsert connector: %v", err)
	}
	if err := store.CreateNamespace(ctx, Namespace{
		Slug: "team", Label: "Team", Epoch: "team-generation", Accounts: []string{"doomed", "kept"},
	}); err != nil {
		t.Fatalf("create namespace: %v", err)
	}

	// Force persistence to fail after all in-memory mutations. Account,
	// namespace membership/revision, and both connector maps must roll back as
	// one snapshot.
	validPath := store.path
	store.path = filepath.Join(t.TempDir(), "missing", "accounts.json")
	doomed, _ := store.Account("doomed")
	if err := store.Delete(ctx, "doomed", doomed.IncarnationID, doomed.Revision); err == nil {
		t.Fatal("delete with unwritable store path unexpectedly succeeded")
	}
	store.path = validPath
	if _, ok := store.Account("doomed"); !ok {
		t.Fatal("failed delete did not restore account")
	}
	connector, _ := store.VirtualConnector(ctx, "work")
	if len(connector.Tools["doomed"]) != 2 || len(connector.Approval["doomed"]) != 1 {
		t.Fatalf("failed delete did not restore connector maps: %+v", connector)
	}
	namespace, _ := store.Namespace(ctx, "team")
	if namespace.Revision != 1 || !sameStrings(namespace.Accounts, []string{"doomed", "kept"}) {
		t.Fatalf("failed delete did not restore namespace: %+v", namespace)
	}

	if err := store.Delete(ctx, "doomed", doomed.IncarnationID, doomed.Revision); err != nil {
		t.Fatalf("delete account: %v", err)
	}
	connector, _ = store.VirtualConnector(ctx, "work")
	if _, exists := connector.Tools["doomed"]; exists {
		t.Fatalf("deleted account remains in connector tools: %+v", connector.Tools)
	}
	if _, exists := connector.Approval["doomed"]; exists {
		t.Fatalf("deleted account remains in connector approval: %+v", connector.Approval)
	}
	if !sameStrings(connector.Tools["kept"], []string{"search"}) ||
		!sameStrings(connector.Approval["kept"], []string{"search"}) {
		t.Fatalf("delete changed unrelated connector entries: %+v", connector)
	}
	namespace, _ = store.Namespace(ctx, "team")
	if namespace.Revision != 2 || !sameStrings(namespace.Accounts, []string{"kept"}) {
		t.Fatalf("namespace was not pruned with account delete: %+v", namespace)
	}

	reopened, err := LoadFileStore(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	connector, _ = reopened.VirtualConnector(ctx, "work")
	if _, tools := connector.Tools["doomed"]; tools {
		t.Fatal("pruned connector tools did not persist")
	}
	if _, approval := connector.Approval["doomed"]; approval {
		t.Fatal("pruned connector approval did not persist")
	}
}

// TestFileStoreLegacyFormats proves backward compat: files written before
// connectors existed still load — both the original bare-array format and a
// wrapper object missing the "connectors" field.
func TestFileStoreLegacyFormats(t *testing.T) {
	ctx := context.Background()

	t.Run("bare account array", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "accounts.json")
		legacy := `[
  {"name": "old", "label": "Old", "group": "W", "url": "https://x/mcp", "auth_mode": "token", "bearer_token": "T"}
]`
		if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
			t.Fatal(err)
		}
		s, err := LoadFileStore(path)
		if err != nil {
			t.Fatalf("LoadFileStore(legacy array): %v", err)
		}
		a, ok := s.Account("old")
		if !ok || a.BearerToken != "T" || a.Group != "W" {
			t.Fatalf("legacy account not loaded: %+v ok=%v", a, ok)
		}
		if list, _ := s.Connectors(ctx); len(list) != 0 {
			t.Fatalf("legacy file should have no connectors, got %+v", list)
		}
		// First write upgrades the file to the new format without losing anything.
		if err := s.UpsertConnector(ctx, VirtualConnector{Slug: "v1", Label: "V1", Tools: map[string][]string{"old": {"t1"}}}); err != nil {
			t.Fatalf("UpsertConnector on legacy store: %v", err)
		}
		s2, err := LoadFileStore(path)
		if err != nil {
			t.Fatalf("reload upgraded file: %v", err)
		}
		if _, ok := s2.Account("old"); !ok {
			t.Fatal("account lost in format upgrade")
		}
		if _, ok := s2.VirtualConnector(ctx, "v1"); !ok {
			t.Fatal("connector lost in format upgrade")
		}
	})

	t.Run("connector without guardrail fields loads as zero", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "accounts.json")
		noGuard := `{"accounts": [], "connectors": [{"slug": "old", "label": "Old", "tools": {"a1": ["t1"]}}]}`
		if err := os.WriteFile(path, []byte(noGuard), 0o600); err != nil {
			t.Fatal(err)
		}
		s, err := LoadFileStore(path)
		if err != nil {
			t.Fatalf("LoadFileStore(no guardrail fields): %v", err)
		}
		c, ok := s.VirtualConnector(ctx, "old")
		if !ok {
			t.Fatal("legacy connector not loaded")
		}
		if c.MaxResultBytes != 0 {
			t.Fatalf("missing maxResultBytes should load as 0, got %d", c.MaxResultBytes)
		}
		if len(c.Redact) != 0 {
			t.Fatalf("missing redact should load as empty, got %+v", c.Redact)
		}
	})

	t.Run("connector without approval field loads as empty", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "accounts.json")
		noApproval := `{"accounts": [], "connectors": [{"slug": "old", "label": "Old", "tools": {"a1": ["t1"]}}]}`
		if err := os.WriteFile(path, []byte(noApproval), 0o600); err != nil {
			t.Fatal(err)
		}
		s, err := LoadFileStore(path)
		if err != nil {
			t.Fatalf("LoadFileStore(no approval field): %v", err)
		}
		c, ok := s.VirtualConnector(ctx, "old")
		if !ok {
			t.Fatal("legacy connector not loaded")
		}
		if len(c.Approval) != 0 {
			t.Fatalf("missing approval field should load as empty, got %+v", c.Approval)
		}
	})

	t.Run("wrapper object without connectors field", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "accounts.json")
		noConn := `{"accounts": [{"name": "old", "url": "https://x/mcp", "auth_mode": "token"}]}`
		if err := os.WriteFile(path, []byte(noConn), 0o600); err != nil {
			t.Fatal(err)
		}
		s, err := LoadFileStore(path)
		if err != nil {
			t.Fatalf("LoadFileStore(no connectors field): %v", err)
		}
		if _, ok := s.Account("old"); !ok {
			t.Fatal("account not loaded from wrapper object")
		}
		if list, _ := s.Connectors(ctx); len(list) != 0 {
			t.Fatalf("missing connectors field should load as empty, got %+v", list)
		}
	})
}

// TestFileStoreConnectorApproval proves the Approval map round-trips through
// the JSON file (including a reload from disk) and that the store hands out
// copies, not its internal map.
func TestFileStoreConnectorApproval(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "accounts.json")
	s, err := LoadFileStore(path)
	if err != nil {
		t.Fatalf("LoadFileStore: %v", err)
	}

	vc := VirtualConnector{
		Slug:     "gated",
		Label:    "Gated",
		Tools:    map[string][]string{"acct1": {"list_issues", "delete_issue"}},
		Approval: map[string][]string{"acct1": {"delete_issue"}},
	}
	if err := s.UpsertConnector(ctx, vc); err != nil {
		t.Fatalf("UpsertConnector: %v", err)
	}

	got, ok := s.VirtualConnector(ctx, "gated")
	if !ok {
		t.Fatal("connector not found after upsert")
	}
	if len(got.Approval["acct1"]) != 1 || got.Approval["acct1"][0] != "delete_issue" {
		t.Fatalf("approval round-trip mismatch: %+v", got.Approval)
	}

	// Returned Approval is a copy — mutating it must not touch store state.
	got.Approval["acct1"][0] = "mutated"
	again, _ := s.VirtualConnector(ctx, "gated")
	if again.Approval["acct1"][0] != "delete_issue" {
		t.Fatal("VirtualConnector leaked internal approval state (mutation visible)")
	}

	// Survives a reload from disk.
	s2, err := LoadFileStore(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	got2, ok := s2.VirtualConnector(ctx, "gated")
	if !ok {
		t.Fatal("connector lost after reload")
	}
	if len(got2.Approval["acct1"]) != 1 || got2.Approval["acct1"][0] != "delete_issue" {
		t.Fatalf("reloaded approval mismatch: %+v", got2.Approval)
	}
}

// TestFileStoreConnectorGuardrails proves MaxResultBytes and Redact round-trip
// through the JSON file (including a reload from disk) and that the store
// hands out a copy of the Redact slice, not its internal one.
func TestFileStoreConnectorGuardrails(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "accounts.json")
	s, err := LoadFileStore(path)
	if err != nil {
		t.Fatalf("LoadFileStore: %v", err)
	}

	vc := VirtualConnector{
		Slug:           "guarded",
		Label:          "Guarded",
		Tools:          map[string][]string{"acct1": {"get_issue"}},
		MaxResultBytes: 4096,
		Redact:         []string{`\bsk-[A-Za-z0-9]+\b`, `(?i)password`},
	}
	if err := s.UpsertConnector(ctx, vc); err != nil {
		t.Fatalf("UpsertConnector: %v", err)
	}

	got, ok := s.VirtualConnector(ctx, "guarded")
	if !ok {
		t.Fatal("connector not found after upsert")
	}
	if got.MaxResultBytes != 4096 {
		t.Fatalf("MaxResultBytes round-trip: want 4096, got %d", got.MaxResultBytes)
	}
	if len(got.Redact) != 2 || got.Redact[0] != `\bsk-[A-Za-z0-9]+\b` || got.Redact[1] != `(?i)password` {
		t.Fatalf("Redact round-trip mismatch: %+v", got.Redact)
	}

	// Returned Redact is a copy — mutating it must not touch store state.
	got.Redact[0] = "mutated"
	again, _ := s.VirtualConnector(ctx, "guarded")
	if again.Redact[0] != `\bsk-[A-Za-z0-9]+\b` {
		t.Fatal("VirtualConnector leaked internal redact state (mutation visible)")
	}

	// Survives a reload from disk.
	s2, err := LoadFileStore(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	got2, ok := s2.VirtualConnector(ctx, "guarded")
	if !ok {
		t.Fatal("connector lost after reload")
	}
	if got2.MaxResultBytes != 4096 || len(got2.Redact) != 2 || got2.Redact[1] != `(?i)password` {
		t.Fatalf("reloaded guardrail fields mismatch: %+v", got2)
	}
}

// TestFileStoreSetReadOnly proves the ReadOnly flag flips, persists across a
// reload, and errors for unknown accounts.
func TestFileStoreSetReadOnly(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "accounts.json")
	s, err := LoadFileStore(path)
	if err != nil {
		t.Fatalf("LoadFileStore: %v", err)
	}
	if err := s.Upsert(ctx, Account{Name: "acct1", URL: "https://x/mcp", AuthMode: "token", BearerToken: "T"}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	if a, _ := s.Account("acct1"); a.ReadOnly {
		t.Fatal("new account should default to ReadOnly=false")
	}
	if err := s.SetReadOnly(ctx, "acct1", true); err != nil {
		t.Fatalf("SetReadOnly: %v", err)
	}
	if a, _ := s.Account("acct1"); !a.ReadOnly {
		t.Fatal("SetReadOnly(true) not reflected")
	}

	// Persists across reload.
	s2, err := LoadFileStore(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if a, _ := s2.Account("acct1"); !a.ReadOnly {
		t.Fatal("ReadOnly lost after reload")
	}
	if err := s2.SetReadOnly(ctx, "acct1", false); err != nil {
		t.Fatalf("SetReadOnly(false): %v", err)
	}
	if a, _ := s2.Account("acct1"); a.ReadOnly {
		t.Fatal("SetReadOnly(false) not reflected")
	}

	if err := s2.SetReadOnly(ctx, "nope", true); err == nil {
		t.Fatal("SetReadOnly on unknown account should error")
	}
}

// TestFileStoreAccountScope proves the static-client OAuth Scope field
// round-trips through the JSON file (including a reload from disk) and that a
// legacy account written before the field existed loads as "" — the DCR path's
// invariant (no scope) survives the schema addition.
func TestFileStoreAccountScope(t *testing.T) {
	ctx := context.Background()

	t.Run("round-trip persists scope", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "accounts.json")
		s, err := LoadFileStore(path)
		if err != nil {
			t.Fatalf("LoadFileStore: %v", err)
		}
		if err := s.Upsert(ctx, Account{
			Name: "slack", URL: "https://slack/mcp", AuthMode: "oauth",
			ClientID: "cid", ClientSecret: "csec", Scope: "channels:read chat:write",
		}); err != nil {
			t.Fatalf("Upsert: %v", err)
		}
		if a, _ := s.Account("slack"); a.Scope != "channels:read chat:write" {
			t.Fatalf("Scope not set on Account: %q", a.Scope)
		}
		// Persists across a reload from disk.
		s2, err := LoadFileStore(path)
		if err != nil {
			t.Fatalf("reload: %v", err)
		}
		a, ok := s2.Account("slack")
		if !ok {
			t.Fatal("account lost after reload")
		}
		if a.Scope != "channels:read chat:write" {
			t.Fatalf("Scope lost after reload: %q", a.Scope)
		}
	})

	t.Run("legacy account without scope loads as empty", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "accounts.json")
		// A DCR-era account: no "scope" key at all.
		legacy := `{"accounts": [{"name": "dcr", "url": "https://x/mcp", "auth_mode": "oauth", "client_id": "cid"}]}`
		if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
			t.Fatal(err)
		}
		s, err := LoadFileStore(path)
		if err != nil {
			t.Fatalf("LoadFileStore(legacy): %v", err)
		}
		a, ok := s.Account("dcr")
		if !ok {
			t.Fatal("legacy account not loaded")
		}
		if a.Scope != "" {
			t.Fatalf("missing scope should load as empty, got %q", a.Scope)
		}
	})
}

// TestFileStorePendingCalls exercises the in-memory ApprovalLog: log, list
// (newest first), decide — and that records are ephemeral (NOT written to the
// JSON file).
func TestFileStorePendingCalls(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "accounts.json")
	s, err := LoadFileStore(path)
	if err != nil {
		t.Fatalf("LoadFileStore: %v", err)
	}

	p1 := PendingCall{ID: "p1", Connector: "eng", Account: "acct1", Tool: "delete_issue",
		Args: map[string]any{"id": "42"}, Status: "pending"}
	if err := s.LogPending(ctx, p1); err != nil {
		t.Fatalf("LogPending: %v", err)
	}
	if err := s.LogPending(ctx, PendingCall{ID: "p2", Connector: "eng", Account: "acct1", Tool: "save_issue", Status: "pending"}); err != nil {
		t.Fatalf("LogPending p2: %v", err)
	}

	list, err := s.PendingCalls(ctx)
	if err != nil {
		t.Fatalf("PendingCalls: %v", err)
	}
	if len(list) != 2 || list[0].ID != "p2" || list[1].ID != "p1" {
		t.Fatalf("want newest-first [p2 p1], got %+v", list)
	}
	if list[1].Args["id"] != "42" || list[1].TS.IsZero() {
		t.Fatalf("record fields lost: %+v", list[1])
	}

	// Decide p1: status flips and DecidedAt is stamped.
	if err := s.SetDecision(ctx, "p1", "approved"); err != nil {
		t.Fatalf("SetDecision: %v", err)
	}
	list, _ = s.PendingCalls(ctx)
	var got PendingCall
	for _, p := range list {
		if p.ID == "p1" {
			got = p
		}
	}
	if got.Status != "approved" || got.DecidedAt == nil {
		t.Fatalf("decision not recorded: %+v", got)
	}
	if err := s.SetDecision(ctx, "nope", "denied"); err == nil {
		t.Fatal("SetDecision on unknown id should error")
	}

	// Ephemeral: a reload from disk starts empty.
	// (Write something first so the file exists.)
	if err := s.Upsert(ctx, Account{Name: "a", URL: "u", AuthMode: "token"}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	s2, err := LoadFileStore(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if list, _ := s2.PendingCalls(ctx); len(list) != 0 {
		t.Fatalf("pending calls should be ephemeral, got %+v", list)
	}
}

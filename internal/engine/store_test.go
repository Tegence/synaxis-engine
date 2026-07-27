package engine

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// Both stores must satisfy ConnectorStore and ApprovalLog.
var (
	_ ConnectorStore = (*FileStore)(nil)
	_ ConnectorStore = (*PgStore)(nil)
	_ ApprovalLog    = (*FileStore)(nil)
	_ ApprovalLog    = (*PgStore)(nil)
)

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

	// Delete, then verify gone (and delete is idempotent).
	if err := s2.DeleteConnector(ctx, "eng"); err != nil {
		t.Fatalf("DeleteConnector: %v", err)
	}
	if _, ok := s2.VirtualConnector(ctx, "eng"); ok {
		t.Fatal("connector still present after delete")
	}
	if err := s2.DeleteConnector(ctx, "eng"); err != nil {
		t.Fatalf("DeleteConnector (idempotent): %v", err)
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

package engine

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

// exerciseMCPClientProfileBinding asserts the store-level invariants of the
// opaque profile binding shared by FileStore and PgStore: shape-only
// validation, revision fencing, epoch rotation on every change, idempotent
// identical rebinding and unbinding, survival across unrelated mutations, and
// the terminal-state rejection. It returns the final (revoked) record.
func exerciseMCPClientProfileBinding(t *testing.T, ctx context.Context, store MCPClientStore, client MCPClient) MCPClient {
	t.Helper()
	digestA, digestB := libraryDigest("policy A"), libraryDigest("policy B")
	pre := func(revision int64) MCPClientPrecondition {
		return MCPClientPrecondition{ID: client.ID, Revision: revision}
	}
	read := func() MCPClient {
		t.Helper()
		current, ok := store.MCPClient(ctx, client.ID)
		if !ok {
			t.Fatal("client vanished")
		}
		return current
	}
	valid := MCPClientProfileBinding{ProfileID: "aap_1", ProfileRevision: 1, PolicyDigest: digestA}

	for name, invalid := range map[string]MCPClientProfileBinding{
		"digest":           {ProfileID: "aap_1", ProfileRevision: 1, PolicyDigest: "not-a-digest"},
		"uppercase digest": {ProfileID: "aap_1", ProfileRevision: 1, PolicyDigest: strings.ToUpper(digestA)},
		"profile id":       {ProfileID: "aap 1", ProfileRevision: 1, PolicyDigest: digestA},
		"empty profile id": {ProfileID: "", ProfileRevision: 1, PolicyDigest: digestA},
		"profile revision": {ProfileID: "aap_1", ProfileRevision: 0, PolicyDigest: digestA},
	} {
		if _, err := store.BindMCPClientProfile(ctx, pre(client.Revision), invalid); !errors.Is(err, ErrInvalidMCPClient) {
			t.Fatalf("%s bind err=%v; want invalid", name, err)
		}
	}
	if after := read(); after.Revision != client.Revision || after.Epoch != client.Epoch || after.AgentProfileBinding != nil {
		t.Fatalf("rejected binds changed the client: %+v", after)
	}
	if _, err := store.BindMCPClientProfile(ctx, MCPClientPrecondition{ID: "mcpcli_missing", Revision: 1}, valid); !errors.Is(err, ErrMCPClientNotFound) {
		t.Fatalf("bind unknown client err=%v", err)
	}
	if _, err := store.UnbindMCPClientProfile(ctx, MCPClientPrecondition{ID: "mcpcli_missing", Revision: 1}); !errors.Is(err, ErrMCPClientNotFound) {
		t.Fatalf("unbind unknown client err=%v", err)
	}
	if _, err := store.BindMCPClientProfile(ctx, pre(client.Revision+7), valid); !errors.Is(err, ErrMCPClientRevision) {
		t.Fatalf("stale bind err=%v; want revision mismatch", err)
	}
	if unchanged, err := store.UnbindMCPClientProfile(ctx, pre(client.Revision)); err != nil || unchanged.Revision != client.Revision || unchanged.Epoch != client.Epoch || unchanged.AgentProfileBinding != nil {
		t.Fatalf("unbind while unbound=%+v err=%v; want no-op", unchanged, err)
	}

	// Binding installs the reference, stamps the store's own BoundAt (the
	// caller's is ignored), rotates the epoch, and bumps the revision.
	notBefore := time.Now().UTC().Add(-time.Minute)
	callerStamped := valid
	callerStamped.BoundAt = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	bound, err := store.BindMCPClientProfile(ctx, pre(client.Revision), callerStamped)
	if err != nil {
		t.Fatalf("bind: %v", err)
	}
	binding := bound.AgentProfileBinding
	if bound.Revision != client.Revision+1 || bound.Epoch == client.Epoch || binding == nil ||
		binding.ProfileID != "aap_1" || binding.ProfileRevision != 1 || binding.PolicyDigest != digestA ||
		binding.BoundAt.Before(notBefore) || binding.BoundAt.Location() != time.UTC {
		t.Fatalf("bound=%+v binding=%+v", bound, binding)
	}
	bySlug, ok := store.MCPClientBySlug(ctx, client.Slug)
	if !ok {
		t.Fatal("client missing by slug")
	}
	all, err := store.MCPClients(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var listed MCPClient
	for _, candidate := range all {
		if candidate.ID == client.ID {
			listed = candidate
		}
	}
	for name, current := range map[string]MCPClient{"by id": read(), "by slug": bySlug, "listed": listed} {
		if current.Epoch != bound.Epoch || current.Revision != bound.Revision || !sameMCPClientProfileBinding(current.AgentProfileBinding, binding) {
			t.Fatalf("%s read=%+v binding=%+v; want %+v", name, current, current.AgentProfileBinding, binding)
		}
	}

	// Identical rebinding is a no-op under the current revision and still
	// revision-fenced under a stale one.
	same, err := store.BindMCPClientProfile(ctx, pre(bound.Revision), valid)
	if err != nil || same.Revision != bound.Revision || same.Epoch != bound.Epoch || !sameMCPClientProfileBinding(same.AgentProfileBinding, binding) {
		t.Fatalf("identical rebind=%+v err=%v; want no-op", same, err)
	}
	if _, err := store.BindMCPClientProfile(ctx, pre(client.Revision), valid); !errors.Is(err, ErrMCPClientRevision) {
		t.Fatalf("identical rebind with stale revision err=%v; want revision mismatch", err)
	}

	// Unrelated mutations keep the binding and cannot alter it.
	renamed, err := store.UpdateMCPClient(ctx, MCPClient{ID: client.ID, Name: "Renamed"}, pre(bound.Revision))
	if err != nil || renamed.Name != "Renamed" || !sameMCPClientProfileBinding(renamed.AgentProfileBinding, binding) {
		t.Fatalf("rename=%+v err=%v; binding must survive", renamed, err)
	}
	for name, update := range map[string]MCPClient{
		"binding value": {ID: client.ID, Name: "Renamed", AgentProfileBinding: &MCPClientProfileBinding{ProfileID: "aap_9", ProfileRevision: 1, PolicyDigest: digestB}},
		"presence bit":  {ID: client.ID, Name: "Renamed", agentProfileBindingSet: true},
	} {
		if _, err := store.UpdateMCPClient(ctx, update, pre(renamed.Revision)); !errors.Is(err, ErrInvalidMCPClient) {
			t.Fatalf("generic update with %s err=%v; want invalid", name, err)
		}
	}
	reset, err := store.ResetMCPClientOAuthClient(ctx, client.ID, pre(renamed.Revision))
	if err != nil || reset.Epoch == renamed.Epoch || !sameMCPClientProfileBinding(reset.AgentProfileBinding, binding) {
		t.Fatalf("oauth reset=%+v err=%v; binding must survive", reset, err)
	}

	// A new revision of the same profile and a different profile both rotate.
	bumped, err := store.BindMCPClientProfile(ctx, pre(reset.Revision), MCPClientProfileBinding{ProfileID: "aap_1", ProfileRevision: 2, PolicyDigest: digestB})
	if err != nil || bumped.Revision != reset.Revision+1 || bumped.Epoch == reset.Epoch || bumped.AgentProfileBinding.ProfileRevision != 2 ||
		bumped.AgentProfileBinding.PolicyDigest != digestB || bumped.AgentProfileBinding.BoundAt.Before(binding.BoundAt) {
		t.Fatalf("profile revision bump=%+v err=%v", bumped, err)
	}
	replaced, err := store.BindMCPClientProfile(ctx, pre(bumped.Revision), MCPClientProfileBinding{ProfileID: "aap_2", ProfileRevision: 1, PolicyDigest: digestB})
	if err != nil || replaced.Revision != bumped.Revision+1 || replaced.Epoch == bumped.Epoch || replaced.AgentProfileBinding.ProfileID != "aap_2" {
		t.Fatalf("profile replace=%+v err=%v", replaced, err)
	}

	// Unbinding rotates once, converges, and is revision-fenced.
	unbound, err := store.UnbindMCPClientProfile(ctx, pre(replaced.Revision))
	if err != nil || unbound.AgentProfileBinding != nil || unbound.Revision != replaced.Revision+1 || unbound.Epoch == replaced.Epoch {
		t.Fatalf("unbind=%+v err=%v", unbound, err)
	}
	if again, err := store.UnbindMCPClientProfile(ctx, pre(unbound.Revision)); err != nil || again.Revision != unbound.Revision || again.Epoch != unbound.Epoch || again.AgentProfileBinding != nil {
		t.Fatalf("second unbind=%+v err=%v; want no-op", again, err)
	}
	if _, err := store.UnbindMCPClientProfile(ctx, pre(replaced.Revision)); !errors.Is(err, ErrMCPClientRevision) {
		t.Fatalf("stale unbind err=%v; want revision mismatch", err)
	}
	if read().AgentProfileBinding != nil {
		t.Fatal("unbound client still carries a binding")
	}

	// A registration is never created pre-bound; the reference is installed
	// only through the explicit operation.
	if _, err := store.CreateMCPClient(ctx, MCPClient{Name: "Pre-bound", Subject: client.Subject, CreatedBy: client.Subject, AgentProfileBinding: &valid}); !errors.Is(err, ErrInvalidMCPClient) {
		t.Fatalf("create with binding err=%v; want invalid", err)
	}

	// Revocation keeps the history but closes both operations.
	final, err := store.BindMCPClientProfile(ctx, pre(unbound.Revision), MCPClientProfileBinding{ProfileID: "aap_3", ProfileRevision: 1, PolicyDigest: digestA})
	if err != nil {
		t.Fatal(err)
	}
	revoked, err := store.RevokeMCPClient(ctx, client.ID, client.Subject, pre(final.Revision))
	if err != nil || revoked.Status != MCPClientStatusRevoked || !sameMCPClientProfileBinding(revoked.AgentProfileBinding, final.AgentProfileBinding) {
		t.Fatalf("revoked=%+v err=%v; binding history must survive", revoked, err)
	}
	if _, err := store.BindMCPClientProfile(ctx, pre(revoked.Revision), valid); !errors.Is(err, ErrMCPClientRevoked) {
		t.Fatalf("bind revoked err=%v; want revoked", err)
	}
	if _, err := store.UnbindMCPClientProfile(ctx, pre(revoked.Revision)); !errors.Is(err, ErrMCPClientRevoked) {
		t.Fatalf("unbind revoked err=%v; want revoked", err)
	}
	return revoked
}

func TestFileStoreMCPClientProfileBindingRotatesEpochAndPersists(t *testing.T) {
	ctx := context.Background()
	store := newLibraryFileStore(t)
	client, err := store.CreateMCPClient(ctx, MCPClient{Name: "Bound", Subject: "usr_bound", CreatedBy: "usr_bound"})
	if err != nil {
		t.Fatal(err)
	}
	final := exerciseMCPClientProfileBinding(t, ctx, store, client)

	reloaded, err := LoadFileStore(store.path)
	if err != nil {
		t.Fatal(err)
	}
	current, ok := reloaded.MCPClient(ctx, client.ID)
	if !ok || !sameMCPClient(current, final) {
		t.Fatalf("reloaded=%+v binding=%+v; want %+v binding=%+v", current, current.AgentProfileBinding, final, final.AgentProfileBinding)
	}
	persisted, err := os.ReadFile(store.path)
	if err != nil {
		t.Fatal(err)
	}
	// The store pretty-prints its JSON, so match the field names and values
	// independently of whitespace.
	for _, field := range []string{`"agent_profile_binding"`, `"profile_id"`, `"aap_3"`, `"profile_revision"`, `"policy_digest"`, `"` + libraryDigest("policy A") + `"`, `"bound_at"`} {
		if !strings.Contains(string(persisted), field) {
			t.Fatalf("persisted binding lacks %s: %s", field, persisted)
		}
	}
	// The presence bit is a request-only flag and is never persisted.
	if strings.Contains(string(persisted), "agentProfileBindingSet") || strings.Contains(string(persisted), "agent_profile_binding_set") {
		t.Fatal("persisted store contains the presence bit")
	}
}

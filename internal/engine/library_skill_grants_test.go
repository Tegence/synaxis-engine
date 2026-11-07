package engine

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/server"
)

type sharedSkillTestStore interface {
	memberSkillTestStore
	AccountStore
	LibrarySkillGrantStore
}

func TestFilePrivateSkillSharingLifecycle(t *testing.T) {
	testPrivateSkillSharingLifecycle(t, newLibraryFileStore(t))
}
func TestPgPrivateSkillSharingLifecycle(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL required")
	}
	s, err := NewPgStore(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	s.SetCipher(testCipher(t, 173))
	testPrivateSkillSharingLifecycle(t, s)
}
func testPrivateSkillSharingLifecycle(t *testing.T, s sharedSkillTestStore) {
	t.Helper()
	ctx := context.Background()
	suffix := newEpoch()
	owner := "usr_owner_" + suffix
	member := "usr_member_" + suffix
	agent := "agt_member_" + suffix
	client, err := s.CreateMCPClient(ctx, MCPClient{Name: "Shared private skill " + suffix, Subject: agent, CreatedBy: member})
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := s.CreateMCPClient(ctx, MCPClient{Name: "Unshared private skill " + suffix, Subject: "agt_foreign_" + suffix, CreatedBy: "usr_foreign_" + suffix})
	if err != nil {
		t.Fatal(err)
	}
	own := LibraryMemberSkillRequest{Operation: "create", Subject: owner, SubjectIDs: []string{owner}, Name: "Private shared procedure", Instructions: "shared-private-instructions-" + suffix}
	made, err := s.MemberLibrarySkills(ctx, own)
	if err != nil {
		t.Fatal(err)
	}
	id := made.Skill.ID
	v1 := made.Versions[0].ID
	marker := made.Versions[0].Instructions
	t.Cleanup(func() {
		if pg, ok := s.(*PgStore); ok {
			for _, q := range []string{`DELETE FROM narthex_library_skill_bindings WHERE skill_id=$1`, `DELETE FROM narthex_library_skill_binding_generations WHERE skill_id=$1`, `DELETE FROM narthex_library_skill_versions WHERE skill_id=$1`, `DELETE FROM narthex_library_skills WHERE id=$1`} {
				if _, err := pg.pool.Exec(ctx, q, id); err != nil {
					t.Errorf("cleanup: %v", err)
				}
			}
			if _, err := pg.pool.Exec(ctx, `DELETE FROM narthex_mcp_clients WHERE id=ANY($1)`, []string{client.ID, foreign.ID}); err != nil {
				t.Errorf("cleanup: %v", err)
			}
		}
	})
	own.SkillID = id
	own.Operation = "version"
	own.BaseVersionID = v1
	own.Instructions = "never-shared-private-version-" + suffix
	privateDescription := "never-shared-private-description-" + suffix
	own.Description = &privateDescription
	second, err := s.MemberLibrarySkills(ctx, own)
	if err != nil {
		t.Fatal(err)
	}
	v2 := second.Skill.LatestVersion.ID
	memberReq := LibraryMemberSkillRequest{Subject: member, SubjectIDs: []string{member, agent}, Operation: "get", SkillID: id}
	if _, err := s.MemberLibrarySkills(ctx, memberReq); !errors.Is(err, ErrLibrarySkillNotFound) {
		t.Fatalf("unshared read: %v", err)
	}
	gateway := NewGateway(s, server.NewMCPServer("private-share-test", "1.0.0", server.WithToolCapabilities(true)))
	if err := gateway.RefreshMCPClients(ctx); err != nil {
		t.Fatal(err)
	}
	mcp := clientLibraryServer(t, gateway, client.Slug)
	foreignMCP := clientLibraryServer(t, gateway, foreign.Slug)
	checks := []struct {
		tool string
		args map[string]any
	}{{"library_skill_list", nil}, {"library_skill_read", map[string]any{"skillId": id}}, {"library_skill_file_read", map[string]any{"skillId": id, "versionId": v1, "path": "SKILL.md"}}, {"library_skill_resolve", nil}, {"library_skill_activation", map[string]any{"contractVersion": LibrarySkillActivationContractVersionV2}}}
	assertRuntime := func(allowed bool) {
		t.Helper()
		for _, check := range checks {
			got := callLibraryTool(t, mcp, check.tool, check.args)
			if strings.Contains(got, privateDescription) {
				t.Fatalf("private description leaked through %s: %s", check.tool, got)
			}
			if allowed {
				want := marker
				if check.tool == "library_skill_list" {
					want = id
				}
				if !strings.Contains(got, want) || strings.Contains(got, v2) || strings.Contains(got, own.Instructions) {
					t.Fatalf("shared %s: %s", check.tool, got)
				}
			} else if strings.Contains(got, id) || strings.Contains(got, marker) || strings.Contains(got, v1) {
				t.Fatalf("revoked %s leaks: %s", check.tool, got)
			}
			other := callLibraryTool(t, foreignMCP, check.tool, check.args)
			if strings.Contains(other, id) || strings.Contains(other, marker) {
				t.Fatalf("unshared %s leaks: %s", check.tool, other)
			}
		}
	}
	for _, kind := range []string{"subject", "team"} {
		t.Run(kind, func(t *testing.T) {
			share := own
			share.Operation = "share"
			share.VersionID = v1
			share.RecipientKind = kind
			share.RecipientRef = "recipient_" + suffix
			share.RecipientSubjects = []string{member, agent}
			if kind == "team" {
				share.RecipientSubjects = []string{}
			}
			granted, err := s.MemberLibrarySkills(ctx, share)
			if err != nil || granted.Share == nil {
				t.Fatalf("share: %+v %v", granted, err)
			}
			grant := *granted.Share
			if kind == "team" {
				if _, err := s.MemberLibrarySkills(ctx, memberReq); !errors.Is(err, ErrLibrarySkillNotFound) {
					t.Fatalf("empty team read: %v", err)
				}
				populated, err := s.LibrarySkillGrants(ctx, LibrarySkillGrantRequest{Operation: "set-recipients", GrantID: grant.ID, Revision: grant.Revision, RecipientSubjects: []string{member, agent}})
				if err != nil {
					t.Fatal(err)
				}
				grant = *populated.Share
				share.RecipientSubjects = []string{member, agent}
			}
			got, err := s.MemberLibrarySkills(ctx, memberReq)
			if err != nil || got.Skill == nil || got.Skill.Access != "shared" || got.Skill.Description != "" || got.Skill.CanEdit || got.Skill.CanShare || !got.Skill.CanAssign || len(got.Versions) != 1 || got.Versions[0].ID != v1 {
				t.Fatalf("recipient projection: %+v %v", got, err)
			}
			for _, operation := range []string{"share", "shares", "version", "revoke-share"} {
				r := memberReq
				r.Operation = operation
				r.VersionID = v1
				r.BaseVersionID = v1
				r.GrantID = grant.ID
				r.Revision = grant.Revision
				r.Instructions = "overwrite"
				if _, err := s.MemberLibrarySkills(ctx, r); !errors.Is(err, ErrLibrarySkillNotFound) {
					t.Fatalf("recipient %s allowed: %v", operation, err)
				}
			}
			bind := memberReq
			bind.Operation = "bind"
			bind.VersionID = v2
			bind.AgentSurfaceID = client.ID
			if _, err := s.MemberLibrarySkills(ctx, bind); !errors.Is(err, ErrLibrarySkillNotFound) {
				t.Fatalf("unshared version bind: %v", err)
			}
			bind.VersionID = v1
			bound, err := s.MemberLibrarySkills(ctx, bind)
			if err != nil || len(bound.Skill.Bindings) != 1 || bound.Skill.Bindings[0].Managed {
				t.Fatalf("recipient bind: %+v %v", bound, err)
			}
			checks[3].args = map[string]any{"explicitBindingId": bound.Skill.Bindings[0].ID}
			assertRuntime(true)
			if _, err := s.UpsertLibrarySkillBinding(ctx, LibrarySkillBinding{SkillID: id, ScopeKind: LibraryScopeAgentSurface, ScopeID: foreign.ID, Mode: LibraryBindingModePin, PinnedVersionID: v1, SharedGrantID: grant.ID}); !errors.Is(err, ErrLibraryMemberSkillAccess) {
				t.Fatalf("generic binding bypass: %v", err)
			}
			revoke := own
			revoke.Operation = "revoke-share"
			revoke.GrantID = grant.ID
			revoke.Revision = grant.Revision
			if _, err := s.MemberLibrarySkills(ctx, revoke); err != nil {
				t.Fatal(err)
			}
			if _, err := s.MemberLibrarySkills(ctx, memberReq); !errors.Is(err, ErrLibrarySkillNotFound) {
				t.Fatalf("revoked saved ID: %v", err)
			}
			assertRuntime(false)
			granted, err = s.MemberLibrarySkills(ctx, share)
			if err != nil {
				t.Fatal(err)
			}
			grant = *granted.Share
			assertRuntime(false) // A fresh grant does not revive a previous assignment.
			if _, err := s.MemberLibrarySkills(ctx, bind); err != nil {
				t.Fatal(err)
			}
			assertRuntime(true)
			removed, err := s.LibrarySkillGrants(ctx, LibrarySkillGrantRequest{Operation: "set-recipients", GrantID: grant.ID, Revision: grant.Revision, RecipientSubjects: []string{}})
			if err != nil {
				t.Fatal(err)
			}
			assertRuntime(false)
			_, err = s.LibrarySkillGrants(ctx, LibrarySkillGrantRequest{Operation: "set-recipients", GrantID: grant.ID, Revision: removed.Share.Revision, RecipientSubjects: []string{member, agent}})
			if err != nil {
				t.Fatal(err)
			}
			assertRuntime(false)
			if _, err := s.MemberLibrarySkills(ctx, bind); err != nil {
				t.Fatal(err)
			}
			// Remove the team recipient first: later offboarding must still prevent
			// an old grant from being restored when that subject joins again.
			latest, err := s.LibrarySkillGrants(ctx, LibrarySkillGrantRequest{Operation: "list"})
			if err != nil {
				t.Fatal(err)
			}
			for _, g := range latest.Shares {
				if g.ID == grant.ID {
					if _, err := s.LibrarySkillGrants(ctx, LibrarySkillGrantRequest{Operation: "set-recipients", GrantID: g.ID, Revision: g.Revision, RecipientSubjects: []string{}}); err != nil {
						t.Fatal(err)
					}
				}
			}

			if _, err := s.LibrarySkillGrants(ctx, LibrarySkillGrantRequest{Operation: "end-subject", Subject: agent}); err != nil {
				t.Fatal(err)
			}
			if _, err := s.LibrarySkillGrants(ctx, LibrarySkillGrantRequest{Operation: "end-subject", Subject: member}); err != nil {
				t.Fatal(err)
			}
			ended, err := s.LibrarySkillGrants(ctx, LibrarySkillGrantRequest{Operation: "list"})
			if err != nil {
				t.Fatal(err)
			}
			revision := int64(0)
			for _, g := range ended.Shares {
				if g.ID == grant.ID {
					revision = g.Revision
				}
			}
			if _, err := s.LibrarySkillGrants(ctx, LibrarySkillGrantRequest{Operation: "set-recipients", GrantID: grant.ID, Revision: revision, RecipientSubjects: []string{member, agent}}); err != nil {
				t.Fatal(err)
			}
			assertRuntime(false)
			if _, err := s.MemberLibrarySkills(ctx, memberReq); !errors.Is(err, ErrLibrarySkillNotFound) {
				t.Fatalf("offboarded subject restored by reconciliation: %v", err)
			}
		})
	}
	// Binding and revocation serialize on the same skill. A racing assignment
	// must not commit durable access after the revoke has completed.
	for attempt := 0; attempt < 4; attempt++ {
		share := own
		share.Operation = "share"
		share.VersionID = v1
		share.RecipientKind = "subject"
		share.RecipientRef = member
		share.RecipientSubjects = []string{member, agent}
		result, err := s.MemberLibrarySkills(ctx, share)
		if err != nil {
			t.Fatal(err)
		}
		bind := memberReq
		bind.Operation = "bind"
		bind.VersionID = v1
		bind.AgentSurfaceID = client.ID
		revoke := own
		revoke.Operation = "revoke-share"
		revoke.GrantID = result.Share.ID
		revoke.Revision = result.Share.Revision
		var wg sync.WaitGroup
		wg.Add(2)
		errorsCh := make(chan error, 2)
		go func() {
			defer wg.Done()
			_, err := s.MemberLibrarySkills(ctx, bind)
			if err != nil && !errors.Is(err, ErrLibrarySkillNotFound) {
				errorsCh <- err
			}
		}()
		go func() {
			defer wg.Done()
			_, err := s.MemberLibrarySkills(ctx, revoke)
			if err != nil {
				errorsCh <- err
			}
		}()
		wg.Wait()
		close(errorsCh)
		for err := range errorsCh {
			t.Fatal(err)
		}
		assertRuntime(false)
		if _, err := s.MemberLibrarySkills(ctx, memberReq); !errors.Is(err, ErrLibrarySkillNotFound) {
			t.Fatalf("concurrent revoke retained skill: %v", err)
		}
	}
	// Expiry is checked on the retained handler, even without a grant mutation.
	expiry := time.Now().UTC().Add(time.Second)
	share := own
	share.Operation = "share"
	share.VersionID = v1
	share.RecipientKind = "subject"
	share.RecipientRef = member
	share.RecipientSubjects = []string{member, agent}
	share.ExpiresAt = &expiry
	expiring, err := s.MemberLibrarySkills(ctx, share)
	if err != nil {
		t.Fatal(err)
	}
	bind := memberReq
	bind.Operation = "bind"
	bind.VersionID = v1
	bind.AgentSurfaceID = client.ID
	bound, err := s.MemberLibrarySkills(ctx, bind)
	if err != nil {
		t.Fatal(err)
	}
	checks[3].args = map[string]any{"explicitBindingId": bound.Skill.Bindings[0].ID}
	assertRuntime(true)
	if pg, ok := s.(*PgStore); ok {
		var payload string
		if err := pg.pool.QueryRow(ctx, `SELECT payload FROM narthex_library_skill_grants WHERE id=$1`, expiring.Share.ID).Scan(&payload); err != nil {
			t.Fatal(err)
		}
		for _, secret := range []string{owner, member, agent} {
			if strings.Contains(payload, secret) {
				t.Fatal("skill recipient metadata stored unencrypted")
			}
		}
	}
	time.Sleep(time.Until(expiry.Add(10 * time.Millisecond)))
	assertRuntime(false)
	if _, err := s.MemberLibrarySkills(ctx, memberReq); !errors.Is(err, ErrLibrarySkillNotFound) {
		t.Fatalf("expired saved ID: %v", err)
	}
	// Ending the source owner's access revokes every recipient's existing share.
	share.ExpiresAt = nil
	if _, err := s.MemberLibrarySkills(ctx, share); err != nil {
		t.Fatal(err)
	}
	if _, err := s.MemberLibrarySkills(ctx, bind); err != nil {
		t.Fatal(err)
	}
	assertRuntime(true)
	if _, err := s.LibrarySkillGrants(ctx, LibrarySkillGrantRequest{Operation: "end-subject", Subject: owner}); err != nil {
		t.Fatal(err)
	}
	assertRuntime(false)
	if _, err := s.MemberLibrarySkills(ctx, memberReq); !errors.Is(err, ErrLibrarySkillNotFound) {
		t.Fatalf("source owner revoked: %v", err)
	}
}
func TestSkillGrantExpiryAndExactBinding(t *testing.T) {
	now := time.Now().UTC()
	future := now.Add(time.Hour)
	past := now.Add(-time.Second)
	g := LibrarySkillGrant{ID: "grant", SkillID: "skill", VersionID: "v1", RecipientSubjects: []string{"agent"}, ExpiresAt: &future}
	b := LibrarySkillBinding{SharedGrantID: "grant", SkillID: "skill", ScopeKind: LibraryScopeAgentSurface, ScopeID: "client", Mode: LibraryBindingModePin, PinnedVersionID: "v1"}
	clients := []MCPClient{{ID: "client", Subject: "agent", Status: MCPClientStatusActive}}
	if !skillBindingGrantAllowed(b, []LibrarySkillGrant{g}, clients, now) {
		t.Fatal("active share denied")
	}
	g.ExpiresAt = &past
	if skillBindingGrantAllowed(b, []LibrarySkillGrant{g}, clients, now) {
		t.Fatal("expired share allowed")
	}
	g.ExpiresAt = nil
	b.Mode = LibraryBindingModeTrack
	if skillBindingGrantAllowed(b, []LibrarySkillGrant{g}, clients, now) {
		t.Fatal("shared version tracks private head")
	}
}

func TestControlSkillGrantsRequiresUnscopedServiceActor(t *testing.T) {
	mux, _, key, now, _ := newHostedControlConsole(t)
	path := "/control/v1/library/skill-grants"
	for _, actor := range []struct{ user, role string }{{"usr_member", "operator"}, {"usr_owner", "owner"}} {
		response := controlLibraryRequest(t, mux, key, now, actor.user, actor.role, "POST", path, `{"operation":"list"}`, "")
		if response.Code != 403 {
			t.Fatalf("%s status=%d %s", actor.role, response.Code, response.Body)
		}
	}
	response := controlLibraryRequest(t, mux, key, now, platformServiceActorID, "service", "POST", path, `{"operation":"list"}`, "")
	if response.Code != 200 || !strings.Contains(response.Body.String(), `"grants":[]`) {
		t.Fatalf("service status=%d %s", response.Code, response.Body)
	}
	scoped := controlLibraryRequest(t, mux, key, now, platformServiceActorID, "service", "POST", path, `{"operation":"list"}`, "usr_member")
	if scoped.Code != 400 {
		t.Fatalf("scoped service status=%d %s", scoped.Code, scoped.Body)
	}
}

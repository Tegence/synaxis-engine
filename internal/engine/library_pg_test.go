package engine

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

// TestPgLibraryRuntimeAttestationIngestAndReplay exercises the Postgres
// migration and the same host-attested result invariants as the FileStore
// suite. It stays gated because contributors may not have a local database.
func TestPgLibraryRuntimeAttestationIngestAndReplay(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to run the Postgres Library runtime-attestation integration test")
	}
	ctx := context.Background()
	store, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatalf("NewPgStore: %v", err)
	}
	defer store.Close()

	var client MCPClient
	var skill LibrarySkill
	var binding LibrarySkillBinding
	var run LibraryRun
	var artifact LibraryArtifact
	defer func() {
		// The verifier references both the run and client, so remove it first.
		if run.ID != "" {
			_, _ = store.pool.Exec(context.Background(), `DELETE FROM narthex_library_runtime_attestations WHERE run_id=$1`, run.ID)
		}
		if artifact.ID != "" {
			_, _ = store.pool.Exec(context.Background(), `DELETE FROM narthex_library_artifact_versions WHERE artifact_id=$1`, artifact.ID)
			_, _ = store.pool.Exec(context.Background(), `DELETE FROM narthex_library_artifacts WHERE id=$1`, artifact.ID)
		}
		if run.ID != "" {
			_, _ = store.pool.Exec(context.Background(), `DELETE FROM narthex_library_runs WHERE id=$1`, run.ID)
		}
		if binding.ID != "" {
			_, _ = store.pool.Exec(context.Background(), `DELETE FROM narthex_library_skill_bindings WHERE id=$1`, binding.ID)
		}
		if skill.ID != "" {
			_, _ = store.pool.Exec(context.Background(), `DELETE FROM narthex_library_skill_versions WHERE skill_id=$1`, skill.ID)
			_, _ = store.pool.Exec(context.Background(), `DELETE FROM narthex_library_skill_binding_generations WHERE skill_id=$1`, skill.ID)
			_, _ = store.pool.Exec(context.Background(), `DELETE FROM narthex_library_skills WHERE id=$1`, skill.ID)
		}
		if client.ID != "" {
			_, _ = store.pool.Exec(context.Background(), `DELETE FROM narthex_mcp_clients WHERE id=$1`, client.ID)
		}
	}()

	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	client, err = store.CreateMCPClient(ctx, MCPClient{
		Name: "PG runtime attestor " + newPgFixtureSuffix(), Subject: "usr_pg_runtime", CreatedBy: "usr_pg_runtime",
		RuntimeAttestorPublicKey: base64.RawURLEncoding.EncodeToString(public),
	})
	if err != nil {
		t.Fatalf("CreateMCPClient: %v", err)
	}
	var storedKey string
	if err := store.pool.QueryRow(ctx, `SELECT runtime_attestor_public_key FROM narthex_mcp_clients WHERE id=$1`, client.ID).Scan(&storedKey); err != nil || storedKey != client.RuntimeAttestorPublicKey {
		t.Fatalf("runtime-attestor key migration/storage = %q err=%v want %q", storedKey, err, client.RuntimeAttestorPublicKey)
	}
	var attestationConstraint bool
	if err := store.pool.QueryRow(ctx, `
SELECT EXISTS(
    SELECT 1 FROM pg_constraint
    WHERE conname='narthex_library_runs_attestation_check'
      AND conrelid='narthex_library_runs'::regclass
)`).Scan(&attestationConstraint); err != nil || !attestationConstraint {
		t.Fatalf("runtime attestation run constraint migration is absent: exists=%t err=%v", attestationConstraint, err)
	}

	skill, initial, err := store.CreateLibrarySkillWithInitialVersion(ctx, LibrarySkill{
		Slug: "pg-runtime-" + newPgFixtureSuffix(), Name: "PG runtime skill", Description: "runtime fixture", CreatedBy: "usr_pg_runtime",
	}, LibrarySkillVersion{Content: "# PG runtime instructions", RequestedCapabilities: []string{"repository.read"}, CreatedBy: "usr_pg_runtime"})
	if err != nil {
		t.Fatalf("CreateLibrarySkillWithInitialVersion: %v", err)
	}
	binding, err = store.UpsertLibrarySkillBinding(ctx, LibrarySkillBinding{
		SkillID: skill.ID, ScopeKind: LibraryScopeAgentSurface, ScopeID: client.ID, Mode: LibraryBindingModePin,
		PinnedVersionID: initial.ID, CapabilityCeiling: []string{"repository.read"}, CreatedBy: "usr_pg_runtime",
	})
	if err != nil {
		t.Fatalf("UpsertLibrarySkillBinding: %v", err)
	}
	bundle, err := BuildLibrarySkillActivationBundleForAgentSurface(ctx, store, client.ID)
	if err != nil {
		t.Fatalf("BuildLibrarySkillActivationBundleForAgentSurface: %v", err)
	}
	nonce := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("n", 32)))
	raw, err := json.Marshal(libraryRuntimeAttestationRequest{
		ContractVersion: LibraryRuntimeAttestationContractVersion,
		ClientEpoch:     client.Epoch,
		ExecutionID:     "pg-runtime-execution",
		Nonce:           nonce,
		ExpiresAt:       time.Now().UTC().Add(5 * time.Minute).Format(time.RFC3339Nano),
		BundleDigest:    bundle.BundleDigest,
		SkillID:         skill.ID,
		SkillVersionID:  initial.ID,
		BindingID:       binding.ID,
		InputDigest:     libraryDigest("pg runtime input"),
		Output:          libraryRuntimeAttestationOutput{Title: "PG host result", Format: LibraryArtifactFormatMarkdown, Body: "# PG host result"},
	})
	if err != nil {
		t.Fatal(err)
	}
	attestation := LibraryRuntimeAttestation{
		ClientID: client.ID, Path: libraryRuntimeAttestationPath(client.Slug), RawBody: raw,
		Signature: ed25519.Sign(private, libraryRuntimeAttestationSigningMessage(libraryRuntimeAttestationPath(client.Slug), raw)),
	}
	run, artifact, version, replayed, err := store.IngestLibraryRuntimeAttestation(ctx, attestation)
	if err != nil || replayed {
		t.Fatalf("IngestLibraryRuntimeAttestation create: run=%+v artifact=%+v version=%+v replayed=%t err=%v", run, artifact, version, replayed, err)
	}
	if run.Origin != LibraryRunOriginSkillRun || run.Attestation != LibraryRunAttestationHost || run.ActorRef != client.Subject || run.SurfaceRef != client.ID ||
		artifact.AgentSurfaceID != client.ID || artifact.CreatedBy != client.Subject || version.Digest != run.OutputDigest {
		t.Fatalf("PG host-attested provenance was not server-derived: run=%+v artifact=%+v version=%+v", run, artifact, version)
	}
	var executionHash, nonceHash, requestDigest string
	if err := store.pool.QueryRow(ctx, `SELECT execution_hash,nonce_hash,request_digest FROM narthex_library_runtime_attestations WHERE run_id=$1`, run.ID).Scan(&executionHash, &nonceHash, &requestDigest); err != nil ||
		executionHash == "pg-runtime-execution" || nonceHash == nonce || requestDigest == string(raw) {
		t.Fatalf("PG runtime verifier metadata leaked raw idempotency material: execution=%q nonce=%q request=%q err=%v", executionHash, nonceHash, requestDigest, err)
	}
	replayRun, replayArtifact, replayVersion, replayed, err := store.IngestLibraryRuntimeAttestation(ctx, attestation)
	if err != nil || !replayed || replayRun.ID != run.ID || replayArtifact.ID != artifact.ID || replayVersion.ID != version.ID {
		t.Fatalf("PG exact replay changed result: run=%+v artifact=%+v version=%+v replayed=%t err=%v", replayRun, replayArtifact, replayVersion, replayed, err)
	}
	page, err := store.LibraryMCPClientArtifactPage(ctx, client, LibraryMCPClientArtifactCursor{}, 10)
	if err != nil || len(page.Artifacts) != 1 || page.Artifacts[0].Artifact.ID != artifact.ID || page.Artifacts[0].Access != "owned" {
		t.Fatalf("PG client-owned host output page=%+v err=%v", page, err)
	}

	// Current-selection revalidation is performed inside the serializable
	// ingest transaction, so a previously signed body cannot be replayed after
	// its selected version is replaced.
	next, err := store.CreateLibrarySkillVersion(ctx, LibrarySkillVersion{
		SkillID: skill.ID, Content: "# PG new selection", RequestedCapabilities: []string{"repository.read"}, CreatedBy: "usr_pg_runtime",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpsertLibrarySkillBinding(ctx, LibrarySkillBinding{
		SkillID: skill.ID, ScopeKind: LibraryScopeAgentSurface, ScopeID: client.ID, Mode: LibraryBindingModePin,
		PinnedVersionID: next.ID, CapabilityCeiling: []string{"repository.read"}, CreatedBy: "usr_pg_runtime",
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err := store.IngestLibraryRuntimeAttestation(ctx, attestation); !errors.Is(err, ErrLibraryRuntimeAttestationInvalid) {
		t.Fatalf("PG stale selected tuple was accepted after rebinding: %v", err)
	}
}

// TestPgLibraryStoreRoundTripAndEncryptsPrivateText is gated like the rest of
// the PgStore suite. It proves that all private Library authored text is
// upgraded from legacy plaintext, read back correctly, and encrypted on new
// writes after PgStore receives a configured at-rest cipher.
func TestPgLibraryStoreRoundTripAndEncryptsPrivateText(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to run the Postgres Library integration test")
	}
	ctx := context.Background()
	store, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatalf("NewPgStore: %v", err)
	}
	defer store.Close()

	var skill LibrarySkill
	var skillVersion LibrarySkillVersion
	var draft LibrarySkillDraft
	var binding LibrarySkillBinding
	var evaluation LibrarySkillEvaluation
	var run LibraryRun
	var artifact LibraryArtifact
	var artifactVersion LibraryArtifactVersion
	var artifactGrant LibraryArtifactGrant
	var artifactClient MCPClient
	var postSkill LibrarySkill
	var postDraft LibrarySkillDraft
	var postBinding LibrarySkillBinding
	var postEvaluation LibrarySkillEvaluation
	var postRun LibraryRun
	var postArtifact LibraryArtifact
	var rootMCPRun LibraryRun
	var rootMCPArtifact LibraryArtifact
	defer func() {
		// Delete only the generated rows, in FK-safe order, so this integration
		// test remains safe alongside the rest of the shared test database.
		if artifactGrant.ID != "" {
			_, _ = store.pool.Exec(context.Background(), `DELETE FROM narthex_library_artifact_grants WHERE id=$1`, artifactGrant.ID)
		}
		if artifact.ID != "" {
			_, _ = store.pool.Exec(context.Background(), `DELETE FROM narthex_library_artifact_versions WHERE artifact_id=$1`, artifact.ID)
			_, _ = store.pool.Exec(context.Background(), `DELETE FROM narthex_library_artifacts WHERE id=$1`, artifact.ID)
		}
		if artifactClient.ID != "" {
			_, _ = store.pool.Exec(context.Background(), `DELETE FROM narthex_mcp_clients WHERE id=$1`, artifactClient.ID)
		}
		if run.ID != "" {
			_, _ = store.pool.Exec(context.Background(), `DELETE FROM narthex_library_runs WHERE id=$1`, run.ID)
		}
		if evaluation.ID != "" {
			_, _ = store.pool.Exec(context.Background(), `DELETE FROM narthex_library_skill_evaluations WHERE id=$1`, evaluation.ID)
		}
		if binding.ID != "" {
			_, _ = store.pool.Exec(context.Background(), `DELETE FROM narthex_library_skill_bindings WHERE id=$1`, binding.ID)
		}
		if skill.ID != "" {
			_, _ = store.pool.Exec(context.Background(), `DELETE FROM narthex_library_skill_versions WHERE skill_id=$1`, skill.ID)
			_, _ = store.pool.Exec(context.Background(), `DELETE FROM narthex_library_skill_binding_generations WHERE skill_id=$1`, skill.ID)
			_, _ = store.pool.Exec(context.Background(), `DELETE FROM narthex_library_skills WHERE id=$1`, skill.ID)
		}
		if draft.ID != "" {
			_, _ = store.pool.Exec(context.Background(), `DELETE FROM narthex_library_skill_drafts WHERE id=$1`, draft.ID)
		}
		if postArtifact.ID != "" {
			_, _ = store.pool.Exec(context.Background(), `DELETE FROM narthex_library_artifact_versions WHERE artifact_id=$1`, postArtifact.ID)
			_, _ = store.pool.Exec(context.Background(), `DELETE FROM narthex_library_artifacts WHERE id=$1`, postArtifact.ID)
		}
		if rootMCPArtifact.ID != "" {
			_, _ = store.pool.Exec(context.Background(), `DELETE FROM narthex_library_artifact_versions WHERE artifact_id=$1`, rootMCPArtifact.ID)
			_, _ = store.pool.Exec(context.Background(), `DELETE FROM narthex_library_artifacts WHERE id=$1`, rootMCPArtifact.ID)
		}
		if postRun.ID != "" {
			_, _ = store.pool.Exec(context.Background(), `DELETE FROM narthex_library_runs WHERE id=$1`, postRun.ID)
		}
		if rootMCPRun.ID != "" {
			_, _ = store.pool.Exec(context.Background(), `DELETE FROM narthex_library_runs WHERE id=$1`, rootMCPRun.ID)
		}
		if postEvaluation.ID != "" {
			_, _ = store.pool.Exec(context.Background(), `DELETE FROM narthex_library_skill_evaluations WHERE id=$1`, postEvaluation.ID)
		}
		if postBinding.ID != "" {
			_, _ = store.pool.Exec(context.Background(), `DELETE FROM narthex_library_skill_bindings WHERE id=$1`, postBinding.ID)
		}
		if postSkill.ID != "" {
			_, _ = store.pool.Exec(context.Background(), `DELETE FROM narthex_library_skill_versions WHERE skill_id=$1`, postSkill.ID)
			_, _ = store.pool.Exec(context.Background(), `DELETE FROM narthex_library_skill_binding_generations WHERE skill_id=$1`, postSkill.ID)
			_, _ = store.pool.Exec(context.Background(), `DELETE FROM narthex_library_skills WHERE id=$1`, postSkill.ID)
		}
		if postDraft.ID != "" {
			_, _ = store.pool.Exec(context.Background(), `DELETE FROM narthex_library_skill_drafts WHERE id=$1`, postDraft.ID)
		}
	}()

	skill, skillVersion, err = store.CreateLibrarySkillWithInitialVersion(ctx, LibrarySkill{
		Slug: "pg-library-" + newPgFixtureSuffix(), Name: "PG Library skill", Description: "Portable test skill", CreatedBy: "actor-pg",
	}, LibrarySkillVersion{Content: "# PG instructions\nKeep this encrypted.", RequestedCapabilities: []string{"repo.read"}, CreatedBy: "actor-pg"})
	if err != nil {
		t.Fatalf("CreateLibrarySkillWithInitialVersion: %v", err)
	}
	draft, err = store.CreateLibrarySkillDraft(ctx, LibrarySkillDraft{
		Name: "PG draft", Description: "Generated draft metadata", Content: "# Draft", Origin: LibraryDraftOriginGenerated, Generator: "test", Model: "test", PromptDigest: libraryDigest("pg brief"), CreatedBy: "actor-pg",
	})
	if err != nil {
		t.Fatalf("CreateLibrarySkillDraft: %v", err)
	}
	binding, err = store.UpsertLibrarySkillBinding(ctx, LibrarySkillBinding{
		SkillID: skill.ID, ScopeKind: LibraryScopeNamespace, ScopeID: "engineering", Mode: LibraryBindingModePin, PinnedVersionID: skillVersion.ID, CapabilityCeiling: []string{"repo.read"}, CreatedBy: "actor-pg",
	})
	if err != nil {
		t.Fatalf("UpsertLibrarySkillBinding: %v", err)
	}
	evaluation, err = store.CreateLibrarySkillEvaluation(ctx, LibrarySkillEvaluation{
		SkillID: skill.ID, SkillVersionID: skillVersion.ID, Evaluator: "deterministic", Score: 100, Passed: true, Summary: "verified", CreatedBy: "actor-pg",
	})
	if err != nil {
		t.Fatalf("CreateLibrarySkillEvaluation: %v", err)
	}
	run, err = store.CreateLibraryRun(ctx, LibraryRun{
		Origin: LibraryRunOriginSkillRun, SkillID: skill.ID, SkillVersionID: skillVersion.ID, BindingID: binding.ID, ActorRef: "agent-pg", SurfaceRef: "mcp", EffectiveCapabilities: []string{"repo.read"}, Status: "succeeded",
	})
	if err != nil {
		t.Fatalf("CreateLibraryRun: %v", err)
	}
	artifact, artifactVersion, err = store.CreateLibraryArtifactWithInitialVersion(ctx, LibraryArtifact{
		Title: "PG artifact", Summary: "Portable artifact", Origin: LibraryArtifactOriginSkillRun, RunID: run.ID, SkillID: skill.ID, SkillVersionID: skillVersion.ID, BindingID: binding.ID, CreatedBy: "agent-pg",
	}, LibraryArtifactVersion{Format: LibraryArtifactFormatMarkdown, Body: "# PG artifact\nKeep this encrypted.", CreatedBy: "agent-pg"})
	if err != nil {
		t.Fatalf("CreateLibraryArtifactWithInitialVersion: %v", err)
	}
	artifactClient, err = store.CreateMCPClient(ctx, MCPClient{Name: "PG artifact reader", Subject: "usr_pg_reader", CreatedBy: "usr_pg_reader"})
	if err != nil {
		t.Fatalf("CreateMCPClient: %v", err)
	}
	if _, err := store.ReviewLibraryArtifactVersion(ctx, artifact.ID, artifactVersion.ID, LibraryRedactionApproved, "reviewer-pg", time.Now().UTC()); err != nil {
		t.Fatalf("ReviewLibraryArtifactVersion: %v", err)
	}
	// Existing plaintext Library rows must be upgraded when a self-hosted
	// Engine first enables encryption, just like account secrets and audit
	// payloads. This is also how a hosted Engine starts safely.
	store.SetCipher(testCipher(t, 47))
	if err := store.EncryptExisting(ctx); err != nil {
		t.Fatalf("EncryptExisting Library migration: %v", err)
	}
	artifactGrant, err = store.CreateLibraryArtifactGrant(ctx, LibraryArtifactGrant{
		ArtifactID: artifact.ID, ArtifactVersionID: artifactVersion.ID, ArtifactVersionDigest: artifactVersion.Digest,
		AgentSurfaceID: artifactClient.ID, CreatedBy: "actor-pg",
	})
	if err != nil {
		t.Fatalf("CreateLibraryArtifactGrant: %v", err)
	}

	assertEncrypted := func(label, stored, plaintext string) {
		t.Helper()
		// The cipher deliberately leaves an empty value empty: there is nothing
		// to protect and a ciphertext would only advertise which optional
		// fields were unset. Every non-empty value must carry the prefix and
		// must not contain its plaintext.
		if plaintext == "" {
			if stored != "" {
				t.Fatalf("%s must stay empty at rest, got %q", label, stored)
			}
			return
		}
		if !strings.HasPrefix(stored, encPrefix) || strings.Contains(stored, plaintext) {
			t.Fatalf("%s was not encrypted at rest", label)
		}
	}

	var skillName, skillDescription, skillCreatedBy, encryptedInstruction, versionCreatedBy string
	if err := store.pool.QueryRow(ctx, `SELECT name,description,created_by FROM narthex_library_skills WHERE id=$1`, skill.ID).Scan(&skillName, &skillDescription, &skillCreatedBy); err != nil {
		t.Fatal(err)
	}
	if err := store.pool.QueryRow(ctx, `SELECT content,created_by FROM narthex_library_skill_versions WHERE id=$1`, skillVersion.ID).Scan(&encryptedInstruction, &versionCreatedBy); err != nil {
		t.Fatal(err)
	}
	var draftName, draftDescription, draftContent, draftGenerator, draftModel, draftCreatedBy string
	if err := store.pool.QueryRow(ctx, `SELECT name,description,content,generator,model,created_by FROM narthex_library_skill_drafts WHERE id=$1`, draft.ID).Scan(&draftName, &draftDescription, &draftContent, &draftGenerator, &draftModel, &draftCreatedBy); err != nil {
		t.Fatal(err)
	}
	var bindingCreatedBy string
	if err := store.pool.QueryRow(ctx, `SELECT created_by FROM narthex_library_skill_bindings WHERE id=$1`, binding.ID).Scan(&bindingCreatedBy); err != nil {
		t.Fatal(err)
	}
	var evaluator, evaluationSummary, evaluationCreatedBy string
	if err := store.pool.QueryRow(ctx, `SELECT evaluator,summary,created_by FROM narthex_library_skill_evaluations WHERE id=$1`, evaluation.ID).Scan(&evaluator, &evaluationSummary, &evaluationCreatedBy); err != nil {
		t.Fatal(err)
	}
	var actorRef, surfaceRef string
	if err := store.pool.QueryRow(ctx, `SELECT actor_ref,surface_ref FROM narthex_library_runs WHERE id=$1`, run.ID).Scan(&actorRef, &surfaceRef); err != nil {
		t.Fatal(err)
	}
	var artifactTitle, artifactSummary, artifactCreatedBy, encryptedArtifact, artifactVersionCreatedBy, reviewedBy string
	if err := store.pool.QueryRow(ctx, `SELECT title,summary,created_by FROM narthex_library_artifacts WHERE id=$1`, artifact.ID).Scan(&artifactTitle, &artifactSummary, &artifactCreatedBy); err != nil {
		t.Fatal(err)
	}
	if err := store.pool.QueryRow(ctx, `SELECT body,created_by,reviewed_by FROM narthex_library_artifact_versions WHERE id=$1`, artifactVersion.ID).Scan(&encryptedArtifact, &artifactVersionCreatedBy, &reviewedBy); err != nil {
		t.Fatal(err)
	}
	var grantCreatedBy string
	if err := store.pool.QueryRow(ctx, `SELECT created_by FROM narthex_library_artifact_grants WHERE id=$1`, artifactGrant.ID).Scan(&grantCreatedBy); err != nil {
		t.Fatal(err)
	}
	assertEncrypted("skill name", skillName, skill.Name)
	assertEncrypted("skill description", skillDescription, skill.Description)
	assertEncrypted("skill created by", skillCreatedBy, skill.CreatedBy)
	assertEncrypted("skill instructions", encryptedInstruction, skillVersion.Content)
	assertEncrypted("skill version created by", versionCreatedBy, skillVersion.CreatedBy)
	assertEncrypted("draft name", draftName, draft.Name)
	assertEncrypted("draft description", draftDescription, draft.Description)
	assertEncrypted("draft content", draftContent, draft.Content)
	assertEncrypted("draft generator", draftGenerator, draft.Generator)
	assertEncrypted("draft model", draftModel, draft.Model)
	assertEncrypted("draft created by", draftCreatedBy, draft.CreatedBy)
	assertEncrypted("binding created by", bindingCreatedBy, binding.CreatedBy)
	assertEncrypted("evaluation evaluator", evaluator, evaluation.Evaluator)
	assertEncrypted("evaluation summary", evaluationSummary, evaluation.Summary)
	assertEncrypted("evaluation created by", evaluationCreatedBy, evaluation.CreatedBy)
	assertEncrypted("run actor reference", actorRef, run.ActorRef)
	assertEncrypted("run surface reference", surfaceRef, run.SurfaceRef)
	assertEncrypted("artifact title", artifactTitle, artifact.Title)
	assertEncrypted("artifact summary", artifactSummary, artifact.Summary)
	assertEncrypted("artifact created by", artifactCreatedBy, artifact.CreatedBy)
	assertEncrypted("artifact body", encryptedArtifact, artifactVersion.Body)
	assertEncrypted("artifact version created by", artifactVersionCreatedBy, artifactVersion.CreatedBy)
	assertEncrypted("artifact reviewed by", reviewedBy, "reviewer-pg")
	assertEncrypted("artifact grant created by", grantCreatedBy, artifactGrant.CreatedBy)

	gotSkill, found := store.LibrarySkill(ctx, skill.ID)
	if !found || gotSkill.Name != skill.Name || gotSkill.Description != skill.Description || gotSkill.CreatedBy != skill.CreatedBy {
		t.Fatalf("skill round trip=%+v found=%t", gotSkill, found)
	}
	gotDraft, found := store.LibrarySkillDraft(ctx, draft.ID)
	if !found || gotDraft.Name != draft.Name || gotDraft.Description != draft.Description || gotDraft.Content != draft.Content || gotDraft.Generator != draft.Generator || gotDraft.Model != draft.Model || gotDraft.CreatedBy != draft.CreatedBy {
		t.Fatalf("draft round trip=%+v found=%t", gotDraft, found)
	}
	evaluations, err := store.LibrarySkillEvaluations(ctx, skill.ID)
	if err != nil || len(evaluations) != 1 || evaluations[0].Evaluator != evaluation.Evaluator || evaluations[0].Summary != evaluation.Summary || evaluations[0].CreatedBy != evaluation.CreatedBy {
		t.Fatalf("evaluations=%#v err=%v", evaluations, err)
	}
	bindings, err := store.LibrarySkillBindings(ctx, skill.ID)
	if err != nil || len(bindings) != 1 || bindings[0].CreatedBy != binding.CreatedBy {
		t.Fatalf("bindings=%#v err=%v", bindings, err)
	}
	gotRun, found := store.LibraryRun(ctx, run.ID)
	if !found || gotRun.ActorRef != run.ActorRef || gotRun.SurfaceRef != run.SurfaceRef {
		t.Fatalf("run round trip=%+v found=%t", gotRun, found)
	}
	gotArtifact, found := store.LibraryArtifact(ctx, artifact.ID)
	if !found || gotArtifact.Title != artifact.Title || gotArtifact.Summary != artifact.Summary || gotArtifact.CreatedBy != artifact.CreatedBy {
		t.Fatalf("artifact round trip=%+v found=%t", gotArtifact, found)
	}
	gotArtifactVersion, found := store.LibraryArtifactVersion(ctx, artifact.ID, artifactVersion.ID)
	if !found || gotArtifactVersion.CreatedBy != artifactVersion.CreatedBy || gotArtifactVersion.ReviewedBy != "reviewer-pg" {
		t.Fatalf("artifact version round trip=%+v found=%t", gotArtifactVersion, found)
	}
	grants, err := store.LibraryArtifactGrants(ctx, artifact.ID)
	if err != nil || len(grants) != 1 || grants[0].ID != artifactGrant.ID || grants[0].CreatedBy != artifactGrant.CreatedBy || grants[0].ArtifactVersionDigest != artifactVersion.Digest {
		t.Fatalf("artifact grants=%#v err=%v", grants, err)
	}
	versions, err := store.LibrarySkillVersions(ctx, skill.ID)
	if err != nil || len(versions) != 1 || versions[0].Content != skillVersion.Content {
		t.Fatalf("skill versions=%#v err=%v", versions, err)
	}
	resolution, err := ResolveLibrarySkills(ctx, store, LibrarySkillResolutionRequest{NamespaceID: "engineering"})
	if err != nil || len(resolution.Skills) != 1 || resolution.Skills[0].SkillID != skill.ID || resolution.Skills[0].VersionID != skillVersion.ID || resolution.Skills[0].Content != skillVersion.Content || resolution.Skills[0].ResolutionSource != LibraryScopeNamespace {
		t.Fatalf("Postgres library resolution=%+v err=%v", resolution, err)
	}
	candidate, err := store.LibraryPublicationCandidate(ctx, artifact.ID)
	if err != nil || candidate.Body != artifactVersion.Body || candidate.Provenance.SkillName != skill.Name || candidate.Provenance.SkillVersion != 1 {
		t.Fatalf("publication candidate=%+v err=%v", candidate, err)
	}
	if _, err := store.ClaimLibraryPublicationCandidate(ctx, artifact.ID, candidate.ArtifactVersionID, candidate.Digest); err != nil {
		t.Fatalf("ClaimLibraryPublicationCandidate: %v", err)
	}
	claimedVersion, found := store.LibraryArtifactVersion(ctx, artifact.ID, artifactVersion.ID)
	if !found || claimedVersion.PublicationClaimedAt.IsZero() {
		t.Fatalf("claimed artifact version=%+v found=%v", claimedVersion, found)
	}
	if _, err := store.ReviewLibraryArtifactVersion(ctx, artifact.ID, artifactVersion.ID, LibraryRedactionRejected, "reviewer-pg", time.Now().UTC()); !errors.Is(err, ErrLibraryArtifactPublicationClaimed) {
		t.Fatalf("claimed artifact version review error=%v, want claim conflict", err)
	}

	// New writes after migration must use the same encrypted columns rather
	// than relying on EncryptExisting to repair them later.
	var postVersion LibrarySkillVersion
	postSkill, postVersion, err = store.CreateLibrarySkillWithInitialVersion(ctx, LibrarySkill{
		Slug: "pg-library-post-" + newPgFixtureSuffix(), Name: "Post-migration skill", Description: "New encrypted skill metadata", CreatedBy: "actor-pg",
	}, LibrarySkillVersion{Content: "# Post-migration instructions", CreatedBy: "actor-pg"})
	if err != nil {
		t.Fatalf("post-migration CreateLibrarySkillWithInitialVersion: %v", err)
	}
	postDraft, err = store.CreateLibrarySkillDraft(ctx, LibrarySkillDraft{
		Name: "Post-migration draft", Description: "New encrypted draft metadata", Content: "# Post-migration draft", Origin: LibraryDraftOriginManual, CreatedBy: "actor-pg",
	})
	if err != nil {
		t.Fatalf("post-migration CreateLibrarySkillDraft: %v", err)
	}
	postBinding, err = store.UpsertLibrarySkillBinding(ctx, LibrarySkillBinding{
		SkillID: postSkill.ID, ScopeKind: LibraryScopeNamespace, ScopeID: "post-migration-engineering", Mode: LibraryBindingModeTrack, CreatedBy: "actor-pg",
	})
	if err != nil {
		t.Fatalf("post-migration UpsertLibrarySkillBinding: %v", err)
	}
	postEvaluation, err = store.CreateLibrarySkillEvaluation(ctx, LibrarySkillEvaluation{
		SkillID: postSkill.ID, SkillVersionID: postVersion.ID, Evaluator: "post-migration evaluator", Score: 100, Passed: true, Summary: "New encrypted evaluation summary", CreatedBy: "actor-pg",
	})
	if err != nil {
		t.Fatalf("post-migration CreateLibrarySkillEvaluation: %v", err)
	}
	postRun, err = store.CreateLibraryRun(ctx, LibraryRun{
		Origin: LibraryRunOriginAgentDirect, ActorRef: "post-migration-agent", SurfaceRef: "post-migration-mcp", Status: "succeeded",
		SourceArtifactID: artifact.ID, SourceArtifactVersionID: artifactVersion.ID, SourceArtifactDigest: artifactVersion.Digest,
	})
	if err != nil {
		t.Fatalf("post-migration CreateLibraryRun: %v", err)
	}
	var postArtifactVersion LibraryArtifactVersion
	postArtifact, postArtifactVersion, err = store.CreateLibraryArtifactWithInitialVersion(ctx, LibraryArtifact{
		Title: "Post-migration artifact", Summary: "New encrypted artifact metadata", Origin: LibraryArtifactOriginAgentDirect, RunID: postRun.ID, CreatedBy: "agent-pg",
		SourceArtifactID: artifact.ID, SourceArtifactVersionID: artifactVersion.ID, SourceArtifactDigest: artifactVersion.Digest,
	}, LibraryArtifactVersion{Format: LibraryArtifactFormatText, Body: "Post-migration artifact body", CreatedBy: "agent-pg"})
	if err != nil {
		t.Fatalf("post-migration CreateLibraryArtifactWithInitialVersion: %v", err)
	}
	if _, err := store.ReviewLibraryArtifactVersion(ctx, postArtifact.ID, postArtifactVersion.ID, LibraryRedactionApproved, "post-migration-reviewer", time.Now().UTC()); err != nil {
		t.Fatalf("post-migration ReviewLibraryArtifactVersion: %v", err)
	}
	rootMCPRun, rootMCPArtifact, _, err = store.CreateLibraryRootMCPArtifactWithInitialVersion(ctx, LibraryArtifact{
		Title: "Post-migration root MCP artifact", Origin: LibraryArtifactOriginAgentDirect,
	}, LibraryArtifactVersion{Format: LibraryArtifactFormatText, Body: "Atomically persisted root MCP artifact"})
	if err != nil {
		t.Fatalf("post-migration CreateLibraryRootMCPArtifactWithInitialVersion: %v", err)
	}
	storedRootMCPRun, found := store.LibraryRun(ctx, rootMCPRun.ID)
	if !found || storedRootMCPRun.ActorRef != libraryRootMCPActorRef || storedRootMCPRun.SurfaceRef != libraryRootMCPSurfaceRef {
		t.Fatalf("post-migration root MCP run=%+v found=%t", storedRootMCPRun, found)
	}
	storedRootMCPArtifact, found := store.LibraryArtifact(ctx, rootMCPArtifact.ID)
	if !found || storedRootMCPArtifact.RunID != rootMCPRun.ID || storedRootMCPArtifact.CreatedBy != libraryRootMCPActorRef || storedRootMCPArtifact.AgentSurfaceID != "" {
		t.Fatalf("post-migration root MCP artifact=%+v found=%t", storedRootMCPArtifact, found)
	}

	if err := store.pool.QueryRow(ctx, `SELECT name,description,created_by FROM narthex_library_skills WHERE id=$1`, postSkill.ID).Scan(&skillName, &skillDescription, &skillCreatedBy); err != nil {
		t.Fatal(err)
	}
	assertEncrypted("new skill name", skillName, postSkill.Name)
	assertEncrypted("new skill description", skillDescription, postSkill.Description)
	assertEncrypted("new skill created by", skillCreatedBy, postSkill.CreatedBy)
	if err := store.pool.QueryRow(ctx, `SELECT content,created_by FROM narthex_library_skill_versions WHERE id=$1`, postVersion.ID).Scan(&encryptedInstruction, &versionCreatedBy); err != nil {
		t.Fatal(err)
	}
	assertEncrypted("new skill instructions", encryptedInstruction, postVersion.Content)
	assertEncrypted("new skill version created by", versionCreatedBy, postVersion.CreatedBy)
	if err := store.pool.QueryRow(ctx, `SELECT name,description,content,generator,model,created_by FROM narthex_library_skill_drafts WHERE id=$1`, postDraft.ID).Scan(&draftName, &draftDescription, &draftContent, &draftGenerator, &draftModel, &draftCreatedBy); err != nil {
		t.Fatal(err)
	}
	assertEncrypted("new draft name", draftName, postDraft.Name)
	assertEncrypted("new draft description", draftDescription, postDraft.Description)
	assertEncrypted("new draft content", draftContent, postDraft.Content)
	assertEncrypted("new draft generator", draftGenerator, postDraft.Generator)
	assertEncrypted("new draft model", draftModel, postDraft.Model)
	assertEncrypted("new draft created by", draftCreatedBy, postDraft.CreatedBy)
	if err := store.pool.QueryRow(ctx, `SELECT created_by FROM narthex_library_skill_bindings WHERE id=$1`, postBinding.ID).Scan(&bindingCreatedBy); err != nil {
		t.Fatal(err)
	}
	assertEncrypted("new binding created by", bindingCreatedBy, postBinding.CreatedBy)
	if err := store.pool.QueryRow(ctx, `SELECT evaluator,summary,created_by FROM narthex_library_skill_evaluations WHERE id=$1`, postEvaluation.ID).Scan(&evaluator, &evaluationSummary, &evaluationCreatedBy); err != nil {
		t.Fatal(err)
	}
	assertEncrypted("new evaluation evaluator", evaluator, postEvaluation.Evaluator)
	assertEncrypted("new evaluation summary", evaluationSummary, postEvaluation.Summary)
	assertEncrypted("new evaluation created by", evaluationCreatedBy, postEvaluation.CreatedBy)
	var sourceArtifactID, sourceArtifactVersionID, sourceArtifactDigest string
	if err := store.pool.QueryRow(ctx, `SELECT actor_ref,surface_ref,source_artifact_id,source_artifact_version_id,source_artifact_digest FROM narthex_library_runs WHERE id=$1`, postRun.ID).Scan(&actorRef, &surfaceRef, &sourceArtifactID, &sourceArtifactVersionID, &sourceArtifactDigest); err != nil {
		t.Fatal(err)
	}
	assertEncrypted("new run actor reference", actorRef, postRun.ActorRef)
	assertEncrypted("new run surface reference", surfaceRef, postRun.SurfaceRef)
	assertEncrypted("new run source artifact", sourceArtifactID, postRun.SourceArtifactID)
	assertEncrypted("new run source artifact version", sourceArtifactVersionID, postRun.SourceArtifactVersionID)
	assertEncrypted("new run source artifact digest", sourceArtifactDigest, postRun.SourceArtifactDigest)
	if err := store.pool.QueryRow(ctx, `SELECT title,summary,source_artifact_id,source_artifact_version_id,source_artifact_digest,created_by FROM narthex_library_artifacts WHERE id=$1`, postArtifact.ID).Scan(&artifactTitle, &artifactSummary, &sourceArtifactID, &sourceArtifactVersionID, &sourceArtifactDigest, &artifactCreatedBy); err != nil {
		t.Fatal(err)
	}
	assertEncrypted("new artifact title", artifactTitle, postArtifact.Title)
	assertEncrypted("new artifact summary", artifactSummary, postArtifact.Summary)
	assertEncrypted("new artifact created by", artifactCreatedBy, postArtifact.CreatedBy)
	assertEncrypted("new artifact source artifact", sourceArtifactID, postArtifact.SourceArtifactID)
	assertEncrypted("new artifact source artifact version", sourceArtifactVersionID, postArtifact.SourceArtifactVersionID)
	assertEncrypted("new artifact source artifact digest", sourceArtifactDigest, postArtifact.SourceArtifactDigest)
	if err := store.pool.QueryRow(ctx, `SELECT body,created_by,reviewed_by FROM narthex_library_artifact_versions WHERE id=$1`, postArtifactVersion.ID).Scan(&encryptedArtifact, &artifactVersionCreatedBy, &reviewedBy); err != nil {
		t.Fatal(err)
	}
	assertEncrypted("new artifact body", encryptedArtifact, postArtifactVersion.Body)
	assertEncrypted("new artifact version created by", artifactVersionCreatedBy, postArtifactVersion.CreatedBy)
	assertEncrypted("new artifact reviewed by", reviewedBy, "post-migration-reviewer")
}

func TestPgLibraryMCPRootPages(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to run the Postgres Library integration test")
	}
	ctx := context.Background()
	store, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatalf("NewPgStore: %v", err)
	}
	defer store.Close()

	var skillIDs []string
	var artifactIDs []string
	defer func() {
		for _, id := range artifactIDs {
			_, _ = store.pool.Exec(context.Background(), `DELETE FROM narthex_library_artifact_versions WHERE artifact_id=$1`, id)
			_, _ = store.pool.Exec(context.Background(), `DELETE FROM narthex_library_artifacts WHERE id=$1`, id)
		}
		for _, id := range skillIDs {
			_, _ = store.pool.Exec(context.Background(), `DELETE FROM narthex_library_skill_versions WHERE skill_id=$1`, id)
			_, _ = store.pool.Exec(context.Background(), `DELETE FROM narthex_library_skill_binding_generations WHERE skill_id=$1`, id)
			_, _ = store.pool.Exec(context.Background(), `DELETE FROM narthex_library_skills WHERE id=$1`, id)
		}
	}()

	// Keep this test's rows first in a shared integration database without
	// relying on global cleanup. Distinct times also exercise the keyset's
	// primary sort key instead of only its ID tie-breaker.
	base := time.Date(2100, time.January, 1, 0, 0, 0, 0, time.UTC)
	prefix := "pg-root-page-" + newPgFixtureSuffix()
	skillVersions := make([]LibrarySkillVersion, 0, 3)
	for index, suffix := range []string{"alpha", "bravo", "charlie"} {
		skill, version, err := store.CreateLibrarySkillWithInitialVersion(ctx, LibrarySkill{
			Slug: prefix + "-" + suffix, Name: "PG root page " + suffix, Description: "metadata only", CreatedBy: "pg-root-page",
		}, LibrarySkillVersion{Content: "# pg-root-page-skill-body " + suffix, CreatedBy: "pg-root-page"})
		if err != nil {
			t.Fatalf("create %s skill: %v", suffix, err)
		}
		if _, err := store.pool.Exec(ctx, `UPDATE narthex_library_skills SET created_at=$2 WHERE id=$1`, skill.ID, base.Add(time.Duration(index)*time.Second)); err != nil {
			t.Fatalf("set %s skill page time: %v", suffix, err)
		}
		if suffix == "charlie" {
			version, err = store.CreateLibrarySkillVersion(ctx, LibrarySkillVersion{
				SkillID: skill.ID, Content: "# pg-root-page-skill-body " + suffix + " v2", CreatedBy: "pg-root-page",
			})
			if err != nil {
				t.Fatalf("create latest %s skill version: %v", suffix, err)
			}
		}
		skillIDs = append(skillIDs, skill.ID)
		skillVersions = append(skillVersions, version)
	}
	for index, suffix := range []string{"alpha", "bravo", "charlie"} {
		artifact, _, err := store.CreateLibraryArtifactWithInitialVersion(ctx, LibraryArtifact{
			Title: "PG root page artifact " + suffix, Origin: LibraryArtifactOriginHuman, CreatedBy: "pg-root-page",
			CreatedAt: base.Add(time.Duration(index) * time.Second),
		}, LibraryArtifactVersion{Format: LibraryArtifactFormatText, Body: "pg-root-page-artifact-body " + suffix, CreatedBy: "pg-root-page"})
		if err != nil {
			t.Fatalf("create %s artifact: %v", suffix, err)
		}
		artifactIDs = append(artifactIDs, artifact.ID)
	}

	skillPage, err := store.LibraryMCPRootSkillPage(ctx, LibraryMCPRootPageCursor{}, 1)
	if err != nil || len(skillPage.Skills) != 1 || skillPage.Skills[0].ID != skillIDs[2] || skillPage.Skills[0].LatestVersionID != skillVersions[2].ID || skillPage.NextCursor.ID == "" {
		t.Fatalf("first Postgres root skill page=%+v err=%v", skillPage, err)
	}
	skillPage, err = store.LibraryMCPRootSkillPage(ctx, skillPage.NextCursor, 1)
	if err != nil || len(skillPage.Skills) != 1 || skillPage.Skills[0].ID != skillIDs[1] {
		t.Fatalf("second Postgres root skill page=%+v err=%v", skillPage, err)
	}

	artifactPage, err := store.LibraryMCPRootArtifactPage(ctx, LibraryMCPRootPageCursor{}, 1)
	if err != nil || len(artifactPage.Artifacts) != 1 || artifactPage.Artifacts[0].ID != artifactIDs[2] || artifactPage.NextCursor.ID == "" {
		t.Fatalf("first Postgres root artifact page=%+v err=%v", artifactPage, err)
	}
	artifactPage, err = store.LibraryMCPRootArtifactPage(ctx, artifactPage.NextCursor, 1)
	if err != nil || len(artifactPage.Artifacts) != 1 || artifactPage.Artifacts[0].ID != artifactIDs[1] {
		t.Fatalf("second Postgres root artifact page=%+v err=%v", artifactPage, err)
	}
}

func TestPgLibraryConsolePages(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to run the Postgres Library integration test")
	}
	ctx := context.Background()
	store, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatalf("NewPgStore: %v", err)
	}
	defer store.Close()

	var skillIDs, artifactIDs, runIDs []string
	defer func() {
		for _, id := range runIDs {
			_, _ = store.pool.Exec(context.Background(), `DELETE FROM narthex_library_runs WHERE id=$1`, id)
		}
		for _, id := range artifactIDs {
			_, _ = store.pool.Exec(context.Background(), `DELETE FROM narthex_library_artifact_versions WHERE artifact_id=$1`, id)
			_, _ = store.pool.Exec(context.Background(), `DELETE FROM narthex_library_artifacts WHERE id=$1`, id)
		}
		for _, id := range skillIDs {
			_, _ = store.pool.Exec(context.Background(), `DELETE FROM narthex_library_skill_versions WHERE skill_id=$1`, id)
			_, _ = store.pool.Exec(context.Background(), `DELETE FROM narthex_library_skill_binding_generations WHERE skill_id=$1`, id)
			_, _ = store.pool.Exec(context.Background(), `DELETE FROM narthex_library_skills WHERE id=$1`, id)
		}
	}()

	// A distant timestamp range makes a shared integration database's ordinary
	// fixture rows irrelevant while still exercising the updated-at keyset.
	base := time.Date(2300, time.January, 1, 0, 0, 0, 0, time.UTC)
	prefix := "pg-console-page-" + newPgFixtureSuffix()
	skillVersions := make([]LibrarySkillVersion, 0, 3)
	for index, suffix := range []string{"alpha", "bravo", "charlie"} {
		skill, version, err := store.CreateLibrarySkillWithInitialVersion(ctx, LibrarySkill{
			Slug: prefix + "-" + suffix, Name: "PG console page " + suffix, Description: "metadata only", CreatedBy: "pg-console-page",
		}, LibrarySkillVersion{Content: "# pg-console-page-skill-body " + suffix, RequestedCapabilities: []string{"artifact.read"}, CreatedBy: "pg-console-page"})
		if err != nil {
			t.Fatalf("create %s skill: %v", suffix, err)
		}
		if _, err := store.pool.Exec(ctx, `UPDATE narthex_library_skills SET created_at=$2,updated_at=$2 WHERE id=$1`, skill.ID, base.Add(time.Duration(index)*time.Second)); err != nil {
			t.Fatalf("set %s skill page time: %v", suffix, err)
		}
		if suffix == "alpha" {
			version, err = store.CreateLibrarySkillVersion(ctx, LibrarySkillVersion{
				SkillID: skill.ID, Content: "# pg-console-page-skill-body " + suffix + " v2", RequestedCapabilities: []string{"artifact.read", "artifact.write"}, CreatedBy: "pg-console-page",
				CreatedAt: base.Add(3 * time.Second),
			})
			if err != nil {
				t.Fatalf("create latest %s skill version: %v", suffix, err)
			}
		}
		skillIDs = append(skillIDs, skill.ID)
		skillVersions = append(skillVersions, version)

		artifact, _, err := store.CreateLibraryArtifactWithInitialVersion(ctx, LibraryArtifact{
			Title: "PG console page artifact " + suffix, Origin: LibraryArtifactOriginHuman, CreatedBy: "pg-console-page",
			CreatedAt: base.Add(time.Duration(index) * time.Second),
		}, LibraryArtifactVersion{Format: LibraryArtifactFormatText, Body: "pg-console-page-artifact-body " + suffix, CreatedBy: "pg-console-page"})
		if err != nil {
			t.Fatalf("create %s artifact: %v", suffix, err)
		}
		artifactIDs = append(artifactIDs, artifact.ID)

		run, err := store.CreateLibraryRun(ctx, LibraryRun{
			Origin: LibraryRunOriginHuman, ActorRef: "pg-console-page", SurfaceRef: "console", Status: "succeeded",
			InputDigest: libraryDigest("pg-console-input-" + suffix), OutputDigest: libraryDigest("pg-console-output-" + suffix),
			StartedAt: base.Add(time.Duration(index) * time.Second), CompletedAt: base.Add(time.Duration(index) * time.Second),
		})
		if err != nil {
			t.Fatalf("create %s run: %v", suffix, err)
		}
		runIDs = append(runIDs, run.ID)
	}

	skillPage, err := store.LibraryConsoleSkillPage(ctx, LibraryConsolePageCursor{}, 1)
	if err != nil || len(skillPage.Skills) != 1 || skillPage.Skills[0].Skill.ID != skillIDs[0] || skillPage.Skills[0].LatestVersion == nil || skillPage.Skills[0].LatestVersion.ID != skillVersions[0].ID || skillPage.NextCursor.ID == "" {
		t.Fatalf("first Postgres Console skill page=%+v err=%v", skillPage, err)
	}
	skillPage, err = store.LibraryConsoleSkillPage(ctx, skillPage.NextCursor, 1)
	if err != nil || len(skillPage.Skills) != 1 || skillPage.Skills[0].Skill.ID != skillIDs[2] || skillPage.NextCursor.ID == "" {
		t.Fatalf("second Postgres Console skill page=%+v err=%v", skillPage, err)
	}
	skillPage, err = store.LibraryConsoleSkillPage(ctx, skillPage.NextCursor, 1)
	if err != nil || len(skillPage.Skills) != 1 || skillPage.Skills[0].Skill.ID != skillIDs[1] || skillPage.NextCursor.ID != "" {
		t.Fatalf("final Postgres Console skill page=%+v err=%v", skillPage, err)
	}

	artifactPage, err := store.LibraryConsoleArtifactPage(ctx, LibraryConsolePageCursor{}, 1)
	if err != nil || len(artifactPage.Artifacts) != 1 || artifactPage.Artifacts[0].ID != artifactIDs[2] || artifactPage.NextCursor.ID == "" {
		t.Fatalf("first Postgres Console artifact page=%+v err=%v", artifactPage, err)
	}
	artifactPage, err = store.LibraryConsoleArtifactPage(ctx, artifactPage.NextCursor, 1)
	if err != nil || len(artifactPage.Artifacts) != 1 || artifactPage.Artifacts[0].ID != artifactIDs[1] || artifactPage.NextCursor.ID == "" {
		t.Fatalf("second Postgres Console artifact page=%+v err=%v", artifactPage, err)
	}
	artifactPage, err = store.LibraryConsoleArtifactPage(ctx, artifactPage.NextCursor, 1)
	if err != nil || len(artifactPage.Artifacts) != 1 || artifactPage.Artifacts[0].ID != artifactIDs[0] || artifactPage.NextCursor.ID != "" {
		t.Fatalf("final Postgres Console artifact page=%+v err=%v", artifactPage, err)
	}

	runPage, err := store.LibraryConsoleRunPage(ctx, LibraryConsolePageCursor{}, 1)
	if err != nil || len(runPage.Runs) != 1 || runPage.Runs[0].ID != runIDs[2] || runPage.NextCursor.ID == "" {
		t.Fatalf("first Postgres Console run page=%+v err=%v", runPage, err)
	}
	runPage, err = store.LibraryConsoleRunPage(ctx, runPage.NextCursor, 1)
	if err != nil || len(runPage.Runs) != 1 || runPage.Runs[0].ID != runIDs[1] || runPage.NextCursor.ID == "" {
		t.Fatalf("second Postgres Console run page=%+v err=%v", runPage, err)
	}
	runPage, err = store.LibraryConsoleRunPage(ctx, runPage.NextCursor, 1)
	if err != nil || len(runPage.Runs) != 1 || runPage.Runs[0].ID != runIDs[0] || runPage.NextCursor.ID != "" {
		t.Fatalf("final Postgres Console run page=%+v err=%v", runPage, err)
	}
}

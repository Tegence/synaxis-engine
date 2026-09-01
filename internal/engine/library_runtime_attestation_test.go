package engine

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type runtimeAttestationFixture struct {
	store   *FileStore
	client  MCPClient
	private ed25519.PrivateKey
	skill   LibrarySkill
	version LibrarySkillVersion
	binding LibrarySkillBinding
	bundle  LibrarySkillActivationBundle
}

func newRuntimeAttestationFixture(t *testing.T, store *FileStore) runtimeAttestationFixture {
	t.Helper()
	ctx := context.Background()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	client, err := store.CreateMCPClient(ctx, MCPClient{
		Name: "Runtime attestor", Subject: "usr_runtime", CreatedBy: "usr_runtime",
		RuntimeAttestorPublicKey: base64.RawURLEncoding.EncodeToString(public),
	})
	if err != nil {
		t.Fatalf("CreateMCPClient: %v", err)
	}
	skill, version := createLibrarySkillForTest(t, store)
	binding, err := store.UpsertLibrarySkillBinding(ctx, LibrarySkillBinding{
		SkillID: skill.ID, ScopeKind: LibraryScopeAgentSurface, ScopeID: client.ID,
		Mode: LibraryBindingModePin, PinnedVersionID: version.ID,
		CapabilityCeiling: []string{"alerts.read"}, CreatedBy: "usr_runtime",
	})
	if err != nil {
		t.Fatalf("UpsertLibrarySkillBinding: %v", err)
	}
	bundle, err := BuildLibrarySkillActivationBundleForAgentSurface(ctx, store, client.ID)
	if err != nil {
		t.Fatalf("BuildLibrarySkillActivationBundleForAgentSurface: %v", err)
	}
	return runtimeAttestationFixture{
		store: store, client: client, private: private, skill: skill, version: version, binding: binding, bundle: bundle,
	}
}

func runtimeAttestationBody(t *testing.T, fixture runtimeAttestationFixture, executionID, nonce, expiresAt, body string) []byte {
	t.Helper()
	raw, err := json.Marshal(libraryRuntimeAttestationRequest{
		ContractVersion: LibraryRuntimeAttestationContractVersion,
		ClientEpoch:     fixture.client.Epoch,
		ExecutionID:     executionID,
		Nonce:           nonce,
		ExpiresAt:       expiresAt,
		BundleDigest:    fixture.bundle.BundleDigest,
		SkillID:         fixture.skill.ID,
		SkillVersionID:  fixture.version.ID,
		BindingID:       fixture.binding.ID,
		InputDigest:     libraryDigest("runtime input"),
		Output: libraryRuntimeAttestationOutput{
			Title: "Host result", Summary: "host-reported", Format: LibraryArtifactFormatMarkdown, Body: body,
		},
	})
	if err != nil {
		t.Fatalf("marshal runtime attestation: %v", err)
	}
	return raw
}

func signedRuntimeAttestationRequest(t *testing.T, fixture runtimeAttestationFixture, raw []byte) *http.Request {
	t.Helper()
	path := libraryRuntimeAttestationPath(fixture.client.Slug)
	signature := ed25519.Sign(fixture.private, libraryRuntimeAttestationSigningMessage(path, raw))
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set(libraryRuntimeAttestationSignatureHeader, base64.RawURLEncoding.EncodeToString(signature))
	return req
}

func serveRuntimeAttestation(t *testing.T, fixture runtimeAttestationFixture, req *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle("/runtime/clients/{slug}/skill-runs", NewLibraryRuntimeAttestationHandler(fixture.store))
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, req)
	return response
}

func decodeRuntimeAttestationResponse(t *testing.T, response *httptest.ResponseRecorder) libraryRuntimeAttestationResponse {
	t.Helper()
	var result libraryRuntimeAttestationResponse
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode runtime attestation response: %v; body=%s", err, response.Body)
	}
	if result.RunID == "" || result.ArtifactID == "" || result.ArtifactVersionID == "" || result.ArtifactVersionDigest == "" {
		t.Fatalf("runtime attestation response omitted durable identities: %+v", result)
	}
	return result
}

func TestLibraryRuntimeAttestationHandlerPersistsHostClaimIdempotentlyAndScopesOutput(t *testing.T) {
	ctx := context.Background()
	fixture := newRuntimeAttestationFixture(t, newLibraryFileStore(t))
	nonce := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	expiresAt := time.Now().UTC().Add(5 * time.Minute).Format(time.RFC3339Nano)
	raw := runtimeAttestationBody(t, fixture, "runtime-execution-1", nonce, expiresAt, "# Host result")

	created := serveRuntimeAttestation(t, fixture, signedRuntimeAttestationRequest(t, fixture, raw))
	if created.Code != http.StatusCreated {
		t.Fatalf("runtime attestation create = %d, body=%s", created.Code, created.Body)
	}
	if created.Header().Get("Access-Control-Allow-Origin") != "" || created.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("runtime response exposed browser semantics: headers=%v", created.Header())
	}
	first := decodeRuntimeAttestationResponse(t, created)
	run, found := fixture.store.LibraryRun(ctx, first.RunID)
	if !found || run.Origin != LibraryRunOriginSkillRun || run.Attestation != LibraryRunAttestationHost ||
		run.SkillID != fixture.skill.ID || run.SkillVersionID != fixture.version.ID || run.BindingID != fixture.binding.ID ||
		run.ActorRef != fixture.client.Subject || run.SurfaceRef != fixture.client.ID ||
		len(run.EffectiveCapabilities) != 0 || run.InputDigest != libraryDigest("runtime input") ||
		run.OutputDigest != first.ArtifactVersionDigest || run.StartedAt.IsZero() || !run.StartedAt.Equal(run.CompletedAt) {
		t.Fatalf("server-derived host run=%+v found=%t", run, found)
	}
	artifact, found := fixture.store.LibraryArtifact(ctx, first.ArtifactID)
	if !found || artifact.Origin != LibraryArtifactOriginSkillRun || artifact.RunID != run.ID ||
		artifact.CreatedBy != fixture.client.Subject || artifact.AgentSurfaceID != fixture.client.ID ||
		artifact.SkillID != fixture.skill.ID || artifact.SkillVersionID != fixture.version.ID || artifact.BindingID != fixture.binding.ID {
		t.Fatalf("server-derived host artifact=%+v found=%t", artifact, found)
	}
	version, found := fixture.store.LibraryArtifactVersion(ctx, artifact.ID, first.ArtifactVersionID)
	if !found || version.Version != 1 || version.Body != "# Host result" || version.CreatedBy != fixture.client.Subject || version.Digest != first.ArtifactVersionDigest {
		t.Fatalf("server-derived host artifact version=%+v found=%t", version, found)
	}

	// The replay key stores scoped digests, never host-controlled plaintext
	// execution IDs, nonces, signatures, or request bodies.
	fixture.store.mu.Lock()
	if len(fixture.store.libraryRuntimeAttestations) != 1 {
		fixture.store.mu.Unlock()
		t.Fatalf("runtime verifier records=%d, want 1", len(fixture.store.libraryRuntimeAttestations))
	}
	record := *fixture.store.libraryRuntimeAttestations[0]
	fixture.store.mu.Unlock()
	if record.ClientID != fixture.client.ID || record.ClientEpoch != fixture.client.Epoch || record.RunID != run.ID ||
		record.ExecutionHash == "runtime-execution-1" || record.NonceHash == nonce || record.RequestDigest == string(raw) {
		t.Fatalf("runtime verifier record leaked or lost scope: %+v", record)
	}

	replayed := serveRuntimeAttestation(t, fixture, signedRuntimeAttestationRequest(t, fixture, raw))
	if replayed.Code != http.StatusOK || replayed.Header().Get("Idempotent-Replay") != "true" {
		t.Fatalf("runtime attestation replay = %d headers=%v body=%s", replayed.Code, replayed.Header(), replayed.Body)
	}
	if second := decodeRuntimeAttestationResponse(t, replayed); second != first {
		t.Fatalf("idempotent replay changed durable identities: first=%+v second=%+v", first, second)
	}

	// Reusing an execution ID with a different exact body is a conflict; a
	// reused nonce under another execution ID is a replay. Neither creates a
	// second result.
	changed := runtimeAttestationBody(t, fixture, "runtime-execution-1", nonce, expiresAt, "# altered host result")
	if response := serveRuntimeAttestation(t, fixture, signedRuntimeAttestationRequest(t, fixture, changed)); response.Code != http.StatusConflict {
		t.Fatalf("different request with same execution ID = %d, body=%s", response.Code, response.Body)
	}
	if response := serveRuntimeAttestation(t, fixture, signedRuntimeAttestationRequest(t, fixture, runtimeAttestationBody(t, fixture, "runtime-execution-2", nonce, expiresAt, "# nonce replay"))); response.Code != http.StatusConflict {
		t.Fatalf("same nonce with another execution ID = %d, body=%s", response.Code, response.Body)
	}
	if runs, err := fixture.store.LibraryRuns(ctx); err != nil || len(runs) != 1 {
		t.Fatalf("rejected runtime writes changed run count: runs=%#v err=%v", runs, err)
	}

	// The same human's second registration cannot read a result merely because
	// its subject matches: trusted host output is owned by one actor/surface
	// pair. A different subject is likewise excluded.
	sameSubject, err := fixture.store.CreateMCPClient(ctx, MCPClient{Name: "Runtime second surface", Subject: fixture.client.Subject, CreatedBy: fixture.client.Subject})
	if err != nil {
		t.Fatal(err)
	}
	otherSubject, err := fixture.store.CreateMCPClient(ctx, MCPClient{Name: "Runtime other subject", Subject: "usr_other", CreatedBy: "usr_other"})
	if err != nil {
		t.Fatal(err)
	}
	ownerPage, err := fixture.store.LibraryMCPClientArtifactPage(ctx, fixture.client, LibraryMCPClientArtifactCursor{}, 10)
	if err != nil || len(ownerPage.Artifacts) != 1 || ownerPage.Artifacts[0].Artifact.ID != artifact.ID || ownerPage.Artifacts[0].Access != "owned" {
		t.Fatalf("owner runtime artifact page=%+v err=%v", ownerPage, err)
	}
	for _, client := range []MCPClient{sameSubject, otherSubject} {
		page, err := fixture.store.LibraryMCPClientArtifactPage(ctx, client, LibraryMCPClientArtifactCursor{}, 10)
		if err != nil || len(page.Artifacts) != 0 {
			t.Fatalf("%s read another surface's host output: page=%+v err=%v", client.Name, page, err)
		}
	}
	if librarySurfaceMayUseArtifactVersion(ctx, fixture.store, artifact.ID, version.ID, version.Digest, fixture.client.Subject, fixture.client.ID, fixture.client.ID) {
		t.Fatal("host-attested output was silently promoted into direct-agent source provenance")
	}

	// The generic store method backs ordinary Console/internal paths and must
	// not be able to mint the host-attested provenance marker.
	if _, err := fixture.store.CreateLibraryRun(ctx, LibraryRun{
		Origin: LibraryRunOriginSkillRun, Attestation: LibraryRunAttestationHost,
		SkillID: fixture.skill.ID, SkillVersionID: fixture.version.ID, BindingID: fixture.binding.ID,
		ActorRef: fixture.client.Subject, SurfaceRef: fixture.client.ID, Status: "succeeded",
	}); !errors.Is(err, ErrLibraryRuntimeAttestationInvalid) {
		t.Fatalf("ordinary CreateLibraryRun accepted host attestation: %v", err)
	}
}

func TestLibraryRuntimeAttestationRejectsBrowserTransportAndRevalidatesSelectionAndKey(t *testing.T) {
	ctx := context.Background()
	fixture := newRuntimeAttestationFixture(t, newLibraryFileStore(t))
	nonce := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
	expiresAt := time.Now().UTC().Add(5 * time.Minute).Format(time.RFC3339Nano)
	raw := runtimeAttestationBody(t, fixture, "runtime-revalidate-1", nonce, expiresAt, "# selection test")

	browser := signedRuntimeAttestationRequest(t, fixture, raw)
	browser.Header.Set("Origin", "https://web.example")
	if response := serveRuntimeAttestation(t, fixture, browser); response.Code != http.StatusNotFound {
		t.Fatalf("browser-origin direct runtime request = %d, body=%s", response.Code, response.Body)
	}
	badSignature := signedRuntimeAttestationRequest(t, fixture, raw)
	badSignature.Header.Set(libraryRuntimeAttestationSignatureHeader, base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0}, ed25519.SignatureSize)))
	if response := serveRuntimeAttestation(t, fixture, badSignature); response.Code != http.StatusUnauthorized {
		t.Fatalf("bad runtime signature = %d, body=%s", response.Code, response.Body)
	}
	expired := runtimeAttestationBody(t, fixture, "runtime-expired", base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{10}, 32)), time.Now().UTC().Add(-time.Second).Format(time.RFC3339Nano), "# expired")
	if response := serveRuntimeAttestation(t, fixture, signedRuntimeAttestationRequest(t, fixture, expired)); response.Code != http.StatusGone {
		t.Fatalf("expired runtime request = %d, body=%s", response.Code, response.Body)
	}

	// A changed currently selected immutable tuple invalidates an otherwise
	// valid signed request before any run/artifact/version record is written.
	newVersion, err := fixture.store.CreateLibrarySkillVersion(ctx, LibrarySkillVersion{
		SkillID: fixture.skill.ID, Content: "# New selected instructions", RequestedCapabilities: []string{"alerts.read"}, CreatedBy: "usr_runtime",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.UpsertLibrarySkillBinding(ctx, LibrarySkillBinding{
		SkillID: fixture.skill.ID, ScopeKind: LibraryScopeAgentSurface, ScopeID: fixture.client.ID,
		Mode: LibraryBindingModePin, PinnedVersionID: newVersion.ID, CapabilityCeiling: []string{"alerts.read"}, CreatedBy: "usr_runtime",
	}); err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(fixture.private, libraryRuntimeAttestationSigningMessage(libraryRuntimeAttestationPath(fixture.client.Slug), raw))
	if _, _, _, _, err := fixture.store.IngestLibraryRuntimeAttestation(ctx, LibraryRuntimeAttestation{
		ClientID: fixture.client.ID, Path: libraryRuntimeAttestationPath(fixture.client.Slug), RawBody: raw, Signature: signature,
	}); !errors.Is(err, ErrLibraryRuntimeAttestationInvalid) {
		t.Fatalf("stale selection attestation error=%v, want invalid", err)
	}
	if runs, err := fixture.store.LibraryRuns(ctx); err != nil || len(runs) != 0 {
		t.Fatalf("stale selection created a run: runs=%#v err=%v", runs, err)
	}

	// Rotating the configured attestor key rotates the client epoch. The old
	// signature and old epoch must fail without waiting for request expiry.
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := fixture.store.UpdateMCPClient(ctx, MCPClient{
		ID: fixture.client.ID, Name: fixture.client.Name,
		RuntimeAttestorPublicKey: base64.RawURLEncoding.EncodeToString(public), runtimeAttestorKeySet: true,
	}, MCPClientPrecondition{ID: fixture.client.ID, Revision: fixture.client.Revision})
	if err != nil {
		t.Fatalf("rotate runtime attestor key: %v", err)
	}
	if rotated.Epoch == fixture.client.Epoch {
		t.Fatal("runtime attestor key rotation did not rotate client epoch")
	}
	if _, _, _, _, err := fixture.store.IngestLibraryRuntimeAttestation(ctx, LibraryRuntimeAttestation{
		ClientID: fixture.client.ID, Path: libraryRuntimeAttestationPath(fixture.client.Slug), RawBody: raw, Signature: signature,
	}); !errors.Is(err, ErrLibraryRuntimeAttestationInvalid) {
		t.Fatalf("old runtime key/epoch remained accepted after rotation: %v", err)
	}

	// The HTTP route resolves only an active client before checking any body,
	// so revocation removes the direct ingress as well as the MCP projection.
	revokedFixture := newRuntimeAttestationFixture(t, newLibraryFileStore(t))
	revokedRaw := runtimeAttestationBody(t, revokedFixture, "runtime-revoked", base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{12}, 32)), expiresAt, "# revoked")
	if _, err := revokedFixture.store.RevokeMCPClient(ctx, revokedFixture.client.ID, revokedFixture.client.Subject, MCPClientPrecondition{ID: revokedFixture.client.ID, Revision: revokedFixture.client.Revision}); err != nil {
		t.Fatal(err)
	}
	if response := serveRuntimeAttestation(t, revokedFixture, signedRuntimeAttestationRequest(t, revokedFixture, revokedRaw)); response.Code != http.StatusNotFound {
		t.Fatalf("revoked runtime client direct ingress = %d, body=%s", response.Code, response.Body)
	}
}

func TestMCPClientRuntimeReceiptIsUnsignedCurrentSelectionOnly(t *testing.T) {
	ctx := context.Background()
	store, gateway := newMCPClientGateway(t)
	fixture := newRuntimeAttestationFixture(t, store)
	// Populate the ordinary owner/root Library projection as production does;
	// the receipt must remain absent there even when other Library tools exist.
	RegisterLibraryArtifactTools(gateway.mcp, store, nil)
	if err := gateway.RefreshMCPClients(ctx); err != nil {
		t.Fatal(err)
	}
	clientMCP := clientLibraryServer(t, gateway, fixture.client.Slug)
	if _, found := clientMCP.ListTools()["library_skill_runtime_receipt"]; !found {
		t.Fatal("subject-bound MCP client does not expose the read-only runtime receipt")
	}
	if _, found := gateway.mcp.ListTools()["library_skill_runtime_receipt"]; found {
		t.Fatal("owner/root MCP unexpectedly exposes the client-only runtime receipt")
	}
	nonce := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{11}, 32))
	response := callLibraryTool(t, clientMCP, "library_skill_runtime_receipt", map[string]any{
		"skillId": fixture.skill.ID, "executionId": "receipt-execution-1", "nonce": nonce,
		"expiresAt": time.Now().UTC().Add(5 * time.Minute).Format(time.RFC3339Nano), "inputDigest": libraryDigest("receipt input"),
	})
	if strings.Contains(response, `"isError":true`) {
		t.Fatalf("runtime receipt=%s", response)
	}
	var receipt librarySkillRuntimeReceipt
	if err := json.Unmarshal([]byte(libraryToolJSONText(t, response)), &receipt); err != nil {
		t.Fatalf("decode runtime receipt: %v", err)
	}
	if receipt.ContractVersion != LibraryRuntimeAttestationContractVersion || receipt.Path != libraryRuntimeAttestationPath(fixture.client.Slug) ||
		receipt.ClientEpoch != fixture.client.Epoch || receipt.BundleDigest != fixture.bundle.BundleDigest ||
		receipt.SkillID != fixture.skill.ID || receipt.SkillVersionID != fixture.version.ID || receipt.BindingID != fixture.binding.ID ||
		receipt.HostSignatureHeader != libraryRuntimeAttestationSignatureHeader || receipt.HostSignatureAlgorithm != "Ed25519" {
		t.Fatalf("runtime receipt did not mirror current selected immutable tuple: %+v", receipt)
	}
	if !strings.Contains(receipt.ReceiptNotice, "unsigned") || !strings.Contains(receipt.ReceiptNotice, "not an Engine-signed token") ||
		!strings.Contains(receipt.HostNotice, "does not prove") || !strings.Contains(receipt.SigningNotice, "raw UTF-8 JSON body") {
		t.Fatalf("runtime receipt confused selection with Engine execution proof: %+v", receipt)
	}
}

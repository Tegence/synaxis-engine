package engine

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func runtimeActivationTimestamp(now time.Time) string {
	return now.UTC().Format(time.RFC3339Nano)
}

// signedRuntimeActivationRequest signs the GET form of the host scheme with
// the fixture key for the fixture client's activation path.
func signedRuntimeActivationRequest(t *testing.T, fixture runtimeAttestationFixture, timestamp string) *http.Request {
	t.Helper()
	return signedRuntimeActivationRequestWithKey(t, fixture.private, libraryRuntimeActivationPath(fixture.client.Slug), timestamp)
}

func signedRuntimeActivationRequestWithKey(t *testing.T, private ed25519.PrivateKey, path, timestamp string) *http.Request {
	t.Helper()
	signature := ed25519.Sign(private, libraryRuntimeActivationSigningMessage(path, timestamp))
	return runtimeActivationRequest(path, timestamp, base64.RawURLEncoding.EncodeToString(signature))
}

func runtimeActivationRequest(path, timestamp, signature string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if timestamp != "" {
		req.Header.Set(libraryRuntimeTimestampHeader, timestamp)
	}
	if signature != "" {
		req.Header.Set(libraryRuntimeAttestationSignatureHeader, signature)
	}
	return req
}

func serveRuntimeActivation(t *testing.T, store LibraryRuntimeAttestationStore, req *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle("/runtime/clients/{slug}/activation", NewLibraryRuntimeActivationHandler(store))
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, req)
	return response
}

func TestLibraryRuntimeActivationHandlerServesFullBundleToSignedHost(t *testing.T) {
	ctx := context.Background()
	fixture := newRuntimeAttestationFixture(t, newLibraryFileStore(t))
	now := time.Now().UTC()

	response := serveRuntimeActivation(t, fixture.store, signedRuntimeActivationRequest(t, fixture, runtimeActivationTimestamp(now)))
	if response.Code != http.StatusOK {
		t.Fatalf("activation=%d body=%s", response.Code, response.Body)
	}
	if response.Header().Get("Access-Control-Allow-Origin") != "" || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("activation headers exposed browser semantics: %v", response.Header())
	}
	if got := response.Header().Get(libraryRuntimeClientEpochHeader); got == "" || got != fixture.client.Epoch {
		t.Fatalf("activation response must name the current client epoch: got %q want %q", got, fixture.client.Epoch)
	}
	var bundle LibrarySkillActivationBundle
	if err := json.Unmarshal(response.Body.Bytes(), &bundle); err != nil {
		t.Fatalf("decode bundle: %v body=%s", err, response.Body)
	}
	if bundle.ContractVersion != LibrarySkillActivationContractVersion || bundle.BundleDigest != fixture.bundle.BundleDigest || len(bundle.Skills) != len(fixture.bundle.Skills) ||
		bundle.Skills[0].SkillID != fixture.skill.ID || bundle.Skills[0].VersionID != fixture.version.ID || bundle.Skills[0].Binding.ID != fixture.binding.ID {
		t.Fatalf("bundle=%+v; want %+v", bundle, fixture.bundle)
	}
	// Unlike the control-plane snapshot, the signed host fetch carries the
	// instruction bodies: it is the same context-only handoff the MCP tool
	// produces.
	if !strings.Contains(response.Body.String(), "Inspect the incident before acting") {
		t.Fatalf("activation omitted instruction bodies: %s", response.Body)
	}

	// The wire message is exactly the documented byte sequence.
	path := libraryRuntimeActivationPath(fixture.client.Slug)
	timestamp := runtimeActivationTimestamp(now)
	literal := []byte("synaxis.library.host-attestation.v1\nGET\n" + path + "\n" + timestamp)
	if !bytes.Equal(literal, libraryRuntimeActivationSigningMessage(path, timestamp)) {
		t.Fatalf("signing message=%q; want %q", libraryRuntimeActivationSigningMessage(path, timestamp), literal)
	}
	literalSignature := base64.RawURLEncoding.EncodeToString(ed25519.Sign(fixture.private, literal))
	if response := serveRuntimeActivation(t, fixture.store, runtimeActivationRequest(path, timestamp, literalSignature)); response.Code != http.StatusOK {
		t.Fatalf("literal-message activation=%d body=%s", response.Code, response.Body)
	}

	// Timestamps anywhere inside the two-minute window are accepted, in both
	// directions, so modest clock drift does not lock a host out.
	for name, at := range map[string]time.Time{"90s behind": now.Add(-90 * time.Second), "90s ahead": now.Add(90 * time.Second), "no fraction": now.Truncate(time.Second)} {
		if response := serveRuntimeActivation(t, fixture.store, signedRuntimeActivationRequest(t, fixture, runtimeActivationTimestamp(at))); response.Code != http.StatusOK {
			t.Fatalf("%s activation=%d body=%s", name, response.Code, response.Body)
		}
	}

	// The fetch is live: changing the selection changes the served bundle.
	newVersion, err := fixture.store.CreateLibrarySkillVersion(ctx, LibrarySkillVersion{
		SkillID: fixture.skill.ID, Content: "# Reselected instructions", RequestedCapabilities: []string{"alerts.read"}, CreatedBy: "usr_runtime",
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
	response = serveRuntimeActivation(t, fixture.store, signedRuntimeActivationRequest(t, fixture, runtimeActivationTimestamp(now)))
	var live LibrarySkillActivationBundle
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &live) != nil || live.BundleDigest == fixture.bundle.BundleDigest || live.Skills[0].VersionID != newVersion.ID {
		t.Fatalf("live activation=%d body=%s", response.Code, response.Body)
	}
}

func TestLibraryRuntimeActivationHandlerFailsClosed(t *testing.T) {
	ctx := context.Background()
	fixture := newRuntimeAttestationFixture(t, newLibraryFileStore(t))
	now := time.Now().UTC()
	path := libraryRuntimeActivationPath(fixture.client.Slug)
	timestamp := runtimeActivationTimestamp(now)
	sign := func(private ed25519.PrivateKey, message []byte) string {
		return base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, message))
	}
	_, otherPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Browser-shaped requests and the wrong method never reach signature
	// verification.
	for name, shape := range map[string]func(*http.Request){
		"origin":         func(r *http.Request) { r.Header.Set("Origin", "https://web.example") },
		"sec-fetch-mode": func(r *http.Request) { r.Header.Set("Sec-Fetch-Mode", "no-cors") },
		"query string":   func(r *http.Request) { r.URL.RawQuery = "slug=other" },
	} {
		req := signedRuntimeActivationRequest(t, fixture, timestamp)
		shape(req)
		if response := serveRuntimeActivation(t, fixture.store, req); response.Code != http.StatusNotFound {
			t.Fatalf("browser-shaped %s=%d body=%s", name, response.Code, response.Body)
		}
	}
	post := httptest.NewRequest(http.MethodPost, path, nil)
	if response := serveRuntimeActivation(t, fixture.store, post); response.Code != http.StatusMethodNotAllowed || response.Header().Get("Allow") != http.MethodGet {
		t.Fatalf("POST=%d headers=%v", response.Code, response.Header())
	}

	unauthorized := map[string]*http.Request{
		"wrong key":         signedRuntimeActivationRequestWithKey(t, otherPrivate, path, timestamp),
		"stale timestamp":   signedRuntimeActivationRequest(t, fixture, runtimeActivationTimestamp(now.Add(-libraryRuntimeActivationMaxSkew-time.Second))),
		"future timestamp":  signedRuntimeActivationRequest(t, fixture, runtimeActivationTimestamp(now.Add(libraryRuntimeActivationMaxSkew+time.Second))),
		"missing timestamp": runtimeActivationRequest(path, "", sign(fixture.private, libraryRuntimeActivationSigningMessage(path, timestamp))),
		"missing signature": runtimeActivationRequest(path, timestamp, ""),
		"zero signature":    runtimeActivationRequest(path, timestamp, base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0}, ed25519.SignatureSize))),
		"padded signature":  runtimeActivationRequest(path, timestamp, sign(fixture.private, libraryRuntimeActivationSigningMessage(path, timestamp))+"="),
		// The signed timestamp must match the header byte-for-byte, so a
		// non-UTC or otherwise non-canonical rendering is rejected even when
		// it names the same instant.
		"offset timestamp": func() *http.Request {
			offset := now.In(time.FixedZone("plus1", 3600)).Format(time.RFC3339Nano)
			return runtimeActivationRequest(path, offset, sign(fixture.private, libraryRuntimeActivationSigningMessage(path, offset)))
		}(),
		"plus-zero timestamp": func() *http.Request {
			plusZero := now.Format("2006-01-02T15:04:05.999999999+00:00")
			return runtimeActivationRequest(path, plusZero, sign(fixture.private, libraryRuntimeActivationSigningMessage(path, plusZero)))
		}(),
		"timestamp mismatch": runtimeActivationRequest(path, runtimeActivationTimestamp(now.Add(time.Second)), sign(fixture.private, libraryRuntimeActivationSigningMessage(path, timestamp))),
		// The path is part of the message: a signature over the skill-runs
		// route, another client's activation route, or the POST form of the
		// scheme does not authorize this fetch.
		"attestation path":   runtimeActivationRequest(path, timestamp, sign(fixture.private, libraryRuntimeActivationSigningMessage(libraryRuntimeAttestationPath(fixture.client.Slug), timestamp))),
		"other client path":  runtimeActivationRequest(path, timestamp, sign(fixture.private, libraryRuntimeActivationSigningMessage(libraryRuntimeActivationPath("other-client"), timestamp))),
		"post form":          runtimeActivationRequest(path, timestamp, sign(fixture.private, libraryRuntimeSigningMessage(http.MethodPost, path, []byte(timestamp)))),
		"attestation scheme": runtimeActivationRequest(path, timestamp, sign(fixture.private, libraryRuntimeAttestationSigningMessage(path, []byte(timestamp)))),
	}
	duplicateTimestamp := signedRuntimeActivationRequest(t, fixture, timestamp)
	duplicateTimestamp.Header.Add(libraryRuntimeTimestampHeader, timestamp)
	unauthorized["duplicate timestamp header"] = duplicateTimestamp
	for name, req := range unauthorized {
		if response := serveRuntimeActivation(t, fixture.store, req); response.Code != http.StatusUnauthorized {
			t.Fatalf("%s=%d body=%s", name, response.Code, response.Body)
		}
	}

	// Unknown, ID-addressed, key-less, and revoked registrations share one 404.
	for name, slug := range map[string]string{"unknown": "no-such-client", "opaque id": fixture.client.ID} {
		req := signedRuntimeActivationRequestWithKey(t, fixture.private, libraryRuntimeActivationPath(slug), timestamp)
		if response := serveRuntimeActivation(t, fixture.store, req); response.Code != http.StatusNotFound {
			t.Fatalf("%s slug=%d body=%s", name, response.Code, response.Body)
		}
	}
	keyless, err := fixture.store.CreateMCPClient(ctx, MCPClient{Name: "No attestor", Subject: "usr_keyless", CreatedBy: "usr_keyless"})
	if err != nil {
		t.Fatal(err)
	}
	if response := serveRuntimeActivation(t, fixture.store, signedRuntimeActivationRequestWithKey(t, fixture.private, libraryRuntimeActivationPath(keyless.Slug), timestamp)); response.Code != http.StatusNotFound {
		t.Fatalf("client without attestor key=%d body=%s", response.Code, response.Body)
	}

	// Rotating the key: the old signature fails, the new key works.
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := fixture.store.UpdateMCPClient(ctx, MCPClient{
		ID: fixture.client.ID, Name: fixture.client.Name,
		RuntimeAttestorPublicKey: base64.RawURLEncoding.EncodeToString(public), runtimeAttestorKeySet: true,
	}, MCPClientPrecondition{ID: fixture.client.ID, Revision: fixture.client.Revision})
	if err != nil {
		t.Fatal(err)
	}
	if response := serveRuntimeActivation(t, fixture.store, signedRuntimeActivationRequest(t, fixture, timestamp)); response.Code != http.StatusUnauthorized {
		t.Fatalf("old key after rotation=%d", response.Code)
	}
	if response := serveRuntimeActivation(t, fixture.store, signedRuntimeActivationRequestWithKey(t, private, path, timestamp)); response.Code != http.StatusOK {
		t.Fatalf("new key after rotation=%d body=%s", response.Code, response.Body)
	}

	if _, err := fixture.store.RevokeMCPClient(ctx, fixture.client.ID, fixture.client.Subject, MCPClientPrecondition{ID: fixture.client.ID, Revision: rotated.Revision}); err != nil {
		t.Fatal(err)
	}
	if response := serveRuntimeActivation(t, fixture.store, signedRuntimeActivationRequestWithKey(t, private, path, timestamp)); response.Code != http.StatusNotFound {
		t.Fatalf("revoked client=%d body=%s", response.Code, response.Body)
	}

	// A store without the Library facet mounts nothing.
	if response := serveRuntimeActivation(t, runtimeAttestationOnlyStore{fixture.store}, signedRuntimeActivationRequestWithKey(t, private, path, timestamp)); response.Code != http.StatusNotFound {
		t.Fatalf("library-less store=%d", response.Code)
	}
}

// runtimeAttestationOnlyStore hides every facet except the attestation one so
// the constructor's facet check can be exercised.
type runtimeAttestationOnlyStore struct {
	LibraryRuntimeAttestationStore
}

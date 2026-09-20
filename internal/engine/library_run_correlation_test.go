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
	"os"
	"strings"
	"testing"
	"time"
)

// libraryRunCorrelationTestStore is the facet set the shared store-level
// suite needs: recording and listing correlations, the registry it
// revalidates against, and the Library facet used to change a selection.
type libraryRunCorrelationTestStore interface {
	LibraryRunCorrelationStore
	MCPClientStore
	LibraryStore
}

func runCorrelationNonce(seed byte) string {
	return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{seed}, 32))
}

func runCorrelationExpiry(now time.Time) string {
	return now.UTC().Add(5 * time.Minute).Format(time.RFC3339Nano)
}

func runCorrelationBody(t *testing.T, fixture runtimeAttestationFixture, runID, gatewayRequestID, executionID, nonce, expiresAt string) []byte {
	t.Helper()
	return runCorrelationBodyFor(t, fixture.client.Epoch, fixture.bundle.BundleDigest, runID, gatewayRequestID, executionID, nonce, expiresAt)
}

func runCorrelationBodyFor(t *testing.T, epoch, bundleDigest, runID, gatewayRequestID, executionID, nonce, expiresAt string) []byte {
	t.Helper()
	raw, err := json.Marshal(libraryRunCorrelationRequest{
		ContractVersion: LibraryRunCorrelationContractVersion, ClientEpoch: epoch,
		RunID: runID, GatewayRequestID: gatewayRequestID, ExecutionID: executionID,
		Nonce: nonce, ExpiresAt: expiresAt, BundleDigest: bundleDigest,
	})
	if err != nil {
		t.Fatalf("marshal run correlation: %v", err)
	}
	return raw
}

func signedRunCorrelationRequest(t *testing.T, fixture runtimeAttestationFixture, raw []byte) *http.Request {
	t.Helper()
	return signedRunCorrelationRequestWithKey(t, fixture.private, libraryRunCorrelationPath(fixture.client.Slug), raw)
}

func signedRunCorrelationRequestWithKey(t *testing.T, private ed25519.PrivateKey, path string, raw []byte) *http.Request {
	t.Helper()
	signature := ed25519.Sign(private, libraryRuntimeSigningMessage(http.MethodPost, path, raw))
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(libraryRuntimeAttestationSignatureHeader, base64.RawURLEncoding.EncodeToString(signature))
	return req
}

func serveRunCorrelation(t *testing.T, store LibraryRunCorrelationStore, req *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle("/runtime/clients/{slug}/run-correlations", NewLibraryRunCorrelationHandler(store))
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, req)
	return response
}

func decodeRunCorrelationResponse(t *testing.T, response *httptest.ResponseRecorder) libraryRunCorrelationResponse {
	t.Helper()
	var result libraryRunCorrelationResponse
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode run correlation response: %v body=%s", err, response.Body)
	}
	if !strings.HasPrefix(result.CorrelationID, "lrc_") || result.RunID == "" || result.GatewayRequestID == "" || !result.Attested {
		t.Fatalf("run correlation response=%+v", result)
	}
	return result
}

func TestLibraryRunCorrelationHandlerRecordsObservationIdempotently(t *testing.T) {
	ctx := context.Background()
	fixture := newRuntimeAttestationFixture(t, newLibraryFileStore(t))
	now := time.Now().UTC()
	nonce := runCorrelationNonce(1)
	raw := runCorrelationBody(t, fixture, "run_1", "greq_1", "exec_secret_1", nonce, runCorrelationExpiry(now))

	created := serveRunCorrelation(t, fixture.store, signedRunCorrelationRequest(t, fixture, raw))
	if created.Code != http.StatusCreated {
		t.Fatalf("create=%d body=%s", created.Code, created.Body)
	}
	if created.Header().Get("Access-Control-Allow-Origin") != "" || created.Header().Get("Cache-Control") != "no-store" || created.Header().Get("Idempotent-Replay") != "" {
		t.Fatalf("create headers=%v", created.Header())
	}
	first := decodeRunCorrelationResponse(t, created)
	if first.RunID != "run_1" || first.GatewayRequestID != "greq_1" {
		t.Fatalf("first=%+v", first)
	}
	var rawResponse map[string]any
	if err := json.Unmarshal(created.Body.Bytes(), &rawResponse); err != nil {
		t.Fatal(err)
	}
	for field := range rawResponse {
		switch field {
		case "correlationId", "runId", "gatewayRequestId", "attested":
		default:
			t.Fatalf("response exposed field %q: %s", field, created.Body)
		}
	}

	records, err := fixture.store.LibraryRunCorrelations(ctx, LibraryRunCorrelationCursor{}, 10)
	if err != nil || len(records) != 1 {
		t.Fatalf("records=%+v err=%v; want one", records, err)
	}
	record := records[0]
	if record.ID != first.CorrelationID || record.ClientID != fixture.client.ID || record.ClientEpoch != fixture.client.Epoch ||
		record.RunID != "run_1" || record.GatewayRequestID != "greq_1" || record.BundleDigest != fixture.bundle.BundleDigest || record.CreatedAt.IsZero() {
		t.Fatalf("record=%+v", record)
	}
	// Only scoped hashes of the host-chosen execution ID and nonce are kept:
	// never the raw value, and never an unscoped digest of it.
	if !libraryDigestPattern.MatchString(record.ExecutionHash) || !libraryDigestPattern.MatchString(record.NonceHash) || !libraryDigestPattern.MatchString(record.RequestDigest) ||
		record.ExecutionHash == libraryDigest("exec_secret_1") || record.NonceHash == libraryDigest(nonce) ||
		record.ExecutionHash == libraryRunCorrelationExecutionHash("mcpcli_other", fixture.client.Epoch, "exec_secret_1") ||
		record.ExecutionHash != libraryRunCorrelationExecutionHash(fixture.client.ID, fixture.client.Epoch, "exec_secret_1") {
		t.Fatalf("record hashes are not client/epoch scoped: %+v", record)
	}
	persisted, err := os.ReadFile(fixture.store.path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(persisted), "exec_secret_1") || strings.Contains(string(persisted), nonce) {
		t.Fatal("persisted store leaked a raw execution ID or nonce")
	}

	replayed := serveRunCorrelation(t, fixture.store, signedRunCorrelationRequest(t, fixture, raw))
	if replayed.Code != http.StatusOK || replayed.Header().Get("Idempotent-Replay") != "true" {
		t.Fatalf("replay=%d headers=%v body=%s", replayed.Code, replayed.Header(), replayed.Body)
	}
	if second := decodeRunCorrelationResponse(t, replayed); second != first {
		t.Fatalf("replay changed identities: first=%+v second=%+v", first, second)
	}

	// The same (client, epoch, run, request) tuple with a different body is a
	// conflict; a reused nonce under another tuple is a replay. Neither writes.
	changed := runCorrelationBody(t, fixture, "run_1", "greq_1", "exec_secret_2", runCorrelationNonce(2), runCorrelationExpiry(now))
	if response := serveRunCorrelation(t, fixture.store, signedRunCorrelationRequest(t, fixture, changed)); response.Code != http.StatusConflict {
		t.Fatalf("same tuple different body=%d body=%s", response.Code, response.Body)
	}
	reused := runCorrelationBody(t, fixture, "run_2", "greq_2", "", nonce, runCorrelationExpiry(now))
	if response := serveRunCorrelation(t, fixture.store, signedRunCorrelationRequest(t, fixture, reused)); response.Code != http.StatusConflict {
		t.Fatalf("nonce replay=%d body=%s", response.Code, response.Body)
	}
	if records, err := fixture.store.LibraryRunCorrelations(ctx, LibraryRunCorrelationCursor{}, 10); err != nil || len(records) != 1 {
		t.Fatalf("rejected claims wrote records: %d err=%v", len(records), err)
	}

	// The same run under another gateway request is a distinct observation,
	// and the execution ID is optional.
	other := runCorrelationBody(t, fixture, "run_1", "greq_2", "", runCorrelationNonce(3), runCorrelationExpiry(now))
	otherResponse := serveRunCorrelation(t, fixture.store, signedRunCorrelationRequest(t, fixture, other))
	if otherResponse.Code != http.StatusCreated {
		t.Fatalf("second observation=%d body=%s", otherResponse.Code, otherResponse.Body)
	}
	otherID := decodeRunCorrelationResponse(t, otherResponse).CorrelationID
	records, err = fixture.store.LibraryRunCorrelations(ctx, LibraryRunCorrelationCursor{}, 10)
	if err != nil || len(records) != 2 || records[0].ID != otherID || records[0].ExecutionHash != "" || records[1].ID != first.CorrelationID {
		t.Fatalf("records after second observation=%+v err=%v", records, err)
	}

	// Records survive a reload and the replay decision is durable.
	reloaded, err := LoadFileStore(fixture.store.path)
	if err != nil {
		t.Fatal(err)
	}
	if again, err := reloaded.LibraryRunCorrelations(ctx, LibraryRunCorrelationCursor{}, 10); err != nil || len(again) != 2 || again[0].ID != otherID || again[1].ID != first.CorrelationID {
		t.Fatalf("reloaded records=%+v err=%v", again, err)
	}
	if response := serveRunCorrelation(t, reloaded, signedRunCorrelationRequest(t, fixture, raw)); response.Code != http.StatusOK || response.Header().Get("Idempotent-Replay") != "true" {
		t.Fatalf("replay after reload=%d headers=%v", response.Code, response.Header())
	}
}

func TestLibraryRunCorrelationHandlerRejectsBrowserTransportAndBadSignatures(t *testing.T) {
	ctx := context.Background()
	fixture := newRuntimeAttestationFixture(t, newLibraryFileStore(t))
	now := time.Now().UTC()
	raw := runCorrelationBody(t, fixture, "run_t", "greq_t", "", runCorrelationNonce(20), runCorrelationExpiry(now))
	path := libraryRunCorrelationPath(fixture.client.Slug)

	for name, shape := range map[string]func(*http.Request){
		"origin":         func(r *http.Request) { r.Header.Set("Origin", "https://web.example") },
		"sec-fetch-mode": func(r *http.Request) { r.Header.Set("Sec-Fetch-Mode", "cors") },
		"query string":   func(r *http.Request) { r.URL.RawQuery = "x=1" },
	} {
		req := signedRunCorrelationRequest(t, fixture, raw)
		shape(req)
		if response := serveRunCorrelation(t, fixture.store, req); response.Code != http.StatusNotFound {
			t.Fatalf("browser-shaped %s=%d body=%s", name, response.Code, response.Body)
		}
	}
	get := httptest.NewRequest(http.MethodGet, path, nil)
	if response := serveRunCorrelation(t, fixture.store, get); response.Code != http.StatusMethodNotAllowed || response.Header().Get("Allow") != http.MethodPost {
		t.Fatalf("GET=%d headers=%v", response.Code, response.Header())
	}
	text := signedRunCorrelationRequest(t, fixture, raw)
	text.Header.Set("Content-Type", "text/plain")
	if response := serveRunCorrelation(t, fixture.store, text); response.Code != http.StatusBadRequest {
		t.Fatalf("non-JSON content type=%d", response.Code)
	}

	otherPublic, otherPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_ = otherPublic
	for name, req := range map[string]*http.Request{
		"missing signature": func() *http.Request {
			r := signedRunCorrelationRequest(t, fixture, raw)
			r.Header.Del(libraryRuntimeAttestationSignatureHeader)
			return r
		}(),
		"zero signature": func() *http.Request {
			r := signedRunCorrelationRequest(t, fixture, raw)
			r.Header.Set(libraryRuntimeAttestationSignatureHeader, base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0}, ed25519.SignatureSize)))
			return r
		}(),
		"padded signature": func() *http.Request {
			r := signedRunCorrelationRequest(t, fixture, raw)
			r.Header.Set(libraryRuntimeAttestationSignatureHeader, r.Header.Get(libraryRuntimeAttestationSignatureHeader)+"=")
			return r
		}(),
		"other key": signedRunCorrelationRequestWithKey(t, otherPrivate, path, raw),
		"attestation path": func() *http.Request {
			// A signature over the skill-runs route (same key, same body) does
			// not authorize the run-correlation route: the path is in the message.
			signature := ed25519.Sign(fixture.private, libraryRuntimeSigningMessage(http.MethodPost, libraryRuntimeAttestationPath(fixture.client.Slug), raw))
			r := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set(libraryRuntimeAttestationSignatureHeader, base64.RawURLEncoding.EncodeToString(signature))
			return r
		}(),
		"wrong method in message": func() *http.Request {
			signature := ed25519.Sign(fixture.private, libraryRuntimeSigningMessage(http.MethodGet, path, raw))
			r := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set(libraryRuntimeAttestationSignatureHeader, base64.RawURLEncoding.EncodeToString(signature))
			return r
		}(),
		"tampered body": func() *http.Request {
			signature := ed25519.Sign(fixture.private, libraryRuntimeSigningMessage(http.MethodPost, path, raw))
			tampered := bytes.Replace(raw, []byte("greq_t"), []byte("greq_x"), 1)
			r := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(tampered))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set(libraryRuntimeAttestationSignatureHeader, base64.RawURLEncoding.EncodeToString(signature))
			return r
		}(),
	} {
		if response := serveRunCorrelation(t, fixture.store, req); response.Code != http.StatusUnauthorized {
			t.Fatalf("%s=%d body=%s", name, response.Code, response.Body)
		}
	}

	// Unknown, ID-addressed, key-less, and revoked registrations all share the
	// same 404 so the route reveals nothing about the registry.
	for name, slug := range map[string]string{"unknown": "no-such-client", "opaque id": fixture.client.ID} {
		req := signedRunCorrelationRequestWithKey(t, fixture.private, libraryRunCorrelationPath(slug), raw)
		if response := serveRunCorrelation(t, fixture.store, req); response.Code != http.StatusNotFound {
			t.Fatalf("%s slug=%d body=%s", name, response.Code, response.Body)
		}
	}
	keyless, err := fixture.store.CreateMCPClient(ctx, MCPClient{Name: "No attestor", Subject: "usr_keyless", CreatedBy: "usr_keyless"})
	if err != nil {
		t.Fatal(err)
	}
	keylessRaw := runCorrelationBodyFor(t, keyless.Epoch, fixture.bundle.BundleDigest, "run_k", "greq_k", "", runCorrelationNonce(21), runCorrelationExpiry(now))
	if response := serveRunCorrelation(t, fixture.store, signedRunCorrelationRequestWithKey(t, fixture.private, libraryRunCorrelationPath(keyless.Slug), keylessRaw)); response.Code != http.StatusNotFound {
		t.Fatalf("client without attestor key=%d body=%s", response.Code, response.Body)
	}
	oversized := signedRunCorrelationRequest(t, fixture, bytes.Repeat([]byte("a"), libraryRunCorrelationMaxBytes+1))
	if response := serveRunCorrelation(t, fixture.store, oversized); response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body=%d", response.Code)
	}
	if _, err := fixture.store.RevokeMCPClient(ctx, fixture.client.ID, fixture.client.Subject, MCPClientPrecondition{ID: fixture.client.ID, Revision: fixture.client.Revision}); err != nil {
		t.Fatal(err)
	}
	if response := serveRunCorrelation(t, fixture.store, signedRunCorrelationRequest(t, fixture, raw)); response.Code != http.StatusNotFound {
		t.Fatalf("revoked client=%d body=%s", response.Code, response.Body)
	}
	if records, err := fixture.store.LibraryRunCorrelations(ctx, LibraryRunCorrelationCursor{}, 10); err != nil || len(records) != 0 {
		t.Fatalf("rejected transport wrote records: %d err=%v", len(records), err)
	}
}

func TestLibraryRunCorrelationHandlerRevalidatesClaimAgainstLiveClient(t *testing.T) {
	ctx := context.Background()
	fixture := newRuntimeAttestationFixture(t, newLibraryFileStore(t))
	now := time.Now().UTC()
	expiry := runCorrelationExpiry(now)
	send := func(raw []byte) *httptest.ResponseRecorder {
		return serveRunCorrelation(t, fixture.store, signedRunCorrelationRequest(t, fixture, raw))
	}
	claim := func(mutate func(map[string]any)) []byte {
		fields := map[string]any{
			"contractVersion": LibraryRunCorrelationContractVersion, "clientEpoch": fixture.client.Epoch,
			"runId": "run_v", "gatewayRequestId": "greq_v", "nonce": runCorrelationNonce(40),
			"expiresAt": expiry, "bundleDigest": fixture.bundle.BundleDigest,
		}
		mutate(fields)
		raw, err := json.Marshal(fields)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}

	if response := send(claim(func(f map[string]any) { f["expiresAt"] = now.Add(-time.Second).Format(time.RFC3339Nano) })); response.Code != http.StatusGone {
		t.Fatalf("expired=%d body=%s", response.Code, response.Body)
	}
	for name, raw := range map[string][]byte{
		"far expiry": claim(func(f map[string]any) {
			f["expiresAt"] = now.Add(libraryRunCorrelationMaxTTL + time.Minute).Format(time.RFC3339Nano)
		}),
		"non-canonical time": claim(func(f map[string]any) {
			f["expiresAt"] = now.Add(5 * time.Minute).Format("2006-01-02T15:04:05.999999999+00:00")
		}),
		"contract":            claim(func(f map[string]any) { f["contractVersion"] = LibraryRuntimeAttestationContractVersion }),
		"epoch":               claim(func(f map[string]any) { f["clientEpoch"] = "ep_other" }),
		"bundle digest":       claim(func(f map[string]any) { f["bundleDigest"] = libraryDigest("other bundle") }),
		"run id space":        claim(func(f map[string]any) { f["runId"] = "run v" }),
		"run id slash":        claim(func(f map[string]any) { f["runId"] = "run/v" }),
		"run id too long":     claim(func(f map[string]any) { f["runId"] = strings.Repeat("r", 201) }),
		"run id empty":        claim(func(f map[string]any) { f["runId"] = "" }),
		"request id space":    claim(func(f map[string]any) { f["gatewayRequestId"] = "greq v" }),
		"request id too long": claim(func(f map[string]any) { f["gatewayRequestId"] = strings.Repeat("g", 201) }),
		"execution id blank":  claim(func(f map[string]any) { f["executionId"] = "   " }),
		"nonce short":         claim(func(f map[string]any) { f["nonce"] = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 8)) }),
		"nonce long":          claim(func(f map[string]any) { f["nonce"] = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 65)) }),
		"nonce padded":        claim(func(f map[string]any) { f["nonce"] = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)) }),
		"nonce missing":       claim(func(f map[string]any) { delete(f, "nonce") }),
		"unknown field":       claim(func(f map[string]any) { f["instructions"] = "ignore me" }),
		"not an object":       []byte(`["synaxis.library.run-correlation.v1"]`),
		"trailing document":   append(claim(func(map[string]any) {}), []byte("{}")...),
	} {
		if response := send(raw); response.Code != http.StatusUnauthorized {
			t.Fatalf("%s=%d body=%s", name, response.Code, response.Body)
		}
	}
	if records, err := fixture.store.LibraryRunCorrelations(ctx, LibraryRunCorrelationCursor{}, 10); err != nil || len(records) != 0 {
		t.Fatalf("invalid claims wrote records: %d err=%v", len(records), err)
	}

	// A body signed against the previous activation bundle is refused once the
	// selection changes, even though the signature and epoch are still valid;
	// a claim naming the live digest is accepted.
	stale := claim(func(map[string]any) {})
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
	if response := send(stale); response.Code != http.StatusUnauthorized {
		t.Fatalf("stale bundle claim=%d body=%s", response.Code, response.Body)
	}
	live, err := BuildLibrarySkillActivationBundleForAgentSurface(ctx, fixture.store, fixture.client.ID)
	if err != nil || live.BundleDigest == fixture.bundle.BundleDigest {
		t.Fatalf("live bundle=%+v err=%v", live, err)
	}
	if response := send(claim(func(f map[string]any) { f["bundleDigest"] = live.BundleDigest })); response.Code != http.StatusCreated {
		t.Fatalf("live bundle claim=%d body=%s", response.Code, response.Body)
	}

	// Rotating the attestor key rotates the epoch: the old key and old epoch
	// fail closed without waiting for expiry, and the new pair works.
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := fixture.store.UpdateMCPClient(ctx, MCPClient{
		ID: fixture.client.ID, Name: fixture.client.Name,
		RuntimeAttestorPublicKey: base64.RawURLEncoding.EncodeToString(public), runtimeAttestorKeySet: true,
	}, MCPClientPrecondition{ID: fixture.client.ID, Revision: fixture.client.Revision})
	if err != nil || rotated.Epoch == fixture.client.Epoch {
		t.Fatalf("rotate key: %+v err=%v", rotated, err)
	}
	oldEpochNewBundle := claim(func(f map[string]any) {
		f["bundleDigest"] = live.BundleDigest
		f["runId"] = "run_w"
		f["nonce"] = runCorrelationNonce(41)
	})
	if response := send(oldEpochNewBundle); response.Code != http.StatusUnauthorized {
		t.Fatalf("old key after rotation=%d", response.Code)
	}
	newRaw := runCorrelationBodyFor(t, rotated.Epoch, live.BundleDigest, "run_w", "greq_w", "", runCorrelationNonce(42), expiry)
	if response := serveRunCorrelation(t, fixture.store, signedRunCorrelationRequestWithKey(t, private, libraryRunCorrelationPath(fixture.client.Slug), newRaw)); response.Code != http.StatusCreated {
		t.Fatalf("new key after rotation=%d body=%s", response.Code, response.Body)
	}
	oldEpochNewKey := runCorrelationBodyFor(t, fixture.client.Epoch, live.BundleDigest, "run_x", "greq_x", "", runCorrelationNonce(43), expiry)
	if response := serveRunCorrelation(t, fixture.store, signedRunCorrelationRequestWithKey(t, private, libraryRunCorrelationPath(fixture.client.Slug), oldEpochNewKey)); response.Code != http.StatusUnauthorized {
		t.Fatalf("old epoch with new key=%d body=%s", response.Code, response.Body)
	}
}

// exerciseLibraryRunCorrelationStore asserts the store-level invariants shared
// by FileStore and PgStore. It returns the records it created, newest first.
func exerciseLibraryRunCorrelationStore(t *testing.T, ctx context.Context, store libraryRunCorrelationTestStore, client MCPClient, skill LibrarySkill, bundle LibrarySkillActivationBundle, base time.Time) []LibraryRunCorrelation {
	t.Helper()
	body := func(runID, gatewayRequestID, executionID, nonce string, at time.Time) []byte {
		return runCorrelationBodyFor(t, client.Epoch, bundle.BundleDigest, runID, gatewayRequestID, executionID, nonce, runCorrelationExpiry(at))
	}
	nonceA, nonceB, nonceC, nonceD := runCorrelationNonce(50), runCorrelationNonce(51), runCorrelationNonce(52), runCorrelationNonce(53)

	first, replayed, err := store.RecordLibraryRunCorrelation(ctx, client, body("run_a", "greq_a", "exec_secret_a", nonceA, base), base)
	if err != nil || replayed {
		t.Fatalf("first record=%+v replayed=%t err=%v", first, replayed, err)
	}
	if !strings.HasPrefix(first.ID, "lrc_") || first.ClientID != client.ID || first.ClientEpoch != client.Epoch || first.RunID != "run_a" || first.GatewayRequestID != "greq_a" ||
		first.BundleDigest != bundle.BundleDigest || !first.CreatedAt.Equal(base) ||
		first.ExecutionHash != libraryRunCorrelationExecutionHash(client.ID, client.Epoch, "exec_secret_a") ||
		first.NonceHash != libraryRunCorrelationNonceHash(client.ID, client.Epoch, nonceA) ||
		!libraryDigestPattern.MatchString(first.RequestDigest) {
		t.Fatalf("first record=%+v", first)
	}
	again, replayed, err := store.RecordLibraryRunCorrelation(ctx, client, body("run_a", "greq_a", "exec_secret_a", nonceA, base), base.Add(time.Minute))
	if err != nil || !replayed || again.ID != first.ID || !again.CreatedAt.Equal(first.CreatedAt) {
		t.Fatalf("exact replay=%+v replayed=%t err=%v", again, replayed, err)
	}
	if _, _, err := store.RecordLibraryRunCorrelation(ctx, client, body("run_a", "greq_a", "exec_secret_b", nonceB, base), base); !errors.Is(err, ErrLibraryRunCorrelationConflict) {
		t.Fatalf("same tuple different body err=%v; want conflict", err)
	}
	if _, _, err := store.RecordLibraryRunCorrelation(ctx, client, body("run_b", "greq_b", "", nonceA, base), base); !errors.Is(err, ErrLibraryRunCorrelationReplay) {
		t.Fatalf("nonce reuse err=%v; want replay", err)
	}
	// The store trusts only the live registration: a caller-supplied stale
	// epoch or status on the client argument changes nothing.
	staleClient := client
	staleClient.Epoch, staleClient.Status = "ep_stale", MCPClientStatusRevoked
	second, replayed, err := store.RecordLibraryRunCorrelation(ctx, staleClient, body("run_b", "greq_b", "", nonceB, base.Add(time.Millisecond)), base.Add(time.Millisecond))
	if err != nil || replayed || second.ExecutionHash != "" || second.ClientEpoch != client.Epoch {
		t.Fatalf("second record=%+v replayed=%t err=%v", second, replayed, err)
	}
	third, replayed, err := store.RecordLibraryRunCorrelation(ctx, client, body("run_a", "greq_c", "exec_secret_c", nonceC, base.Add(2*time.Millisecond)), base.Add(2*time.Millisecond))
	if err != nil || replayed {
		t.Fatalf("third record=%+v replayed=%t err=%v", third, replayed, err)
	}

	page, err := store.LibraryRunCorrelations(ctx, LibraryRunCorrelationCursor{}, 10)
	if err != nil || len(page) != 3 || page[0].ID != third.ID || page[1].ID != second.ID || page[2].ID != first.ID {
		t.Fatalf("newest-first page=%+v err=%v", page, err)
	}
	page, err = store.LibraryRunCorrelations(ctx, LibraryRunCorrelationCursor{CreatedAt: third.CreatedAt, ID: third.ID}, 10)
	if err != nil || len(page) != 2 || page[0].ID != second.ID || page[1].ID != first.ID {
		t.Fatalf("page after cursor=%+v err=%v", page, err)
	}
	page, err = store.LibraryRunCorrelations(ctx, LibraryRunCorrelationCursor{CreatedAt: second.CreatedAt, ID: second.ID}, 1)
	if err != nil || len(page) != 1 || page[0].ID != first.ID {
		t.Fatalf("limited page after cursor=%+v err=%v", page, err)
	}
	if page, err = store.LibraryRunCorrelations(ctx, LibraryRunCorrelationCursor{}, 0); err != nil || len(page) != 0 {
		t.Fatalf("zero limit page=%+v err=%v", page, err)
	}

	for name, test := range map[string]struct {
		client MCPClient
		raw    []byte
		want   error
	}{
		"epoch":          {client, runCorrelationBodyFor(t, "ep_other", bundle.BundleDigest, "run_e", "greq_e", "", nonceD, runCorrelationExpiry(base)), ErrLibraryRunCorrelationInvalid},
		"bundle":         {client, runCorrelationBodyFor(t, client.Epoch, libraryDigest("other"), "run_e", "greq_e", "", nonceD, runCorrelationExpiry(base)), ErrLibraryRunCorrelationInvalid},
		"expired":        {client, runCorrelationBodyFor(t, client.Epoch, bundle.BundleDigest, "run_e", "greq_e", "", nonceD, base.Add(-time.Second).Format(time.RFC3339Nano)), ErrLibraryRunCorrelationExpired},
		"unknown client": {MCPClient{ID: "mcpcli_missing"}, body("run_e", "greq_e", "", nonceD, base), ErrMCPClientNotFound},
	} {
		if _, _, err := store.RecordLibraryRunCorrelation(ctx, test.client, test.raw, base); !errors.Is(err, test.want) {
			t.Fatalf("%s err=%v; want %v", name, err, test.want)
		}
	}

	// Changing the selection changes the live bundle digest: the old digest is
	// refused and the new one is recorded.
	newVersion, err := store.CreateLibrarySkillVersion(ctx, LibrarySkillVersion{
		SkillID: skill.ID, Content: "# Reselected instructions", RequestedCapabilities: []string{"alerts.read"}, CreatedBy: client.Subject,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpsertLibrarySkillBinding(ctx, LibrarySkillBinding{
		SkillID: skill.ID, ScopeKind: LibraryScopeAgentSurface, ScopeID: client.ID,
		Mode: LibraryBindingModePin, PinnedVersionID: newVersion.ID, CapabilityCeiling: []string{"alerts.read"}, CreatedBy: client.Subject,
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.RecordLibraryRunCorrelation(ctx, client, body("run_d", "greq_d", "", nonceD, base.Add(3*time.Millisecond)), base.Add(3*time.Millisecond)); !errors.Is(err, ErrLibraryRunCorrelationInvalid) {
		t.Fatalf("stale bundle err=%v; want invalid", err)
	}
	live, err := BuildLibrarySkillActivationBundleForAgentSurface(ctx, store, client.ID)
	if err != nil || live.BundleDigest == bundle.BundleDigest {
		t.Fatalf("live bundle=%+v err=%v", live, err)
	}
	fourth, replayed, err := store.RecordLibraryRunCorrelation(ctx, client, runCorrelationBodyFor(t, client.Epoch, live.BundleDigest, "run_d", "greq_d", "", nonceD, runCorrelationExpiry(base.Add(3*time.Millisecond))), base.Add(3*time.Millisecond))
	if err != nil || replayed || fourth.BundleDigest != live.BundleDigest {
		t.Fatalf("live bundle record=%+v replayed=%t err=%v", fourth, replayed, err)
	}

	// Revocation closes the ingress at the store as well as the route.
	if _, err := store.RevokeMCPClient(ctx, client.ID, client.Subject, MCPClientPrecondition{ID: client.ID, Revision: client.Revision}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.RecordLibraryRunCorrelation(ctx, client, runCorrelationBodyFor(t, client.Epoch, live.BundleDigest, "run_z", "greq_z", "", runCorrelationNonce(54), runCorrelationExpiry(base)), base); !errors.Is(err, ErrMCPClientRevoked) {
		t.Fatalf("revoked client err=%v; want revoked", err)
	}
	return []LibraryRunCorrelation{fourth, third, second, first}
}

func TestFileStoreLibraryRunCorrelationsPersistScopedHashesOnly(t *testing.T) {
	ctx := context.Background()
	fixture := newRuntimeAttestationFixture(t, newLibraryFileStore(t))
	base := time.Now().UTC().Truncate(time.Millisecond)
	records := exerciseLibraryRunCorrelationStore(t, ctx, fixture.store, fixture.client, fixture.skill, fixture.bundle, base)

	reloaded, err := LoadFileStore(fixture.store.path)
	if err != nil {
		t.Fatal(err)
	}
	page, err := reloaded.LibraryRunCorrelations(ctx, LibraryRunCorrelationCursor{}, 10)
	if err != nil || len(page) != len(records) {
		t.Fatalf("reloaded page=%+v err=%v", page, err)
	}
	for i := range records {
		if page[i].ID != records[i].ID || page[i].NonceHash != records[i].NonceHash || page[i].ExecutionHash != records[i].ExecutionHash || !page[i].CreatedAt.Equal(records[i].CreatedAt) {
			t.Fatalf("reloaded record %d=%+v; want %+v", i, page[i], records[i])
		}
	}
	persisted, err := os.ReadFile(fixture.store.path)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"exec_secret_a", "exec_secret_c", runCorrelationNonce(50), runCorrelationNonce(53)} {
		if strings.Contains(string(persisted), secret) {
			t.Fatalf("persisted store leaked %q", secret)
		}
	}
}

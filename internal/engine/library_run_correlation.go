package engine

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"time"
	"unicode/utf8"
)

// LibraryRunCorrelationContractVersion names the body a runtime host signs
// when it claims a run against the activation bundle it fetched. It is
// distinct from the host-attestation contract, which names the signing
// scheme shared by every /runtime ingress.
const LibraryRunCorrelationContractVersion = "synaxis.library.run-correlation.v1"

const (
	libraryRunCorrelationMaxBytes = 16 << 10
	libraryRunCorrelationMaxTTL   = libraryRuntimeAttestationMaxTTL
)

var (
	ErrLibraryRunCorrelationInvalid  = errors.New("invalid library run correlation")
	ErrLibraryRunCorrelationExpired  = errors.New("library run correlation expired")
	ErrLibraryRunCorrelationReplay   = errors.New("library run correlation nonce was already used")
	ErrLibraryRunCorrelationConflict = errors.New("library run correlation conflicts with an existing record")
)

// LibraryRunCorrelation records what the Engine observed: this client, at
// this epoch, claimed RunID for GatewayRequestID while its activation bundle
// digest was as stated. It is not proof that a host injected instructions or
// executed anything. Only hashes of the host-chosen execution ID and nonce
// are kept; the signature and raw body are never persisted.
type LibraryRunCorrelation struct {
	ID               string    `json:"id"`
	ClientID         string    `json:"client_id"`
	ClientEpoch      string    `json:"client_epoch"`
	RunID            string    `json:"run_id"`
	GatewayRequestID string    `json:"gateway_request_id"`
	ExecutionHash    string    `json:"execution_hash,omitempty"`
	NonceHash        string    `json:"nonce_hash"`
	BundleDigest     string    `json:"bundle_digest"`
	RequestDigest    string    `json:"request_digest"`
	CreatedAt        time.Time `json:"created_at"`
}

// LibraryRunCorrelationCursor is a keyset position in the newest-first feed.
// A zero cursor starts from the newest record.
type LibraryRunCorrelationCursor struct {
	CreatedAt time.Time
	ID        string
}

// LibraryRunCorrelationStore is the narrow persistence boundary for host run
// claims. Implementations reload the client and rebuild the current activation
// bundle under their native lock or transaction before writing.
type LibraryRunCorrelationStore interface {
	// RecordLibraryRunCorrelation validates the exact signed body against the
	// live client and returns the durable record. replayed is true when an
	// identical claim for the same (client, epoch, run, request) tuple already
	// existed.
	RecordLibraryRunCorrelation(ctx context.Context, client MCPClient, raw []byte, now time.Time) (LibraryRunCorrelation, bool, error)
	// LibraryRunCorrelations returns up to limit records newer-first, starting
	// strictly after the cursor position.
	LibraryRunCorrelations(ctx context.Context, cursor LibraryRunCorrelationCursor, limit int) ([]LibraryRunCorrelation, error)
	// LibraryRunCorrelationsForRuns returns every correlation whose claimed
	// run ID is in runIDs, newest first. It is Console evidence for one
	// skill's runs and carries only the stored hashes and digests.
	LibraryRunCorrelationsForRuns(ctx context.Context, runIDs []string) ([]LibraryRunCorrelation, error)
}

func newLibraryRunCorrelationID() string { return "lrc_" + newEpoch() }

func libraryRunCorrelationPath(slug string) string {
	return "/runtime/clients/" + slug + "/run-correlations"
}

type libraryRunCorrelationRequest struct {
	ContractVersion  string `json:"contractVersion"`
	ClientEpoch      string `json:"clientEpoch"`
	RunID            string `json:"runId"`
	GatewayRequestID string `json:"gatewayRequestId"`
	ExecutionID      string `json:"executionId,omitempty"`
	Nonce            string `json:"nonce"`
	ExpiresAt        string `json:"expiresAt"`
	BundleDigest     string `json:"bundleDigest"`
}

type parsedLibraryRunCorrelation struct {
	Request       libraryRunCorrelationRequest
	RequestDigest string
}

func decodeLibraryRunCorrelation(raw []byte, now time.Time) (parsedLibraryRunCorrelation, error) {
	if !utf8.Valid(raw) {
		return parsedLibraryRunCorrelation{}, fmt.Errorf("%w: request must be UTF-8 JSON", ErrLibraryRunCorrelationInvalid)
	}
	var request libraryRunCorrelationRequest
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return parsedLibraryRunCorrelation{}, fmt.Errorf("%w: malformed request", ErrLibraryRunCorrelationInvalid)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return parsedLibraryRunCorrelation{}, fmt.Errorf("%w: malformed request", ErrLibraryRunCorrelationInvalid)
	}
	if request.ContractVersion != LibraryRunCorrelationContractVersion ||
		validateLibraryOpaqueRef("client epoch", request.ClientEpoch, false) != nil ||
		!validActorIdentifier(request.RunID) ||
		!validActorIdentifier(request.GatewayRequestID) ||
		validateLibraryOpaqueRef("execution id", request.ExecutionID, true) != nil ||
		validateLibraryDigest("bundle", request.BundleDigest, false) != nil {
		return parsedLibraryRunCorrelation{}, ErrLibraryRunCorrelationInvalid
	}
	nonce, err := base64.RawURLEncoding.DecodeString(request.Nonce)
	if err != nil || len(nonce) < 16 || len(nonce) > 64 || base64.RawURLEncoding.EncodeToString(nonce) != request.Nonce {
		return parsedLibraryRunCorrelation{}, ErrLibraryRunCorrelationInvalid
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, request.ExpiresAt)
	if err != nil || request.ExpiresAt != expiresAt.UTC().Format(time.RFC3339Nano) {
		return parsedLibraryRunCorrelation{}, ErrLibraryRunCorrelationInvalid
	}
	now = now.UTC()
	if !expiresAt.After(now) {
		return parsedLibraryRunCorrelation{}, ErrLibraryRunCorrelationExpired
	}
	if expiresAt.After(now.Add(libraryRunCorrelationMaxTTL)) {
		return parsedLibraryRunCorrelation{}, ErrLibraryRunCorrelationInvalid
	}
	return parsedLibraryRunCorrelation{Request: request, RequestDigest: libraryDigest(string(raw))}, nil
}

func libraryRunCorrelationExecutionHash(clientID, epoch, executionID string) string {
	if executionID == "" {
		return ""
	}
	return libraryDigest("run-correlation-execution\x00" + clientID + "\x00" + epoch + "\x00" + executionID)
}

func libraryRunCorrelationNonceHash(clientID, epoch, nonce string) string {
	return libraryDigest("run-correlation-nonce\x00" + clientID + "\x00" + epoch + "\x00" + nonce)
}

// verifyLibraryRunCorrelationForClient is the store-side revalidation shared
// by FileStore and PgStore. The caller supplies the client it reloaded under
// its own lock and the selection it collected there; the bundle digest is
// rebuilt from that selection so the claim binds to the live activation.
func verifyLibraryRunCorrelationForClient(client MCPClient, raw []byte, now time.Time, selections []LibraryAgentSurfaceSkillSelection, currentBuiltInVersionID string, builtInManifestInstalled bool) (parsedLibraryRunCorrelation, error) {
	if client.Status != MCPClientStatusActive {
		return parsedLibraryRunCorrelation{}, ErrMCPClientRevoked
	}
	parsed, err := decodeLibraryRunCorrelation(raw, now)
	if err != nil {
		return parsedLibraryRunCorrelation{}, err
	}
	if parsed.Request.ClientEpoch != client.Epoch {
		return parsedLibraryRunCorrelation{}, fmt.Errorf("%w: client epoch changed", ErrLibraryRunCorrelationInvalid)
	}
	resolution, err := libraryResolutionForAgentSurfaceSelections(client.ID, selections, currentBuiltInVersionID, builtInManifestInstalled)
	if err != nil {
		return parsedLibraryRunCorrelation{}, fmt.Errorf("%w: current selection", ErrLibraryRunCorrelationInvalid)
	}
	bundle, err := buildLibrarySkillActivationBundleForResolution(client.ID, resolution)
	if err != nil || bundle.BundleDigest != parsed.Request.BundleDigest {
		return parsedLibraryRunCorrelation{}, fmt.Errorf("%w: activation bundle changed", ErrLibraryRunCorrelationInvalid)
	}
	return parsed, nil
}

func newLibraryRunCorrelationRecord(client MCPClient, parsed parsedLibraryRunCorrelation, now time.Time) LibraryRunCorrelation {
	return LibraryRunCorrelation{
		ID:               newLibraryRunCorrelationID(),
		ClientID:         client.ID,
		ClientEpoch:      client.Epoch,
		RunID:            parsed.Request.RunID,
		GatewayRequestID: parsed.Request.GatewayRequestID,
		ExecutionHash:    libraryRunCorrelationExecutionHash(client.ID, client.Epoch, parsed.Request.ExecutionID),
		NonceHash:        libraryRunCorrelationNonceHash(client.ID, client.Epoch, parsed.Request.Nonce),
		BundleDigest:     parsed.Request.BundleDigest,
		RequestDigest:    parsed.RequestDigest,
		CreatedAt:        now.UTC(),
	}
}

func sameLibraryRunCorrelationTuple(record LibraryRunCorrelation, client MCPClient, parsed parsedLibraryRunCorrelation) bool {
	return record.ClientID == client.ID && record.ClientEpoch == client.Epoch &&
		record.RunID == parsed.Request.RunID && record.GatewayRequestID == parsed.Request.GatewayRequestID
}

// libraryRunCorrelationsAfter applies the keyset cursor to a newest-first
// ordering. Records at or before the cursor position are excluded.
func libraryRunCorrelationsAfter(cursor LibraryRunCorrelationCursor, record LibraryRunCorrelation) bool {
	if cursor.ID == "" && cursor.CreatedAt.IsZero() {
		return true
	}
	if record.CreatedAt.Before(cursor.CreatedAt) {
		return true
	}
	return record.CreatedAt.Equal(cursor.CreatedAt) && record.ID < cursor.ID
}

type libraryRunCorrelationResponse struct {
	CorrelationID    string `json:"correlationId"`
	RunID            string `json:"runId"`
	GatewayRequestID string `json:"gatewayRequestId"`
	Attested         bool   `json:"attested"`
}

// NewLibraryRunCorrelationHandler serves the signed, non-browser run-claim
// ingress. Like the skill-run attestation route it has no CORS handling, is
// never mounted under /api or /mcp, resolves the client by endpoint slug only,
// and verifies the per-client Ed25519 signature before parsing the body. The
// store then revalidates the epoch and activation digest under its own lock.
func NewLibraryRunCorrelationHandler(store LibraryRunCorrelationStore) http.Handler {
	mcpStore, ok := store.(MCPClientStore)
	if !ok {
		return http.NotFoundHandler()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if r.URL.RawQuery != "" || r.Header.Get("Origin") != "" || r.Header.Get("Sec-Fetch-Mode") != "" {
			http.NotFound(w, r)
			return
		}
		mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || mediaType != "application/json" {
			http.Error(w, "invalid run correlation", http.StatusBadRequest)
			return
		}
		client, key, found := libraryRuntimeClientForSlug(r, mcpStore)
		if !found {
			http.NotFound(w, r)
			return
		}
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, libraryRunCorrelationMaxBytes))
		if err != nil {
			http.Error(w, "run correlation body too large", http.StatusRequestEntityTooLarge)
			return
		}
		signature, err := decodeLibraryRuntimeSignature(r.Header.Get(libraryRuntimeAttestationSignatureHeader))
		if err != nil || !ed25519.Verify(key, libraryRuntimeSigningMessage(http.MethodPost, r.URL.Path, raw), signature) {
			http.Error(w, "invalid run correlation", http.StatusUnauthorized)
			return
		}
		now := time.Now().UTC()
		if _, err := decodeLibraryRunCorrelation(raw, now); err != nil {
			writeLibraryRunCorrelationError(w, err)
			return
		}
		record, replayed, err := store.RecordLibraryRunCorrelation(r.Context(), client, raw, now)
		if err != nil {
			writeLibraryRunCorrelationError(w, err)
			return
		}
		response := libraryRunCorrelationResponse{
			CorrelationID: record.ID, RunID: record.RunID, GatewayRequestID: record.GatewayRequestID, Attested: true,
		}
		if replayed {
			w.Header().Set("Idempotent-Replay", "true")
			writeJSON(w, http.StatusOK, response)
			return
		}
		writeJSON(w, http.StatusCreated, response)
	})
}

// libraryRuntimeClientForSlug resolves the active registration named by the
// {slug} path value and its configured attestor key. It deliberately uses the
// slug-only lookup so an opaque ID can never address a direct runtime route.
func libraryRuntimeClientForSlug(r *http.Request, store MCPClientStore) (MCPClient, ed25519.PublicKey, bool) {
	slug := r.PathValue("slug")
	if slug == "" || normalizeMCPClientSlug(slug) != slug {
		return MCPClient{}, nil, false
	}
	client, found := store.MCPClientBySlug(r.Context(), slug)
	if !found || client.Status != MCPClientStatusActive {
		return MCPClient{}, nil, false
	}
	key, configured := mcpClientRuntimeAttestorPublicKey(client.RuntimeAttestorPublicKey)
	if !configured {
		return MCPClient{}, nil, false
	}
	return client, key, true
}

func writeLibraryRunCorrelationError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrLibraryRunCorrelationExpired):
		http.Error(w, "run correlation expired", http.StatusGone)
	case errors.Is(err, ErrLibraryRunCorrelationConflict), errors.Is(err, ErrLibraryRunCorrelationReplay):
		http.Error(w, "run correlation conflicts with a prior request", http.StatusConflict)
	case errors.Is(err, ErrLibraryRunCorrelationInvalid), errors.Is(err, ErrMCPClientNotFound), errors.Is(err, ErrMCPClientRevoked):
		http.Error(w, "invalid run correlation", http.StatusUnauthorized)
	default:
		http.Error(w, "run correlation unavailable", http.StatusServiceUnavailable)
	}
}

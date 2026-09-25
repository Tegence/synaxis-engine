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
	"strings"
	"time"
	"unicode/utf8"
)

// LibraryRuntimeAttestationContractVersion is intentionally distinct from the
// context-only activation v1 contract. Changing this ingress does not change
// what a third-party host receives through library_skill_activation.
const LibraryRuntimeAttestationContractVersion = "synaxis.library.host-attestation.v1"

const (
	libraryRuntimeAttestationSignatureHeader = "X-Synaxis-Runtime-Signature"
	libraryRuntimeAttestationMaxBytes        = libraryMaxContentBytes + 16<<10
	libraryRuntimeAttestationMaxTTL          = 10 * time.Minute
)

// LibraryRuntimeAttestation carries the only trusted transport material into
// a native store transaction. Client identity is derived from the route; the
// raw body and signature are checked a second time by each store after it has
// reloaded the current client key and agent-surface selection. Store code
// always obtains its own current time; a transport caller cannot choose an
// expiry-validation or durable-created-at timestamp.
type LibraryRuntimeAttestation struct {
	ClientID  string
	Path      string
	RawBody   []byte
	Signature []byte
}

type libraryRuntimeAttestationRequest struct {
	ContractVersion string                          `json:"contractVersion"`
	ClientEpoch     string                          `json:"clientEpoch"`
	ExecutionID     string                          `json:"executionId"`
	Nonce           string                          `json:"nonce"`
	ExpiresAt       string                          `json:"expiresAt"`
	BundleDigest    string                          `json:"bundleDigest"`
	SkillID         string                          `json:"skillId"`
	SkillVersionID  string                          `json:"skillVersionId"`
	BindingID       string                          `json:"bindingId"`
	InputDigest     string                          `json:"inputDigest"`
	Output          libraryRuntimeAttestationOutput `json:"output"`
}

type libraryRuntimeAttestationOutput struct {
	Title   string `json:"title"`
	Summary string `json:"summary,omitempty"`
	Format  string `json:"format"`
	Body    string `json:"body"`
}

type parsedLibraryRuntimeAttestation struct {
	Request       libraryRuntimeAttestationRequest
	RequestDigest string
}

// libraryRuntimeAttestationRecord persists only scoped SHA-256 verifier
// values, never a host execution ID, nonce, signature, or raw request body.
// It is the FileStore counterpart of the PostgreSQL idempotency table.
type libraryRuntimeAttestationRecord struct {
	RunID         string `json:"run_id"`
	ClientID      string `json:"client_id"`
	ClientEpoch   string `json:"client_epoch"`
	ExecutionHash string `json:"execution_hash"`
	NonceHash     string `json:"nonce_hash"`
	RequestDigest string `json:"request_digest"`
}

// librarySkillRuntimeReceiptInput is deliberately output-free. A host calls
// it before signing, then creates its own exact JSON body containing the
// output it wants to persist. Sending output through this read-only MCP tool
// would create an unnecessary second copy of potentially private content.
type librarySkillRuntimeReceiptInput struct {
	SkillID     string `json:"skillId"`
	ExecutionID string `json:"executionId"`
	Nonce       string `json:"nonce"`
	ExpiresAt   string `json:"expiresAt"`
	InputDigest string `json:"inputDigest"`
}

type librarySkillRuntimeReceipt struct {
	ContractVersion        string `json:"contractVersion"`
	Path                   string `json:"path"`
	HostSignatureHeader    string `json:"hostSignatureHeader"`
	HostSignatureAlgorithm string `json:"hostSignatureAlgorithm"`
	ClientEpoch            string `json:"clientEpoch"`
	ExecutionID            string `json:"executionId"`
	Nonce                  string `json:"nonce"`
	ExpiresAt              string `json:"expiresAt"`
	BundleDigest           string `json:"bundleDigest"`
	SkillID                string `json:"skillId"`
	SkillVersionID         string `json:"skillVersionId"`
	BindingID              string `json:"bindingId"`
	InputDigest            string `json:"inputDigest"`
	ReceiptNotice          string `json:"receiptNotice"`
	HostNotice             string `json:"hostNotice"`
	SigningNotice          string `json:"signingNotice"`
}

func libraryRuntimeAttestationPath(slug string) string {
	return "/runtime/clients/" + slug + "/skill-runs"
}

func libraryRuntimeAttestationSigningMessage(path string, body []byte) []byte {
	return libraryRuntimeSigningMessage(http.MethodPost, path, body)
}

// libraryRuntimeSigningMessage is the one host signing scheme shared by every
// /runtime ingress: the host-attestation contract name, the HTTP method, the
// exact route path, and then the signed material (a raw JSON body for POST
// routes, the request timestamp for GET routes), each separated by a newline.
// The method and path give every route its own signing domain.
func libraryRuntimeSigningMessage(method, path string, body []byte) []byte {
	prefix := []byte(LibraryRuntimeAttestationContractVersion + "\n" + method + "\n" + path + "\n")
	message := make([]byte, 0, len(prefix)+len(body))
	message = append(message, prefix...)
	return append(message, body...)
}

func decodeLibraryRuntimeSignature(value string) ([]byte, error) {
	if strings.TrimSpace(value) != value || value == "" {
		return nil, ErrLibraryRuntimeAttestationInvalid
	}
	signature, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(signature) != ed25519.SignatureSize || base64.RawURLEncoding.EncodeToString(signature) != value {
		return nil, ErrLibraryRuntimeAttestationInvalid
	}
	return signature, nil
}

func decodeLibraryRuntimeAttestation(raw []byte, now time.Time) (parsedLibraryRuntimeAttestation, error) {
	if !utf8.Valid(raw) {
		return parsedLibraryRuntimeAttestation{}, fmt.Errorf("%w: request must be UTF-8 JSON", ErrLibraryRuntimeAttestationInvalid)
	}
	var request libraryRuntimeAttestationRequest
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return parsedLibraryRuntimeAttestation{}, fmt.Errorf("%w: malformed request", ErrLibraryRuntimeAttestationInvalid)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return parsedLibraryRuntimeAttestation{}, fmt.Errorf("%w: malformed request", ErrLibraryRuntimeAttestationInvalid)
	}
	if _, err := validateLibraryRuntimeAttestationEnvelope(request, now); err != nil {
		return parsedLibraryRuntimeAttestation{}, err
	}
	if err := validateLibraryArtifact(LibraryArtifact{
		Title: request.Output.Title, Summary: request.Output.Summary, Origin: LibraryArtifactOriginSkillRun,
		RunID: "runtime-attestation", SkillID: request.SkillID, SkillVersionID: request.SkillVersionID, BindingID: request.BindingID,
	}); err != nil {
		return parsedLibraryRuntimeAttestation{}, fmt.Errorf("%w: invalid output", ErrLibraryRuntimeAttestationInvalid)
	}
	if err := validateLibraryArtifactVersion(LibraryArtifactVersion{ArtifactID: "runtime-attestation", Format: request.Output.Format, Body: request.Output.Body}); err != nil {
		return parsedLibraryRuntimeAttestation{}, fmt.Errorf("%w: invalid output", ErrLibraryRuntimeAttestationInvalid)
	}
	return parsedLibraryRuntimeAttestation{Request: request, RequestDigest: libraryDigest(string(raw))}, nil
}

func validateLibraryRuntimeAttestationEnvelope(request libraryRuntimeAttestationRequest, now time.Time) (time.Time, error) {
	if request.ContractVersion != LibraryRuntimeAttestationContractVersion ||
		validateLibraryOpaqueRef("client epoch", request.ClientEpoch, false) != nil ||
		validateLibraryOpaqueRef("execution id", request.ExecutionID, false) != nil ||
		validateLibraryOpaqueRef("skill", request.SkillID, false) != nil ||
		validateLibraryOpaqueRef("skill version", request.SkillVersionID, false) != nil ||
		validateLibraryOpaqueRef("binding", request.BindingID, false) != nil ||
		validateLibraryDigest("bundle", request.BundleDigest, false) != nil ||
		validateLibraryDigest("run input", request.InputDigest, false) != nil {
		return time.Time{}, ErrLibraryRuntimeAttestationInvalid
	}
	nonce, err := base64.RawURLEncoding.DecodeString(request.Nonce)
	if err != nil || len(nonce) < 16 || len(nonce) > 64 || base64.RawURLEncoding.EncodeToString(nonce) != request.Nonce {
		return time.Time{}, ErrLibraryRuntimeAttestationInvalid
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, request.ExpiresAt)
	if err != nil || request.ExpiresAt != expiresAt.UTC().Format(time.RFC3339Nano) {
		return time.Time{}, ErrLibraryRuntimeAttestationInvalid
	}
	now = now.UTC()
	if !expiresAt.After(now) {
		return time.Time{}, ErrLibraryRuntimeAttestationExpired
	}
	if expiresAt.After(now.Add(libraryRuntimeAttestationMaxTTL)) {
		return time.Time{}, ErrLibraryRuntimeAttestationInvalid
	}
	return expiresAt, nil
}

func verifyLibraryRuntimeAttestation(client MCPClient, attestation LibraryRuntimeAttestation, now time.Time) (parsedLibraryRuntimeAttestation, error) {
	if attestation.ClientID != client.ID || attestation.Path != libraryRuntimeAttestationPath(client.Slug) || client.Status != MCPClientStatusActive {
		return parsedLibraryRuntimeAttestation{}, ErrLibraryRuntimeAttestationInvalid
	}
	key, ok := mcpClientRuntimeAttestorPublicKey(client.RuntimeAttestorPublicKey)
	if !ok || !ed25519.Verify(key, libraryRuntimeAttestationSigningMessage(attestation.Path, attestation.RawBody), attestation.Signature) {
		return parsedLibraryRuntimeAttestation{}, ErrLibraryRuntimeAttestationInvalid
	}
	parsed, err := decodeLibraryRuntimeAttestation(attestation.RawBody, now)
	if err != nil {
		return parsedLibraryRuntimeAttestation{}, err
	}
	if parsed.Request.ClientEpoch != client.Epoch {
		return parsedLibraryRuntimeAttestation{}, ErrLibraryRuntimeAttestationInvalid
	}
	return parsed, nil
}

func libraryRuntimeAttestationExecutionHash(clientID, epoch, executionID string) string {
	return libraryDigest("runtime-execution\x00" + clientID + "\x00" + epoch + "\x00" + executionID)
}

func libraryRuntimeAttestationNonceHash(clientID, epoch, nonce string) string {
	return libraryDigest("runtime-nonce\x00" + clientID + "\x00" + epoch + "\x00" + nonce)
}

func validateLibraryRuntimeAttestationSelection(client MCPClient, parsed parsedLibraryRuntimeAttestation, selections []LibraryAgentSurfaceSkillSelection, currentBuiltInVersionID string, builtInManifestInstalled bool) error {
	resolution, err := libraryResolutionForAgentSurfaceSelections(client.ID, selections, currentBuiltInVersionID, builtInManifestInstalled)
	if err != nil {
		return fmt.Errorf("%w: current selection", ErrLibraryRuntimeAttestationInvalid)
	}
	bundle, matched := libraryActivationBundleDigestMatches(client.ID, resolution, parsed.Request.BundleDigest)
	if !matched {
		return fmt.Errorf("%w: activation bundle changed", ErrLibraryRuntimeAttestationInvalid)
	}
	for _, selected := range bundle.Skills {
		if selected.SkillID == parsed.Request.SkillID && selected.VersionID == parsed.Request.SkillVersionID && selected.Binding.ID == parsed.Request.BindingID {
			return nil
		}
	}
	return fmt.Errorf("%w: selected immutable tuple is no longer assigned", ErrLibraryRuntimeAttestationInvalid)
}

func prepareLibraryRuntimeAttestationOutput(client MCPClient, parsed parsedLibraryRuntimeAttestation, now time.Time) (LibraryRun, LibraryArtifact, LibraryArtifactVersion, error) {
	if client.ID == "" || client.Subject == "" {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, ErrLibraryRuntimeAttestationInvalid
	}
	now = now.UTC()
	runID := newLibraryRunID()
	artifact := LibraryArtifact{
		ID: clientScopedRuntimeArtifactID(), Title: parsed.Request.Output.Title, Summary: parsed.Request.Output.Summary,
		Origin: LibraryArtifactOriginSkillRun, RunID: runID,
		SkillID: parsed.Request.SkillID, SkillVersionID: parsed.Request.SkillVersionID, BindingID: parsed.Request.BindingID,
		AgentSurfaceID: client.ID, CreatedBy: client.Subject, CreatedAt: now,
	}
	if err := validateLibraryArtifact(artifact); err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
	}
	version, err := normalizedLibraryArtifactVersion(LibraryArtifactVersion{
		ID: newLibraryArtifactVersionID(), ArtifactID: artifact.ID, Version: 1,
		Format: parsed.Request.Output.Format, Body: parsed.Request.Output.Body, CreatedBy: client.Subject, CreatedAt: now,
	})
	if err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
	}
	run, err := normalizedLibraryRun(LibraryRun{
		ID: runID, Origin: LibraryRunOriginSkillRun, Attestation: LibraryRunAttestationHost,
		SkillID: parsed.Request.SkillID, SkillVersionID: parsed.Request.SkillVersionID, BindingID: parsed.Request.BindingID,
		ActorRef: client.Subject, SurfaceRef: client.ID, EffectiveCapabilities: []string{}, Status: "succeeded",
		InputDigest: parsed.Request.InputDigest, OutputDigest: version.Digest, StartedAt: now, CompletedAt: now,
	})
	if err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
	}
	return run, artifact, version, nil
}

// clientScopedRuntimeArtifactID exists solely to make it explicit that every
// durable output identity is generated server-side. It intentionally carries
// no client data; client association is the separately validated projection.
func clientScopedRuntimeArtifactID() string { return newLibraryArtifactID() }

func buildLibrarySkillRuntimeReceipt(ctx context.Context, store LibraryStore, client MCPClient, input librarySkillRuntimeReceiptInput, now time.Time) (librarySkillRuntimeReceipt, error) {
	request := libraryRuntimeAttestationRequest{
		ContractVersion: LibraryRuntimeAttestationContractVersion, ClientEpoch: client.Epoch,
		ExecutionID: input.ExecutionID, Nonce: input.Nonce, ExpiresAt: input.ExpiresAt, InputDigest: input.InputDigest,
		SkillID: input.SkillID, SkillVersionID: "receipt", BindingID: "receipt", BundleDigest: libraryDigest("receipt"),
	}
	if _, err := validateLibraryRuntimeAttestationEnvelope(request, now); err != nil {
		return librarySkillRuntimeReceipt{}, err
	}
	bundle, err := BuildLibrarySkillActivationBundleForAgentSurface(ctx, store, client.ID)
	if err != nil {
		return librarySkillRuntimeReceipt{}, err
	}
	for _, skill := range bundle.Skills {
		if skill.SkillID != input.SkillID {
			continue
		}
		return librarySkillRuntimeReceipt{
			ContractVersion:        LibraryRuntimeAttestationContractVersion,
			Path:                   libraryRuntimeAttestationPath(client.Slug),
			HostSignatureHeader:    libraryRuntimeAttestationSignatureHeader,
			HostSignatureAlgorithm: "Ed25519",
			ClientEpoch:            client.Epoch,
			ExecutionID:            input.ExecutionID,
			Nonce:                  input.Nonce,
			ExpiresAt:              input.ExpiresAt,
			BundleDigest:           bundle.BundleDigest,
			SkillID:                skill.SkillID,
			SkillVersionID:         skill.VersionID,
			BindingID:              skill.Binding.ID,
			InputDigest:            input.InputDigest,
			ReceiptNotice:          "This is an unsigned Engine-issued current-selection receipt. It is not an Engine-signed token, a bearer credential, or persistent proof of execution.",
			HostNotice:             "A successful ingest records only a host-attested skill-result claim. It does not prove Synaxis injected instructions, invoked a tool, or granted authority.",
			SigningNotice:          "Construct one exact JSON body containing these protocol fields plus output {title,summary,format,body}. The host signs the byte sequence \"synaxis.library.host-attestation.v1\\nPOST\\n<path>\\n\" followed immediately by the raw UTF-8 JSON body, and puts raw-base64url Ed25519 signature bytes in the stated host header. The Engine revalidates the active client, epoch, key, whole bundle, and selected immutable tuple before writing.",
		}, nil
	}
	return librarySkillRuntimeReceipt{}, ErrLibraryRuntimeAttestationInvalid
}

// NewLibraryRuntimeAttestationHandler serves the non-browser, non-BFF direct
// ingress. It deliberately has no CORS handling and is not mounted under
// /api or /mcp. A signature is checked before parsing useful request details,
// then checked again in the native persistence transaction.
func NewLibraryRuntimeAttestationHandler(store LibraryRuntimeAttestationStore) http.Handler {
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
			http.Error(w, "invalid runtime attestation", http.StatusBadRequest)
			return
		}
		slug := r.PathValue("slug")
		if slug == "" || normalizeMCPClientSlug(slug) != slug {
			http.NotFound(w, r)
			return
		}
		// This direct route identifies a registration by its stable endpoint
		// slug only. Do not use ActiveMCPClient here because that helper also
		// accepts opaque IDs for internal callers.
		client, found := mcpStore.MCPClientBySlug(r.Context(), slug)
		if !found || client.Status != MCPClientStatusActive {
			http.NotFound(w, r)
			return
		}
		key, configured := mcpClientRuntimeAttestorPublicKey(client.RuntimeAttestorPublicKey)
		if !configured {
			http.NotFound(w, r)
			return
		}
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, libraryRuntimeAttestationMaxBytes))
		if err != nil {
			http.Error(w, "runtime attestation body too large", http.StatusRequestEntityTooLarge)
			return
		}
		signature, err := decodeLibraryRuntimeSignature(r.Header.Get(libraryRuntimeAttestationSignatureHeader))
		if err != nil || !ed25519.Verify(key, libraryRuntimeAttestationSigningMessage(r.URL.Path, raw), signature) {
			http.Error(w, "invalid runtime attestation", http.StatusUnauthorized)
			return
		}
		now := time.Now().UTC()
		if _, err := decodeLibraryRuntimeAttestation(raw, now); err != nil {
			writeLibraryRuntimeAttestationError(w, err)
			return
		}
		run, artifact, version, replayed, err := store.IngestLibraryRuntimeAttestation(r.Context(), LibraryRuntimeAttestation{
			ClientID: client.ID, Path: r.URL.Path, RawBody: raw, Signature: signature,
		})
		if err != nil {
			writeLibraryRuntimeAttestationError(w, err)
			return
		}
		if replayed {
			w.Header().Set("Idempotent-Replay", "true")
			writeJSON(w, http.StatusOK, newLibraryRuntimeAttestationResponse(run, artifact, version))
			return
		}
		writeJSON(w, http.StatusCreated, newLibraryRuntimeAttestationResponse(run, artifact, version))
	})
}

type libraryRuntimeAttestationResponse struct {
	RunID                 string `json:"runId"`
	ArtifactID            string `json:"artifactId"`
	ArtifactVersionID     string `json:"artifactVersionId"`
	ArtifactVersionDigest string `json:"artifactVersionDigest"`
}

// The runtime host needs durable identities to make a safe retry, but it does
// not need the Engine's opaque actor/surface provenance or a reflected copy of
// the body it just submitted. Keep that private metadata behind normal Engine
// authorization paths.
func newLibraryRuntimeAttestationResponse(run LibraryRun, artifact LibraryArtifact, version LibraryArtifactVersion) libraryRuntimeAttestationResponse {
	return libraryRuntimeAttestationResponse{
		RunID:                 run.ID,
		ArtifactID:            artifact.ID,
		ArtifactVersionID:     version.ID,
		ArtifactVersionDigest: version.Digest,
	}
}

func writeLibraryRuntimeAttestationError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrLibraryRuntimeAttestationExpired):
		http.Error(w, "runtime attestation expired", http.StatusGone)
	case errors.Is(err, ErrLibraryRuntimeAttestationConflict), errors.Is(err, ErrLibraryRuntimeAttestationReplay):
		http.Error(w, "runtime attestation conflicts with a prior request", http.StatusConflict)
	case errors.Is(err, ErrLibraryRuntimeAttestationInvalid), errors.Is(err, ErrMCPClientNotFound), errors.Is(err, ErrMCPClientRevoked):
		http.Error(w, "invalid runtime attestation", http.StatusUnauthorized)
	default:
		http.Error(w, "runtime attestation unavailable", http.StatusServiceUnavailable)
	}
}

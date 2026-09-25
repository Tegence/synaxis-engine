package engine

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// /control/v1 is the versioned, machine-to-machine control contract described
// in docs/CONTROL_V1.md. It shares every handler and store with the
// self-hosted /api console; only the wire boundary differs: RFC 9457 problem
// details with a stable code registry, an echoed correlation ID, natural-key
// and terminal-state convergence on retries, and an optional Idempotency-Key.
//
// The Engine stays tenant-blind on this surface. The actor assertion's
// workspace and user IDs, the provision generation, and the opaque profile
// binding are all references it stores or echoes; it never resolves them.
const (
	controlV1PathPrefix            = "/control/v1/"
	controlContractVersion         = "v1"
	controlRequestIDHeader         = "X-Synaxis-Request-ID"
	controlIdempotencyKeyHeader    = "Idempotency-Key"
	controlIdempotentReplayHeader  = "Idempotent-Replay"
	controlCursorHeader            = "X-Synaxis-Cursor"
	controlProblemContentType      = "application/problem+json"
	maxControlRequestIDBytes       = 128
	maxControlIdempotencyKeyBytes  = 200
	controlIdempotencyHorizon      = 24 * time.Hour
	controlRunCorrelationPageLimit = 100
)

// Stable machine-readable codes. Titles may change; codes may only be added.
const (
	controlCodeUnauthorized           = "unauthorized"
	controlCodeActorAssertionInvalid  = "actor_assertion_invalid"
	controlCodeForbidden              = "forbidden"
	controlCodeNotFound               = "not_found"
	controlCodeAlreadyExists          = "already_exists"
	controlCodeRevisionMismatch       = "revision_mismatch"
	controlCodeValidationFailed       = "validation_failed"
	controlCodeCapacityLimited        = "capacity_limited"
	controlCodeCapabilityUnavailable  = "capability_unavailable"
	controlCodeEngineUnavailable      = "engine_unavailable"
	controlCodeIdempotencyKeyConflict = "idempotency_key_conflict"
	controlCodeProfileBindingConflict = "profile_binding_conflict"
	controlCodeClientRevoked          = "client_revoked"
	// controlCodeGrantSourceChanged reports that the exact artifact version
	// and digest a caller reviewed no longer describe the artifact's head, so
	// a grant must not be minted from that review.
	controlCodeGrantSourceChanged = "grant_source_changed"
	// controlCodeWorkloadBindingConflict reports a workload client whose OAuth
	// binding is not its reserved workload identity; an explicit
	// oauth-client/reset is the recovery.
	controlCodeWorkloadBindingConflict = "workload_binding_conflict"
)

// controlCapabilities advertises the v1 resource groups this Engine build
// serves. Absence of a route is still the downgrade signal; this list lets a
// control plane confirm positively before it relies on a group.
var controlCapabilities = []string{"mcp-clients", "profile-binding", "activation-snapshot", "run-correlations", "library-artifacts", "connection-evidence"}

// controlCapabilityWorkloadClients is advertised only when this Engine can
// actually mint workload tokens (see ConsoleAPI.workloadTokensAvailable): a
// control plane uses it to decide whether it may create cloud agents here.
const controlCapabilityWorkloadClients = "workload-clients"

func (c *ConsoleAPI) controlCapabilities() []string {
	capabilities := append([]string(nil), controlCapabilities...)
	if c.workloadTokensAvailable() {
		capabilities = append(capabilities, controlCapabilityWorkloadClients)
	}
	return capabilities
}

type controlProblem struct {
	Type      string `json:"type"`
	Title     string `json:"title"`
	Status    int    `json:"status"`
	Code      string `json:"code"`
	RequestID string `json:"requestId"`
}

// writeControlProblem serializes one RFC 9457 problem. The correlation ID is
// read from the response header the control wrapper set before any handler
// ran, so every error body carries the same ID the header echoes.
func writeControlProblem(w http.ResponseWriter, status int, code, title string) {
	requestID := w.Header().Get(controlRequestIDHeader)
	w.Header().Set("Content-Type", controlProblemContentType)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(controlProblem{
		Type: "about:blank", Title: title, Status: status, Code: code, RequestID: requestID,
	})
}

func newControlRequestID() string { return "req_" + newEpoch() }

// controlRequestID echoes a well-formed caller correlation ID and otherwise
// mints one. The alphabet is bounded so a caller cannot smuggle header or
// log-line control characters through the echo.
func controlRequestID(r *http.Request) string {
	values := r.Header.Values(controlRequestIDHeader)
	if len(values) == 1 && validControlRequestID(values[0]) {
		return values[0]
	}
	return newControlRequestID()
}

func validControlRequestID(value string) bool {
	if value == "" || len(value) > maxControlRequestIDBytes {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			character == '-' || character == '_' || character == '.' || character == ':' {
			continue
		}
		return false
	}
	return true
}

func validControlIdempotencyKey(value string) bool {
	if value == "" || len(value) > maxControlIdempotencyKeyBytes || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return true
}

// authorizeControl is the shared authentication chain with a machine-readable
// failure. Both failures are a non-leaking 401 on the wire; only the problem
// code distinguishes a credential problem from an assertion problem so a
// control plane can tell "reconcile the engine token" from "signing-key or
// clock drift" without exposing that distinction to anyone else.
func (c *ConsoleAPI) authorizeControl(r *http.Request) (*http.Request, *consoleFailure) {
	unauthorized := newConsoleFailure(http.StatusUnauthorized, controlCodeUnauthorized, "unauthorized")
	if c.actorVerifier != nil {
		// Hosted engines intentionally do not fall back to a local session.
		// Possession of the machine token alone is also insufficient: a request
		// must carry a Platform-signed actor assertion bound to its body/path.
		if !c.machineAuthed(r) {
			return nil, unauthorized
		}
		actor, err := c.actorVerifier.VerifyRequest(r)
		if err != nil {
			return nil, newConsoleFailure(http.StatusUnauthorized, controlCodeActorAssertionInvalid, "unauthorized")
		}
		return r.WithContext(withPlatformActor(r.Context(), actor)), nil
	}
	if c.machineAuthed(r) {
		return r, nil
	}
	if c.localAdminAuth {
		token, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if c.validToken(token) {
			return r, nil
		}
	}
	return nil, unauthorized
}

// controlV1 wraps one /control/v1 handler with the same CORS and
// authentication chain as the /api sec wrapper, then adds the v1 boundary:
// the echoed correlation ID, no-store caching, problem-details failures, and
// optional Idempotency-Key replay.
func (c *ConsoleAPI) controlV1(fn http.HandlerFunc) http.HandlerFunc {
	return c.controlV1Boundary(fn, true)
}

// controlV1Credential is controlV1 for a route whose success body is a bearer
// credential. It keeps the whole v1 boundary except Idempotency-Key replay:
// that layer persists 2xx bodies for a day and hands them out again, and a
// credential must never be written at rest or issued twice. The header is
// accepted and ignored, exactly as on a store without the idempotency facet;
// such a route must be safe to repeat without a key.
func (c *ConsoleAPI) controlV1Credential(fn http.HandlerFunc) http.HandlerFunc {
	return c.controlV1Boundary(fn, false)
}

func (c *ConsoleAPI) controlV1Boundary(fn http.HandlerFunc, replay bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(controlRequestIDHeader, controlRequestID(r))
		w.Header().Set("Cache-Control", "no-store")
		if c.cors(w, r) {
			return
		}
		authorized, failure := c.authorizeControl(r)
		if failure != nil {
			writeControlProblem(w, failure.status, failure.code, failure.message)
			return
		}
		if !replay {
			fn(w, authorized)
			return
		}
		c.serveControlWithIdempotency(w, authorized, fn)
	}
}

// handleControlNotFound answers any /control/v1 path that did not match a
// specific route. It always runs behind the same controlV1 auth chain, so a
// service principal outside its narrow allowlist, or any caller using the
// wrong method, gets the same signed 401 an unregistered path would
// otherwise hide behind Go's default plain-text 404. A genuinely authorized
// caller (owner/admin, or local admin session) reaching here has asked for a
// resource that does not exist.
func (c *ConsoleAPI) handleControlNotFound(w http.ResponseWriter, r *http.Request) {
	writeControlProblem(w, http.StatusNotFound, controlCodeNotFound, "not found")
}

// controlActorRef scopes idempotency records to the principal that made the
// first request, so a key chosen by one member can never replay a response
// containing a record another member could not read. The separator is outside
// the actor identifier alphabet the assertion verifier enforces, and it is a
// plain printable byte so the reference is storable in a PostgreSQL TEXT
// column (which rejects NUL).
func controlActorRef(r *http.Request) string {
	if actor, ok := PlatformActorFromContext(r.Context()); ok {
		return actor.WorkspaceID + "|" + actor.UserID + "|" + actor.Role
	}
	return "local-admin"
}

func (c *ConsoleAPI) serveControlWithIdempotency(w http.ResponseWriter, r *http.Request, fn http.HandlerFunc) {
	keys := r.Header.Values(controlIdempotencyKeyHeader)
	if len(keys) == 0 || r.Method == http.MethodGet || r.Method == http.MethodHead {
		fn(w, r)
		return
	}
	if len(keys) != 1 || !validControlIdempotencyKey(keys[0]) {
		writeControlProblem(w, http.StatusBadRequest, controlCodeValidationFailed, "Idempotency-Key must be one printable value of at most 200 characters")
		return
	}
	store, ok := c.store.(ControlIdempotencyStore)
	if !ok {
		// A store without the facet still serves the natural-key and
		// revision-fence behavior; the key is accepted and ignored.
		fn(w, r)
		return
	}
	body, err := readBoundedActorRequestBody(r)
	if err != nil {
		writeControlProblem(w, http.StatusRequestEntityTooLarge, controlCodeValidationFailed, "request body is too large")
		return
	}
	digest := sha256.Sum256(body)
	record := ControlIdempotencyRecord{
		Key:          keys[0],
		ResourcePath: r.URL.Path,
		ActorRef:     controlActorRef(r),
		BodyDigest:   hex.EncodeToString(digest[:]),
	}
	now := time.Now().UTC()
	existing, found, err := store.ControlIdempotencyRecord(r.Context(), record.Key, record.ResourcePath, now)
	if err != nil {
		writeControlProblem(w, http.StatusBadGateway, controlCodeEngineUnavailable, "idempotency store is unavailable")
		return
	}
	if found {
		if existing.ActorRef != record.ActorRef || existing.BodyDigest != record.BodyDigest {
			writeControlProblem(w, http.StatusConflict, controlCodeIdempotencyKeyConflict, "Idempotency-Key was already used with a different request")
			return
		}
		w.Header().Set(controlIdempotentReplayHeader, "true")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(existing.Status)
		_, _ = w.Write(existing.Body)
		return
	}
	recorder := &controlResponseRecorder{ResponseWriter: w, status: http.StatusOK}
	fn(recorder, r)
	recorder.flush()
	if recorder.status < 200 || recorder.status > 299 {
		// Only a completed mutation is worth pinning to the key. A failed
		// attempt (validation, conflict, transport) must be retried freshly so
		// a transient error is not replayed for a day.
		return
	}
	record.Status = recorder.status
	record.Body = append([]byte(nil), recorder.body.Bytes()...)
	record.CreatedAt = now
	record.ExpiresAt = now.Add(controlIdempotencyHorizon)
	_, _, _ = store.StoreControlIdempotencyRecord(r.Context(), record)
}

// controlResponseRecorder buffers a handler's status and body so a successful
// mutation can be stored under its idempotency key after it is sent. Headers
// pass straight through to the underlying writer.
type controlResponseRecorder struct {
	http.ResponseWriter
	status  int
	wrote   bool
	body    bytes.Buffer
	flushed bool
}

func (r *controlResponseRecorder) WriteHeader(status int) {
	if r.wrote {
		return
	}
	r.wrote = true
	r.status = status
}

func (r *controlResponseRecorder) Write(p []byte) (int, error) {
	if !r.wrote {
		r.WriteHeader(http.StatusOK)
	}
	return r.body.Write(p)
}

func (r *controlResponseRecorder) flush() {
	if r.flushed {
		return
	}
	r.flushed = true
	r.ResponseWriter.WriteHeader(r.status)
	_, _ = r.ResponseWriter.Write(r.body.Bytes())
}

// WithEngineVersion sets the build string reported by GET /control/v1/meta.
func WithEngineVersion(version string) ConsoleOption {
	return func(c *ConsoleAPI) {
		c.engineVersion = strings.TrimSpace(version)
	}
}

// WithProvisionGeneration reports the hosted provision generation on
// GET /control/v1/meta. The Engine treats it as an opaque pinning number;
// self-hosted Engines report 0.
func WithProvisionGeneration(generation int64) ConsoleOption {
	return func(c *ConsoleAPI) {
		if generation < 0 {
			generation = 0
		}
		c.provisionGeneration = generation
	}
}

type controlMetaDTO struct {
	ControlContract     string   `json:"controlContract"`
	EngineVersion       string   `json:"engineVersion"`
	ProvisionGeneration int64    `json:"provisionGeneration"`
	Capabilities        []string `json:"capabilities"`
}

// handleControlMeta is the positive version signal for the contract. Any
// verified principal may read it; the service actor reaches it through its
// closed allowlist.
func (c *ConsoleAPI) handleControlMeta(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		controlWire.writeMethodNotAllowed(w, http.MethodGet)
		return
	}
	version := c.engineVersion
	if version == "" {
		version = "dev"
	}
	writeJSON(w, http.StatusOK, controlMetaDTO{
		ControlContract:     controlContractVersion,
		EngineVersion:       version,
		ProvisionGeneration: c.provisionGeneration,
		Capabilities:        c.controlCapabilities(),
	})
}

func (c *ConsoleAPI) handleControlMCPClients(w http.ResponseWriter, r *http.Request) {
	c.serveMCPClients(w, r, controlWire)
}

func (c *ConsoleAPI) handleControlMCPClientByID(w http.ResponseWriter, r *http.Request) {
	c.serveMCPClientByID(w, r, controlWire)
}

func (c *ConsoleAPI) handleControlMCPClientNamespaces(w http.ResponseWriter, r *http.Request) {
	c.serveMCPClientNamespaces(w, r, controlWire)
}

func (c *ConsoleAPI) handleControlMCPClientOAuthReset(w http.ResponseWriter, r *http.Request) {
	c.serveMCPClientOAuthReset(w, r, controlWire)
}

func (c *ConsoleAPI) handleControlMCPClientRevoke(w http.ResponseWriter, r *http.Request) {
	c.serveMCPClientRevoke(w, r, controlWire)
}

func (c *ConsoleAPI) handleControlMCPClientProfileBinding(w http.ResponseWriter, r *http.Request) {
	c.serveMCPClientProfileBinding(w, r, controlWire)
}

// controlActivationSnapshotDTO is the metadata-only projection of a client's
// activation bundle: the digest plus the selected immutable tuples, without
// instruction bodies. A control plane compares digests; it never needs the
// instructions, which stay on the signed runtime fetch.
type controlActivationSnapshotDTO struct {
	ContractVersion string                              `json:"contractVersion"`
	BundleDigest    string                              `json:"bundleDigest"`
	Skills          []controlActivationSnapshotSkillDTO `json:"skills"`
}

type controlActivationSnapshotSkillDTO struct {
	SkillID       string `json:"skillId"`
	SkillSlug     string `json:"skillSlug"`
	VersionID     string `json:"versionId"`
	Version       int    `json:"version"`
	ContentDigest string `json:"contentDigest"`
	BindingID     string `json:"bindingId"`
}

func newControlActivationSnapshotDTO(bundle LibrarySkillActivationBundle) controlActivationSnapshotDTO {
	dto := controlActivationSnapshotDTO{
		ContractVersion: bundle.ContractVersion,
		BundleDigest:    bundle.BundleDigest,
		Skills:          make([]controlActivationSnapshotSkillDTO, 0, len(bundle.Skills)),
	}
	for _, skill := range bundle.Skills {
		dto.Skills = append(dto.Skills, controlActivationSnapshotSkillDTO{
			SkillID: skill.SkillID, SkillSlug: skill.SkillSlug, VersionID: skill.VersionID, Version: skill.Version,
			ContentDigest: skill.ContentDigest, BindingID: skill.Binding.ID,
		})
	}
	return dto
}

func activationSnapshotFailure(err error) *consoleFailure {
	switch {
	case errors.Is(err, ErrLibrarySkillActivationLimit):
		return newConsoleFailure(http.StatusUnprocessableEntity, controlCodeValidationFailed, "activation bundle exceeds the engine safety limit")
	default:
		return newConsoleFailure(http.StatusBadGateway, controlCodeEngineUnavailable, "activation bundle is unavailable")
	}
}

func (c *ConsoleAPI) handleControlMCPClientActivationSnapshot(w http.ResponseWriter, r *http.Request) {
	store, actor, failure := c.mcpClientAdministration(r)
	if failure != nil {
		controlWire.writeFailure(w, failure)
		return
	}
	client, failure := c.managedMCPClient(r, store, actor)
	if failure != nil {
		controlWire.writeFailure(w, failure)
		return
	}
	if r.Method != http.MethodGet {
		controlWire.writeMethodNotAllowed(w, http.MethodGet)
		return
	}
	if c.libraryStore == nil {
		controlWire.writeFailure(w, newConsoleFailure(http.StatusNotImplemented, controlCodeCapabilityUnavailable, "library activation is not supported by this store"))
		return
	}
	bundle, err := BuildLibrarySkillActivationBundleForAgentSurface(r.Context(), c.libraryStore, client.ID)
	if err != nil {
		controlWire.writeFailure(w, activationSnapshotFailure(err))
		return
	}
	writeJSON(w, http.StatusOK, newControlActivationSnapshotDTO(bundle))
}

// controlRunCorrelationDTO is the sanitized feed record. It carries the
// observation tuple and digest only; nonce and request hashes stay internal.
type controlRunCorrelationDTO struct {
	CorrelationID     string `json:"correlationId"`
	ClientID          string `json:"clientId"`
	ClientEpoch       string `json:"clientEpoch"`
	RunID             string `json:"runId"`
	GatewayRequestID  string `json:"gatewayRequestId"`
	BundleDigest      string `json:"bundleDigest"`
	ExecutionAttested bool   `json:"executionAttested"`
	CreatedAt         string `json:"createdAt"`
}

func newControlRunCorrelationDTO(record LibraryRunCorrelation) controlRunCorrelationDTO {
	return controlRunCorrelationDTO{
		CorrelationID:     record.ID,
		ClientID:          record.ClientID,
		ClientEpoch:       record.ClientEpoch,
		RunID:             record.RunID,
		GatewayRequestID:  record.GatewayRequestID,
		BundleDigest:      record.BundleDigest,
		ExecutionAttested: record.ExecutionHash != "",
		CreatedAt:         record.CreatedAt.UTC().Format(time.RFC3339Nano),
	}
}

// Cursors travel in headers, never query strings, because a signed actor
// assertion binds a bare path. The token is opaque to callers: the keyset
// timestamp in nanoseconds plus the record ID, base64url encoded. Every v1
// keyset feed shares this encoding; each decoder validates the ID for its own
// record kind.
func encodeControlKeysetCursor(at time.Time, id string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.FormatInt(at.UTC().UnixNano(), 10) + ":" + id))
}

func decodeControlKeysetCursor(raw string) (time.Time, string, error) {
	invalid := errors.New("invalid cursor")
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != raw {
		return time.Time{}, "", invalid
	}
	nanos, id, ok := strings.Cut(string(decoded), ":")
	if !ok || id == "" {
		return time.Time{}, "", invalid
	}
	unixNanos, err := strconv.ParseInt(nanos, 10, 64)
	if err != nil || strconv.FormatInt(unixNanos, 10) != nanos {
		return time.Time{}, "", invalid
	}
	return time.Unix(0, unixNanos).UTC(), id, nil
}

func encodeControlRunCorrelationCursor(cursor LibraryRunCorrelationCursor) string {
	return encodeControlKeysetCursor(cursor.CreatedAt, cursor.ID)
}

func decodeControlRunCorrelationCursor(raw string) (LibraryRunCorrelationCursor, error) {
	createdAt, id, err := decodeControlKeysetCursor(raw)
	if err != nil {
		return LibraryRunCorrelationCursor{}, err
	}
	if validateLibraryOpaqueRef("correlation", id, false) != nil {
		return LibraryRunCorrelationCursor{}, errors.New("invalid cursor")
	}
	return LibraryRunCorrelationCursor{CreatedAt: createdAt, ID: id}, nil
}

func (c *ConsoleAPI) handleControlRunCorrelations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		controlWire.writeMethodNotAllowed(w, http.MethodGet)
		return
	}
	actor, ok := c.connectionNamespaceActor(r)
	if !ok {
		controlWire.writeFailure(w, newConsoleFailure(http.StatusForbidden, controlCodeForbidden, "connection namespace access is not permitted"))
		return
	}
	if !mcpClientRegistryAdministrator(actor) {
		controlWire.writeFailure(w, newConsoleFailure(http.StatusForbidden, controlCodeForbidden, "run correlations require a workspace owner, admin, or the Platform service"))
		return
	}
	store, ok := c.store.(LibraryRunCorrelationStore)
	if !ok {
		controlWire.writeFailure(w, newConsoleFailure(http.StatusNotImplemented, controlCodeCapabilityUnavailable, "run correlations are not supported by this store"))
		return
	}
	var cursor LibraryRunCorrelationCursor
	if raw := r.Header.Get(controlCursorHeader); raw != "" {
		var err error
		if cursor, err = decodeControlRunCorrelationCursor(raw); err != nil {
			controlWire.writeFailure(w, newConsoleFailure(http.StatusBadRequest, controlCodeValidationFailed, "invalid "+controlCursorHeader))
			return
		}
	}
	records, err := store.LibraryRunCorrelations(r.Context(), cursor, controlRunCorrelationPageLimit+1)
	if err != nil {
		controlWire.writeFailure(w, newConsoleFailure(http.StatusBadGateway, controlCodeEngineUnavailable, "run correlations are unavailable"))
		return
	}
	if len(records) > controlRunCorrelationPageLimit {
		records = records[:controlRunCorrelationPageLimit]
		last := records[len(records)-1]
		w.Header().Set(controlCursorHeader, encodeControlRunCorrelationCursor(LibraryRunCorrelationCursor{CreatedAt: last.CreatedAt, ID: last.ID}))
	}
	out := make([]controlRunCorrelationDTO, 0, len(records))
	for _, record := range records {
		out = append(out, newControlRunCorrelationDTO(record))
	}
	writeJSON(w, http.StatusOK, out)
}

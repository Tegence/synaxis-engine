package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

// The authoring window is intentionally fixed server policy. Neither a
// Console request nor an MCP tool may lengthen it or increase its quota.
const (
	libraryMCPClientSkillAuthoringLeaseDuration   = 10 * time.Minute
	libraryMCPClientSkillAuthoringLeaseMaxCreates = 3
	// Staged bundle-file uploads have their own bounded budget so a multi-file
	// bundle cannot starve the three create/update writes. Each upload is at
	// most 4 MiB, so a lease can stage at most 128 MiB of file bytes.
	libraryMCPClientSkillAuthoringLeaseMaxUploads = 32
	libraryMCPClientSkillAuthoringRequestIDMax    = 256
)

const (
	// Generic is the original authoring-window behaviour: the client can
	// create skills and revise only the exact automatically-bound skills it
	// created. Adoption is deliberately narrower: it has one target skill and
	// cannot create arbitrary skills.
	LibraryMCPClientSkillAuthoringLeaseKindGeneric  = "generic"
	LibraryMCPClientSkillAuthoringLeaseKindAdoption = "adoption"
)

const (
	LibraryMCPClientSkillAuthoringLeaseStatusActive    = "active"
	LibraryMCPClientSkillAuthoringLeaseStatusExpired   = "expired"
	LibraryMCPClientSkillAuthoringLeaseStatusExhausted = "exhausted"
	LibraryMCPClientSkillAuthoringLeaseStatusRevoked   = "revoked"
	LibraryMCPClientSkillAuthoringLeaseStatusInvalid   = "invalid"
)

const (
	LibraryMCPClientSkillAuthoringAuditActionGranted  = "granted"
	LibraryMCPClientSkillAuthoringAuditActionRevoked  = "revoked"
	LibraryMCPClientSkillAuthoringAuditActionConsumed = "consumed"
	LibraryMCPClientSkillAuthoringAuditActionRejected = "rejected"

	LibraryMCPClientSkillAuthoringAuditOperationGrant  = "grant"
	LibraryMCPClientSkillAuthoringAuditOperationRevoke = "revoke"
	LibraryMCPClientSkillAuthoringAuditOperationCreate = "create"
	LibraryMCPClientSkillAuthoringAuditOperationUpdate = "update"
	LibraryMCPClientSkillAuthoringAuditOperationAdopt  = "adopt"
	// Upload is a staged bundle-file write under the same lease budget as a
	// create or update. It records no path, content, or blob ID in audit.
	LibraryMCPClientSkillAuthoringAuditOperationUpload = "upload"
)

var (
	ErrLibraryMCPClientSkillAuthoringLeaseNotFound = errors.New("library MCP client skill authoring lease not found")
	ErrLibraryMCPClientSkillAuthoringLeaseActive   = errors.New("library MCP client skill authoring lease is still active")
	// ErrLibraryMCPClientSkillAuthoringUnavailable is deliberately neutral for
	// MCP callers. It covers an absent, expired, revoked, exhausted, or stale
	// epoch lease and never reveals which condition applied.
	ErrLibraryMCPClientSkillAuthoringUnavailable       = errors.New("library MCP client skill authoring is unavailable")
	ErrLibraryMCPClientSkillAuthoringRequestConflict   = errors.New("library MCP client skill authoring request conflicts with an existing request")
	ErrLibraryMCPClientSkillAuthoringClientUnavailable = errors.New("MCP client is not active and OAuth-bound")
	// Adoption errors are Console-only feedback. MCP callers receive the
	// neutral unavailable error if a lease cannot be used.
	ErrLibraryMCPClientSkillAuthoringAdoptionTargetBound  = errors.New("selected MCP client already has an incompatible skill binding")
	ErrLibraryMCPClientSkillAuthoringAdoptionHeadConflict = errors.New("skill changed before temporary revision delegation could be granted")
)

// LibraryMCPClientSkillAuthoringLease is a server-side, client-and-epoch
// scoped exception to ordinary owner/admin-only skill authoring. It is not a
// bearer token, connection credential, binding, capability grant, or proof of
// one live Claude/Codex transport session.
//
// GrantedBy and RevokedBy are opaque private actor references. PgStore encrypts
// them at rest; client ID and epoch remain structural lookup keys so a stale
// endpoint can be rejected without decrypting an unrelated actor record.
type LibraryMCPClientSkillAuthoringLease struct {
	ID             string `json:"id"`
	MCPClientID    string `json:"mcpClientId"`
	MCPClientEpoch string `json:"mcpClientEpoch"`
	// Kind defaults to generic for records written before adoption support.
	// It is policy metadata, not an MCP-supplied claim.
	Kind      string    `json:"kind"`
	GrantedBy string    `json:"grantedBy,omitempty"`
	GrantedAt time.Time `json:"grantedAt"`
	ExpiresAt time.Time `json:"expiresAt"`
	// RemainingCreates is retained as the public wire name for compatibility.
	// It is the number of bounded authoring writes left in this lease: an
	// initial create or a permitted immutable-version update each consumes one.
	RemainingCreates int `json:"remainingCreates"`
	// RemainingUploads is the separate bounded budget for staged bundle-file
	// uploads (library_skill_upload_blob). Uploads never consume a create.
	RemainingUploads int        `json:"remainingUploads"`
	RevokedAt        *time.Time `json:"revokedAt,omitempty"`
	RevokedBy        string     `json:"revokedBy,omitempty"`
	CreatedAt        time.Time  `json:"createdAt"`
	UpdatedAt        time.Time  `json:"updatedAt"`
	// Adoption targets are populated only for Kind=adoption. The binding
	// survives lease expiry so it remains a normal delivery selection, while
	// this exact structural fingerprint gates the temporary write authority.
	TargetSkillID       string `json:"targetSkillId,omitempty"`
	TargetVersionID     string `json:"targetVersionId,omitempty"`
	TargetVersionDigest string `json:"targetVersionDigest,omitempty"`
	TargetBindingID     string `json:"targetBindingId,omitempty"`
	TargetBindingDigest string `json:"targetBindingDigest,omitempty"`
	// TargetBindingGeneration is a monotonic per-skill binding-set marker. It
	// closes the add/remove restoration gap that an exact binding fingerprint
	// alone cannot detect.
	TargetBindingGeneration int64 `json:"targetBindingGeneration,omitempty"`
	// Status is calculated from the Engine clock and current MCP client at
	// read time. It is never the source of authorization.
	Status string `json:"status"`
}

// LibraryMCPClientSkillAuthoringRequest is the caller-controlled part of one
// initial skill creation. CreatedBy is never accepted here: the store derives
// it from the durable subject bound to the live MCP client.
type LibraryMCPClientSkillAuthoringRequest struct {
	RequestID             string   `json:"requestId"`
	Name                  string   `json:"name"`
	Slug                  string   `json:"slug,omitempty"`
	Description           string   `json:"description,omitempty"`
	Content               string   `json:"content"`
	RequestedCapabilities []string `json:"requestedCapabilities,omitempty"`
	// Files makes the version a bundle. Content stays the SKILL.md shorthand;
	// a SKILL.md file entry is accepted when it does not contradict Content.
	Files []LibrarySkillFileInput `json:"files,omitempty"`
	// bundle is populated by normalization and consumed by the store under
	// its lock. It is never serialized.
	bundle librarySkillAuthoringBundleInput
}

// librarySkillAuthoringBundleInput is the decoded bundle half of a leased
// write: inline files with bytes, staged references the store resolves, and
// whether the caller authored a bundle (which makes SKILL.md front matter
// mandatory).
type librarySkillAuthoringBundleInput struct {
	inline   []LibrarySkillFileContent
	refs     []librarySkillBlobRef
	authored bool
}

// LibraryMCPClientSkillBlobUploadRequest stages one bundle file under the
// active lease. Path decides the media type; the bytes are verified against
// it. CreatedBy, lease, and expiry are derived by the store.
type LibraryMCPClientSkillBlobUploadRequest struct {
	RequestID  string `json:"requestId"`
	Path       string `json:"path"`
	DataBase64 string `json:"dataBase64"`
}

// LibraryMCPClientSkillBlobUploadResult returns the opaque staging receipt a
// later create or update may reference as blobId, plus the digest a host can
// verify. It carries no bytes and no storage locator.
type LibraryMCPClientSkillBlobUploadResult struct {
	BlobID      string                              `json:"blobId"`
	Digest      string                              `json:"digest"`
	ContentType string                              `json:"contentType"`
	SizeBytes   int64                               `json:"sizeBytes"`
	ExpiresAt   time.Time                           `json:"expiresAt"`
	Lease       LibraryMCPClientSkillAuthoringLease `json:"lease"`
	Replayed    bool                                `json:"replayed"`
}

// LibraryMCPClientSkillBlobStore is the separate narrow facet for staged
// bundle uploads. It is deliberately not part of the authoring facet so an
// implementation without blob storage keeps its existing single-document
// authoring behaviour.
type LibraryMCPClientSkillBlobStore interface {
	StageLibraryMCPClientSkillBlob(context.Context, MCPClient, LibraryMCPClientSkillBlobUploadRequest) (LibraryMCPClientSkillBlobUploadResult, error)
}

// LibraryMCPClientSkillAuthoringUpdateRequest is the caller-controlled part
// of one immutable version append. It deliberately accepts neither skill
// metadata nor bindings, grants, publication state, creator identity, client
// identity, or a lease ID. The expected version pair is a compare-and-swap
// fence: a client cannot accidentally replace an owner/admin's newer version.
type LibraryMCPClientSkillAuthoringUpdateRequest struct {
	RequestID             string                  `json:"requestId"`
	SkillID               string                  `json:"skillId"`
	ExpectedVersionID     string                  `json:"expectedVersionId"`
	ExpectedVersionDigest string                  `json:"expectedVersionDigest"`
	Content               string                  `json:"content"`
	RequestedCapabilities []string                `json:"requestedCapabilities,omitempty"`
	Files                 []LibrarySkillFileInput `json:"files,omitempty"`
	bundle                librarySkillAuthoringBundleInput
}

// LibraryMCPClientSkillAuthoringAdoptionRequest is accepted only from the
// owner/admin Console route. It carries the client revision and exact current
// immutable head needed to atomically create (or adopt) a client-surface
// track binding. It has no request ID because it is not an MCP write and
// cannot be replayed to consume a client lease slot.
type LibraryMCPClientSkillAuthoringAdoptionRequest struct {
	SkillID               string `json:"skillId"`
	ExpectedVersionID     string `json:"expectedVersionId"`
	ExpectedVersionDigest string `json:"expectedVersionDigest"`
}

// LibraryMCPClientSkillAuthoringResult returns only the newly created
// immutable skill/version, the automatic client-surface binding identity, and
// dynamic lease state. BindingID is the durable receipt of the automatic
// binding made by a leased create (and carried by later version results). It
// is an opaque applicability reference, never a credential, tool grant, OAuth
// scope, or effective authority. Replayed means the store recognized the same
// request ID and canonical payload; it never consumes an additional quota
// slot.
type LibraryMCPClientSkillAuthoringResult struct {
	Skill     LibrarySkill                        `json:"skill"`
	Version   LibrarySkillVersion                 `json:"version"`
	BindingID string                              `json:"bindingId,omitempty"`
	Lease     LibraryMCPClientSkillAuthoringLease `json:"lease"`
	Replayed  bool                                `json:"replayed"`
}

// LibraryMCPClientSkillAuthoringSkill is the deliberately metadata-only
// discovery projection used by a leased client to obtain the exact current
// version pair required for a later update. It never contains instructions,
// bindings, grants, or any other client's skills.
type LibraryMCPClientSkillAuthoringSkill struct {
	SkillID             string `json:"skillId"`
	Slug                string `json:"slug"`
	Name                string `json:"name"`
	Description         string `json:"description,omitempty"`
	LatestVersionID     string `json:"latestVersionId"`
	LatestVersion       int    `json:"latestVersion"`
	LatestVersionDigest string `json:"latestVersionDigest"`
	// LatestManifestDigest is the current bundle manifest digest, returned
	// beside the SKILL.md digest so a bundle update can fence on both.
	LatestManifestDigest string    `json:"latestManifestDigest"`
	UpdatedAt            time.Time `json:"updatedAt"`
}

// LibraryMCPClientSkillAuthoringAuditEvent is a durable, append-only record
// of a lease state transition or a rejected authoring attempt. It contains no
// raw MCP request ID, instructions, or other request body: idempotency fields
// are one-way scoped hashes. ActorRef is an opaque private reference and is
// encrypted by PgStore.
type LibraryMCPClientSkillAuthoringAuditEvent struct {
	ID             string    `json:"id"`
	LeaseID        string    `json:"leaseId,omitempty"`
	MCPClientID    string    `json:"mcpClientId"`
	MCPClientEpoch string    `json:"mcpClientEpoch"`
	Action         string    `json:"action"`
	Operation      string    `json:"operation"`
	ActorRef       string    `json:"actorRef,omitempty"`
	RequestIDHash  string    `json:"requestIdHash,omitempty"`
	PayloadDigest  string    `json:"payloadDigest,omitempty"`
	SkillID        string    `json:"skillId,omitempty"`
	VersionID      string    `json:"versionId,omitempty"`
	CreatedAt      time.Time `json:"createdAt"`
}

// LibraryMCPClientSkillAuthoringStore is intentionally a separate narrow
// facet. General LibraryStore users cannot acquire a leased-client skill
// write merely by holding ordinary artifact or skill access.
type LibraryMCPClientSkillAuthoringStore interface {
	MCPClientSkillAuthoringLease(context.Context, string) (LibraryMCPClientSkillAuthoringLease, bool, error)
	GrantMCPClientSkillAuthoringLease(context.Context, string, MCPClientPrecondition, string) (LibraryMCPClientSkillAuthoringLease, error)
	GrantMCPClientSkillAuthoringAdoptionLease(context.Context, string, MCPClientPrecondition, LibraryMCPClientSkillAuthoringAdoptionRequest, string) (LibraryMCPClientSkillAuthoringLease, error)
	RevokeMCPClientSkillAuthoringLease(context.Context, string, string, MCPClientPrecondition, string) (LibraryMCPClientSkillAuthoringLease, error)
	CreateLibraryMCPClientSkillWithAuthoringLease(context.Context, MCPClient, LibraryMCPClientSkillAuthoringRequest) (LibraryMCPClientSkillAuthoringResult, error)
	UpdateLibraryMCPClientSkillWithAuthoringLease(context.Context, MCPClient, LibraryMCPClientSkillAuthoringUpdateRequest) (LibraryMCPClientSkillAuthoringResult, error)
	ListLibraryMCPClientAuthoredSkillsWithAuthoringLease(context.Context, MCPClient) ([]LibraryMCPClientSkillAuthoringSkill, LibraryMCPClientSkillAuthoringLease, error)
}

// LibraryMCPClientSkillAuthoringAuditStore is read-only and intentionally
// separate from the lease write facet. It exists for internal verification and
// future owner/admin audit projections; MCP clients never receive it.
type LibraryMCPClientSkillAuthoringAuditStore interface {
	MCPClientSkillAuthoringLeaseAuditEvents(context.Context, string) ([]LibraryMCPClientSkillAuthoringAuditEvent, error)
}

type libraryMCPClientSkillAuthoringRequestRecord struct {
	MCPClientID    string `json:"mcpClientId"`
	MCPClientEpoch string `json:"mcpClientEpoch"`
	LeaseID        string `json:"leaseId"`
	RequestIDHash  string `json:"requestIdHash"`
	PayloadDigest  string `json:"payloadDigest"`
	SkillID        string `json:"skillId"`
	VersionID      string `json:"versionId"`
	// BindingID is populated by an initial leased create and copied into an
	// authored immutable-version append. It lets future update/list checks
	// distinguish the exact auto-created client binding from a later
	// owner/admin binding that happens to target the same scope.
	BindingID string `json:"bindingId,omitempty"`
	// BindingDigest and BindingGeneration together make the automatic-binding
	// receipt non-revivable. The digest checks the exact structural binding;
	// the monotonic per-skill generation also detects an owner/admin adding and
	// then removing a separate binding before the short authoring window ends.
	// New records must contain all three fields. BindingID is empty only for
	// legacy no-binding records, which remain compatible only while unbound.
	BindingDigest     string    `json:"bindingDigest,omitempty"`
	BindingGeneration int64     `json:"bindingGeneration,omitempty"`
	CreatedAt         time.Time `json:"createdAt"`
}

// newLibraryMCPClientSkillAuthoringBinding derives the one automatic
// applicability binding created with a leased skill. Its track mode means a
// later allowed immutable version append is visible only to this exact durable
// MCP client. The ceiling is the initial requested-capability intent, which
// can narrow future versions but can never grant authority by itself.
func newLibraryMCPClientSkillAuthoringBinding(client MCPClient, skill LibrarySkill, initialCapabilities []string, now time.Time) (LibrarySkillBinding, error) {
	binding, err := normalizedLibraryBinding(LibrarySkillBinding{
		ID:                newLibrarySkillBindingID(),
		SkillID:           skill.ID,
		ScopeKind:         LibraryScopeAgentSurface,
		ScopeID:           client.ID,
		Mode:              LibraryBindingModeTrack,
		CapabilityCeiling: append([]string(nil), initialCapabilities...),
		Priority:          0,
		CreatedBy:         client.Subject,
		CreatedAt:         now,
	})
	if err != nil {
		return LibrarySkillBinding{}, err
	}
	return binding, nil
}

// libraryMCPClientSkillAuthoringBindingDigest is stable across FileStore and
// PostgreSQL timestamp precision while covering every structural field an
// authoring receipt can rely on. Lifecycle changes are additionally guarded
// by BindingGeneration, rather than by timestamps that can be rounded by a
// database driver.
func libraryMCPClientSkillAuthoringBindingDigest(binding LibrarySkillBinding) (string, error) {
	capabilities, err := normalizeLibraryCapabilities(binding.CapabilityCeiling)
	if err != nil {
		return "", err
	}
	canonical, err := json.Marshal(struct {
		ID                string   `json:"id"`
		SkillID           string   `json:"skillId"`
		ScopeKind         string   `json:"scopeKind"`
		ScopeID           string   `json:"scopeId"`
		Mode              string   `json:"mode"`
		PinnedVersionID   string   `json:"pinnedVersionId"`
		CapabilityCeiling []string `json:"capabilityCeiling"`
		Priority          int      `json:"priority"`
		CreatedBy         string   `json:"createdBy"`
	}{
		ID: binding.ID, SkillID: binding.SkillID, ScopeKind: binding.ScopeKind,
		ScopeID: binding.ScopeID, Mode: binding.Mode, PinnedVersionID: binding.PinnedVersionID,
		CapabilityCeiling: capabilities, Priority: binding.Priority, CreatedBy: binding.CreatedBy,
	})
	if err != nil {
		return "", fmt.Errorf("encode MCP client skill authoring binding: %w", err)
	}
	return libraryDigest(string(canonical)), nil
}

// libraryMCPClientSkillAuthoringBindingEligible accepts only a legacy
// no-binding skill or the exact automatic binding recorded by the initial
// leased create. A separately added binding, a deleted/recreated replacement,
// a reversible edit, or a pinned self-binding transfers version management
// back to the owner/admin surface for the remainder of that window.
func libraryMCPClientSkillAuthoringBindingEligible(clientID, bindingID, bindingDigest string, bindingGeneration, currentGeneration int64, bindings []LibrarySkillBinding) bool {
	if bindingID == "" {
		// Legacy no-binding receipts are compatible only if the skill has never
		// entered the binding-generation lifecycle. Otherwise an owner/admin
		// could add and remove a binding, restore the empty set, and revive the
		// temporary client write window.
		return bindingDigest == "" && bindingGeneration == 0 && currentGeneration == 0 && len(bindings) == 0
	}
	if bindingDigest == "" || bindingGeneration <= 0 || currentGeneration != bindingGeneration {
		return false
	}
	if len(bindings) != 1 {
		return false
	}
	binding := bindings[0]
	if binding.ID != bindingID {
		return false
	}
	if binding.ScopeKind != LibraryScopeAgentSurface || binding.ScopeID != clientID || binding.Mode != LibraryBindingModeTrack || binding.PinnedVersionID != "" {
		return false
	}
	digest, err := libraryMCPClientSkillAuthoringBindingDigest(binding)
	return err == nil && digest == bindingDigest
}

func libraryMCPClientSkillAuthoringLeaseKind(lease LibraryMCPClientSkillAuthoringLease) string {
	// Existing durable records predate explicit lease kinds. Treat their zero
	// value as the original generic mode rather than silently invalidating a
	// live but otherwise valid authoring window during a rolling upgrade.
	if lease.Kind == "" {
		return LibraryMCPClientSkillAuthoringLeaseKindGeneric
	}
	return lease.Kind
}

func libraryMCPClientSkillAuthoringAdoptionLeaseWellFormed(lease LibraryMCPClientSkillAuthoringLease) bool {
	return lease.TargetSkillID != "" && lease.TargetVersionID != "" &&
		lease.TargetVersionDigest != "" && lease.TargetBindingID != "" &&
		lease.TargetBindingDigest != "" && lease.TargetBindingGeneration > 0
}

func libraryMCPClientSkillAuthoringBindingIsExactAdoptionTrack(binding LibrarySkillBinding, skillID, clientID string) bool {
	return binding.ID != "" && binding.SkillID == skillID &&
		binding.ScopeKind == LibraryScopeAgentSurface && binding.ScopeID == clientID &&
		binding.Mode == LibraryBindingModeTrack && binding.PinnedVersionID == ""
}

// libraryMCPClientSkillAuthoringAdoptionCapabilitiesAllowed makes adoption a
// monotonic delegation. A temporary MCP client may preserve or narrow the
// target head's requested capability intent, but it cannot broaden it. This
// applies even when reusing an existing unrestricted delivery binding: the
// write lease, not that binding, is the authority boundary.
func libraryMCPClientSkillAuthoringAdoptionCapabilitiesAllowed(current, requested []string) bool {
	allowed := make(map[string]struct{}, len(current))
	for _, capability := range current {
		allowed[capability] = struct{}{}
	}
	for _, capability := range requested {
		if _, ok := allowed[capability]; !ok {
			return false
		}
	}
	return true
}

func newLibraryMCPClientSkillAuthoringLeaseID() string      { return "libmcpal_" + newEpoch() }
func newLibraryMCPClientSkillAuthoringAuditEventID() string { return "libmcpale_" + newEpoch() }
func newLibrarySkillBlobStagingID() string                  { return "libblob_" + newEpoch() }

func copyLibraryMCPClientSkillAuthoringLease(lease LibraryMCPClientSkillAuthoringLease) LibraryMCPClientSkillAuthoringLease {
	copy := lease
	if lease.RevokedAt != nil {
		revokedAt := *lease.RevokedAt
		copy.RevokedAt = &revokedAt
	}
	return copy
}

func copyLibraryMCPClientSkillAuthoringAuditEvent(event LibraryMCPClientSkillAuthoringAuditEvent) LibraryMCPClientSkillAuthoringAuditEvent {
	return event
}

func copyLibraryMCPClientSkillAuthoringAuditEvents(in []*LibraryMCPClientSkillAuthoringAuditEvent) []*LibraryMCPClientSkillAuthoringAuditEvent {
	out := make([]*LibraryMCPClientSkillAuthoringAuditEvent, len(in))
	for i, event := range in {
		if event == nil {
			continue
		}
		copy := copyLibraryMCPClientSkillAuthoringAuditEvent(*event)
		out[i] = &copy
	}
	return out
}

func copyLibraryMCPClientSkillAuthoringLeases(in []*LibraryMCPClientSkillAuthoringLease) []*LibraryMCPClientSkillAuthoringLease {
	out := make([]*LibraryMCPClientSkillAuthoringLease, len(in))
	for i, lease := range in {
		if lease == nil {
			continue
		}
		copy := copyLibraryMCPClientSkillAuthoringLease(*lease)
		out[i] = &copy
	}
	return out
}

func copyLibraryMCPClientSkillAuthoringRequestRecords(in []*libraryMCPClientSkillAuthoringRequestRecord) []*libraryMCPClientSkillAuthoringRequestRecord {
	out := make([]*libraryMCPClientSkillAuthoringRequestRecord, len(in))
	for i, record := range in {
		if record == nil {
			continue
		}
		copy := *record
		out[i] = &copy
	}
	return out
}

func libraryMCPClientSkillAuthoringLeaseStatus(lease LibraryMCPClientSkillAuthoringLease, client MCPClient, clientFound bool, now time.Time) string {
	switch libraryMCPClientSkillAuthoringLeaseKind(lease) {
	case LibraryMCPClientSkillAuthoringLeaseKindGeneric:
	case LibraryMCPClientSkillAuthoringLeaseKindAdoption:
		if !libraryMCPClientSkillAuthoringAdoptionLeaseWellFormed(lease) {
			return LibraryMCPClientSkillAuthoringLeaseStatusInvalid
		}
	default:
		return LibraryMCPClientSkillAuthoringLeaseStatusInvalid
	}
	if lease.RevokedAt != nil {
		return LibraryMCPClientSkillAuthoringLeaseStatusRevoked
	}
	if !clientFound || client.Status != MCPClientStatusActive || client.OAuthClientID == "" || client.Epoch == "" || client.Epoch != lease.MCPClientEpoch {
		return LibraryMCPClientSkillAuthoringLeaseStatusInvalid
	}
	if lease.ExpiresAt.IsZero() || !now.Before(lease.ExpiresAt) {
		return LibraryMCPClientSkillAuthoringLeaseStatusExpired
	}
	if lease.RemainingCreates <= 0 {
		return LibraryMCPClientSkillAuthoringLeaseStatusExhausted
	}
	return LibraryMCPClientSkillAuthoringLeaseStatusActive
}

func libraryMCPClientSkillAuthoringRequestIDHash(clientID, epoch, requestID string) string {
	return libraryDigest("library-mcp-client-skill-authoring:v1\x00" + clientID + "\x00" + epoch + "\x00" + requestID)
}

// Updates use a separate idempotency namespace from creates. This preserves
// replay compatibility for pre-update create receipts while making it safe for
// an agent to use the same opaque request ID for one create and one update.
func libraryMCPClientSkillAuthoringUpdateRequestIDHash(clientID, epoch, requestID string) string {
	return libraryDigest("library-mcp-client-skill-authoring:update:v1\x00" + clientID + "\x00" + epoch + "\x00" + requestID)
}

// Blob uploads use their own idempotency namespace for the same reason.
func libraryMCPClientSkillAuthoringUploadRequestIDHash(clientID, epoch, requestID string) string {
	return libraryDigest("library-mcp-client-skill-authoring:upload:v1\x00" + clientID + "\x00" + epoch + "\x00" + requestID)
}

// normalizeLibrarySkillAuthoringFiles decodes the bundle half of a leased
// request. SKILL.md may only arrive inline (as content or a text entry) and is
// folded into content so the existing single-document validation applies;
// every other entry is kept for the store to normalize under its lock.
func normalizeLibrarySkillAuthoringFiles(content string, inputs []LibrarySkillFileInput) (string, librarySkillAuthoringBundleInput, error) {
	if len(inputs) == 0 {
		return content, librarySkillAuthoringBundleInput{}, nil
	}
	inline, refs, err := decodeLibrarySkillFileInputs(inputs)
	if err != nil {
		return "", librarySkillAuthoringBundleInput{}, err
	}
	for _, ref := range refs {
		if librarySkillPathKey(ref.Path) == librarySkillPathKey(LibrarySkillInstructionsPath) {
			return "", librarySkillAuthoringBundleInput{}, fmt.Errorf("%w: SKILL.md must be supplied inline", ErrLibrarySkillBundleInvalid)
		}
	}
	kept := make([]LibrarySkillFileContent, 0, len(inline))
	for _, file := range inline {
		if librarySkillPathKey(file.Path) != librarySkillPathKey(LibrarySkillInstructionsPath) {
			kept = append(kept, file)
			continue
		}
		if file.Path != LibrarySkillInstructionsPath {
			return "", librarySkillAuthoringBundleInput{}, fmt.Errorf("%w: the instructions file must be named exactly SKILL.md", ErrLibrarySkillBundleInvalid)
		}
		if !utf8.Valid(file.Data) {
			return "", librarySkillAuthoringBundleInput{}, fmt.Errorf("%w: SKILL.md is not UTF-8 text", ErrLibrarySkillBundleInvalid)
		}
		text := string(file.Data)
		if content != "" && content != text {
			return "", librarySkillAuthoringBundleInput{}, fmt.Errorf("%w: content and the SKILL.md file entry disagree", ErrLibrarySkillBundleInvalid)
		}
		content = text
	}
	return content, librarySkillAuthoringBundleInput{inline: kept, refs: refs, authored: true}, nil
}

// normalizeLibraryMCPClientSkillBlobUploadRequest validates one staged file
// at the tool boundary: a valid request ID, an allowlisted path, and bytes
// that match the derived media type and the per-file cap.
func normalizeLibraryMCPClientSkillBlobUploadRequest(request LibraryMCPClientSkillBlobUploadRequest) (LibraryMCPClientSkillBlobUploadRequest, LibrarySkillFileContent, string, error) {
	if !validLibraryMCPClientSkillAuthoringRequestID(request.RequestID) {
		return LibraryMCPClientSkillBlobUploadRequest{}, LibrarySkillFileContent{}, "", errors.New("a valid request id is required")
	}
	normalized, err := normalizeLibrarySkillPath(strings.TrimSpace(request.Path))
	if err != nil {
		return LibraryMCPClientSkillBlobUploadRequest{}, LibrarySkillFileContent{}, "", err
	}
	if normalized == LibrarySkillInstructionsPath {
		return LibraryMCPClientSkillBlobUploadRequest{}, LibrarySkillFileContent{}, "", fmt.Errorf("%w: SKILL.md must be supplied inline", ErrLibrarySkillBundleInvalid)
	}
	contentType, err := librarySkillContentTypeForPath(normalized)
	if err != nil {
		return LibraryMCPClientSkillBlobUploadRequest{}, LibrarySkillFileContent{}, "", err
	}
	inline, _, err := decodeLibrarySkillFileInputs([]LibrarySkillFileInput{{Path: normalized, Encoding: LibrarySkillFileEncodingBase64, Content: request.DataBase64}})
	if err != nil {
		return LibraryMCPClientSkillBlobUploadRequest{}, LibrarySkillFileContent{}, "", err
	}
	if len(inline) != 1 {
		return LibraryMCPClientSkillBlobUploadRequest{}, LibrarySkillFileContent{}, "", fmt.Errorf("%w: dataBase64 is required", ErrLibrarySkillBundleInvalid)
	}
	file := inline[0]
	file.ContentType = contentType
	if err := validateLibrarySkillFileBytes(normalized, contentType, file.Data); err != nil {
		return LibraryMCPClientSkillBlobUploadRequest{}, LibrarySkillFileContent{}, "", err
	}
	request.Path = normalized
	payloadDigest := libraryDigest("upload\x00" + normalized + "\x00" + contentType + "\x00" + librarySkillFileDigest(file.Data))
	return request, file, payloadDigest, nil
}

// normalizeLibraryMCPClientSkillAuthoringRequest produces the immutable
// payload representation used by storage idempotency. Instruction content is
// intentionally preserved byte-for-byte because it becomes the skill version
// digest; human-facing metadata is trimmed at the boundary.
func normalizeLibraryMCPClientSkillAuthoringRequest(request LibraryMCPClientSkillAuthoringRequest) (LibraryMCPClientSkillAuthoringRequest, string, error) {
	if !validLibraryMCPClientSkillAuthoringRequestID(request.RequestID) {
		return LibraryMCPClientSkillAuthoringRequest{}, "", errors.New("a valid request id is required")
	}
	request.Name = strings.TrimSpace(request.Name)
	request.Slug = strings.ToLower(strings.TrimSpace(request.Slug))
	request.Description = strings.TrimSpace(request.Description)
	content, bundle, err := normalizeLibrarySkillAuthoringFiles(request.Content, request.Files)
	if err != nil {
		return LibraryMCPClientSkillAuthoringRequest{}, "", err
	}
	request.Content = content
	request.bundle = bundle
	if bundle.authored {
		// An imported bundle may carry its identity only in SKILL.md front
		// matter; a caller-supplied name or description still wins.
		applyLibrarySkillFrontMatterDefaults(&request.Name, &request.Description, request.Content)
	}
	if request.Slug == "" {
		request.Slug = librarySlugFromName(request.Name)
	}
	capabilities, err := normalizeLibraryCapabilities(request.RequestedCapabilities)
	if err != nil {
		return LibraryMCPClientSkillAuthoringRequest{}, "", err
	}
	request.RequestedCapabilities = capabilities
	if err := validateLibrarySkill(LibrarySkill{Slug: request.Slug, Name: request.Name, Description: request.Description}); err != nil {
		return LibraryMCPClientSkillAuthoringRequest{}, "", err
	}
	if err := validateLibrarySkillVersion(LibrarySkillVersion{
		SkillID: "pending", Content: request.Content, RequestedCapabilities: request.RequestedCapabilities,
	}); err != nil {
		return LibraryMCPClientSkillAuthoringRequest{}, "", err
	}
	canonical, err := json.Marshal(struct {
		Name                  string   `json:"name"`
		Slug                  string   `json:"slug"`
		Description           string   `json:"description"`
		Content               string   `json:"content"`
		RequestedCapabilities []string `json:"requestedCapabilities"`
		Files                 []string `json:"files,omitempty"`
	}{request.Name, request.Slug, request.Description, request.Content, request.RequestedCapabilities, librarySkillFileInputsPayloadMaterial(bundle.inline, bundle.refs)})
	if err != nil {
		return LibraryMCPClientSkillAuthoringRequest{}, "", fmt.Errorf("encode skill authoring payload: %w", err)
	}
	return request, libraryDigest(string(canonical)), nil
}

// normalizeLibraryMCPClientSkillAuthoringUpdateRequest preserves instruction
// bytes exactly while canonicalizing only capability intent and validating the
// immutable version compare-and-swap fence supplied by the caller.
func normalizeLibraryMCPClientSkillAuthoringUpdateRequest(request LibraryMCPClientSkillAuthoringUpdateRequest) (LibraryMCPClientSkillAuthoringUpdateRequest, string, error) {
	if !validLibraryMCPClientSkillAuthoringRequestID(request.RequestID) {
		return LibraryMCPClientSkillAuthoringUpdateRequest{}, "", errors.New("a valid request id is required")
	}
	request.SkillID = strings.TrimSpace(request.SkillID)
	request.ExpectedVersionID = strings.TrimSpace(request.ExpectedVersionID)
	request.ExpectedVersionDigest = strings.ToLower(strings.TrimSpace(request.ExpectedVersionDigest))
	if err := validateLibraryOpaqueRef("skill", request.SkillID, false); err != nil {
		return LibraryMCPClientSkillAuthoringUpdateRequest{}, "", err
	}
	if err := validateLibraryOpaqueRef("expected skill version", request.ExpectedVersionID, false); err != nil {
		return LibraryMCPClientSkillAuthoringUpdateRequest{}, "", err
	}
	if err := validateLibraryDigest("expected skill version", request.ExpectedVersionDigest, false); err != nil {
		return LibraryMCPClientSkillAuthoringUpdateRequest{}, "", err
	}
	content, bundle, err := normalizeLibrarySkillAuthoringFiles(request.Content, request.Files)
	if err != nil {
		return LibraryMCPClientSkillAuthoringUpdateRequest{}, "", err
	}
	request.Content = content
	request.bundle = bundle
	capabilities, err := normalizeLibraryCapabilities(request.RequestedCapabilities)
	if err != nil {
		return LibraryMCPClientSkillAuthoringUpdateRequest{}, "", err
	}
	request.RequestedCapabilities = capabilities
	if err := validateLibrarySkillVersion(LibrarySkillVersion{
		SkillID: request.SkillID, Content: request.Content, RequestedCapabilities: request.RequestedCapabilities,
	}); err != nil {
		return LibraryMCPClientSkillAuthoringUpdateRequest{}, "", err
	}
	canonical, err := json.Marshal(struct {
		SkillID               string   `json:"skillId"`
		ExpectedVersionID     string   `json:"expectedVersionId"`
		ExpectedVersionDigest string   `json:"expectedVersionDigest"`
		Content               string   `json:"content"`
		RequestedCapabilities []string `json:"requestedCapabilities"`
		Files                 []string `json:"files,omitempty"`
	}{
		SkillID: request.SkillID, ExpectedVersionID: request.ExpectedVersionID,
		ExpectedVersionDigest: request.ExpectedVersionDigest, Content: request.Content,
		RequestedCapabilities: request.RequestedCapabilities,
		Files:                 librarySkillFileInputsPayloadMaterial(bundle.inline, bundle.refs),
	})
	if err != nil {
		return LibraryMCPClientSkillAuthoringUpdateRequest{}, "", fmt.Errorf("encode skill authoring update payload: %w", err)
	}
	return request, libraryDigest(string(canonical)), nil
}

func normalizeLibraryMCPClientSkillAuthoringAdoptionRequest(request LibraryMCPClientSkillAuthoringAdoptionRequest) (LibraryMCPClientSkillAuthoringAdoptionRequest, error) {
	request.SkillID = strings.TrimSpace(request.SkillID)
	request.ExpectedVersionID = strings.TrimSpace(request.ExpectedVersionID)
	request.ExpectedVersionDigest = strings.ToLower(strings.TrimSpace(request.ExpectedVersionDigest))
	if err := validateLibraryOpaqueRef("skill", request.SkillID, false); err != nil {
		return LibraryMCPClientSkillAuthoringAdoptionRequest{}, err
	}
	if err := validateLibraryOpaqueRef("expected skill version", request.ExpectedVersionID, false); err != nil {
		return LibraryMCPClientSkillAuthoringAdoptionRequest{}, err
	}
	if err := validateLibraryDigest("expected skill version", request.ExpectedVersionDigest, false); err != nil {
		return LibraryMCPClientSkillAuthoringAdoptionRequest{}, err
	}
	return request, nil
}

func validLibraryMCPClientSkillAuthoringRequestID(value string) bool {
	if value == "" || len(value) > libraryMCPClientSkillAuthoringRequestIDMax || strings.TrimSpace(value) != value || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character == 0x7f {
			return false
		}
	}
	return true
}

func newLibraryMCPClientSkillAuthoringAuditEvent(
	client MCPClient,
	leaseID, action, operation, actorRef, requestIDHash, payloadDigest, skillID, versionID string,
	now time.Time,
) (LibraryMCPClientSkillAuthoringAuditEvent, error) {
	if err := validateLibraryOpaqueRef("MCP client", client.ID, false); err != nil {
		return LibraryMCPClientSkillAuthoringAuditEvent{}, err
	}
	if client.Epoch == "" {
		return LibraryMCPClientSkillAuthoringAuditEvent{}, errors.New("MCP client epoch is required for authoring audit")
	}
	if err := validateLibraryOpaqueRef("authoring audit actor", actorRef, false); err != nil {
		return LibraryMCPClientSkillAuthoringAuditEvent{}, err
	}
	if leaseID != "" {
		if err := validateLibraryOpaqueRef("authoring audit lease", leaseID, false); err != nil {
			return LibraryMCPClientSkillAuthoringAuditEvent{}, err
		}
	}
	if requestIDHash != "" {
		if err := validateLibraryDigest("authoring audit request", requestIDHash, false); err != nil {
			return LibraryMCPClientSkillAuthoringAuditEvent{}, err
		}
	}
	if payloadDigest != "" {
		if err := validateLibraryDigest("authoring audit payload", payloadDigest, false); err != nil {
			return LibraryMCPClientSkillAuthoringAuditEvent{}, err
		}
	}
	switch action {
	case LibraryMCPClientSkillAuthoringAuditActionGranted,
		LibraryMCPClientSkillAuthoringAuditActionRevoked,
		LibraryMCPClientSkillAuthoringAuditActionConsumed,
		LibraryMCPClientSkillAuthoringAuditActionRejected:
	default:
		return LibraryMCPClientSkillAuthoringAuditEvent{}, errors.New("invalid MCP client authoring audit action")
	}
	switch operation {
	case LibraryMCPClientSkillAuthoringAuditOperationGrant,
		LibraryMCPClientSkillAuthoringAuditOperationRevoke,
		LibraryMCPClientSkillAuthoringAuditOperationCreate,
		LibraryMCPClientSkillAuthoringAuditOperationUpdate,
		LibraryMCPClientSkillAuthoringAuditOperationAdopt,
		LibraryMCPClientSkillAuthoringAuditOperationUpload:
	default:
		return LibraryMCPClientSkillAuthoringAuditEvent{}, errors.New("invalid MCP client authoring audit operation")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	return LibraryMCPClientSkillAuthoringAuditEvent{
		ID: newLibraryMCPClientSkillAuthoringAuditEventID(), LeaseID: leaseID,
		MCPClientID: client.ID, MCPClientEpoch: client.Epoch, Action: action, Operation: operation,
		ActorRef: actorRef, RequestIDHash: requestIDHash, PayloadDigest: payloadDigest,
		SkillID: skillID, VersionID: versionID, CreatedAt: now,
	}, nil
}

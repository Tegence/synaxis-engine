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
	libraryMCPClientSkillAuthoringRequestIDMax    = 256
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
	ID             string    `json:"id"`
	MCPClientID    string    `json:"mcpClientId"`
	MCPClientEpoch string    `json:"mcpClientEpoch"`
	GrantedBy      string    `json:"grantedBy,omitempty"`
	GrantedAt      time.Time `json:"grantedAt"`
	ExpiresAt      time.Time `json:"expiresAt"`
	// RemainingCreates is retained as the public wire name for compatibility.
	// It is the number of bounded authoring writes left in this lease: an
	// initial create or a permitted immutable-version update each consumes one.
	RemainingCreates int        `json:"remainingCreates"`
	RevokedAt        *time.Time `json:"revokedAt,omitempty"`
	RevokedBy        string     `json:"revokedBy,omitempty"`
	CreatedAt        time.Time  `json:"createdAt"`
	UpdatedAt        time.Time  `json:"updatedAt"`
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
}

// LibraryMCPClientSkillAuthoringUpdateRequest is the caller-controlled part
// of one immutable version append. It deliberately accepts neither skill
// metadata nor bindings, grants, publication state, creator identity, client
// identity, or a lease ID. The expected version pair is a compare-and-swap
// fence: a client cannot accidentally replace an owner/admin's newer version.
type LibraryMCPClientSkillAuthoringUpdateRequest struct {
	RequestID             string   `json:"requestId"`
	SkillID               string   `json:"skillId"`
	ExpectedVersionID     string   `json:"expectedVersionId"`
	ExpectedVersionDigest string   `json:"expectedVersionDigest"`
	Content               string   `json:"content"`
	RequestedCapabilities []string `json:"requestedCapabilities,omitempty"`
}

// LibraryMCPClientSkillAuthoringResult returns only the newly created
// immutable skill/version and dynamic lease state. Replayed means the store
// recognized the same request ID and canonical payload; it never consumes an
// additional quota slot.
type LibraryMCPClientSkillAuthoringResult struct {
	Skill    LibrarySkill                        `json:"skill"`
	Version  LibrarySkillVersion                 `json:"version"`
	Lease    LibraryMCPClientSkillAuthoringLease `json:"lease"`
	Replayed bool                                `json:"replayed"`
}

// LibraryMCPClientSkillAuthoringSkill is the deliberately metadata-only
// discovery projection used by a leased client to obtain the exact current
// version pair required for a later update. It never contains instructions,
// bindings, grants, or any other client's skills.
type LibraryMCPClientSkillAuthoringSkill struct {
	SkillID             string    `json:"skillId"`
	Slug                string    `json:"slug"`
	Name                string    `json:"name"`
	Description         string    `json:"description,omitempty"`
	LatestVersionID     string    `json:"latestVersionId"`
	LatestVersion       int       `json:"latestVersion"`
	LatestVersionDigest string    `json:"latestVersionDigest"`
	UpdatedAt           time.Time `json:"updatedAt"`
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
	MCPClientID    string    `json:"mcpClientId"`
	MCPClientEpoch string    `json:"mcpClientEpoch"`
	LeaseID        string    `json:"leaseId"`
	RequestIDHash  string    `json:"requestIdHash"`
	PayloadDigest  string    `json:"payloadDigest"`
	SkillID        string    `json:"skillId"`
	VersionID      string    `json:"versionId"`
	CreatedAt      time.Time `json:"createdAt"`
}

func newLibraryMCPClientSkillAuthoringLeaseID() string      { return "libmcpal_" + newEpoch() }
func newLibraryMCPClientSkillAuthoringAuditEventID() string { return "libmcpale_" + newEpoch() }

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
	}{request.Name, request.Slug, request.Description, request.Content, request.RequestedCapabilities})
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
	}{
		SkillID: request.SkillID, ExpectedVersionID: request.ExpectedVersionID,
		ExpectedVersionDigest: request.ExpectedVersionDigest, Content: request.Content,
		RequestedCapabilities: request.RequestedCapabilities,
	})
	if err != nil {
		return LibraryMCPClientSkillAuthoringUpdateRequest{}, "", fmt.Errorf("encode skill authoring update payload: %w", err)
	}
	return request, libraryDigest(string(canonical)), nil
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
		LibraryMCPClientSkillAuthoringAuditOperationUpdate:
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

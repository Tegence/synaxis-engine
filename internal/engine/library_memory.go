package engine

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// LibraryMemoryStore is the deliberately separate persistence facet for
// durable agent memory. Memory is context, never executable instruction or an
// authorization input. Keeping this facet separate from LibraryStore prevents
// an ordinary skill/artifact dependency from accidentally acquiring memory
// write, recall, sharing, or forgetting authority.
type LibraryMemoryStore interface {
	LibraryConsoleMemoryPage(context.Context, LibraryConsolePageCursor, int) (LibraryConsoleMemoryPage, error)
	LibraryMemory(context.Context, string) (LibraryMemory, bool)
	LibraryMemoryVersions(context.Context, string) ([]LibraryMemoryVersion, error)
	LibraryMemoryVersion(context.Context, string, string) (LibraryMemoryVersion, bool)
	CreateLibraryMemoryWithInitialVersion(context.Context, LibraryMemory, LibraryMemoryVersion) (LibraryMemory, LibraryMemoryVersion, error)
	CreateLibraryMCPClientMemoryProposal(context.Context, MCPClient, LibraryMemory, LibraryMemoryVersion) (LibraryMemory, LibraryMemoryVersion, error)
	CreateLibraryMemoryVersion(context.Context, string, LibraryMemoryVersion, string) (LibraryMemory, LibraryMemoryVersion, error)
	ReviewLibraryMemory(context.Context, string, LibraryMemoryReview) (LibraryMemory, error)

	LibraryMemoryGrants(context.Context, string) ([]LibraryMemoryGrant, error)
	CreateLibraryMemoryGrant(context.Context, LibraryMemoryGrant) (LibraryMemoryGrant, error)
	RevokeLibraryMemoryGrant(context.Context, string, string, string, time.Time) (LibraryMemoryGrant, error)

	// LibraryMemoryRecallSelections returns only active, unexpired memory visible
	// to the exact live client: that surface's current head plus live grants
	// pinned to an immutable version and digest. Implementations must reload the
	// durable registration while taking their native snapshot/transaction.
	LibraryMemoryRecallSelections(context.Context, MCPClient, time.Time) ([]LibraryMemorySelection, error)
	// LibraryMemoryReadSelection applies the same boundary to one exact
	// immutable version. It deliberately does not mean "latest".
	LibraryMemoryReadSelection(context.Context, MCPClient, string, string, time.Time) (LibraryMemorySelection, bool, error)

	// ForgetLibraryMemory hard-deletes authored content, immutable versions,
	// and grants. The logical ID is intentionally not retained in queryable
	// Library state; general request/audit infrastructure may still record that
	// an administrator invoked the route without recording memory content.
	ForgetLibraryMemory(context.Context, string) error
}

const (
	LibraryMemoryKindDecision   = "decision"
	LibraryMemoryKindConstraint = "constraint"
	LibraryMemoryKindPreference = "preference"
	LibraryMemoryKindLesson     = "lesson"
	LibraryMemoryKindFact       = "fact"
	LibraryMemoryKindHandoff    = "handoff"

	LibraryMemoryStateProposed   = "proposed"
	LibraryMemoryStateActive     = "active"
	LibraryMemoryStateDisputed   = "disputed"
	LibraryMemoryStateSuperseded = "superseded"
	LibraryMemoryStateExpired    = "expired"

	LibraryMemoryTrustAgentObserved     = "agent_observed"
	LibraryMemoryTrustHumanConfirmed    = "human_confirmed"
	LibraryMemoryTrustWorkspaceApproved = "workspace_approved"
	LibraryMemoryTrustHostAttested      = "host_attested"

	LibraryMemoryAccessOwnSurface = "own_surface"
	LibraryMemoryAccessGranted    = "granted_exact_version"

	libraryMemoryMaxContentBytes    = 8 << 10
	libraryMemoryMaxQueryBytes      = 4 << 10
	libraryMemoryPreviewRunes       = 160
	libraryMemoryRecallDefault      = 5
	libraryMemoryRecallMax          = 20
	libraryMemoryRecallBytesDefault = 32 << 10
	libraryMemoryRecallBytesMax     = 32 << 10
)

var (
	ErrLibraryMemoryNotFound               = errors.New("library memory not found")
	ErrLibraryMemoryVersionNotFound        = errors.New("library memory version not found")
	ErrLibraryMemoryVersionConflict        = errors.New("library memory version is not the current head")
	ErrLibraryMemoryGrantNotFound          = errors.New("library memory grant not found")
	ErrLibraryMemoryGrantExists            = errors.New("library memory already has a live grant for that agent surface")
	ErrLibraryMemoryGrantOwner             = errors.New("library memory owner already has direct access")
	ErrLibraryMemoryGrantIneligible        = errors.New("only an active, unexpired current memory version may be granted")
	ErrLibraryMemorySupersessionIneligible = errors.New("superseding memory must be a different active, unexpired memory")
	// ErrLibraryMemoryEvidenceUnavailable intentionally collapses missing,
	// mismatched, and unauthorized evidence for subject-bound proposals. MCP
	// callers must not be able to use proposal validation as a workspace-wide
	// run/artifact existence oracle.
	ErrLibraryMemoryEvidenceUnavailable = errors.New("library memory evidence is unavailable")
)

// LibraryMemory is the stable lifecycle record. Authored content exists only
// in immutable LibraryMemoryVersion values. AgentSurfaceID is a durable MCP
// client registration ID; it is never a public slug, subject, credential
// namespace, or caller-selected recall scope.
type LibraryMemory struct {
	ID                   string `json:"id"`
	Kind                 string `json:"kind"`
	State                string `json:"state"`
	Trust                string `json:"trust"`
	AgentSurfaceID       string `json:"agentSurfaceId"`
	CurrentVersionID     string `json:"currentVersionId"`
	CurrentVersionDigest string `json:"currentVersionDigest"`
	// Preview is a transient list projection derived from the decrypted
	// current version. It is never persisted as a second authored content copy.
	Preview              string    `json:"preview,omitempty"`
	CreatedBy            string    `json:"createdBy,omitempty"`
	CreatedAt            time.Time `json:"createdAt"`
	UpdatedAt            time.Time `json:"updatedAt"`
	ExpiresAt            time.Time `json:"expiresAt,omitzero"`
	ReviewAfter          time.Time `json:"reviewAfter,omitzero"`
	ReviewedBy           string    `json:"reviewedBy,omitempty"`
	ReviewedAt           time.Time `json:"reviewedAt,omitzero"`
	SupersededByMemoryID string    `json:"supersededByMemoryId,omitempty"`
}

// LibraryMemoryVersion is immutable. SourceArtifact* is all-or-nothing and
// pins one exact evidence snapshot. SourceRunID is an optional opaque run
// citation. None of these references grants access to the cited source.
type LibraryMemoryVersion struct {
	ID                      string    `json:"id"`
	MemoryID                string    `json:"memoryId"`
	Version                 int       `json:"version"`
	Content                 string    `json:"content"`
	Digest                  string    `json:"digest"`
	SourceRunID             string    `json:"sourceRunId,omitempty"`
	SourceArtifactID        string    `json:"sourceArtifactId,omitempty"`
	SourceArtifactVersionID string    `json:"sourceArtifactVersionId,omitempty"`
	SourceDigest            string    `json:"sourceDigest,omitempty"`
	CreatedBy               string    `json:"createdBy,omitempty"`
	CreatedAt               time.Time `json:"createdAt"`
}

// LibraryMemoryGrant delegates one exact immutable current version to one
// durable MCP client. A correction revokes every live grant; access to the new
// head requires a new explicit grant and never advances implicitly.
type LibraryMemoryGrant struct {
	ID                  string    `json:"id"`
	MemoryID            string    `json:"memoryId"`
	MemoryVersionID     string    `json:"memoryVersionId"`
	MemoryVersionDigest string    `json:"memoryVersionDigest"`
	AgentSurfaceID      string    `json:"agentSurfaceId"`
	CreatedBy           string    `json:"createdBy,omitempty"`
	CreatedAt           time.Time `json:"createdAt"`
	RevokedBy           string    `json:"revokedBy,omitempty"`
	RevokedAt           time.Time `json:"revokedAt,omitzero"`
}

// LibraryMemoryReview is a compare-to-version lifecycle mutation. Nil
// freshness pointers preserve the values observed under the store's native
// lock/transaction; a non-nil pointer explicitly replaces (or clears) one.
type LibraryMemoryReview struct {
	MemoryVersionID      string
	State                string
	Trust                string
	ExpiresAt            *time.Time
	ReviewAfter          *time.Time
	SupersededByMemoryID string
	ReviewedBy           string
	ReviewedAt           time.Time
}

// LibraryMemorySelection is the internal exact-version access projection used
// by recall and read. The public MCP contract strips administrator/provenance
// identities while retaining immutable evidence IDs and freshness metadata.
type LibraryMemorySelection struct {
	Memory  LibraryMemory
	Version LibraryMemoryVersion
	Access  string
	GrantID string
}

// LibraryConsoleMemoryPage is a bounded keyset page. Preview is the only
// authored-content projection and is derived from each returned current head.
type LibraryConsoleMemoryPage struct {
	Memories   []LibraryMemory
	NextCursor LibraryConsolePageCursor
}

func newLibraryMemoryID() string        { return "libmem_" + newEpoch() }
func newLibraryMemoryVersionID() string { return "libmemv_" + newEpoch() }
func newLibraryMemoryGrantID() string   { return "libmemg_" + newEpoch() }

func validLibraryMemoryKind(kind string) bool {
	switch kind {
	case LibraryMemoryKindDecision, LibraryMemoryKindConstraint, LibraryMemoryKindPreference, LibraryMemoryKindLesson, LibraryMemoryKindFact, LibraryMemoryKindHandoff:
		return true
	default:
		return false
	}
}

func validLibraryMemoryState(state string) bool {
	switch state {
	case LibraryMemoryStateProposed, LibraryMemoryStateActive, LibraryMemoryStateDisputed, LibraryMemoryStateSuperseded, LibraryMemoryStateExpired:
		return true
	default:
		return false
	}
}

func validLibraryMemoryTrust(trust string) bool {
	switch trust {
	case LibraryMemoryTrustAgentObserved, LibraryMemoryTrustHumanConfirmed, LibraryMemoryTrustWorkspaceApproved, LibraryMemoryTrustHostAttested:
		return true
	default:
		return false
	}
}

func validLibraryMemoryAdministrativeReview(state, trust string) bool {
	state = strings.ToLower(strings.TrimSpace(state))
	trust = strings.ToLower(strings.TrimSpace(trust))
	switch state {
	case LibraryMemoryStateActive, LibraryMemoryStateDisputed, LibraryMemoryStateSuperseded, LibraryMemoryStateExpired:
	default:
		return false
	}
	return trust == LibraryMemoryTrustHumanConfirmed || trust == LibraryMemoryTrustWorkspaceApproved
}

func validateLibraryMemory(memory LibraryMemory) error {
	if !validLibraryMemoryKind(memory.Kind) {
		return fmt.Errorf("invalid memory kind %q", memory.Kind)
	}
	if !validLibraryMemoryState(memory.State) {
		return fmt.Errorf("invalid memory state %q", memory.State)
	}
	if !validLibraryMemoryTrust(memory.Trust) {
		return fmt.Errorf("invalid memory trust %q", memory.Trust)
	}
	if err := validateLibraryOpaqueRef("memory agent surface", memory.AgentSurfaceID, false); err != nil {
		return err
	}
	if err := validateLibraryOpaqueRef("memory creator", memory.CreatedBy, true); err != nil {
		return err
	}
	if err := validateLibraryOpaqueRef("memory current version", memory.CurrentVersionID, true); err != nil {
		return err
	}
	if err := validateLibraryDigest("memory current version", memory.CurrentVersionDigest, memory.CurrentVersionID == ""); err != nil {
		return err
	}
	if (memory.CurrentVersionID == "") != (memory.CurrentVersionDigest == "") {
		return errors.New("memory current version id and digest must be present together")
	}
	if err := validateLibraryOpaqueRef("memory reviewer", memory.ReviewedBy, true); err != nil {
		return err
	}
	if memory.ReviewedAt.IsZero() != (memory.ReviewedBy == "") {
		return errors.New("memory review actor and timestamp must be present together")
	}
	if err := validateLibraryOpaqueRef("superseding memory", memory.SupersededByMemoryID, true); err != nil {
		return err
	}
	if memory.State == LibraryMemoryStateSuperseded {
		if memory.SupersededByMemoryID == "" || memory.SupersededByMemoryID == memory.ID {
			return errors.New("superseded memory requires a different replacement memory")
		}
	} else if memory.SupersededByMemoryID != "" {
		return errors.New("only a superseded memory may name a replacement")
	}
	if memory.State == LibraryMemoryStateActive && memory.Trust == LibraryMemoryTrustAgentObserved {
		return errors.New("agent-observed memory must be human-confirmed or attested before activation")
	}
	return nil
}

func validateLibraryMemoryVersion(version LibraryMemoryVersion) error {
	if err := validateLibraryOpaqueRef("memory", version.MemoryID, false); err != nil {
		return err
	}
	if strings.TrimSpace(version.Content) == "" || len(version.Content) > libraryMemoryMaxContentBytes {
		return fmt.Errorf("memory content is required and must be at most %d bytes", libraryMemoryMaxContentBytes)
	}
	if err := validateLibraryOpaqueRef("memory source run", version.SourceRunID, true); err != nil {
		return err
	}
	hasArtifactSource := version.SourceArtifactID != "" || version.SourceArtifactVersionID != "" || version.SourceDigest != ""
	if hasArtifactSource {
		if err := validateLibraryOpaqueRef("memory source artifact", version.SourceArtifactID, false); err != nil {
			return err
		}
		if err := validateLibraryOpaqueRef("memory source artifact version", version.SourceArtifactVersionID, false); err != nil {
			return err
		}
		if err := validateLibraryDigest("memory source", version.SourceDigest, false); err != nil {
			return err
		}
	}
	return validateLibraryOpaqueRef("memory version creator", version.CreatedBy, true)
}

func validateLibraryMemoryGrant(grant LibraryMemoryGrant) error {
	if err := validateLibraryOpaqueRef("memory", grant.MemoryID, false); err != nil {
		return err
	}
	if err := validateLibraryOpaqueRef("memory version", grant.MemoryVersionID, false); err != nil {
		return err
	}
	if err := validateLibraryDigest("memory version", grant.MemoryVersionDigest, false); err != nil {
		return err
	}
	if err := validateLibraryOpaqueRef("memory grant agent surface", grant.AgentSurfaceID, false); err != nil {
		return err
	}
	if err := validateLibraryOpaqueRef("memory grant creator", grant.CreatedBy, true); err != nil {
		return err
	}
	if err := validateLibraryOpaqueRef("memory grant revoker", grant.RevokedBy, true); err != nil {
		return err
	}
	if grant.RevokedAt.IsZero() != (grant.RevokedBy == "") {
		return errors.New("memory grant revoker and timestamp must be present together")
	}
	return nil
}

func normalizeLibraryMemory(memory LibraryMemory) (LibraryMemory, error) {
	memory.Kind = strings.TrimSpace(strings.ToLower(memory.Kind))
	memory.State = strings.TrimSpace(strings.ToLower(memory.State))
	memory.Trust = strings.TrimSpace(strings.ToLower(memory.Trust))
	if memory.CreatedAt.IsZero() {
		memory.CreatedAt = time.Now().UTC()
	} else {
		memory.CreatedAt = memory.CreatedAt.UTC()
	}
	if memory.UpdatedAt.IsZero() {
		memory.UpdatedAt = memory.CreatedAt
	} else {
		memory.UpdatedAt = memory.UpdatedAt.UTC()
	}
	memory.ExpiresAt = memory.ExpiresAt.UTC()
	memory.ReviewAfter = memory.ReviewAfter.UTC()
	memory.ReviewedAt = memory.ReviewedAt.UTC()
	if err := validateLibraryMemory(memory); err != nil {
		return LibraryMemory{}, err
	}
	return memory, nil
}

func normalizeLibraryMemoryVersion(version LibraryMemoryVersion) (LibraryMemoryVersion, error) {
	if err := validateLibraryMemoryVersion(version); err != nil {
		return LibraryMemoryVersion{}, err
	}
	version.Digest = libraryDigest(version.Content)
	if version.CreatedAt.IsZero() {
		version.CreatedAt = time.Now().UTC()
	} else {
		version.CreatedAt = version.CreatedAt.UTC()
	}
	return version, nil
}

func normalizeLibraryMemoryGrant(grant LibraryMemoryGrant) (LibraryMemoryGrant, error) {
	if err := validateLibraryMemoryGrant(grant); err != nil {
		return LibraryMemoryGrant{}, err
	}
	if grant.CreatedAt.IsZero() {
		grant.CreatedAt = time.Now().UTC()
	} else {
		grant.CreatedAt = grant.CreatedAt.UTC()
	}
	grant.RevokedAt = grant.RevokedAt.UTC()
	return grant, nil
}

func prepareLibraryMemoryInitial(memory LibraryMemory, version LibraryMemoryVersion) (LibraryMemory, LibraryMemoryVersion, error) {
	if memory.ID == "" {
		memory.ID = newLibraryMemoryID()
	}
	if version.ID == "" {
		version.ID = newLibraryMemoryVersionID()
	}
	if version.MemoryID == "" {
		version.MemoryID = memory.ID
	}
	if version.MemoryID != memory.ID {
		return LibraryMemory{}, LibraryMemoryVersion{}, errors.New("memory version belongs to another memory")
	}
	version.Version = 1
	normalizedVersion, err := normalizeLibraryMemoryVersion(version)
	if err != nil {
		return LibraryMemory{}, LibraryMemoryVersion{}, err
	}
	memory.CurrentVersionID = normalizedVersion.ID
	memory.CurrentVersionDigest = normalizedVersion.Digest
	if memory.CreatedAt.IsZero() {
		memory.CreatedAt = normalizedVersion.CreatedAt
	}
	memory.UpdatedAt = memory.CreatedAt
	normalizedMemory, err := normalizeLibraryMemory(memory)
	if err != nil {
		return LibraryMemory{}, LibraryMemoryVersion{}, err
	}
	return normalizedMemory, normalizedVersion, nil
}

func libraryMemoryIsRecallable(memory LibraryMemory, now time.Time) bool {
	return memory.State == LibraryMemoryStateActive && (memory.ExpiresAt.IsZero() || memory.ExpiresAt.After(now))
}

func copyLibraryMemory(memory LibraryMemory) LibraryMemory                       { return memory }
func copyLibraryMemoryVersion(version LibraryMemoryVersion) LibraryMemoryVersion { return version }
func copyLibraryMemoryGrant(grant LibraryMemoryGrant) LibraryMemoryGrant         { return grant }

func sortLibraryMemorySelections(selections []LibraryMemorySelection) {
	sort.Slice(selections, func(i, j int) bool {
		if !selections[i].Memory.UpdatedAt.Equal(selections[j].Memory.UpdatedAt) {
			return selections[i].Memory.UpdatedAt.After(selections[j].Memory.UpdatedAt)
		}
		if selections[i].Memory.ID != selections[j].Memory.ID {
			return selections[i].Memory.ID < selections[j].Memory.ID
		}
		return selections[i].Version.ID < selections[j].Version.ID
	})
}

func libraryMemoryPreview(content string) string {
	runes := []rune(content)
	if len(runes) <= libraryMemoryPreviewRunes {
		return content
	}
	return string(runes[:libraryMemoryPreviewRunes]) + "…"
}

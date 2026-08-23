package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

// LibraryStore is the Engine-native, tenant-blind persistence facet for the
// portable Library v2.  It deliberately uses only opaque actor and scope
// references: workspace membership, folder hierarchy, public-link policy, and
// billing stay in Platform.  A self-hosted Engine can use the same model
// without importing Platform packages.
//
// Library v2 is intentionally separate from SkillStore.  SkillStore is the
// legacy Git-source/virtual-connector implementation; LibraryStore represents
// authored portable skills, generic bindings, artifacts, and provenance.
type LibraryStore interface {
	LibrarySkills(context.Context) ([]LibrarySkill, error)
	// LibraryConsoleSkillPage is the bounded Console projection. It includes
	// the newest immutable version's metadata but never reads its instruction
	// content merely to render a management list.
	LibraryConsoleSkillPage(context.Context, LibraryConsolePageCursor, int) (LibraryConsoleSkillPage, error)
	// LibraryMCPRootSkillPage is a bounded, metadata-only projection for the
	// owner/admin root MCP resource. It must not fetch immutable instruction
	// bodies merely to discover a skill's latest version.
	LibraryMCPRootSkillPage(context.Context, LibraryMCPRootPageCursor, int) (LibraryMCPRootSkillPage, error)
	LibrarySkill(context.Context, string) (LibrarySkill, bool)
	CreateLibrarySkillWithInitialVersion(context.Context, LibrarySkill, LibrarySkillVersion) (LibrarySkill, LibrarySkillVersion, error)
	LibrarySkillVersions(context.Context, string) ([]LibrarySkillVersion, error)
	LibrarySkillVersion(context.Context, string, string) (LibrarySkillVersion, bool)
	CreateLibrarySkillVersion(context.Context, LibrarySkillVersion) (LibrarySkillVersion, error)

	CreateLibrarySkillDraft(context.Context, LibrarySkillDraft) (LibrarySkillDraft, error)
	LibrarySkillDraft(context.Context, string) (LibrarySkillDraft, bool)
	// ImportPlatformLibrarySkillDraft is a hosted-control-plane-only storage
	// operation. It persists an editable generated draft and returns replayed
	// when the same opaque request id was already accepted with identical
	// candidate content. It has no authority to create a skill, binding, run,
	// artifact, or public link.
	ImportPlatformLibrarySkillDraft(context.Context, LibraryPlatformSkillDraftImport, string) (draft LibrarySkillDraft, replayed bool, err error)

	LibrarySkillBindings(context.Context, string) ([]LibrarySkillBinding, error)
	UpsertLibrarySkillBinding(context.Context, LibrarySkillBinding) (LibrarySkillBinding, error)
	DeleteLibrarySkillBinding(context.Context, string, string) error
	// LibrarySkillResolutionSelections atomically snapshots every generic
	// resolution input that can affect a returned instruction: the matching
	// binding and its selected immutable version. A track binding must not be
	// paired with a version made visible after that binding was removed or
	// replaced on another store read.
	LibrarySkillResolutionSelections(context.Context, LibrarySkillResolutionRequest) ([]LibraryResolvedSkill, error)
	// LibraryAgentSurfaceSkillSelections atomically snapshots the skill,
	// explicit agent-surface binding, and resolved immutable version. It exists
	// only for subject-bound surfaces: generic resolution retains its broader
	// multi-scope precedence contract.
	LibraryAgentSurfaceSkillSelections(context.Context, string) ([]LibraryAgentSurfaceSkillSelection, error)

	LibrarySkillEvaluations(context.Context, string) ([]LibrarySkillEvaluation, error)
	CreateLibrarySkillEvaluation(context.Context, LibrarySkillEvaluation) (LibrarySkillEvaluation, error)

	LibraryArtifacts(context.Context) ([]LibraryArtifact, error)
	// LibraryConsoleArtifactPage is a bounded Console metadata projection.
	// Artifact bodies remain behind the explicit read-by-ID endpoint.
	LibraryConsoleArtifactPage(context.Context, LibraryConsolePageCursor, int) (LibraryConsoleArtifactPage, error)
	// LibraryMCPRootArtifactPage is the bounded, metadata-only counterpart for
	// the owner/admin root MCP resource. Artifact bodies remain available only
	// through the explicit read-by-ID tool.
	LibraryMCPRootArtifactPage(context.Context, LibraryMCPRootPageCursor, int) (LibraryMCPRootArtifactPage, error)
	LibraryArtifact(context.Context, string) (LibraryArtifact, bool)
	CreateLibraryArtifactWithInitialVersion(context.Context, LibraryArtifact, LibraryArtifactVersion) (LibraryArtifact, LibraryArtifactVersion, error)
	// CreateLibraryRootMCPArtifactWithInitialVersion is the only Library write
	// used by the owner/admin root MCP resource. It derives the fixed root MCP
	// direct-run provenance and commits that run, artifact, and first version as
	// one store operation, so an artifact failure cannot strand a run.
	CreateLibraryRootMCPArtifactWithInitialVersion(context.Context, LibraryArtifact, LibraryArtifactVersion) (LibraryRun, LibraryArtifact, LibraryArtifactVersion, error)
	// CreateLibraryMCPClientArtifactWithInitialVersion is the only Library
	// write used by a subject-bound MCP client. It derives the agent-direct run
	// and its client/surface projection from the live registration, then commits
	// the run, artifact, and first version as one store operation.
	CreateLibraryMCPClientArtifactWithInitialVersion(context.Context, MCPClient, LibraryArtifact, LibraryArtifactVersion) (LibraryRun, LibraryArtifact, LibraryArtifactVersion, error)
	LibraryArtifactVersions(context.Context, string) ([]LibraryArtifactVersion, error)
	LibraryArtifactVersion(context.Context, string, string) (LibraryArtifactVersion, bool)
	CreateLibraryArtifactVersion(context.Context, LibraryArtifactVersion) (LibraryArtifactVersion, error)
	// LibraryMCPClientArtifactPage projects only one active subject-bound MCP
	// surface's direct artifacts and live grants. It must not fall back to a
	// workspace-wide artifact scan at a client endpoint.
	LibraryMCPClientArtifactPage(context.Context, MCPClient, LibraryMCPClientArtifactCursor, int) (LibraryMCPClientArtifactPage, error)
	ReviewLibraryArtifactVersion(context.Context, string, string, string, string, time.Time) (LibraryArtifactVersion, error)
	// Artifact grants are immutable capability records for one exact artifact
	// version. They deliberately name an agent surface, never a human subject
	// or a connection namespace: an MCP client can be revoked independently and
	// a grant never becomes a route to connection credentials.
	LibraryArtifactGrants(context.Context, string) ([]LibraryArtifactGrant, error)
	ActiveLibraryArtifactGrantsForAgentSurface(context.Context, string) ([]LibraryArtifactGrant, error)
	ActiveLibraryArtifactGrant(context.Context, string, string) (LibraryArtifactGrant, bool)
	CreateLibraryArtifactGrant(context.Context, LibraryArtifactGrant) (LibraryArtifactGrant, error)
	RevokeLibraryArtifactGrant(context.Context, string, string, string, time.Time) (LibraryArtifactGrant, error)
	LibraryPublicationCandidate(context.Context, string) (LibraryPublicationCandidate, error)
	// ClaimLibraryPublicationCandidate compares a Platform-observed immutable
	// artifact version/digest with the current reviewed head and returns the
	// candidate only while they still match. Implementations hold their native
	// artifact-head lock for both the comparison and projection, so Platform
	// cannot mint a link from a stale reviewed-latest observation.
	ClaimLibraryPublicationCandidate(context.Context, string, string, string) (LibraryPublicationCandidate, error)

	LibraryRuns(context.Context) ([]LibraryRun, error)
	// LibraryConsoleRunPage is a bounded Console metadata projection. Detailed
	// provenance remains available through the explicit read-by-ID endpoint.
	LibraryConsoleRunPage(context.Context, LibraryConsolePageCursor, int) (LibraryConsoleRunPage, error)
	LibraryRun(context.Context, string) (LibraryRun, bool)
	CreateLibraryRun(context.Context, LibraryRun) (LibraryRun, error)
}

// LibraryRuntimeAttestationStore is the deliberately narrow persistence
// boundary for a host-attested external skill result. It is intentionally not
// part of LibraryStore: ordinary Console and MCP code must not acquire a
// write capability merely by depending on the general Library facet.
//
// Implementations verify the exact signed request again while holding their
// native client/selection lock or transaction. The result records what the
// configured host attested; it does not prove that a third-party host injected
// instructions or executed a particular tool.
type LibraryRuntimeAttestationStore interface {
	IngestLibraryRuntimeAttestation(context.Context, LibraryRuntimeAttestation) (LibraryRun, LibraryArtifact, LibraryArtifactVersion, bool, error)
}

// LibraryArtifactMediaStore is the intentionally narrow private-image facet.
// It is kept separate from LibraryStore so ordinary Library list/detail code
// cannot accidentally gain byte-read or binary-write authority merely by
// depending on the general authored-content store.
//
// The create methods accept only a server-canonical image value. MCP ingress
// must call normalizeLibraryArtifactImage before reaching this boundary; the
// store then commits the direct run, artifact, initial version, and one image
// blob in the same native transaction/save. Raster bytes are limited to safe
// inline-image delivery. The all-image byte method exists solely for an
// already-authorized, explicit parent-version download: callers must not make
// it independently addressable, render SVG, or return a storage URL.
type LibraryArtifactMediaStore interface {
	CreateLibraryRootMCPImageArtifactWithInitialVersion(context.Context, LibraryArtifact, libraryArtifactImageCanonical, string) (LibraryRun, LibraryArtifact, LibraryArtifactVersion, error)
	CreateLibraryMCPClientImageArtifactWithInitialVersion(context.Context, MCPClient, LibraryArtifact, libraryArtifactImageCanonical, string) (LibraryRun, LibraryArtifact, LibraryArtifactVersion, error)
	CreateLibraryMCPClientImageArtifactVersion(context.Context, MCPClient, LibraryMCPClientImageArtifactVersionCreateRequest) (LibraryMCPClientArtifactVersionCreateResult, error)
	LibraryArtifactMedia(context.Context, string, string) (LibraryArtifactMedia, bool, error)
	LibraryArtifactRasterBytes(context.Context, string, string) ([]byte, bool, error)
	LibraryArtifactImageBytes(context.Context, string, string) ([]byte, bool, error)
}

const (
	LibraryBindingModePin   = "pin"
	LibraryBindingModeTrack = "track"

	LibraryScopeWorkspace = "workspace"
	// LibraryScopeNamespace is a generic organization/delivery scope. It is
	// intentionally unrelated to ConnectionNamespace, which owns credentials.
	LibraryScopeNamespace    = "namespace"
	LibraryScopeFolder       = "folder"
	LibraryScopeRepository   = "repository"
	LibraryScopeProject      = "project"
	LibraryScopeAgentSurface = "agent_surface"

	LibraryDraftOriginGenerated = "generated"
	LibraryDraftOriginManual    = "manual"

	LibraryRunOriginSkillRun    = "skill_run"
	LibraryRunOriginAgentDirect = "agent_direct"
	LibraryRunOriginAutomation  = "automation"
	LibraryRunOriginHuman       = "human"

	// LibraryRunAttestationHost is reserved for the separate Ed25519-signed
	// host-attestation ingress. It is never accepted by generic run creation,
	// browser/admin routes, or ordinary MCP tools.
	LibraryRunAttestationHost = "host_attested"

	LibraryArtifactOriginSkillRun    = "skill_run"
	LibraryArtifactOriginAgentDirect = "agent_direct"
	LibraryArtifactOriginAutomation  = "automation"
	LibraryArtifactOriginHuman       = "human"

	LibraryArtifactFormatMarkdown = "markdown"
	LibraryArtifactFormatText     = "text"
	// LibraryArtifactFormatImage is a private, immutable image-only artifact
	// version. Image bytes never live in Body: they are stored in the narrow
	// LibraryArtifactMediaStore blob facet, with this version digest pinned to
	// the accepted canonical media bytes.
	LibraryArtifactFormatImage = "image"

	LibraryRedactionPending  = "pending"
	LibraryRedactionApproved = "approved"
	LibraryRedactionRejected = "rejected"
)

const (
	libraryMaxNameBytes                 = 160
	libraryMaxDescriptionBytes          = 4 << 10
	libraryMaxContentBytes              = 1 << 20
	libraryMaxOpaqueRefBytes            = 512
	libraryMaxCapabilities              = 64
	libraryMCPClientArtifactPageDefault = 50
	libraryMCPClientArtifactPageMax     = 100
	libraryMCPRootPageDefault           = 50
	libraryMCPRootPageMax               = 100
	libraryConsolePageDefault           = 50
	libraryConsolePageMax               = 100
	libraryRootMCPActorRef              = "mcp-agent"
	libraryRootMCPSurfaceRef            = "mcp"
)

var (
	ErrLibrarySkillNotFound              = errors.New("library skill not found")
	ErrLibrarySkillExists                = errors.New("library skill already exists")
	ErrLibrarySkillVersionNotFound       = errors.New("library skill version not found")
	ErrLibrarySkillDraftNotFound         = errors.New("library skill draft not found")
	ErrLibraryBindingNotFound            = errors.New("library skill binding not found")
	ErrLibraryArtifactNotFound           = errors.New("library artifact not found")
	ErrLibraryArtifactVersionNotFound    = errors.New("library artifact version not found")
	ErrLibraryArtifactGrantNotFound      = errors.New("library artifact grant not found")
	ErrLibraryArtifactGrantExists        = errors.New("library artifact already has a live grant for that agent surface")
	ErrLibraryArtifactPublicationClaimed = errors.New("library artifact version is already claimed for publication")
	ErrLibraryRuntimeAttestationInvalid  = errors.New("invalid library runtime attestation")
	ErrLibraryRuntimeAttestationExpired  = errors.New("library runtime attestation expired")
	ErrLibraryRuntimeAttestationReplay   = errors.New("library runtime attestation nonce was already used")
	ErrLibraryRuntimeAttestationConflict = errors.New("library runtime attestation execution conflicts with an existing result")
	ErrLibraryRunNotFound                = errors.New("library run not found")
	ErrLibraryPublicationNotReady        = errors.New("library artifact is not approved for publication")
	ErrLibraryPublicationClaimConflict   = errors.New("library artifact changed before publication could be claimed")
	ErrLibraryDraftGeneratorUnavailable  = errors.New("skill draft generator is unavailable")
)

// LibrarySkill is portable, authored skill metadata.  Its content is stored
// only in immutable LibrarySkillVersion rows; changing instructions always
// creates another version.
type LibrarySkill struct {
	ID          string    `json:"id"`
	Slug        string    `json:"slug"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	CreatedBy   string    `json:"createdBy,omitempty"` // opaque actor ref
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

// LibrarySkillVersion is an immutable portable instruction bundle. Requested
// capabilities communicate intent only; they never grant tools or credentials.
type LibrarySkillVersion struct {
	ID                    string    `json:"id"`
	SkillID               string    `json:"skillId"`
	Version               int       `json:"version"`
	Content               string    `json:"content"`
	Digest                string    `json:"digest"`
	RequestedCapabilities []string  `json:"requestedCapabilities"`
	CreatedBy             string    `json:"createdBy,omitempty"`
	CreatedAt             time.Time `json:"createdAt"`
}

// LibrarySkillDraft is a candidate, not a runnable skill. Generated drafts
// retain only a digest of their prompt; the raw prompt is never persisted.
type LibrarySkillDraft struct {
	ID                    string    `json:"id"`
	Name                  string    `json:"name"`
	Description           string    `json:"description,omitempty"`
	Content               string    `json:"content"`
	RequestedCapabilities []string  `json:"requestedCapabilities"`
	Origin                string    `json:"origin"`
	Generator             string    `json:"generator,omitempty"`
	Model                 string    `json:"model,omitempty"`
	PromptDigest          string    `json:"promptDigest,omitempty"`
	CreatedBy             string    `json:"createdBy,omitempty"`
	CreatedAt             time.Time `json:"createdAt"`
}

// LibrarySkillBinding attaches a skill to a generic opaque scope.  It must
// never point at a ConnectionNamespace: those are credential ownership
// boundaries, not Library organization or delivery scopes.
type LibrarySkillBinding struct {
	ID                string    `json:"id"`
	SkillID           string    `json:"skillId"`
	ScopeKind         string    `json:"scopeKind"`
	ScopeID           string    `json:"scopeId"`
	Mode              string    `json:"mode"`
	PinnedVersionID   string    `json:"pinnedVersionId,omitempty"`
	CapabilityCeiling []string  `json:"capabilityCeiling"`
	Priority          int       `json:"priority"`
	CreatedBy         string    `json:"createdBy,omitempty"`
	CreatedAt         time.Time `json:"createdAt"`
	UpdatedAt         time.Time `json:"updatedAt"`
}

// LibraryAgentSurfaceSkillSelection is the storage-level atomic unit behind
// a verified MCP-client activation. A track binding resolves its head and a
// pin binding resolves its named version in the same store snapshot as the
// binding, so a caller never combines a pre-revocation binding with a later
// skill version from a separate read.
type LibraryAgentSurfaceSkillSelection struct {
	Skill   LibrarySkill        `json:"skill"`
	Binding LibrarySkillBinding `json:"binding"`
	Version LibrarySkillVersion `json:"version"`
}

// LibrarySkillEvaluation is append-only evidence attached to one immutable
// version. EvidenceDigest is intentionally a digest, not an unbounded trace.
type LibrarySkillEvaluation struct {
	ID             string    `json:"id"`
	SkillID        string    `json:"skillId"`
	SkillVersionID string    `json:"skillVersionId"`
	Evaluator      string    `json:"evaluator"`
	Score          int       `json:"score"`
	Passed         bool      `json:"passed"`
	Summary        string    `json:"summary,omitempty"`
	EvidenceDigest string    `json:"evidenceDigest,omitempty"`
	CreatedBy      string    `json:"createdBy,omitempty"`
	CreatedAt      time.Time `json:"createdAt"`
}

// LibraryRun is immutable execution provenance. Direct agent actions retain
// Origin=agent_direct with empty skill/version/binding references by design.
type LibraryRun struct {
	ID     string `json:"id"`
	Origin string `json:"origin"`
	// Attestation is empty for ordinary provenance. "host_attested" means a
	// separately configured external host signed the exact ingestion request;
	// it is an assertion about host-reported provenance, not tool-execution
	// proof from the Engine.
	Attestation           string   `json:"attestation,omitempty"`
	SkillID               string   `json:"skillId,omitempty"`
	SkillVersionID        string   `json:"skillVersionId,omitempty"`
	BindingID             string   `json:"bindingId,omitempty"`
	ActorRef              string   `json:"actorRef,omitempty"`
	SurfaceRef            string   `json:"surfaceRef,omitempty"`
	EffectiveCapabilities []string `json:"effectiveCapabilities"`
	Status                string   `json:"status"`
	InputDigest           string   `json:"inputDigest,omitempty"`
	OutputDigest          string   `json:"outputDigest,omitempty"`
	// SourceArtifact* is an optional, immutable input citation for an
	// agent-direct run. It is never a mutable artifact-head reference.
	SourceArtifactID        string    `json:"sourceArtifactId,omitempty"`
	SourceArtifactVersionID string    `json:"sourceArtifactVersionId,omitempty"`
	SourceArtifactDigest    string    `json:"sourceArtifactDigest,omitempty"`
	StartedAt               time.Time `json:"startedAt"`
	CompletedAt             time.Time `json:"completedAt"`
}

// LibraryArtifact is a logical artifact record. Body data only exists on an
// immutable LibraryArtifactVersion, so a publication can always point to a
// stable version/digest instead of a mutable head.
type LibraryArtifact struct {
	ID             string `json:"id"`
	Title          string `json:"title"`
	Summary        string `json:"summary,omitempty"`
	Origin         string `json:"origin"`
	RunID          string `json:"runId,omitempty"`
	SkillID        string `json:"skillId,omitempty"`
	SkillVersionID string `json:"skillVersionId,omitempty"`
	BindingID      string `json:"bindingId,omitempty"`
	// AgentSurfaceID is a non-secret, durable client projection key for a
	// subject-bound direct artifact. Actor identity remains private in
	// CreatedBy; this opaque structural ID is intentionally not returned by
	// generic/root artifact APIs.
	AgentSurfaceID string `json:"-"`
	// SourceArtifact* mirrors the direct run's exact immutable input. Keeping
	// it on the artifact makes provenance usable without exposing run bodies.
	SourceArtifactID        string    `json:"sourceArtifactId,omitempty"`
	SourceArtifactVersionID string    `json:"sourceArtifactVersionId,omitempty"`
	SourceArtifactDigest    string    `json:"sourceArtifactDigest,omitempty"`
	CreatedBy               string    `json:"createdBy,omitempty"`
	CreatedAt               time.Time `json:"createdAt"`
}

// LibraryMCPClientArtifact is the exact artifact/version a subject-bound
// client may read. Grants remain pinned; direct ownership selects its current
// head. The containing page never exposes another surface's metadata.
type LibraryMCPClientArtifact struct {
	Artifact LibraryArtifact        `json:"artifact"`
	Version  LibraryArtifactVersion `json:"version"`
	Access   string                 `json:"access"`
}

// LibraryMCPClientArtifactCursor is a keyset cursor over immutable artifact
// creation metadata. It is scoped again by the store's client predicate, so a
// caller cannot use a fabricated cursor to cross an agent surface boundary.
type LibraryMCPClientArtifactCursor struct {
	CreatedAt  time.Time
	ArtifactID string
}

type LibraryMCPClientArtifactPage struct {
	Artifacts  []LibraryMCPClientArtifact
	NextCursor LibraryMCPClientArtifactCursor
}

// LibraryMCPRootPageCursor is a keyset cursor over immutable Library-record
// creation metadata. The MCP wire representation is opaque and type-tagged by
// the root list tool; stores validate the timestamp/ID pair independently.
type LibraryMCPRootPageCursor struct {
	CreatedAt time.Time
	ID        string
}

// LibraryMCPRootSkill is the metadata-only root MCP list projection. The
// immutable instruction Content and requested capabilities stay behind
// library_skill_read, while the latest version identity remains discoverable.
type LibraryMCPRootSkill struct {
	ID              string
	Slug            string
	Name            string
	Description     string
	LatestVersion   int
	LatestVersionID string
	CreatedAt       time.Time
}

type LibraryMCPRootSkillPage struct {
	Skills     []LibraryMCPRootSkill
	NextCursor LibraryMCPRootPageCursor
}

// LibraryMCPRootArtifact is the metadata-only root MCP list projection.
// Provenance internals and immutable version bodies remain available only
// through their explicit inspection tools.
type LibraryMCPRootArtifact struct {
	ID        string
	Title     string
	Summary   string
	Origin    string
	CreatedAt time.Time
}

type LibraryMCPRootArtifactPage struct {
	Artifacts  []LibraryMCPRootArtifact
	NextCursor LibraryMCPRootPageCursor
}

// LibraryConsolePageCursor is an internal keyset position for one Console
// Library list. The HTTP cursor is opaque and type-tagged by the Console
// handler, while stores independently validate the timestamp/ID pair.
// Timestamp is a creation time for skills/artifacts and a start time for runs.
type LibraryConsolePageCursor struct {
	Timestamp time.Time
	ID        string
}

// LibraryConsoleSkillVersionSummary deliberately excludes the immutable
// instruction body. It supplies only the metadata needed to render a skill
// list without turning every page into a content read.
type LibraryConsoleSkillVersionSummary struct {
	ID                    string
	Version               int
	Digest                string
	RequestedCapabilities []string
	CreatedAt             time.Time
}

type LibraryConsoleSkill struct {
	Skill         LibrarySkill
	LatestVersion *LibraryConsoleSkillVersionSummary
}

type LibraryConsoleSkillPage struct {
	Skills     []LibraryConsoleSkill
	NextCursor LibraryConsolePageCursor
}

// LibraryConsoleArtifactPage has the existing artifact metadata shape, but
// never includes an immutable artifact-version body.
type LibraryConsoleArtifactPage struct {
	Artifacts  []LibraryArtifact
	NextCursor LibraryConsolePageCursor
}

// LibraryConsoleRunPage has the existing run metadata shape. Run details are
// still fetched explicitly so a list stays bounded as provenance accumulates.
type LibraryConsoleRunPage struct {
	Runs       []LibraryRun
	NextCursor LibraryConsolePageCursor
}

type LibraryArtifactVersion struct {
	ID              string `json:"id"`
	ArtifactID      string `json:"artifactId"`
	Version         int    `json:"version"`
	Format          string `json:"format"`
	Body            string `json:"body"`
	Digest          string `json:"digest"`
	SizeBytes       int64  `json:"sizeBytes"`
	RedactionStatus string `json:"redactionStatus"`
	// CreatedBy is set by the trusted console or subject-bound MCP endpoint;
	// callers never get to claim another agent's authorship through a tool
	// argument. It is encrypted at rest by PgStore like other actor refs.
	CreatedBy  string    `json:"createdBy,omitempty"`
	ReviewedBy string    `json:"-"`
	ReviewedAt time.Time `json:"reviewedAt,omitempty"`
	// PublicationClaimedAt is set by the service-only reviewed-latest CAS. A
	// claimed version cannot be re-reviewed, so an immutable Platform snapshot
	// never outlives or contradicts the Engine review decision that authorized
	// it.
	PublicationClaimedAt time.Time `json:"publicationClaimedAt,omitempty"`
	CreatedAt            time.Time `json:"createdAt"`
}

// LibraryArtifactMedia is the metadata for exactly one immutable private
// image blob attached to an image-format artifact version. The blob's bytes
// are deliberately absent from this type: list/read authorization is always
// decided against the parent artifact version, never an independently
// addressable storage key.
//
// AltText is private metadata. PgStore encrypts it together with the image
// bytes; metadata-only list projections intentionally omit it.
type LibraryArtifactMedia struct {
	ArtifactVersionID string `json:"artifactVersionId"`
	MIMEType          string `json:"mimeType"`
	Digest            string `json:"digest"`
	SizeBytes         int64  `json:"sizeBytes"`
	Width             int    `json:"width,omitempty"`
	Height            int    `json:"height,omitempty"`
	AltText           string `json:"altText,omitempty"`
	DeliveryMode      string `json:"deliveryMode"`
}

// LibraryArtifactGrant delegates one immutable artifact version to one
// durable MCP-client agent surface. A grant records the source digest as a
// second immutable fence: a corrupted/mismatched version ID cannot silently
// turn into another artifact body. Revocation only changes access; it never
// edits the historical grant or its target snapshot.
type LibraryArtifactGrant struct {
	ID                    string    `json:"id"`
	ArtifactID            string    `json:"artifactId"`
	ArtifactVersionID     string    `json:"artifactVersionId"`
	ArtifactVersionDigest string    `json:"artifactVersionDigest"`
	AgentSurfaceID        string    `json:"agentSurfaceId"`
	CreatedBy             string    `json:"createdBy,omitempty"`
	CreatedAt             time.Time `json:"createdAt"`
	RevokedBy             string    `json:"revokedBy,omitempty"`
	RevokedAt             time.Time `json:"revokedAt,omitempty"`
}

// LibraryPublicationCandidate is the sole Engine response suitable for the
// Platform public-link flow. It intentionally omits raw run inputs/outputs,
// credentials, connection data, actor identity, and non-approved versions.
type LibraryPublicationCandidate struct {
	ArtifactID        string                       `json:"artifactId"`
	ArtifactVersionID string                       `json:"artifactVersionId"`
	Digest            string                       `json:"digest"`
	Title             string                       `json:"title"`
	Summary           string                       `json:"summary,omitempty"`
	Format            string                       `json:"format"`
	Body              string                       `json:"body"`
	ArtifactCreatedAt time.Time                    `json:"artifactCreatedAt"`
	Provenance        LibraryPublicationProvenance `json:"provenance"`
	RedactionStatus   string                       `json:"redactionStatus"`
	ReviewedAt        time.Time                    `json:"reviewedAt"`
}

type LibraryPublicationProvenance struct {
	Origin       string `json:"origin"`
	SkillName    string `json:"skillName,omitempty"`
	SkillVersion int    `json:"skillVersion,omitempty"`
	RunID        string `json:"runId,omitempty"`
}

// SkillDraftGenerator is a server-side seam. Its implementation receives a
// bounded user request and returns a candidate only; it cannot publish, bind,
// access connector credentials, or make an agent call.
type SkillDraftGenerator interface {
	GenerateSkillDraft(context.Context, SkillDraftGenerationRequest) (SkillDraftGeneration, error)
}

type SkillDraftGenerationRequest struct {
	Name                  string
	Description           string
	Prompt                string
	RequestedCapabilities []string
}

type SkillDraftGeneration struct {
	Name                  string
	Description           string
	Content               string
	RequestedCapabilities []string
	Generator             string
	Model                 string
}

func newLibrarySkillID() string           { return "libsk_" + newEpoch() }
func newLibrarySkillVersionID() string    { return "libskv_" + newEpoch() }
func newLibrarySkillDraftID() string      { return "libskd_" + newEpoch() }
func newLibrarySkillBindingID() string    { return "libskb_" + newEpoch() }
func newLibrarySkillEvaluationID() string { return "libske_" + newEpoch() }
func newLibraryArtifactID() string        { return "libart_" + newEpoch() }
func newLibraryArtifactVersionID() string { return "libartv_" + newEpoch() }
func newLibraryArtifactGrantID() string   { return "libartg_" + newEpoch() }
func newLibraryRunID() string             { return "librun_" + newEpoch() }

func libraryDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func librarySlugFromName(name string) string {
	var builder strings.Builder
	previousDash := false
	for _, character := range strings.ToLower(strings.TrimSpace(name)) {
		switch {
		case character >= 'a' && character <= 'z', character >= '0' && character <= '9':
			builder.WriteRune(character)
			previousDash = false
		case !previousDash && builder.Len() > 0:
			builder.WriteByte('-')
			previousDash = true
		}
	}
	slug := strings.Trim(builder.String(), "-")
	if len(slug) > 128 {
		slug = strings.TrimRight(slug[:128], "-")
	}
	return slug
}

var libraryCapabilityPattern = regexp.MustCompile(`^[a-z][a-z0-9_.:-]{0,127}$`)
var librarySlugPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,127}$`)
var libraryDigestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

func normalizeLibraryCapabilities(values []string) ([]string, error) {
	if len(values) > libraryMaxCapabilities {
		return nil, fmt.Errorf("at most %d capabilities are allowed", libraryMaxCapabilities)
	}
	seen := make(map[string]struct{}, len(values))
	for _, raw := range values {
		value := strings.ToLower(strings.TrimSpace(raw))
		if !libraryCapabilityPattern.MatchString(value) {
			return nil, fmt.Errorf("invalid capability %q", raw)
		}
		seen[value] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for value := range seen {
		out = append(out, value)
	}
	sort.Strings(out)
	return out, nil
}

// ResolveLibraryCapabilities is deliberately an intersection. A skill's
// request and a binding's ceiling can reduce authority, never expand it.
func ResolveLibraryCapabilities(requested, bindingCeiling, runtimeGranted []string) []string {
	allowed := make(map[string]struct{}, len(runtimeGranted))
	for _, capability := range runtimeGranted {
		allowed[capability] = struct{}{}
	}
	if len(bindingCeiling) > 0 {
		ceiling := make(map[string]struct{}, len(bindingCeiling))
		for _, capability := range bindingCeiling {
			ceiling[capability] = struct{}{}
		}
		for capability := range allowed {
			if _, ok := ceiling[capability]; !ok {
				delete(allowed, capability)
			}
		}
	}
	out := make([]string, 0, len(requested))
	for _, capability := range requested {
		if _, ok := allowed[capability]; ok {
			out = append(out, capability)
		}
	}
	sort.Strings(out)
	return out
}

func validateLibrarySkill(skill LibrarySkill) error {
	if strings.TrimSpace(skill.Name) == "" || len(skill.Name) > libraryMaxNameBytes {
		return fmt.Errorf("skill name is required and must be at most %d bytes", libraryMaxNameBytes)
	}
	if len(skill.Description) > libraryMaxDescriptionBytes {
		return fmt.Errorf("skill description must be at most %d bytes", libraryMaxDescriptionBytes)
	}
	if skill.Slug == "" || !librarySlugPattern.MatchString(skill.Slug) {
		return fmt.Errorf("invalid skill slug")
	}
	return validateLibraryOpaqueRef("created by", skill.CreatedBy, true)
}

func validateLibrarySkillVersion(version LibrarySkillVersion) error {
	if version.SkillID == "" {
		return errors.New("skill id is required")
	}
	if len(version.Content) > libraryMaxContentBytes {
		return fmt.Errorf("skill content must be at most %d bytes", libraryMaxContentBytes)
	}
	if strings.TrimSpace(version.Content) == "" {
		return errors.New("skill content is required")
	}
	if _, err := normalizeLibraryCapabilities(version.RequestedCapabilities); err != nil {
		return err
	}
	return validateLibraryOpaqueRef("created by", version.CreatedBy, true)
}

func validateLibrarySkillDraft(draft LibrarySkillDraft) error {
	if strings.TrimSpace(draft.Name) == "" || len(draft.Name) > libraryMaxNameBytes {
		return fmt.Errorf("draft name is required and must be at most %d bytes", libraryMaxNameBytes)
	}
	if len(draft.Description) > libraryMaxDescriptionBytes || len(draft.Content) > libraryMaxContentBytes || strings.TrimSpace(draft.Content) == "" {
		return errors.New("draft content or description is invalid")
	}
	if draft.Origin != LibraryDraftOriginGenerated && draft.Origin != LibraryDraftOriginManual {
		return fmt.Errorf("invalid draft origin %q", draft.Origin)
	}
	if draft.Origin == LibraryDraftOriginGenerated && strings.TrimSpace(draft.Generator) == "" {
		return errors.New("generated draft requires generator provenance")
	}
	if len(draft.Generator) > libraryMaxNameBytes || len(draft.Model) > libraryMaxNameBytes {
		return errors.New("draft generator metadata is too long")
	}
	if err := validateLibraryDigest("prompt", draft.PromptDigest, draft.Origin == LibraryDraftOriginManual); err != nil {
		return err
	}
	if _, err := normalizeLibraryCapabilities(draft.RequestedCapabilities); err != nil {
		return err
	}
	return validateLibraryOpaqueRef("created by", draft.CreatedBy, true)
}

func validateLibraryBinding(binding LibrarySkillBinding) error {
	if binding.SkillID == "" || !validLibraryScopeKind(binding.ScopeKind) || strings.TrimSpace(binding.ScopeID) == "" {
		return errors.New("skill id, scope kind, and scope id are required")
	}
	if len(binding.ScopeID) > libraryMaxOpaqueRefBytes {
		return fmt.Errorf("scope id must be at most %d bytes", libraryMaxOpaqueRefBytes)
	}
	if binding.Mode != LibraryBindingModePin && binding.Mode != LibraryBindingModeTrack {
		return fmt.Errorf("invalid binding mode %q", binding.Mode)
	}
	if binding.Mode == LibraryBindingModePin && binding.PinnedVersionID == "" {
		return errors.New("pinned version id is required for a pin binding")
	}
	if binding.Mode == LibraryBindingModeTrack && binding.PinnedVersionID != "" {
		return errors.New("track binding cannot pin a version")
	}
	if _, err := normalizeLibraryCapabilities(binding.CapabilityCeiling); err != nil {
		return err
	}
	return validateLibraryOpaqueRef("created by", binding.CreatedBy, true)
}

func validLibraryScopeKind(kind string) bool {
	switch kind {
	case LibraryScopeWorkspace, LibraryScopeNamespace, LibraryScopeFolder, LibraryScopeRepository, LibraryScopeProject, LibraryScopeAgentSurface:
		return true
	default:
		return false
	}
}

func validateLibraryEvaluation(evaluation LibrarySkillEvaluation) error {
	if evaluation.SkillID == "" || evaluation.SkillVersionID == "" || strings.TrimSpace(evaluation.Evaluator) == "" {
		return errors.New("skill id, skill version id, and evaluator are required")
	}
	if len(evaluation.Evaluator) > libraryMaxNameBytes || len(evaluation.Summary) > libraryMaxDescriptionBytes || evaluation.Score < 0 || evaluation.Score > 100 {
		return errors.New("invalid evaluation")
	}
	if err := validateLibraryDigest("evidence", evaluation.EvidenceDigest, true); err != nil {
		return err
	}
	return validateLibraryOpaqueRef("created by", evaluation.CreatedBy, true)
}

func validateLibraryRun(run LibraryRun) error {
	if run.Attestation != "" && run.Attestation != LibraryRunAttestationHost {
		return errors.New("invalid run attestation")
	}
	if run.Attestation != "" && run.Origin != LibraryRunOriginSkillRun {
		return errors.New("only skill runs may carry an attestation")
	}
	switch run.Origin {
	case LibraryRunOriginSkillRun:
		if run.SkillID == "" || run.SkillVersionID == "" || run.BindingID == "" {
			return errors.New("skill run provenance requires skill, version, and binding")
		}
		if err := validateLibraryArtifactSourceReference(run.SourceArtifactID, run.SourceArtifactVersionID, run.SourceArtifactDigest, false); err != nil {
			return err
		}
	case LibraryRunOriginAgentDirect, LibraryRunOriginAutomation, LibraryRunOriginHuman:
		if run.SkillID != "" || run.SkillVersionID != "" || run.BindingID != "" {
			return errors.New("non-skill run must not claim skill provenance")
		}
		if err := validateLibraryArtifactSourceReference(run.SourceArtifactID, run.SourceArtifactVersionID, run.SourceArtifactDigest, run.Origin == LibraryRunOriginAgentDirect); err != nil {
			return err
		}
	default:
		return fmt.Errorf("invalid run origin %q", run.Origin)
	}
	if strings.TrimSpace(run.Status) == "" || len(run.Status) > 64 {
		return errors.New("run status is required")
	}
	if _, err := normalizeLibraryCapabilities(run.EffectiveCapabilities); err != nil {
		return err
	}
	if err := validateLibraryOpaqueRef("actor", run.ActorRef, true); err != nil {
		return err
	}
	if err := validateLibraryOpaqueRef("surface", run.SurfaceRef, true); err != nil {
		return err
	}
	if err := validateLibraryDigest("run input", run.InputDigest, true); err != nil {
		return err
	}
	return validateLibraryDigest("run output", run.OutputDigest, true)
}

func validateLibraryArtifact(artifact LibraryArtifact) error {
	if strings.TrimSpace(artifact.Title) == "" || len(artifact.Title) > libraryMaxNameBytes {
		return fmt.Errorf("artifact title is required and must be at most %d bytes", libraryMaxNameBytes)
	}
	if len(artifact.Summary) > libraryMaxDescriptionBytes {
		return fmt.Errorf("artifact summary must be at most %d bytes", libraryMaxDescriptionBytes)
	}
	switch artifact.Origin {
	case LibraryArtifactOriginSkillRun:
		if artifact.RunID == "" || artifact.SkillID == "" || artifact.SkillVersionID == "" || artifact.BindingID == "" {
			return errors.New("skill-run artifact requires complete skill provenance")
		}
		if err := validateLibraryArtifactSourceReference(artifact.SourceArtifactID, artifact.SourceArtifactVersionID, artifact.SourceArtifactDigest, false); err != nil {
			return err
		}
	case LibraryArtifactOriginAgentDirect, LibraryArtifactOriginAutomation, LibraryArtifactOriginHuman:
		if artifact.SkillID != "" || artifact.SkillVersionID != "" || artifact.BindingID != "" {
			return errors.New("non-skill artifact must not claim skill provenance")
		}
		if err := validateLibraryArtifactSourceReference(artifact.SourceArtifactID, artifact.SourceArtifactVersionID, artifact.SourceArtifactDigest, artifact.Origin == LibraryArtifactOriginAgentDirect); err != nil {
			return err
		}
		if artifact.SourceArtifactID != "" && artifact.RunID == "" {
			return errors.New("an artifact source reference requires direct run provenance")
		}
	default:
		return fmt.Errorf("invalid artifact origin %q", artifact.Origin)
	}
	if artifact.AgentSurfaceID != "" {
		if artifact.RunID == "" || (artifact.Origin != LibraryArtifactOriginAgentDirect && artifact.Origin != LibraryArtifactOriginSkillRun) {
			return errors.New("agent surface projection requires direct or host-attested skill-run provenance")
		}
		if err := validateLibraryOpaqueRef("agent surface", artifact.AgentSurfaceID, false); err != nil {
			return err
		}
	}
	return validateLibraryOpaqueRef("created by", artifact.CreatedBy, true)
}

func validateLibraryArtifactVersion(version LibraryArtifactVersion) error {
	if version.ArtifactID == "" {
		return errors.New("artifact id is required")
	}
	if len(version.Body) > libraryMaxContentBytes {
		return fmt.Errorf("artifact body must be at most %d bytes", libraryMaxContentBytes)
	}
	if version.Format != LibraryArtifactFormatMarkdown && version.Format != LibraryArtifactFormatText {
		return fmt.Errorf("invalid artifact format %q", version.Format)
	}
	return validateLibraryOpaqueRef("created by", version.CreatedBy, true)
}

// validateLibraryArtifactSourceReference makes source lineage all-or-nothing.
// A source is only meaningful when it resolves one immutable artifact version
// and its digest. Allowing a bare artifact ID would accidentally mean "latest"
// and would make grants mutable by later artifact edits.
func validateLibraryArtifactSourceReference(artifactID, versionID, digest string, allow bool) error {
	hasAny := artifactID != "" || versionID != "" || digest != ""
	if !hasAny {
		return nil
	}
	if !allow {
		return errors.New("artifact source references are allowed only for direct agent provenance")
	}
	if err := validateLibraryOpaqueRef("source artifact", artifactID, false); err != nil {
		return err
	}
	if err := validateLibraryOpaqueRef("source artifact version", versionID, false); err != nil {
		return err
	}
	return validateLibraryDigest("source artifact", digest, false)
}

func validateLibraryArtifactGrant(grant LibraryArtifactGrant) error {
	if err := validateLibraryOpaqueRef("artifact", grant.ArtifactID, false); err != nil {
		return err
	}
	if err := validateLibraryOpaqueRef("artifact version", grant.ArtifactVersionID, false); err != nil {
		return err
	}
	if err := validateLibraryDigest("artifact version", grant.ArtifactVersionDigest, false); err != nil {
		return err
	}
	if err := validateLibraryOpaqueRef("agent surface", grant.AgentSurfaceID, false); err != nil {
		return err
	}
	if err := validateLibraryOpaqueRef("created by", grant.CreatedBy, true); err != nil {
		return err
	}
	if err := validateLibraryOpaqueRef("revoked by", grant.RevokedBy, true); err != nil {
		return err
	}
	if !grant.RevokedAt.IsZero() && grant.RevokedBy == "" {
		return errors.New("revoked artifact grant requires a revoker")
	}
	if grant.RevokedAt.IsZero() && grant.RevokedBy != "" {
		return errors.New("live artifact grant cannot name a revoker")
	}
	return nil
}

func validateLibraryOpaqueRef(label, value string, allowEmpty bool) error {
	if value == "" && allowEmpty {
		return nil
	}
	if strings.TrimSpace(value) == "" || len(value) > libraryMaxOpaqueRefBytes {
		return fmt.Errorf("invalid %s reference", label)
	}
	return nil
}

// validateLibraryDigest keeps fields named "digest" from becoming an escape
// hatch for raw prompts, evidence, or tool payloads. Every Library digest is
// a lowercase SHA-256 hex value produced by libraryDigest.
func validateLibraryDigest(label, value string, allowEmpty bool) error {
	if value == "" && allowEmpty {
		return nil
	}
	if !libraryDigestPattern.MatchString(value) {
		return fmt.Errorf("invalid %s digest", label)
	}
	return nil
}

func normalizedLibraryVersion(version LibrarySkillVersion) (LibrarySkillVersion, error) {
	if err := validateLibrarySkillVersion(version); err != nil {
		return LibrarySkillVersion{}, err
	}
	capabilities, err := normalizeLibraryCapabilities(version.RequestedCapabilities)
	if err != nil {
		return LibrarySkillVersion{}, err
	}
	version.RequestedCapabilities = capabilities
	version.Digest = libraryDigest(version.Content)
	if version.CreatedAt.IsZero() {
		version.CreatedAt = time.Now().UTC()
	}
	return version, nil
}

func normalizedLibraryArtifactVersion(version LibraryArtifactVersion) (LibraryArtifactVersion, error) {
	if err := validateLibraryArtifactVersion(version); err != nil {
		return LibraryArtifactVersion{}, err
	}
	version.Digest = libraryDigest(version.Body)
	version.SizeBytes = int64(len([]byte(version.Body)))
	version.RedactionStatus = LibraryRedactionPending
	version.ReviewedBy = ""
	version.ReviewedAt = time.Time{}
	version.PublicationClaimedAt = time.Time{}
	if version.CreatedAt.IsZero() {
		version.CreatedAt = time.Now().UTC()
	}
	return version, nil
}

func normalizedLibraryArtifactGrant(grant LibraryArtifactGrant) (LibraryArtifactGrant, error) {
	if err := validateLibraryArtifactGrant(grant); err != nil {
		return LibraryArtifactGrant{}, err
	}
	if grant.CreatedAt.IsZero() {
		grant.CreatedAt = time.Now().UTC()
	}
	return grant, nil
}

func normalizedLibraryBinding(binding LibrarySkillBinding) (LibrarySkillBinding, error) {
	if err := validateLibraryBinding(binding); err != nil {
		return LibrarySkillBinding{}, err
	}
	capabilities, err := normalizeLibraryCapabilities(binding.CapabilityCeiling)
	if err != nil {
		return LibrarySkillBinding{}, err
	}
	binding.CapabilityCeiling = capabilities
	if binding.CreatedAt.IsZero() {
		binding.CreatedAt = time.Now().UTC()
	}
	binding.UpdatedAt = time.Now().UTC()
	return binding, nil
}

func normalizedLibraryRun(run LibraryRun) (LibraryRun, error) {
	if err := validateLibraryRun(run); err != nil {
		return LibraryRun{}, err
	}
	capabilities, err := normalizeLibraryCapabilities(run.EffectiveCapabilities)
	if err != nil {
		return LibraryRun{}, err
	}
	run.EffectiveCapabilities = capabilities
	if run.StartedAt.IsZero() {
		run.StartedAt = time.Now().UTC()
	}
	if run.CompletedAt.IsZero() {
		run.CompletedAt = run.StartedAt
	}
	return run, nil
}

// prepareLibraryMCPClientArtifact derives every mutable provenance field for a
// subject-bound MCP direct artifact. Store implementations still verify the
// supplied registration is live in their own lock/transaction, but callers
// never get to nominate the actor, surface, run ID, or artifact ownership.
func prepareLibraryMCPClientArtifact(client MCPClient, artifact LibraryArtifact, version LibraryArtifactVersion) (LibraryRun, LibraryArtifact, LibraryArtifactVersion, error) {
	if err := validateLibraryOpaqueRef("agent surface", client.ID, false); err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
	}
	if err := validateLibraryOpaqueRef("client subject", client.Subject, false); err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
	}
	if artifact.Origin != LibraryArtifactOriginAgentDirect || artifact.ID != "" || artifact.RunID != "" || artifact.CreatedBy != "" || artifact.AgentSurfaceID != "" {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, errors.New("MCP client artifact must derive direct provenance")
	}
	if version.ID != "" || version.ArtifactID != "" || version.Version != 0 || version.CreatedBy != "" {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, errors.New("MCP client artifact version must derive immutable identity")
	}

	artifact.ID = newLibraryArtifactID()
	artifact.RunID = newLibraryRunID()
	artifact.CreatedBy = client.Subject
	artifact.AgentSurfaceID = client.ID
	if artifact.CreatedAt.IsZero() {
		artifact.CreatedAt = time.Now().UTC()
	}
	if err := validateLibraryArtifact(artifact); err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
	}

	version.ArtifactID = artifact.ID
	version.Version = 1
	version.CreatedBy = client.Subject
	if version.CreatedAt.IsZero() {
		version.CreatedAt = artifact.CreatedAt
	}
	normalizedVersion, err := normalizedLibraryArtifactVersion(version)
	if err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
	}
	normalizedVersion.ID = newLibraryArtifactVersionID()

	run, err := normalizedLibraryRun(LibraryRun{
		ID:                      artifact.RunID,
		Origin:                  LibraryRunOriginAgentDirect,
		ActorRef:                client.Subject,
		SurfaceRef:              client.ID,
		Status:                  "succeeded",
		InputDigest:             libraryDigest(artifact.Title + "\n" + normalizedVersion.Body),
		OutputDigest:            libraryDigest(normalizedVersion.Body),
		SourceArtifactID:        artifact.SourceArtifactID,
		SourceArtifactVersionID: artifact.SourceArtifactVersionID,
		SourceArtifactDigest:    artifact.SourceArtifactDigest,
		StartedAt:               artifact.CreatedAt,
		CompletedAt:             artifact.CreatedAt,
	})
	if err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
	}
	return run, artifact, normalizedVersion, nil
}

// prepareLibraryRootMCPArtifact is the root-resource counterpart to the
// subject-bound MCP helper above. The caller supplies only authored artifact
// fields; it cannot nominate a run ID, actor, surface, or structural client
// projection. Root artifacts intentionally have no AgentSurfaceID, so they
// never appear in a subject-bound client projection.
func prepareLibraryRootMCPArtifact(artifact LibraryArtifact, version LibraryArtifactVersion) (LibraryRun, LibraryArtifact, LibraryArtifactVersion, error) {
	if artifact.Origin != LibraryArtifactOriginAgentDirect || artifact.ID != "" || artifact.RunID != "" || artifact.CreatedBy != "" || artifact.AgentSurfaceID != "" {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, errors.New("root MCP artifact must derive direct provenance")
	}
	if version.ID != "" || version.ArtifactID != "" || version.Version != 0 || version.CreatedBy != "" {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, errors.New("root MCP artifact version must derive immutable identity")
	}

	artifact.ID = newLibraryArtifactID()
	artifact.RunID = newLibraryRunID()
	artifact.CreatedBy = libraryRootMCPActorRef
	if artifact.CreatedAt.IsZero() {
		artifact.CreatedAt = time.Now().UTC()
	}
	if err := validateLibraryArtifact(artifact); err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
	}

	version.ArtifactID = artifact.ID
	version.Version = 1
	version.CreatedBy = libraryRootMCPActorRef
	if version.CreatedAt.IsZero() {
		version.CreatedAt = artifact.CreatedAt
	}
	normalizedVersion, err := normalizedLibraryArtifactVersion(version)
	if err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
	}
	normalizedVersion.ID = newLibraryArtifactVersionID()

	run, err := normalizedLibraryRun(LibraryRun{
		ID:                      artifact.RunID,
		Origin:                  LibraryRunOriginAgentDirect,
		ActorRef:                libraryRootMCPActorRef,
		SurfaceRef:              libraryRootMCPSurfaceRef,
		Status:                  "succeeded",
		InputDigest:             libraryDigest(artifact.Title + "\n" + normalizedVersion.Body),
		OutputDigest:            libraryDigest(normalizedVersion.Body),
		SourceArtifactID:        artifact.SourceArtifactID,
		SourceArtifactVersionID: artifact.SourceArtifactVersionID,
		SourceArtifactDigest:    artifact.SourceArtifactDigest,
		StartedAt:               artifact.CreatedAt,
		CompletedAt:             artifact.CreatedAt,
	})
	if err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
	}
	return run, artifact, normalizedVersion, nil
}

func normalizeLibraryMCPClientArtifactPageLimit(limit int) (int, error) {
	if limit == 0 {
		return libraryMCPClientArtifactPageDefault, nil
	}
	if limit < 0 || limit > libraryMCPClientArtifactPageMax {
		return 0, fmt.Errorf("artifact page limit must be between 1 and %d", libraryMCPClientArtifactPageMax)
	}
	return limit, nil
}

func normalizeLibraryMCPRootPageLimit(limit int) (int, error) {
	if limit == 0 {
		return libraryMCPRootPageDefault, nil
	}
	if limit < 0 || limit > libraryMCPRootPageMax {
		return 0, fmt.Errorf("root MCP page limit must be between 1 and %d", libraryMCPRootPageMax)
	}
	return limit, nil
}

func normalizeLibraryConsolePageLimit(limit int) (int, error) {
	if limit == 0 {
		return libraryConsolePageDefault, nil
	}
	if limit < 0 || limit > libraryConsolePageMax {
		return 0, fmt.Errorf("library console page limit must be between 1 and %d", libraryConsolePageMax)
	}
	return limit, nil
}

func validateLibraryMCPRootPageCursor(cursor LibraryMCPRootPageCursor) error {
	if cursor.CreatedAt.IsZero() != (cursor.ID == "") {
		return errors.New("invalid root MCP page cursor")
	}
	if cursor.ID != "" {
		if err := validateLibraryOpaqueRef("root MCP page cursor", cursor.ID, false); err != nil {
			return err
		}
	}
	return nil
}

func validateLibraryConsolePageCursor(cursor LibraryConsolePageCursor) error {
	if cursor.Timestamp.IsZero() != (cursor.ID == "") {
		return errors.New("invalid library console page cursor")
	}
	if cursor.ID != "" {
		if err := validateLibraryOpaqueRef("library console page cursor", cursor.ID, false); err != nil {
			return err
		}
	}
	return nil
}

func copyLibrarySkill(skill LibrarySkill) LibrarySkill { return skill }

func copyLibrarySkillVersion(version LibrarySkillVersion) LibrarySkillVersion {
	version.RequestedCapabilities = append([]string(nil), version.RequestedCapabilities...)
	return version
}

func copyLibrarySkillDraft(draft LibrarySkillDraft) LibrarySkillDraft {
	draft.RequestedCapabilities = append([]string(nil), draft.RequestedCapabilities...)
	return draft
}

func copyLibrarySkillBinding(binding LibrarySkillBinding) LibrarySkillBinding {
	binding.CapabilityCeiling = append([]string(nil), binding.CapabilityCeiling...)
	return binding
}

func copyLibrarySkillEvaluation(evaluation LibrarySkillEvaluation) LibrarySkillEvaluation {
	return evaluation
}

func copyLibraryArtifact(artifact LibraryArtifact) LibraryArtifact { return artifact }

// libraryArtifactMetadata strips private provenance identifiers from a list
// projection. Artifact read enforces the separate exact-ID authorization path.
func libraryArtifactMetadata(artifact LibraryArtifact) LibraryArtifact {
	return LibraryArtifact{
		ID:        artifact.ID,
		Title:     artifact.Title,
		Summary:   artifact.Summary,
		Origin:    artifact.Origin,
		CreatedAt: artifact.CreatedAt,
	}
}

func copyLibraryArtifactVersion(version LibraryArtifactVersion) LibraryArtifactVersion {
	return version
}

// libraryArtifactVersionMetadata strips private body and author/reviewer data
// from a list projection. Callers that need a body must go through the
// separately authorized exact-artifact read path.
func libraryArtifactVersionMetadata(version LibraryArtifactVersion) LibraryArtifactVersion {
	return LibraryArtifactVersion{
		ID:              version.ID,
		ArtifactID:      version.ArtifactID,
		Version:         version.Version,
		Format:          version.Format,
		Digest:          version.Digest,
		SizeBytes:       version.SizeBytes,
		RedactionStatus: version.RedactionStatus,
		CreatedAt:       version.CreatedAt,
	}
}

func copyLibraryArtifactGrant(grant LibraryArtifactGrant) LibraryArtifactGrant { return grant }

func copyLibraryRun(run LibraryRun) LibraryRun {
	run.EffectiveCapabilities = append([]string(nil), run.EffectiveCapabilities...)
	return run
}

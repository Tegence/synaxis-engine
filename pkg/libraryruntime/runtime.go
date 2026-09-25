// Package libraryruntime is a small, provider-neutral reference adapter for
// hosts that consume Synaxis Library activation bundles.
//
// It intentionally does not execute tools, fetch credentials, resolve
// connections, authenticate a user, or inject text into any model. Those are
// host responsibilities. The package verifies the deterministic, context-only
// activation format, creates a bounded canonical context document, and offers
// a host-owned interception point that intersects live host grants with the
// selected skill's requested capabilities and binding ceiling immediately
// before a tool call.
//
// A valid activation-bundle digest is an integrity check, not a signature or
// authorization grant. Hosts must obtain the bundle over an authenticated
// channel and independently authenticate and authorize every action.
package libraryruntime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

// ActivationContractVersion is the only Engine activation contract understood
// by this reference adapter. A changed Engine contract must use a new version
// rather than silently changing how a host interprets instructions.
const ActivationContractVersion = "synaxis.library.activation.v1"

// ActivationContractVersionV2 is v1 plus each selected version's bundle
// manifest (file paths, media types, sizes, and SHA-256 digests) and one extra
// host responsibility: fetch bundle files on demand and verify each against
// its digest. File bytes are never inlined into an activation bundle.
const ActivationContractVersionV2 = "synaxis.library.activation.v2"

// SupportedActivationContracts lists the contracts this adapter verifies.
func SupportedActivationContracts() []string {
	return []string{ActivationContractVersion, ActivationContractVersionV2}
}

func supportedActivationContract(contract string) bool {
	return contract == ActivationContractVersion || contract == ActivationContractVersionV2
}

// SkillRunEvidenceContractVersion describes the host-side, immutable evidence
// input produced after a single tool call has been authorized. It is not an
// Engine write API or an authorization token.
const SkillRunEvidenceContractVersion = "synaxis.library.skill-run-evidence.v1"

// SkillRunOrigin is the Engine-compatible provenance source for evidence made
// from a selected immutable Library skill.
const SkillRunOrigin = "skill_run"

var (
	// ErrUnsupportedActivationContract means the host must not interpret this
	// bundle with this adapter.
	ErrUnsupportedActivationContract = errors.New("unsupported library activation contract")
	// ErrActivationIntegrity means the JSON shape, instruction digests, or
	// deterministic bundle digest do not match the v1 contract.
	ErrActivationIntegrity = errors.New("library activation integrity check failed")
	// ErrActivationLimit means an untrusted activation payload exceeded a
	// host-configured resource bound. The adapter never truncates instructions.
	ErrActivationLimit = errors.New("library activation exceeds host limit")
	// ErrUnknownSkillSelection means a host tried to authorize a skill tuple
	// that is not in the verified immutable activation snapshot.
	ErrUnknownSkillSelection = errors.New("library skill selection is not in activation bundle")
	// ErrToolDenied means the host's live grant, the skill request, and the
	// binding ceiling did not all allow the tool's required capability.
	ErrToolDenied = errors.New("library tool call denied")
	// ErrInvalidToolCall means the host did not provide a complete canonical
	// capability mapping for the tool call.
	ErrInvalidToolCall = errors.New("invalid library tool call")
)

const (
	defaultMaxBundleBytes = 256 << 10
	// One Engine-owned operating guide is delivered alongside the existing
	// budget of 32 workspace-assigned skills.
	defaultMaxSkills = 33
	// Preserve the prior 128 KiB workspace-instruction budget when the managed
	// guide is added. Its exact canonical Context selection is bounded by this
	// separate 4 KiB reserve; hosts may still choose lower explicit limits.
	defaultManagedGuideContextReserve = 4 << 10
	defaultMaxInstructionBytes        = 32 << 10
	defaultMaxContextBytes            = (128 << 10) + defaultManagedGuideContextReserve
	maxCapabilities                   = 64
	maxOpaqueRefBytes                 = 512
	maxNameBytes                      = 160
)

var (
	capabilityPattern = regexp.MustCompile(`^[a-z][a-z0-9_.:-]{0,127}$`)
	digestPattern     = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

// Limits bound hostile or unexpectedly large activation data. Zero values use
// conservative defaults; negative values are rejected. Hosts may lower the
// defaults for their own context window or runtime policy.
type Limits struct {
	MaxBundleBytes      int
	MaxSkills           int
	MaxInstructionBytes int
	MaxContextBytes     int
}

// DefaultLimits returns the bounds used by zero-value Limits.
func DefaultLimits() Limits {
	return Limits{
		MaxBundleBytes:      defaultMaxBundleBytes,
		MaxSkills:           defaultMaxSkills,
		MaxInstructionBytes: defaultMaxInstructionBytes,
		MaxContextBytes:     defaultMaxContextBytes,
	}
}

func normalizedLimits(limits Limits) (Limits, error) {
	defaults := DefaultLimits()
	values := []*int{
		&limits.MaxBundleBytes,
		&limits.MaxSkills,
		&limits.MaxInstructionBytes,
		&limits.MaxContextBytes,
	}
	defaultValues := []int{
		defaults.MaxBundleBytes,
		defaults.MaxSkills,
		defaults.MaxInstructionBytes,
		defaults.MaxContextBytes,
	}
	for index, value := range values {
		if *value < 0 {
			return Limits{}, fmt.Errorf("%w: limits must not be negative", ErrActivationLimit)
		}
		if *value == 0 {
			*value = defaultValues[index]
		}
	}
	return limits, nil
}

// ActivationBundle mirrors the portable JSON returned by Engine's
// library_skill_activation tool. It contains only context and authored
// constraints: it has no credential, connection, grant, tool, or actor data.
type ActivationBundle struct {
	ContractVersion      string       `json:"contractVersion"`
	AgentSurface         AgentSurface `json:"agentSurface"`
	Skills               []Skill      `json:"skills"`
	BundleDigest         string       `json:"bundleDigest"`
	AuthorityNotice      string       `json:"authorityNotice"`
	HostResponsibilities []string     `json:"hostResponsibilities"`
}

// AgentSurface is an opaque durable Engine identifier. It is deliberately not
// a user identity, credential, OAuth client ID, endpoint URL, or grant.
type AgentSurface struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}

// Skill is one immutable instruction version selected for an agent surface.
// RequestedCapabilities and Binding.CapabilityCeiling are constraints only;
// neither is an effective grant.
type Skill struct {
	SkillID       string      `json:"skillId"`
	SkillSlug     string      `json:"skillSlug"`
	SkillName     string      `json:"skillName"`
	VersionID     string      `json:"versionId"`
	Version       int         `json:"version"`
	Instructions  string      `json:"instructions"`
	ContentDigest string      `json:"contentDigest"`
	Binding       Binding     `json:"binding"`
	Constraints   Constraints `json:"constraints"`
	// Manifest is present under v2 only. It describes the version's bundle;
	// the host fetches each file separately and verifies it by digest.
	Manifest *Manifest `json:"manifest,omitempty"`
}

// Manifest is a v2 bundle description. ManifestDigest is deterministic over
// Files (see manifestDigest) and covers metadata and file digests only.
type Manifest struct {
	ManifestDigest string         `json:"manifestDigest"`
	Files          []ManifestFile `json:"files"`
}

// ManifestFile is one bundle entry. SKILL.md is always present and its digest
// equals the skill's contentDigest. Files are data: a host must never execute
// a bundle script on the strength of this manifest.
type ManifestFile struct {
	Path        string `json:"path"`
	ContentType string `json:"contentType"`
	SizeBytes   int64  `json:"sizeBytes"`
	Digest      string `json:"digest"`
}

const (
	manifestDigestPrefix = "synaxis.library.skill-manifest.v1\n"
	instructionsPath     = "SKILL.md"
	maxManifestFiles     = 256
	maxManifestPathBytes = 255
)

// Binding explains why an immutable version was selected. It does not grant
// a capability, credential, connection, or tool.
type Binding struct {
	ID       string `json:"id"`
	Mode     string `json:"mode"`
	Priority int    `json:"priority"`
}

// Constraints preserve the authored request and binding ceiling. An empty
// CapabilityCeiling means the binding adds no ceiling; a skill still needs a
// matching requested capability and a live host grant to use a tool.
type Constraints struct {
	RequestedCapabilities []string `json:"requestedCapabilities"`
	CapabilityCeiling     []string `json:"capabilityCeiling"`
}

// SkillReference is the immutable skill/version/binding tuple that a host
// must present when asking the interceptor to authorize a tool call.
type SkillReference struct {
	SkillID   string `json:"skillId"`
	VersionID string `json:"versionId"`
	BindingID string `json:"bindingId"`
}

// Reference returns the exact immutable tuple for this selected skill.
func (skill Skill) Reference() SkillReference {
	return SkillReference{
		SkillID:   skill.SkillID,
		VersionID: skill.VersionID,
		BindingID: skill.Binding.ID,
	}
}

// VerifiedActivationBundle is an activation snapshot that passed structural
// and digest verification. Its contents are private and all accessors return
// copies, preventing a caller from mutating a verified selection in place.
type VerifiedActivationBundle struct {
	bundle ActivationBundle
}

// AgentSurface returns a copy of the bundle's opaque agent-surface reference.
func (bundle VerifiedActivationBundle) AgentSurface() AgentSurface {
	return bundle.bundle.AgentSurface
}

// BundleDigest returns the verified deterministic activation digest.
func (bundle VerifiedActivationBundle) BundleDigest() string {
	return bundle.bundle.BundleDigest
}

// Skills returns copied selected immutable skills in Engine's deterministic
// priority order.
func (bundle VerifiedActivationBundle) Skills() []Skill {
	return cloneSkills(bundle.bundle.Skills)
}

// Skill returns one copied selected skill by its exact immutable tuple.
func (bundle VerifiedActivationBundle) Skill(reference SkillReference) (Skill, bool) {
	for _, skill := range bundle.bundle.Skills {
		if skill.SkillID == reference.SkillID && skill.VersionID == reference.VersionID && skill.Binding.ID == reference.BindingID {
			return cloneSkill(skill), true
		}
	}
	return Skill{}, false
}

// DecodeAndVerifyActivationBundle parses exactly one strict JSON activation
// bundle from reader and verifies it under limits. It rejects unknown fields
// so a host cannot accidentally ignore a future authority-bearing field.
func DecodeAndVerifyActivationBundle(reader io.Reader, limits Limits) (VerifiedActivationBundle, error) {
	if reader == nil {
		return VerifiedActivationBundle{}, fmt.Errorf("%w: activation reader is required", ErrActivationIntegrity)
	}
	resolvedLimits, err := normalizedLimits(limits)
	if err != nil {
		return VerifiedActivationBundle{}, err
	}
	payload, err := io.ReadAll(io.LimitReader(reader, int64(resolvedLimits.MaxBundleBytes)+1))
	if err != nil {
		return VerifiedActivationBundle{}, fmt.Errorf("read activation bundle: %w", err)
	}
	if len(payload) > resolvedLimits.MaxBundleBytes {
		return VerifiedActivationBundle{}, fmt.Errorf("%w: bundle is larger than %d bytes", ErrActivationLimit, resolvedLimits.MaxBundleBytes)
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var activation ActivationBundle
	if err := decoder.Decode(&activation); err != nil {
		return VerifiedActivationBundle{}, fmt.Errorf("%w: decode activation bundle: %v", ErrActivationIntegrity, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return VerifiedActivationBundle{}, fmt.Errorf("%w: activation bundle has trailing JSON", ErrActivationIntegrity)
		}
		return VerifiedActivationBundle{}, fmt.Errorf("%w: trailing activation data: %v", ErrActivationIntegrity, err)
	}
	return VerifyActivationBundle(activation, resolvedLimits)
}

// VerifyActivationBundle verifies a previously decoded activation bundle.
// Verification establishes self-consistency only; an authenticated host still
// has to decide whether the transport and remote endpoint are trusted.
func VerifyActivationBundle(activation ActivationBundle, limits Limits) (VerifiedActivationBundle, error) {
	resolvedLimits, err := normalizedLimits(limits)
	if err != nil {
		return VerifiedActivationBundle{}, err
	}
	if !supportedActivationContract(activation.ContractVersion) {
		return VerifiedActivationBundle{}, fmt.Errorf("%w: got %q", ErrUnsupportedActivationContract, activation.ContractVersion)
	}
	if activation.AgentSurface.Kind != "mcp_client" || !validOpaqueRef(activation.AgentSurface.ID, maxOpaqueRefBytes) {
		return VerifiedActivationBundle{}, fmt.Errorf("%w: invalid agent surface", ErrActivationIntegrity)
	}
	if activation.Skills == nil {
		return VerifiedActivationBundle{}, fmt.Errorf("%w: skills must be an array", ErrActivationIntegrity)
	}
	if len(activation.Skills) > resolvedLimits.MaxSkills {
		return VerifiedActivationBundle{}, fmt.Errorf("%w: %d skills exceeds %d", ErrActivationLimit, len(activation.Skills), resolvedLimits.MaxSkills)
	}
	if activation.AuthorityNotice != activationAuthorityNotice || !sameStrings(activation.HostResponsibilities, activationHostResponsibilitiesFor(activation.ContractVersion)) {
		return VerifiedActivationBundle{}, fmt.Errorf("%w: authority contract changed", ErrActivationIntegrity)
	}
	seenSkills := make(map[string]struct{}, len(activation.Skills))
	for index, skill := range activation.Skills {
		if err := validateSkill(skill, resolvedLimits, activation.ContractVersion); err != nil {
			return VerifiedActivationBundle{}, err
		}
		if _, found := seenSkills[skill.SkillID]; found {
			return VerifiedActivationBundle{}, fmt.Errorf("%w: repeated skill %q", ErrActivationIntegrity, skill.SkillID)
		}
		seenSkills[skill.SkillID] = struct{}{}
		if index > 0 && compareSkills(activation.Skills[index-1], skill) >= 0 {
			return VerifiedActivationBundle{}, fmt.Errorf("%w: skills are not in deterministic order", ErrActivationIntegrity)
		}
	}
	if !validDigest(activation.BundleDigest) {
		return VerifiedActivationBundle{}, fmt.Errorf("%w: invalid bundle digest", ErrActivationIntegrity)
	}
	expectedDigest, err := activationDigest(activation)
	if err != nil {
		return VerifiedActivationBundle{}, fmt.Errorf("%w: encode activation digest: %v", ErrActivationIntegrity, err)
	}
	if activation.BundleDigest != expectedDigest {
		return VerifiedActivationBundle{}, fmt.Errorf("%w: bundle digest does not match contents", ErrActivationIntegrity)
	}
	return VerifiedActivationBundle{bundle: cloneActivationBundle(activation)}, nil
}

func validateSkill(skill Skill, limits Limits, contract string) error {
	if !validOpaqueRef(skill.SkillID, maxOpaqueRefBytes) || !validOpaqueRef(skill.SkillSlug, maxOpaqueRefBytes) ||
		!validText(skill.SkillName, maxNameBytes) || !validOpaqueRef(skill.VersionID, maxOpaqueRefBytes) || skill.Version < 1 ||
		!validOpaqueRef(skill.Binding.ID, maxOpaqueRefBytes) || (skill.Binding.Mode != "pin" && skill.Binding.Mode != "track") {
		return fmt.Errorf("%w: invalid selected skill metadata", ErrActivationIntegrity)
	}
	if !utf8.ValidString(skill.Instructions) {
		return fmt.Errorf("%w: skill %q instructions are not valid UTF-8", ErrActivationIntegrity, skill.SkillID)
	}
	if len(skill.Instructions) > limits.MaxInstructionBytes {
		return fmt.Errorf("%w: skill %q instructions exceed %d bytes", ErrActivationLimit, skill.SkillID, limits.MaxInstructionBytes)
	}
	if !validDigest(skill.ContentDigest) || skill.ContentDigest != digestString(skill.Instructions) {
		return fmt.Errorf("%w: skill %q instruction digest does not match", ErrActivationIntegrity, skill.SkillID)
	}
	if err := requireCanonicalCapabilities(skill.Constraints.RequestedCapabilities); err != nil {
		return fmt.Errorf("%w: skill %q requested capabilities: %v", ErrActivationIntegrity, skill.SkillID, err)
	}
	if err := requireCanonicalCapabilities(skill.Constraints.CapabilityCeiling); err != nil {
		return fmt.Errorf("%w: skill %q capability ceiling: %v", ErrActivationIntegrity, skill.SkillID, err)
	}
	switch contract {
	case ActivationContractVersion:
		if skill.Manifest != nil {
			return fmt.Errorf("%w: skill %q carries a manifest under the v1 contract", ErrActivationIntegrity, skill.SkillID)
		}
	case ActivationContractVersionV2:
		if skill.Manifest == nil {
			return fmt.Errorf("%w: skill %q has no manifest under the v2 contract", ErrActivationIntegrity, skill.SkillID)
		}
		if err := validateManifest(*skill.Manifest, skill.Instructions, skill.ContentDigest); err != nil {
			return fmt.Errorf("%w: skill %q manifest: %v", ErrActivationIntegrity, skill.SkillID, err)
		}
	}
	return nil
}

// validateManifest checks the structural manifest invariants a host relies on
// before fetching any file: sorted unique paths, safe relative paths, valid
// digests, a SKILL.md entry that matches the instructions, and a manifest
// digest that matches its entries.
func validateManifest(manifest Manifest, instructions, contentDigest string) error {
	if len(manifest.Files) == 0 || len(manifest.Files) > maxManifestFiles {
		return errors.New("file count is out of range")
	}
	seen := make(map[string]struct{}, len(manifest.Files))
	instructionsSeen := false
	for index, file := range manifest.Files {
		if !validManifestPath(file.Path) {
			return fmt.Errorf("invalid path %q", file.Path)
		}
		if index > 0 && manifest.Files[index-1].Path >= file.Path {
			return errors.New("files are not sorted by path")
		}
		key := strings.ToLower(file.Path)
		if _, duplicate := seen[key]; duplicate {
			return fmt.Errorf("duplicate path %q", file.Path)
		}
		seen[key] = struct{}{}
		if !validText(file.ContentType, 128) || file.SizeBytes < 0 || !validDigest(file.Digest) {
			return fmt.Errorf("invalid entry %q", file.Path)
		}
		if file.Path == instructionsPath {
			instructionsSeen = true
			if file.Digest != contentDigest || file.SizeBytes != int64(len(instructions)) {
				return errors.New("SKILL.md entry does not match the instructions")
			}
		}
	}
	if !instructionsSeen {
		return errors.New("SKILL.md is missing")
	}
	expected, err := manifestDigest(manifest.Files)
	if err != nil {
		return err
	}
	if !validDigest(manifest.ManifestDigest) || manifest.ManifestDigest != expected {
		return errors.New("manifest digest does not match its files")
	}
	return nil
}

func validManifestPath(value string) bool {
	if value == "" || len(value) > maxManifestPathBytes || !utf8.ValidString(value) || strings.HasPrefix(value, "/") || strings.HasSuffix(value, "/") || strings.ContainsAny(value, "\\:") {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "" || segment == "." || segment == ".." || strings.TrimSpace(segment) != segment {
			return false
		}
	}
	return true
}

// manifestDigest mirrors the Engine's canonical manifest material: the
// contract prefix followed by a JSON array of {path, contentType, sizeBytes,
// digest} objects sorted by path, encoded without whitespace or HTML escaping.
func manifestDigest(files []ManifestFile) (string, error) {
	sorted := append([]ManifestFile(nil), files...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Path < sorted[j].Path })
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(sorted); err != nil {
		return "", fmt.Errorf("encode manifest: %w", err)
	}
	encoded := bytes.TrimRight(buffer.Bytes(), "\n")
	return digestString(manifestDigestPrefix + string(encoded)), nil
}

func compareSkills(left, right Skill) int {
	if left.Binding.Priority != right.Binding.Priority {
		if left.Binding.Priority > right.Binding.Priority {
			return -1
		}
		return 1
	}
	for _, values := range [][2]string{
		{left.SkillSlug, right.SkillSlug},
		{left.SkillID, right.SkillID},
		{left.Binding.ID, right.Binding.ID},
	} {
		if values[0] < values[1] {
			return -1
		}
		if values[0] > values[1] {
			return 1
		}
	}
	return 0
}

func activationDigest(activation ActivationBundle) (string, error) {
	// This material and field order intentionally match Engine's v1 digest
	// contract. BundleDigest itself is omitted to avoid self-reference.
	material := struct {
		ContractVersion      string       `json:"contractVersion"`
		AgentSurface         AgentSurface `json:"agentSurface"`
		Skills               []Skill      `json:"skills"`
		AuthorityNotice      string       `json:"authorityNotice"`
		HostResponsibilities []string     `json:"hostResponsibilities"`
	}{
		ContractVersion:      activation.ContractVersion,
		AgentSurface:         activation.AgentSurface,
		Skills:               activation.Skills,
		AuthorityNotice:      activation.AuthorityNotice,
		HostResponsibilities: activation.HostResponsibilities,
	}
	encoded, err := json.Marshal(material)
	if err != nil {
		return "", err
	}
	return digestBytes(encoded), nil
}

const activationAuthorityNotice = "This activation bundle is context only. It grants no credentials, OAuth scopes, permissions, tools, connection access, or effective capabilities. Independently authorize and enforce policy for every action."

var activationHostResponsibilities = []string{
	"Decide whether and how to place these instructions into a host-model turn; Synaxis Engine does not inject or execute them in a third-party host.",
	"Verify each instruction body against contentDigest before use and reject an unsupported contractVersion.",
	"Independently authenticate and enforce every tool, connection, credential, and capability policy immediately before an action; requestedCapabilities and capabilityCeiling are constraints, never grants.",
}

const activationBundleFilesResponsibility = "Fetch bundle files on demand through library_skill_file_read, never from this bundle, and verify each file against its manifest digest before use; files are data that Synaxis never executes."

func activationHostResponsibilitiesFor(contract string) []string {
	responsibilities := append([]string(nil), activationHostResponsibilities...)
	if contract == ActivationContractVersionV2 {
		responsibilities = append(responsibilities, activationBundleFilesResponsibility)
	}
	return responsibilities
}

// Context is a bounded, deterministic host-side representation of selected
// instructions. Document is canonical JSON rather than a prompt template so
// the adapter never chooses a model role or injection mechanism for a host.
type Context struct {
	ContractVersion string             `json:"contractVersion"`
	BundleDigest    string             `json:"bundleDigest"`
	AgentSurface    AgentSurface       `json:"agentSurface"`
	Skills          []ContextSelection `json:"skills"`
	Document        string             `json:"-"`
}

// ContextSelection is a model-agnostic copy of an immutable selected skill.
// Capability constraints are explanatory context only; ToolInterceptor
// enforces them independently and never relies on a model to obey them.
type ContextSelection struct {
	Reference             SkillReference `json:"reference"`
	Name                  string         `json:"name"`
	Instructions          string         `json:"instructions"`
	RequestedCapabilities []string       `json:"requestedCapabilities"`
	CapabilityCeiling     []string       `json:"capabilityCeiling"`
	// Manifest is copied for v2 selections so a host can list the files it may
	// fetch; it carries digests, never bytes.
	Manifest *Manifest `json:"manifest,omitempty"`
}

// BuildContext turns a verified activation into canonical JSON under limits.
// It preserves Engine's deterministic skill order and rejects oversized output
// rather than truncating an instruction body. A host chooses whether, where,
// and how to use Context.Document in a model turn.
func BuildContext(activation VerifiedActivationBundle, limits Limits) (Context, error) {
	resolvedLimits, err := normalizedLimits(limits)
	if err != nil {
		return Context{}, err
	}
	if !supportedActivationContract(activation.bundle.ContractVersion) {
		return Context{}, fmt.Errorf("%w: activation was not verified", ErrActivationIntegrity)
	}
	if len(activation.bundle.Skills) > resolvedLimits.MaxSkills {
		return Context{}, fmt.Errorf("%w: %d skills exceeds %d", ErrActivationLimit, len(activation.bundle.Skills), resolvedLimits.MaxSkills)
	}
	selections := make([]ContextSelection, 0, len(activation.bundle.Skills))
	for _, skill := range activation.bundle.Skills {
		if len(skill.Instructions) > resolvedLimits.MaxInstructionBytes {
			return Context{}, fmt.Errorf("%w: skill %q instructions exceed %d bytes", ErrActivationLimit, skill.SkillID, resolvedLimits.MaxInstructionBytes)
		}
		selections = append(selections, ContextSelection{
			Reference:             skill.Reference(),
			Name:                  skill.SkillName,
			Instructions:          skill.Instructions,
			RequestedCapabilities: append([]string(nil), skill.Constraints.RequestedCapabilities...),
			CapabilityCeiling:     append([]string(nil), skill.Constraints.CapabilityCeiling...),
			Manifest:              cloneManifest(skill.Manifest),
		})
	}
	contextValue := Context{
		ContractVersion: activation.bundle.ContractVersion,
		BundleDigest:    activation.bundle.BundleDigest,
		AgentSurface:    activation.bundle.AgentSurface,
		Skills:          selections,
	}
	// Marshal an explicit material type so Document never contains a model
	// policy or an accidental future Context field.
	material := struct {
		ContractVersion string             `json:"contractVersion"`
		BundleDigest    string             `json:"bundleDigest"`
		AgentSurface    AgentSurface       `json:"agentSurface"`
		AuthorityNotice string             `json:"authorityNotice"`
		Skills          []ContextSelection `json:"skills"`
	}{
		ContractVersion: contextValue.ContractVersion,
		BundleDigest:    contextValue.BundleDigest,
		AgentSurface:    contextValue.AgentSurface,
		AuthorityNotice: activation.bundle.AuthorityNotice,
		Skills:          contextValue.Skills,
	}
	document, err := json.Marshal(material)
	if err != nil {
		return Context{}, fmt.Errorf("encode library context: %w", err)
	}
	if len(document) > resolvedLimits.MaxContextBytes {
		return Context{}, fmt.Errorf("%w: context is larger than %d bytes", ErrActivationLimit, resolvedLimits.MaxContextBytes)
	}
	contextValue.Document = string(document)
	return contextValue, nil
}

// ToolCall is a host-owned mapping from one tool invocation to every
// capability required by that invocation. The host must authenticate the
// caller before it constructs this value and must not let a model choose or
// weaken RequiredCapabilities.
type ToolCall struct {
	Tool                 string   `json:"tool"`
	RequiredCapabilities []string `json:"requiredCapabilities"`
}

// GrantRequest carries the verified activation selection and host-owned tool
// mapping into a live host-policy lookup. AgentSurface and Skill are useful
// policy constraints, not authentication facts: implementations must still
// obtain identity and grants from host-controlled state.
type GrantRequest struct {
	AgentSurface AgentSurface   `json:"agentSurface"`
	Skill        SkillReference `json:"skill"`
	Tool         ToolCall       `json:"tool"`
}

// GrantProvider resolves live grants for a host-authenticated tool call.
// Implementations must obtain identity and policy from host-controlled state
// (for example an authenticated session in context), not from activation data
// or a model. It is called once for every Authorize invocation; do not cache
// its result across tool calls.
type GrantProvider interface {
	GrantedCapabilities(context.Context, GrantRequest) ([]string, error)
}

// ToolInterceptor performs the non-authoritative Library side of per-call
// enforcement. The host still invokes (or denies) its own tool after success.
type ToolInterceptor struct {
	Grants GrantProvider
}

// ToolAuthorization is a successful, per-call authorization. Its fields are
// private so a host cannot construct or mutate an authorization without
// calling ToolInterceptor.Authorize against a verified selection and live
// GrantProvider.
type ToolAuthorization struct {
	reference             SkillReference
	agentSurface          AgentSurface
	bundleDigest          string
	tool                  string
	effectiveCapabilities []string
}

// SkillReference returns the exact immutable skill/version/binding selection
// that was authorized for this tool call.
func (authorization ToolAuthorization) SkillReference() SkillReference {
	return authorization.reference
}

// AgentSurface returns the opaque Engine surface from the verified activation.
func (authorization ToolAuthorization) AgentSurface() AgentSurface {
	return authorization.agentSurface
}

// BundleDigest returns the verified snapshot digest used for authorization.
func (authorization ToolAuthorization) BundleDigest() string {
	return authorization.bundleDigest
}

// Tool returns the host-owned tool identifier that was authorized.
func (authorization ToolAuthorization) Tool() string {
	return authorization.tool
}

// EffectiveCapabilities returns the exact capability set required and allowed
// for this one tool call, not all capabilities a host session happens to have.
func (authorization ToolAuthorization) EffectiveCapabilities() []string {
	return append([]string(nil), authorization.effectiveCapabilities...)
}

// Authorize intersects a fresh host runtime grant with the selected skill's
// requested capabilities and binding ceiling immediately before a tool call.
// Success is not tool execution: the host must invoke its own tool only after
// this method returns and should not cache ToolAuthorization for a later call.
func (interceptor ToolInterceptor) Authorize(ctx context.Context, activation VerifiedActivationBundle, reference SkillReference, call ToolCall) (ToolAuthorization, error) {
	if interceptor.Grants == nil {
		return ToolAuthorization{}, fmt.Errorf("%w: grant provider is required", ErrToolDenied)
	}
	if !supportedActivationContract(activation.bundle.ContractVersion) {
		return ToolAuthorization{}, fmt.Errorf("%w: activation was not verified", ErrActivationIntegrity)
	}
	skill, found := activation.Skill(reference)
	if !found {
		return ToolAuthorization{}, fmt.Errorf("%w: %s/%s/%s", ErrUnknownSkillSelection, reference.SkillID, reference.VersionID, reference.BindingID)
	}
	canonicalCall, err := canonicalToolCall(call)
	if err != nil {
		return ToolAuthorization{}, err
	}
	hostGranted, err := interceptor.Grants.GrantedCapabilities(ctx, GrantRequest{
		AgentSurface: activation.bundle.AgentSurface,
		Skill:        reference,
		Tool:         canonicalCall,
	})
	if err != nil {
		return ToolAuthorization{}, fmt.Errorf("resolve host grants: %w", err)
	}
	if err := requireCanonicalCapabilities(hostGranted); err != nil {
		return ToolAuthorization{}, fmt.Errorf("%w: host grants: %v", ErrToolDenied, err)
	}
	allowed := intersectCapabilities(skill.Constraints.RequestedCapabilities, skill.Constraints.CapabilityCeiling, hostGranted)
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, capability := range allowed {
		allowedSet[capability] = struct{}{}
	}
	for _, capability := range canonicalCall.RequiredCapabilities {
		if _, found := allowedSet[capability]; !found {
			return ToolAuthorization{}, fmt.Errorf("%w: tool %q requires %q", ErrToolDenied, canonicalCall.Tool, capability)
		}
	}
	return ToolAuthorization{
		reference:             reference,
		agentSurface:          activation.bundle.AgentSurface,
		bundleDigest:          activation.bundle.BundleDigest,
		tool:                  canonicalCall.Tool,
		effectiveCapabilities: append([]string(nil), canonicalCall.RequiredCapabilities...),
	}, nil
}

func canonicalToolCall(call ToolCall) (ToolCall, error) {
	if !validOpaqueRef(call.Tool, maxOpaqueRefBytes) || strings.TrimSpace(call.Tool) != call.Tool {
		return ToolCall{}, fmt.Errorf("%w: tool is required", ErrInvalidToolCall)
	}
	if len(call.RequiredCapabilities) == 0 {
		return ToolCall{}, fmt.Errorf("%w: a tool must declare at least one required capability", ErrInvalidToolCall)
	}
	if err := requireCanonicalCapabilities(call.RequiredCapabilities); err != nil {
		return ToolCall{}, fmt.Errorf("%w: required capabilities: %v", ErrInvalidToolCall, err)
	}
	return ToolCall{Tool: call.Tool, RequiredCapabilities: append([]string(nil), call.RequiredCapabilities...)}, nil
}

// SkillRunEvidenceInput is a serializable, credential-free input for a
// separately authenticated host evidence-ingestion boundary. It pins the exact
// skill version and binding selected at authorization time and contains only a
// digest of tool input. Constructing it does not write an Engine run or prove
// that a tool actually executed.
type SkillRunEvidenceInput struct {
	ContractVersion        string   `json:"contractVersion"`
	Origin                 string   `json:"origin"`
	AgentSurfaceID         string   `json:"agentSurfaceId"`
	ActivationBundleDigest string   `json:"activationBundleDigest"`
	SkillID                string   `json:"skillId"`
	SkillVersionID         string   `json:"skillVersionId"`
	BindingID              string   `json:"bindingId"`
	EffectiveCapabilities  []string `json:"effectiveCapabilities"`
	InputDigest            string   `json:"inputDigest"`
}

// SkillRunEvidence returns immutable selection evidence for this authorized
// call. Raw tool input is never retained by the adapter; only its SHA-256
// digest is included. A host should emit this only after it has a trusted
// execution/audit path for recording provenance.
func (authorization ToolAuthorization) SkillRunEvidence(input []byte) (SkillRunEvidenceInput, error) {
	if !validAuthorization(authorization) {
		return SkillRunEvidenceInput{}, fmt.Errorf("%w: authorization was not produced by a valid interception", ErrActivationIntegrity)
	}
	return SkillRunEvidenceInput{
		ContractVersion:        SkillRunEvidenceContractVersion,
		Origin:                 SkillRunOrigin,
		AgentSurfaceID:         authorization.agentSurface.ID,
		ActivationBundleDigest: authorization.bundleDigest,
		SkillID:                authorization.reference.SkillID,
		SkillVersionID:         authorization.reference.VersionID,
		BindingID:              authorization.reference.BindingID,
		EffectiveCapabilities:  append([]string(nil), authorization.effectiveCapabilities...),
		InputDigest:            digestBytes(input),
	}, nil
}

// CompletedSkillRunEvidence adds a digest of the completed tool output to a
// previously created immutable evidence input. It carries no raw input/output,
// credentials, connection data, or authorization grant.
type CompletedSkillRunEvidence struct {
	SkillRunEvidenceInput
	OutputDigest string `json:"outputDigest"`
}

// Complete returns a copy of evidence with a SHA-256 digest of output.
func (evidence SkillRunEvidenceInput) Complete(output []byte) (CompletedSkillRunEvidence, error) {
	if err := validateSkillRunEvidenceInput(evidence); err != nil {
		return CompletedSkillRunEvidence{}, err
	}
	return CompletedSkillRunEvidence{
		SkillRunEvidenceInput: cloneSkillRunEvidenceInput(evidence),
		OutputDigest:          digestBytes(output),
	}, nil
}

func validAuthorization(authorization ToolAuthorization) bool {
	return validOpaqueRef(authorization.reference.SkillID, maxOpaqueRefBytes) &&
		validOpaqueRef(authorization.reference.VersionID, maxOpaqueRefBytes) &&
		validOpaqueRef(authorization.reference.BindingID, maxOpaqueRefBytes) &&
		authorization.agentSurface.Kind == "mcp_client" && validOpaqueRef(authorization.agentSurface.ID, maxOpaqueRefBytes) &&
		validDigest(authorization.bundleDigest) && validOpaqueRef(authorization.tool, maxOpaqueRefBytes) &&
		len(authorization.effectiveCapabilities) > 0 && requireCanonicalCapabilities(authorization.effectiveCapabilities) == nil
}

func validateSkillRunEvidenceInput(evidence SkillRunEvidenceInput) error {
	if evidence.ContractVersion != SkillRunEvidenceContractVersion || evidence.Origin != SkillRunOrigin ||
		!validOpaqueRef(evidence.AgentSurfaceID, maxOpaqueRefBytes) || !validDigest(evidence.ActivationBundleDigest) ||
		!validOpaqueRef(evidence.SkillID, maxOpaqueRefBytes) || !validOpaqueRef(evidence.SkillVersionID, maxOpaqueRefBytes) ||
		!validOpaqueRef(evidence.BindingID, maxOpaqueRefBytes) || !validDigest(evidence.InputDigest) ||
		len(evidence.EffectiveCapabilities) == 0 {
		return fmt.Errorf("%w: invalid skill-run evidence input", ErrActivationIntegrity)
	}
	if err := requireCanonicalCapabilities(evidence.EffectiveCapabilities); err != nil {
		return fmt.Errorf("%w: invalid effective capabilities: %v", ErrActivationIntegrity, err)
	}
	return nil
}

func normalizeCapabilities(values []string) ([]string, error) {
	if len(values) > maxCapabilities {
		return nil, fmt.Errorf("at most %d capabilities are allowed", maxCapabilities)
	}
	seen := make(map[string]struct{}, len(values))
	for _, raw := range values {
		value := strings.ToLower(strings.TrimSpace(raw))
		if !capabilityPattern.MatchString(value) {
			return nil, fmt.Errorf("invalid capability %q", raw)
		}
		seen[value] = struct{}{}
	}
	normalized := make([]string, 0, len(seen))
	for capability := range seen {
		normalized = append(normalized, capability)
	}
	sort.Strings(normalized)
	return normalized, nil
}

func requireCanonicalCapabilities(values []string) error {
	if values == nil {
		return errors.New("capabilities must be an array")
	}
	normalized, err := normalizeCapabilities(values)
	if err != nil {
		return err
	}
	if !sameStrings(values, normalized) {
		return errors.New("capabilities must be lowercase, sorted, and unique")
	}
	return nil
}

func intersectCapabilities(requested, ceiling, hostGranted []string) []string {
	allowed := make(map[string]struct{}, len(hostGranted))
	for _, capability := range hostGranted {
		allowed[capability] = struct{}{}
	}
	if len(ceiling) > 0 {
		ceilingSet := make(map[string]struct{}, len(ceiling))
		for _, capability := range ceiling {
			ceilingSet[capability] = struct{}{}
		}
		for capability := range allowed {
			if _, found := ceilingSet[capability]; !found {
				delete(allowed, capability)
			}
		}
	}
	result := make([]string, 0, len(requested))
	for _, capability := range requested {
		if _, found := allowed[capability]; found {
			result = append(result, capability)
		}
	}
	sort.Strings(result)
	return result
}

func validOpaqueRef(value string, maximum int) bool {
	return validText(value, maximum) && strings.TrimSpace(value) == value
}

func validText(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && utf8.ValidString(value)
}

func validDigest(value string) bool {
	return digestPattern.MatchString(value)
}

func digestString(value string) string {
	return digestBytes([]byte(value))
}

func digestBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func sameStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func cloneActivationBundle(activation ActivationBundle) ActivationBundle {
	copy := activation
	copy.Skills = cloneSkills(activation.Skills)
	copy.HostResponsibilities = append([]string(nil), activation.HostResponsibilities...)
	return copy
}

func cloneSkills(skills []Skill) []Skill {
	copy := make([]Skill, len(skills))
	for index, skill := range skills {
		copy[index] = cloneSkill(skill)
	}
	return copy
}

func cloneSkill(skill Skill) Skill {
	copy := skill
	copy.Constraints.RequestedCapabilities = append([]string(nil), skill.Constraints.RequestedCapabilities...)
	copy.Constraints.CapabilityCeiling = append([]string(nil), skill.Constraints.CapabilityCeiling...)
	copy.Manifest = cloneManifest(skill.Manifest)
	return copy
}

func cloneManifest(manifest *Manifest) *Manifest {
	if manifest == nil {
		return nil
	}
	copy := *manifest
	copy.Files = append([]ManifestFile(nil), manifest.Files...)
	return &copy
}

func cloneSkillRunEvidenceInput(evidence SkillRunEvidenceInput) SkillRunEvidenceInput {
	copy := evidence
	copy.EffectiveCapabilities = append([]string(nil), evidence.EffectiveCapabilities...)
	return copy
}

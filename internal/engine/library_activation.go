package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"unicode/utf8"

	"narthex/backend/pkg/libraryruntime"
)

// LibrarySkillActivationContractVersion identifies the stable, portable
// activation-bundle shape. Hosts can use this to reject a bundle they do not
// understand rather than silently applying a changed interpretation.
const LibrarySkillActivationContractVersion = "synaxis.library.activation.v1"

var (
	ErrLibrarySkillActivationIntegrity = errors.New("library skill activation integrity check failed")
	// ErrLibrarySkillActivationLimit means the Engine refused to construct an
	// activation bundle that the portable default host runtime could not safely
	// consume. It never returns a partial selection.
	ErrLibrarySkillActivationLimit = errors.New("library skill activation exceeds engine safety limit")
)

// LibrarySkillActivationBundle is the context-only handoff from the Engine to
// an external agent host. It is deliberately not an execution plan, an OAuth
// grant, a credential bundle, or a tool allowlist.
//
// The Engine produces this bundle only from a verified agent surface in the
// subject-bound MCP-client projection. An external host decides whether and
// how to inject its Instructions into a model turn, and independently enforces
// every tool/connection policy at execution time.
type LibrarySkillActivationBundle struct {
	ContractVersion      string                             `json:"contractVersion"`
	AgentSurface         LibrarySkillActivationAgentSurface `json:"agentSurface"`
	Skills               []LibrarySkillActivation           `json:"skills"`
	BundleDigest         string                             `json:"bundleDigest"`
	AuthorityNotice      string                             `json:"authorityNotice"`
	HostResponsibilities []string                           `json:"hostResponsibilities"`
}

// LibrarySkillActivationAgentSurface is an opaque, durable Engine identifier.
// It intentionally excludes the client subject, OAuth client ID, endpoint
// slug, connection namespace grants, and any other credential-delivery data.
type LibrarySkillActivationAgentSurface struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}

// LibrarySkillActivation is one selected immutable instruction version. Its
// ContentDigest covers Instructions exactly. Binding and constraint fields are
// context for a host's independent runtime-policy enforcement, not authority.
type LibrarySkillActivation struct {
	SkillID       string                            `json:"skillId"`
	SkillSlug     string                            `json:"skillSlug"`
	SkillName     string                            `json:"skillName"`
	VersionID     string                            `json:"versionId"`
	Version       int                               `json:"version"`
	Instructions  string                            `json:"instructions"`
	ContentDigest string                            `json:"contentDigest"`
	Binding       LibrarySkillActivationBinding     `json:"binding"`
	Constraints   LibrarySkillActivationConstraints `json:"constraints"`
}

// LibrarySkillActivationBinding identifies why this immutable version was
// selected. All bundles produced today use an explicit agent-surface binding;
// scope IDs are intentionally not re-exposed because the endpoint itself is
// the verified surface context.
type LibrarySkillActivationBinding struct {
	ID       string `json:"id"`
	Mode     string `json:"mode"`
	Priority int    `json:"priority"`
}

// LibrarySkillActivationConstraints retains authored intent and the binding
// ceiling separately. Neither field is an effective grant. A host must derive
// any effective authority from its independently authenticated runtime grant.
type LibrarySkillActivationConstraints struct {
	RequestedCapabilities []string `json:"requestedCapabilities"`
	CapabilityCeiling     []string `json:"capabilityCeiling"`
}

const librarySkillActivationAuthorityNotice = "This activation bundle is context only. It grants no credentials, OAuth scopes, permissions, tools, connection access, or effective capabilities. Independently authorize and enforce policy for every action."

var librarySkillActivationHostResponsibilities = []string{
	"Decide whether and how to place these instructions into a host-model turn; Synaxis Engine does not inject or execute them in a third-party host.",
	"Verify each instruction body against contentDigest before use and reject an unsupported contractVersion.",
	"Independently authenticate and enforce every tool, connection, credential, and capability policy immediately before an action; requestedCapabilities and capabilityCeiling are constraints, never grants.",
}

// BuildLibrarySkillActivationBundleForAgentSurface materializes the
// deterministic, context-only activation handoff for one opaque agent-surface
// ID. It performs no client authentication itself: its only network exposure
// is library_skill_activation on a subject-bound MCP-client endpoint, which
// derives this ID from a live durable registration and rejects caller-supplied
// scope context before invoking this function.
//
// The result contains selected immutable versions only. It has no actor,
// credential, connection, OAuth, tool, runtime-grant, or effective-capability
// fields. The caller must treat ErrLibrarySkillActivationIntegrity as a hard
// failure rather than activating a partially trusted bundle.
func BuildLibrarySkillActivationBundleForAgentSurface(ctx context.Context, store LibraryStore, agentSurfaceID string) (LibrarySkillActivationBundle, error) {
	resolution, err := ResolveLibrarySkillsForAgentSurface(ctx, store, agentSurfaceID)
	if err != nil {
		return LibrarySkillActivationBundle{}, err
	}
	return buildLibrarySkillActivationBundleForResolution(agentSurfaceID, resolution)
}

// buildLibrarySkillActivationBundleForResolution is shared by the ordinary
// read-only MCP activation tool and the store-native host-attestation commit
// path. The latter supplies a selection collected under its native lock or
// transaction, so it must not call back into the store while committing.
func buildLibrarySkillActivationBundleForResolution(agentSurfaceID string, resolution LibrarySkillResolution) (LibrarySkillActivationBundle, error) {
	limits := libraryruntime.DefaultLimits()
	bundle := LibrarySkillActivationBundle{
		ContractVersion: LibrarySkillActivationContractVersion,
		AgentSurface: LibrarySkillActivationAgentSurface{
			Kind: "mcp_client",
			ID:   agentSurfaceID,
		},
		Skills:               []LibrarySkillActivation{},
		AuthorityNotice:      librarySkillActivationAuthorityNotice,
		HostResponsibilities: append([]string(nil), librarySkillActivationHostResponsibilities...),
	}

	if len(resolution.Skills) > limits.MaxSkills {
		return LibrarySkillActivationBundle{}, fmt.Errorf("%w: %d selected skills exceeds %d", ErrLibrarySkillActivationLimit, len(resolution.Skills), limits.MaxSkills)
	}
	bundle.Skills = make([]LibrarySkillActivation, 0, len(resolution.Skills))
	instructionBytes := 0
	for _, resolved := range resolution.Skills {
		if resolved.ScopeKind != LibraryScopeAgentSurface || resolved.ScopeID != agentSurfaceID ||
			resolved.BindingID == "" || resolved.SkillID == "" || resolved.VersionID == "" || resolved.Version < 1 {
			return bundle, fmt.Errorf("%w: resolver returned an invalid agent-surface selection", ErrLibrarySkillActivationIntegrity)
		}
		if len(resolved.Content) > limits.MaxInstructionBytes {
			return LibrarySkillActivationBundle{}, fmt.Errorf("%w: skill %q instructions exceed %d bytes", ErrLibrarySkillActivationLimit, resolved.SkillID, limits.MaxInstructionBytes)
		}
		if instructionBytes > limits.MaxContextBytes-len(resolved.Content) {
			return LibrarySkillActivationBundle{}, fmt.Errorf("%w: selected instructions exceed %d bytes", ErrLibrarySkillActivationLimit, limits.MaxContextBytes)
		}
		instructionBytes += len(resolved.Content)
		if !utf8.ValidString(resolved.Content) {
			return bundle, fmt.Errorf("%w: skill %q version %q instructions are not valid UTF-8", ErrLibrarySkillActivationIntegrity, resolved.SkillID, resolved.VersionID)
		}
		if !libraryDigestPattern.MatchString(resolved.Digest) || resolved.Digest != libraryDigest(resolved.Content) {
			return bundle, fmt.Errorf("%w: skill %q version %q digest does not match instructions", ErrLibrarySkillActivationIntegrity, resolved.SkillID, resolved.VersionID)
		}
		requested, err := normalizeLibraryCapabilities(resolved.RequestedCapabilities)
		if err != nil {
			return bundle, fmt.Errorf("%w: skill %q requested capabilities: %v", ErrLibrarySkillActivationIntegrity, resolved.SkillID, err)
		}
		ceiling, err := normalizeLibraryCapabilities(resolved.CapabilityCeiling)
		if err != nil {
			return bundle, fmt.Errorf("%w: skill %q capability ceiling: %v", ErrLibrarySkillActivationIntegrity, resolved.SkillID, err)
		}
		bundle.Skills = append(bundle.Skills, LibrarySkillActivation{
			SkillID:       resolved.SkillID,
			SkillSlug:     resolved.SkillSlug,
			SkillName:     resolved.SkillName,
			VersionID:     resolved.VersionID,
			Version:       resolved.Version,
			Instructions:  resolved.Content,
			ContentDigest: resolved.Digest,
			Binding: LibrarySkillActivationBinding{
				ID: resolved.BindingID, Mode: resolved.BindingMode, Priority: resolved.Priority,
			},
			Constraints: LibrarySkillActivationConstraints{
				RequestedCapabilities: requested,
				CapabilityCeiling:     ceiling,
			},
		})
	}

	// Preserve the resolver's priority semantics while making output order
	// independent of the backing store's row/list order. Hosts may use this
	// sequence for deterministic context assembly.
	sort.Slice(bundle.Skills, func(i, j int) bool {
		if bundle.Skills[i].Binding.Priority != bundle.Skills[j].Binding.Priority {
			return bundle.Skills[i].Binding.Priority > bundle.Skills[j].Binding.Priority
		}
		if bundle.Skills[i].SkillSlug != bundle.Skills[j].SkillSlug {
			return bundle.Skills[i].SkillSlug < bundle.Skills[j].SkillSlug
		}
		if bundle.Skills[i].SkillID != bundle.Skills[j].SkillID {
			return bundle.Skills[i].SkillID < bundle.Skills[j].SkillID
		}
		return bundle.Skills[i].Binding.ID < bundle.Skills[j].Binding.ID
	})

	digest, err := librarySkillActivationBundleDigest(bundle)
	if err != nil {
		return bundle, fmt.Errorf("encode activation bundle digest: %w", err)
	}
	bundle.BundleDigest = digest
	if err := validateLibrarySkillActivationRuntimeLimits(bundle, limits); err != nil {
		return LibrarySkillActivationBundle{}, err
	}
	return bundle, nil
}

// validateLibrarySkillActivationRuntimeLimits validates the exact wire and
// canonical host-context representations through the portable reference
// adapter. The incremental checks above avoid building large selections; this
// final check accounts for JSON and metadata overhead in the 128 KiB context
// limit as well.
func validateLibrarySkillActivationRuntimeLimits(bundle LibrarySkillActivationBundle, limits libraryruntime.Limits) error {
	payload, err := json.Marshal(bundle)
	if err != nil {
		return fmt.Errorf("%w: encode Engine activation bundle: %v", ErrLibrarySkillActivationIntegrity, err)
	}
	verified, err := libraryruntime.DecodeAndVerifyActivationBundle(bytes.NewReader(payload), limits)
	if err != nil {
		if errors.Is(err, libraryruntime.ErrActivationLimit) {
			return fmt.Errorf("%w: %v", ErrLibrarySkillActivationLimit, err)
		}
		return fmt.Errorf("%w: portable activation verification: %v", ErrLibrarySkillActivationIntegrity, err)
	}
	if _, err := libraryruntime.BuildContext(verified, limits); err != nil {
		if errors.Is(err, libraryruntime.ErrActivationLimit) {
			return fmt.Errorf("%w: %v", ErrLibrarySkillActivationLimit, err)
		}
		return fmt.Errorf("%w: portable activation context: %v", ErrLibrarySkillActivationIntegrity, err)
	}
	return nil
}

// librarySkillActivationBundleDigest hashes the deterministic Engine contract
// material. It intentionally excludes BundleDigest itself and contains no
// maps, clocks, random values, or database insertion ordering, so equal
// selected skill state produces exactly the same digest.
func librarySkillActivationBundleDigest(bundle LibrarySkillActivationBundle) (string, error) {
	material := struct {
		ContractVersion      string                             `json:"contractVersion"`
		AgentSurface         LibrarySkillActivationAgentSurface `json:"agentSurface"`
		Skills               []LibrarySkillActivation           `json:"skills"`
		AuthorityNotice      string                             `json:"authorityNotice"`
		HostResponsibilities []string                           `json:"hostResponsibilities"`
	}{
		ContractVersion:      bundle.ContractVersion,
		AgentSurface:         bundle.AgentSurface,
		Skills:               bundle.Skills,
		AuthorityNotice:      bundle.AuthorityNotice,
		HostResponsibilities: bundle.HostResponsibilities,
	}
	encoded, err := json.Marshal(material)
	if err != nil {
		return "", err
	}
	return libraryDigest(string(encoded)), nil
}

package engine

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// mcpClientLibraryToolNames are registered only on a subject-bound
// /mcp/clients/{slug} endpoint. Keep them in the endpoint's names list so a
// refresh removes every previous built-in before rebuilding the projection.
var mcpClientLibraryToolNames = []string{
	"library_skill_create",
	"library_skill_authoring_list",
	"library_skill_update",
	"library_skill_list",
	"library_skill_read",
	"library_skill_resolve",
	"library_skill_activation",
	"library_skill_runtime_receipt",
	"library_artifact_create",
	"library_artifact_version_create",
	"library_artifact_image_create",
	"library_artifact_image_version_create",
	"library_artifact_image_download",
	"library_artifact_read",
	"library_artifact_list",
}

// registerMCPClientLibraryTools adds a deliberately narrow Library projection
// for one durable MCP client. The endpoint's client record, not MCP tool
// arguments, supplies both the subject and agent-surface ID. This makes
// direct-agent artifacts useful while keeping the owner/admin root projection
// separate from a client's private Library view.
func registerMCPClientLibraryTools(s *server.MCPServer, store LibraryStore, sink AuditSink, client MCPClient, live func(context.Context) bool) []string {
	if s == nil || store == nil || client.ID == "" || client.Subject == "" || client.Slug == "" || live == nil {
		return nil
	}
	available := func(ctx context.Context) bool {
		return live(ctx)
	}
	denyUnavailable := func() (*mcp.CallToolResult, error) {
		return mcp.NewToolResultError("this Library surface is no longer available to this MCP client"), nil
	}
	audit := func(tool string) {
		if sink != nil {
			sink.LogCall(CallRecord{
				Account: "engine", Tool: tool, OK: true,
				Connector: client.Slug, EndpointKind: endpointKindClient, EndpointGeneration: client.Epoch,
			})
		}
	}
	// Keep this tool statically advertised on every subject-bound Library
	// endpoint. A server-side lease is intentionally checked at invocation time
	// rather than influencing the cached endpoint projection, so expiry or a
	// revoke cannot leave an authoring capability advertised as usable.
	s.AddTool(
		mcp.NewTool(
			"library_skill_create",
			mcp.WithDescription("Create one unbound portable Synaxis Library skill only while this MCP client's owner/admin-issued authoring window is active. The window is server-clock-bound and does not grant credentials, tools, OAuth scopes, bindings, publication, or authority."),
			mcp.WithInputSchema[libraryMCPClientSkillCreateInput](),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			var input libraryMCPClientSkillCreateInput
			if err := request.BindArguments(&input); err != nil {
				return mcp.NewToolResultError("invalid skill authoring input"), nil
			}
			authoringStore, supported := store.(LibraryMCPClientSkillAuthoringStore)
			if !supported {
				return mcp.NewToolResultError("skill authoring is not currently available"), nil
			}
			// Do not return early on a stale endpoint projection. The atomic
			// store method reloads and fences the durable client before any
			// write; letting it make this rejected call also creates the durable
			// lease audit receipt. It cannot revive a revoked client or lease.
			result, err := authoringStore.CreateLibraryMCPClientSkillWithAuthoringLease(ctx, client, LibraryMCPClientSkillAuthoringRequest{
				RequestID: input.RequestID, Name: input.Name, Slug: input.Slug, Description: input.Description,
				Content: input.Content, RequestedCapabilities: input.RequestedCapabilities,
			})
			if err != nil {
				switch {
				case errors.Is(err, ErrLibraryMCPClientSkillAuthoringRequestConflict):
					return mcp.NewToolResultError("skill authoring request conflicts with a prior request"), nil
				case errors.Is(err, ErrLibraryMCPClientSkillAuthoringUnavailable),
					errors.Is(err, ErrLibraryMCPClientSkillAuthoringClientUnavailable),
					errors.Is(err, ErrLibraryMCPClientSkillAuthoringLeaseActive),
					errors.Is(err, ErrLibrarySkillExists),
					errors.Is(err, ErrMCPClientNotFound),
					errors.Is(err, ErrMCPClientRevoked):
					// Match a duplicate global slug with a closed authoring window;
					// the subject-bound client must not gain a Library membership
					// oracle from a create attempt.
					return mcp.NewToolResultError("skill authoring is not currently available"), nil
				default:
					return mcp.NewToolResultError("could not create skill"), nil
				}
			}
			return mcp.NewToolResultJSON(struct {
				SkillID          string `json:"skillId"`
				SkillVersionID   string `json:"skillVersionId"`
				Digest           string `json:"digest"`
				RemainingCreates int    `json:"remainingCreates"`
				ExpiresAt        string `json:"expiresAt"`
				Replayed         bool   `json:"replayed"`
			}{
				SkillID: result.Skill.ID, SkillVersionID: result.Version.ID, Digest: result.Version.Digest,
				RemainingCreates: result.Lease.RemainingCreates, ExpiresAt: result.Lease.ExpiresAt.UTC().Format(time.RFC3339Nano), Replayed: result.Replayed,
			})
		},
	)

	// Discovery is intentionally as narrow as the update operation: an agent
	// may see only its own still-unbound, lease-created skills while the same
	// bounded authoring window is active. That gives a later turn the exact
	// version ID/digest pair required for a conflict-safe update without turning
	// this endpoint into a general Library inventory.
	s.AddTool(
		mcp.NewTool(
			"library_skill_authoring_list",
			mcp.WithDescription("List only this MCP client's still-unbound skills created through its authoring lease, while its current owner/admin-issued authoring window is active. Returns metadata and the exact latest immutable version ID/digest needed for library_skill_update; never returns instructions, bindings, credentials, authority, or other clients' skills."),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		func(ctx context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			authoringStore, supported := store.(LibraryMCPClientSkillAuthoringStore)
			if !supported {
				return mcp.NewToolResultError("skill authoring is not currently available"), nil
			}
			items, lease, err := authoringStore.ListLibraryMCPClientAuthoredSkillsWithAuthoringLease(ctx, client)
			if err != nil {
				switch {
				case errors.Is(err, ErrLibraryMCPClientSkillAuthoringUnavailable),
					errors.Is(err, ErrLibraryMCPClientSkillAuthoringClientUnavailable),
					errors.Is(err, ErrMCPClientNotFound),
					errors.Is(err, ErrMCPClientRevoked):
					return mcp.NewToolResultError("skill authoring is not currently available"), nil
				default:
					return mcp.NewToolResultError("could not list authored skills"), nil
				}
			}
			type authoredSkill struct {
				SkillID             string `json:"skillId"`
				Slug                string `json:"slug"`
				Name                string `json:"name"`
				Description         string `json:"description,omitempty"`
				LatestVersionID     string `json:"latestVersionId"`
				LatestVersion       int    `json:"latestVersion"`
				LatestVersionDigest string `json:"latestVersionDigest"`
				UpdatedAt           string `json:"updatedAt"`
			}
			out := make([]authoredSkill, 0, len(items))
			for _, item := range items {
				out = append(out, authoredSkill{
					SkillID: item.SkillID, Slug: item.Slug, Name: item.Name, Description: item.Description,
					LatestVersionID: item.LatestVersionID, LatestVersion: item.LatestVersion,
					LatestVersionDigest: item.LatestVersionDigest, UpdatedAt: item.UpdatedAt.UTC().Format(time.RFC3339Nano),
				})
			}
			return mcp.NewToolResultJSON(struct {
				Skills           []authoredSkill `json:"skills"`
				RemainingCreates int             `json:"remainingCreates"`
				ExpiresAt        string          `json:"expiresAt"`
			}{
				Skills: out, RemainingCreates: lease.RemainingCreates, ExpiresAt: lease.ExpiresAt.UTC().Format(time.RFC3339Nano),
			})
		},
	)

	s.AddTool(
		mcp.NewTool(
			"library_skill_update",
			mcp.WithDescription("Append one immutable version to a still-unbound Library skill originally created by this exact MCP client, only while its owner/admin-issued authoring window is active. Supply the exact current version ID and digest from library_skill_authoring_list or a prior result. This consumes one bounded authoring write and cannot change names, bindings, publication, credentials, OAuth scopes, tools, or authority."),
			mcp.WithInputSchema[libraryMCPClientSkillUpdateInput](),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			var input libraryMCPClientSkillUpdateInput
			if err := request.BindArguments(&input); err != nil {
				return mcp.NewToolResultError("invalid skill update input"), nil
			}
			authoringStore, supported := store.(LibraryMCPClientSkillAuthoringStore)
			if !supported {
				return mcp.NewToolResultError("skill authoring is not currently available"), nil
			}
			// As with create, do not short-circuit a stale endpoint projection. The
			// atomic store method reloads and fences the durable client before any
			// mutation and writes a safe rejected-attempt receipt when appropriate.
			result, err := authoringStore.UpdateLibraryMCPClientSkillWithAuthoringLease(ctx, client, LibraryMCPClientSkillAuthoringUpdateRequest{
				RequestID: input.RequestID, SkillID: input.SkillID, ExpectedVersionID: input.ExpectedVersionID,
				ExpectedVersionDigest: input.ExpectedVersionDigest, Content: input.Content,
				RequestedCapabilities: input.RequestedCapabilities,
			})
			if err != nil {
				switch {
				case errors.Is(err, ErrLibraryMCPClientSkillAuthoringRequestConflict):
					return mcp.NewToolResultError("skill authoring request conflicts with a prior request"), nil
				case errors.Is(err, ErrLibraryMCPClientSkillAuthoringUnavailable),
					errors.Is(err, ErrLibraryMCPClientSkillAuthoringClientUnavailable),
					errors.Is(err, ErrLibrarySkillNotFound),
					errors.Is(err, ErrLibrarySkillVersionNotFound),
					errors.Is(err, ErrMCPClientNotFound),
					errors.Is(err, ErrMCPClientRevoked):
					return mcp.NewToolResultError("skill authoring is not currently available"), nil
				default:
					return mcp.NewToolResultError("could not update skill"), nil
				}
			}
			return mcp.NewToolResultJSON(struct {
				SkillID          string `json:"skillId"`
				SkillVersionID   string `json:"skillVersionId"`
				Digest           string `json:"digest"`
				RemainingCreates int    `json:"remainingCreates"`
				ExpiresAt        string `json:"expiresAt"`
				Replayed         bool   `json:"replayed"`
			}{
				SkillID: result.Skill.ID, SkillVersionID: result.Version.ID, Digest: result.Version.Digest,
				RemainingCreates: result.Lease.RemainingCreates, ExpiresAt: result.Lease.ExpiresAt.UTC().Format(time.RFC3339Nano), Replayed: result.Replayed,
			})
		},
	)

	registerMCPClientLibraryArtifactImageCreateTool(s, store, sink, client, available, denyUnavailable, audit)
	registerMCPClientLibraryArtifactImageVersionCreateTool(s, store, client, available, denyUnavailable, audit)
	registerMCPClientLibraryArtifactImageDownloadTool(s, store, client, available, denyUnavailable, audit)

	s.AddTool(
		mcp.NewTool(
			"library_skill_list",
			mcp.WithDescription("List only portable Synaxis Library skills explicitly assigned to this MCP client. Skills are instructions and capability constraints, not credentials or authority."),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		func(ctx context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			if !available(ctx) {
				return denyUnavailable()
			}
			resolution, err := ResolveLibrarySkillsForAgentSurface(ctx, store, client.ID)
			if err != nil {
				return mcp.NewToolResultError("could not list assigned skills"), nil
			}
			type skillSummary struct {
				ID          string `json:"id"`
				Slug        string `json:"slug"`
				Name        string `json:"name"`
				Description string `json:"description,omitempty"`
				Version     int    `json:"version"`
				VersionID   string `json:"versionId"`
				BindingID   string `json:"bindingId"`
			}
			out := make([]skillSummary, 0, len(resolution.Skills))
			for _, resolved := range resolution.Skills {
				skill, found := store.LibrarySkill(ctx, resolved.SkillID)
				if !found {
					return mcp.NewToolResultError("assigned skill is unavailable"), nil
				}
				out = append(out, skillSummary{
					ID: skill.ID, Slug: skill.Slug, Name: skill.Name, Description: skill.Description,
					Version: resolved.Version, VersionID: resolved.VersionID, BindingID: resolved.BindingID,
				})
			}
			audit("library_skill_list")
			return mcp.NewToolResultJSON(out)
		},
	)

	// This tool is an unsigned, read-only current-selection receipt for a
	// separately authenticated host-attestation endpoint. It intentionally does
	// not write a run, accept output content, or alter the activation v1
	// contract. It is not an Engine-signed token or bearer capability; the host
	// must sign its exact final JSON body with its configured per-client Ed25519
	// key.
	s.AddTool(
		mcp.NewTool(
			"library_skill_runtime_receipt",
			mcp.WithDescription("Prepare an unsigned read-only current-selection receipt for one currently assigned immutable skill version. It is not an Engine-signed token or bearer capability, and does not create a run, inject a skill, execute a tool, grant authority, or prove tool execution. A configured external host must sign its exact output request at the separate runtime endpoint."),
			mcp.WithInputSchema[librarySkillRuntimeReceiptInput](),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			if !available(ctx) {
				return denyUnavailable()
			}
			if _, configured := mcpClientRuntimeAttestorPublicKey(client.RuntimeAttestorPublicKey); !configured {
				return mcp.NewToolResultError("runtime attestation is not configured for this MCP client"), nil
			}
			var input librarySkillRuntimeReceiptInput
			if err := request.BindArguments(&input); err != nil {
				return mcp.NewToolResultError("invalid runtime receipt input"), nil
			}
			receipt, err := buildLibrarySkillRuntimeReceipt(ctx, store, client, input, time.Now().UTC())
			if err != nil {
				return mcp.NewToolResultError("could not prepare a runtime receipt for this assigned skill"), nil
			}
			audit("library_skill_runtime_receipt")
			return mcp.NewToolResultJSON(receipt)
		},
	)

	s.AddTool(
		mcp.NewTool(
			"library_skill_read",
			mcp.WithDescription("Read the version of a portable Library skill assigned to this MCP client. Only this client's explicit agent-surface bindings are returned."),
			mcp.WithInputSchema[librarySkillReadInput](),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			if !available(ctx) {
				return denyUnavailable()
			}
			var input librarySkillReadInput
			if err := request.BindArguments(&input); err != nil || strings.TrimSpace(input.SkillID) == "" {
				return mcp.NewToolResultError("skillId is required"), nil
			}
			resolution, err := ResolveLibrarySkillsForAgentSurface(ctx, store, client.ID)
			if err != nil {
				return mcp.NewToolResultError("could not read assigned skill"), nil
			}
			var selected *LibraryResolvedSkill
			for index := range resolution.Skills {
				if resolution.Skills[index].SkillID == input.SkillID {
					selected = &resolution.Skills[index]
					break
				}
			}
			if selected == nil {
				// The same response for an unknown skill and an unassigned skill
				// avoids turning this endpoint into a Library membership oracle.
				return mcp.NewToolResultError("skill not found"), nil
			}
			skill, found := store.LibrarySkill(ctx, selected.SkillID)
			if !found {
				return mcp.NewToolResultError("skill not found"), nil
			}
			bindings, err := libraryAgentSurfaceBindings(ctx, store, selected.SkillID, client.ID)
			if err != nil {
				return mcp.NewToolResultError("skill bindings are unavailable"), nil
			}
			type skillMetadata struct {
				ID          string `json:"id"`
				Slug        string `json:"slug"`
				Name        string `json:"name"`
				Description string `json:"description,omitempty"`
			}
			type version struct {
				ID                    string   `json:"id"`
				Version               int      `json:"version"`
				Content               string   `json:"content"`
				Digest                string   `json:"digest"`
				RequestedCapabilities []string `json:"requestedCapabilities"`
			}
			type binding struct {
				ID                string   `json:"id"`
				Mode              string   `json:"mode"`
				PinnedVersionID   string   `json:"pinnedVersionId,omitempty"`
				CapabilityCeiling []string `json:"capabilityCeiling"`
				Priority          int      `json:"priority"`
			}
			outBindings := make([]binding, 0, len(bindings))
			for _, assigned := range bindings {
				outBindings = append(outBindings, binding{
					ID: assigned.ID, Mode: assigned.Mode, PinnedVersionID: assigned.PinnedVersionID,
					CapabilityCeiling: append([]string(nil), assigned.CapabilityCeiling...), Priority: assigned.Priority,
				})
			}
			audit("library_skill_read")
			return mcp.NewToolResultJSON(struct {
				Skill           skillMetadata `json:"skill"`
				Version         version       `json:"version"`
				Bindings        []binding     `json:"bindings"`
				AuthorityNotice string        `json:"authorityNotice"`
			}{
				Skill: skillMetadata{ID: skill.ID, Slug: skill.Slug, Name: skill.Name, Description: skill.Description},
				Version: version{
					ID: selected.VersionID, Version: selected.Version, Content: selected.Content, Digest: selected.Digest,
					RequestedCapabilities: append([]string(nil), selected.RequestedCapabilities...),
				},
				Bindings:        outBindings,
				AuthorityNotice: "Requested capabilities and bindings describe intent and applicability only. They do not grant credentials, scopes, or tool authority.",
			})
		},
	)

	s.AddTool(
		mcp.NewTool(
			"library_skill_resolve",
			mcp.WithDescription("Resolve only skills explicitly assigned to this MCP client. The agent surface is derived from the endpoint; caller-supplied scopes and binding IDs are ignored."),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		func(ctx context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			if !available(ctx) {
				return denyUnavailable()
			}
			resolution, err := ResolveLibrarySkillsForAgentSurface(ctx, store, client.ID)
			if err != nil {
				return mcp.NewToolResultError("could not resolve assigned skills"), nil
			}
			audit("library_skill_resolve")
			return mcp.NewToolResultJSON(resolution)
		},
	)

	// Unlike library_skill_resolve, this contract is intentionally unavailable
	// on the owner/admin root resource. Its context must come from this live,
	// subject-bound MCP client, never arbitrary MCP arguments or a generic
	// scope supplied by an external host.
	s.AddTool(
		mcp.NewTool(
			"library_skill_activation",
			mcp.WithDescription("Return a deterministic Synaxis Library activation bundle for this verified MCP client. It contains assigned immutable instructions and constraints only; it does not inject into a host, execute a skill, or grant credentials, tools, permissions, OAuth scopes, or capabilities."),
			mcp.WithInputSchema[librarySkillActivationInput](),
			mcp.WithOutputSchema[LibrarySkillActivationBundle](),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		func(ctx context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			if !available(ctx) {
				return denyUnavailable()
			}
			bundle, err := BuildLibrarySkillActivationBundleForAgentSurface(ctx, store, client.ID)
			if err != nil {
				if errors.Is(err, ErrLibrarySkillActivationLimit) {
					return mcp.NewToolResultError("assigned skills exceed the activation safety limit"), nil
				}
				return mcp.NewToolResultError("could not build the assigned skill activation bundle"), nil
			}
			audit("library_skill_activation")
			return mcp.NewToolResultJSON(bundle)
		},
	)

	s.AddTool(
		mcp.NewTool(
			"library_artifact_create",
			mcp.WithDescription("Create a private text or markdown artifact owned by this MCP client. This does not publish it."),
			mcp.WithInputSchema[libraryArtifactCreateInput](),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			if !available(ctx) {
				return denyUnavailable()
			}
			var input libraryArtifactCreateInput
			if err := request.BindArguments(&input); err != nil {
				return mcp.NewToolResultError("invalid artifact input"), nil
			}
			input.Format = strings.TrimSpace(input.Format)
			if input.Format == "" {
				input.Format = LibraryArtifactFormatMarkdown
			}
			if err := validateLibraryArtifactSourceReference(input.SourceArtifactID, input.SourceArtifactVersionID, input.SourceArtifactDigest, true); err != nil {
				return mcp.NewToolResultError("invalid source artifact reference"), nil
			}
			if input.SourceArtifactID != "" && !librarySurfaceMayUseArtifactVersion(ctx, store, input.SourceArtifactID, input.SourceArtifactVersionID, input.SourceArtifactDigest, client.Subject, client.ID, client.ID) {
				// Same response for unknown, revoked, ungranted, or mismatched
				// sources. An agent must not be able to use source validation as
				// an artifact/grant membership oracle.
				return mcp.NewToolResultError("source artifact not found"), nil
			}
			// Validate caller-controlled text before the store derives the
			// subject/surface/run provenance and commits every record together.
			if err := validateLibraryArtifact(LibraryArtifact{
				Title: input.Title, Summary: input.Summary, Origin: LibraryArtifactOriginAgentDirect,
			}); err != nil {
				return mcp.NewToolResultError("invalid artifact input"), nil
			}
			if err := validateLibraryArtifactVersion(LibraryArtifactVersion{ArtifactID: "pending", Format: input.Format, Body: input.Body}); err != nil {
				return mcp.NewToolResultError("invalid artifact input"), nil
			}
			run, artifact, version, err := store.CreateLibraryMCPClientArtifactWithInitialVersion(ctx, client, LibraryArtifact{
				Title: input.Title, Summary: input.Summary, Origin: LibraryArtifactOriginAgentDirect,
				SourceArtifactID: input.SourceArtifactID, SourceArtifactVersionID: input.SourceArtifactVersionID, SourceArtifactDigest: input.SourceArtifactDigest,
			}, LibraryArtifactVersion{Format: input.Format, Body: input.Body})
			if err != nil {
				if errors.Is(err, ErrLibraryArtifactNotFound) || errors.Is(err, ErrLibraryArtifactVersionNotFound) {
					return mcp.NewToolResultError("source artifact not found"), nil
				}
				if errors.Is(err, ErrMCPClientNotFound) || errors.Is(err, ErrMCPClientRevoked) {
					return denyUnavailable()
				}
				return mcp.NewToolResultError("could not create artifact"), nil
			}
			audit("library_artifact_create")
			return mcp.NewToolResultJSON(struct {
				ArtifactID string `json:"artifactId"`
				VersionID  string `json:"artifactVersionId"`
				Digest     string `json:"digest"`
				RunID      string `json:"runId"`
			}{artifact.ID, version.ID, version.Digest, run.ID})
		},
	)

	// This is intentionally a separate, client-only primitive instead of
	// exposing LibraryStore.CreateLibraryArtifactVersion. The narrow store facet
	// rechecks durable ownership and the expected current head in the same
	// transaction/save as the append, so an MCP client cannot update a grant,
	// another registration's direct output, a Console artifact, or a stale head.
	s.AddTool(
		mcp.NewTool(
			"library_artifact_version_create",
			mcp.WithDescription("Append one immutable version to a private direct text or Markdown artifact owned by this exact MCP client. Supply a unique requestId and the exact current artifact version ID and digest from library_artifact_read or library_artifact_list. The existing artifact format is preserved. This never overwrites an old version, changes artifact metadata, advances a grant, publishes content, or grants credentials, tools, permissions, OAuth scopes, or authority."),
			mcp.WithInputSchema[libraryMCPClientArtifactVersionCreateInput](),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			if !available(ctx) {
				return denyUnavailable()
			}
			var input libraryMCPClientArtifactVersionCreateInput
			if err := request.BindArguments(&input); err != nil {
				return mcp.NewToolResultError("invalid artifact version input"), nil
			}
			update, _, err := normalizeLibraryMCPClientArtifactVersionCreateRequest(LibraryMCPClientArtifactVersionCreateRequest{
				RequestID:                 input.RequestID,
				ArtifactID:                input.ArtifactID,
				ExpectedArtifactVersionID: input.ExpectedArtifactVersionID,
				ExpectedDigest:            input.ExpectedDigest,
				Body:                      input.Body,
			})
			if err != nil {
				return mcp.NewToolResultError("invalid artifact version input"), nil
			}
			versionStore, supported := store.(LibraryMCPClientArtifactVersionStore)
			if !supported {
				return mcp.NewToolResultError("artifact version updates are not currently available"), nil
			}
			result, err := versionStore.CreateLibraryMCPClientArtifactVersion(ctx, client, update)
			if err != nil {
				switch {
				case errors.Is(err, ErrLibraryMCPClientArtifactVersionConflict):
					return mcp.NewToolResultError("artifact version conflict; read the current artifact and retry"), nil
				case errors.Is(err, ErrLibraryMCPClientArtifactVersionRequestConflict):
					return mcp.NewToolResultError("artifact version request conflicts with a prior request"), nil
				case errors.Is(err, ErrLibraryArtifactNotFound), errors.Is(err, ErrLibraryArtifactVersionNotFound):
					// Keep direct ownership and grant/other-client records from
					// becoming an artifact-membership oracle.
					return mcp.NewToolResultError("artifact not found"), nil
				case errors.Is(err, ErrMCPClientNotFound), errors.Is(err, ErrMCPClientRevoked):
					return denyUnavailable()
				default:
					return mcp.NewToolResultError("could not create artifact version"), nil
				}
			}
			audit("library_artifact_version_create")
			return mcp.NewToolResultJSON(struct {
				ArtifactID        string `json:"artifactId"`
				ArtifactVersionID string `json:"artifactVersionId"`
				Version           int    `json:"version"`
				Format            string `json:"format"`
				Digest            string `json:"digest"`
				Replayed          bool   `json:"replayed"`
			}{
				ArtifactID: result.Version.ArtifactID, ArtifactVersionID: result.Version.ID, Version: result.Version.Version,
				Format: result.Version.Format, Digest: result.Version.Digest, Replayed: result.Replayed,
			})
		},
	)

	s.AddTool(
		mcp.NewTool(
			"library_artifact_read",
			mcp.WithDescription("Read an artifact this MCP client owns or has been granted. Owned artifacts return this client's current private head; granted artifacts always return the exact immutable version and digest selected by the live grant."),
			mcp.WithInputSchema[libraryArtifactReadInput](),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			if !available(ctx) {
				return denyUnavailable()
			}
			var input libraryArtifactReadInput
			if err := request.BindArguments(&input); err != nil || strings.TrimSpace(input.ArtifactID) == "" {
				return mcp.NewToolResultError("artifactId is required"), nil
			}
			artifact, found := store.LibraryArtifact(ctx, input.ArtifactID)
			if !found {
				// Match an unknown ID so a client cannot probe another subject's
				// private Library records.
				return mcp.NewToolResultError("artifact not found"), nil
			}
			access, allowed := libraryMCPClientArtifactAccess(ctx, store, artifact, client)
			if !allowed {
				return mcp.NewToolResultError("artifact not found"), nil
			}
			if access.Version.Format == LibraryArtifactFormatImage {
				mediaStore, supported := store.(LibraryArtifactMediaStore)
				if !supported {
					return mcp.NewToolResultError("artifact media is unavailable"), nil
				}
				result, err := libraryArtifactImageReadResult(ctx, mediaStore, access.Artifact, access.Version, access.Mode)
				if err != nil {
					return mcp.NewToolResultError("artifact media is unavailable"), nil
				}
				audit("library_artifact_read")
				return result, nil
			}
			audit("library_artifact_read")
			return mcp.NewToolResultJSON(struct {
				ArtifactID        string `json:"artifactId"`
				ArtifactVersionID string `json:"artifactVersionId"`
				Version           int    `json:"version"`
				Access            string `json:"access"`
				Title             string `json:"title"`
				Format            string `json:"format"`
				Body              string `json:"body"`
				Digest            string `json:"digest"`
			}{access.Artifact.ID, access.Version.ID, access.Version.Version, access.Mode, access.Artifact.Title, access.Version.Format, access.Version.Body, access.Version.Digest})
		},
	)

	s.AddTool(
		mcp.NewTool(
			"library_artifact_list",
			mcp.WithDescription("List a bounded page of private artifacts this MCP client owns plus immutable versions explicitly granted to it. Every row includes the exact version/digest library_artifact_read will return. The cursor orders immutable artifact creation history; refresh from the first page to discover a newly granted older artifact."),
			mcp.WithInputSchema[libraryArtifactListInput](),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			if !available(ctx) {
				return denyUnavailable()
			}
			var input libraryArtifactListInput
			if err := request.BindArguments(&input); err != nil {
				return mcp.NewToolResultError("invalid artifact page"), nil
			}
			cursor, err := decodeLibraryMCPClientArtifactCursor(input.Cursor)
			if err != nil {
				return mcp.NewToolResultError("invalid artifact page"), nil
			}
			page, err := store.LibraryMCPClientArtifactPage(ctx, client, cursor, input.Limit)
			if err != nil {
				if errors.Is(err, ErrMCPClientNotFound) || errors.Is(err, ErrMCPClientRevoked) {
					return denyUnavailable()
				}
				return mcp.NewToolResultError("could not list artifacts"), nil
			}
			type artifactSummary struct {
				ID                string `json:"id"`
				ArtifactVersionID string `json:"artifactVersionId"`
				Version           int    `json:"version"`
				Digest            string `json:"digest"`
				Format            string `json:"format"`
				SizeBytes         int64  `json:"sizeBytes"`
				Access            string `json:"access"`
				Title             string `json:"title"`
				Summary           string `json:"summary,omitempty"`
				Origin            string `json:"origin"`
				CreatedAt         string `json:"createdAt"`
			}
			out := make([]artifactSummary, 0, len(page.Artifacts))
			for _, item := range page.Artifacts {
				out = append(out, artifactSummary{
					ID: item.Artifact.ID, ArtifactVersionID: item.Version.ID, Version: item.Version.Version,
					Digest: item.Version.Digest, Format: item.Version.Format, SizeBytes: item.Version.SizeBytes, Access: item.Access, Title: item.Artifact.Title,
					Summary: item.Artifact.Summary, Origin: item.Artifact.Origin,
					CreatedAt: item.Artifact.CreatedAt.UTC().Format(time.RFC3339Nano),
				})
			}
			audit("library_artifact_list")
			return mcp.NewToolResultJSON(struct {
				Artifacts  []artifactSummary `json:"artifacts"`
				NextCursor string            `json:"nextCursor,omitempty"`
			}{Artifacts: out, NextCursor: encodeLibraryMCPClientArtifactCursor(page.NextCursor)})
		},
	)

	return append([]string(nil), mcpClientLibraryToolNames...)
}

type libraryArtifactListInput struct {
	Cursor string `json:"cursor,omitempty" jsonschema:"Opaque cursor returned by a previous library_artifact_list page"`
	Limit  int    `json:"limit,omitempty" jsonschema:"Optional page size from 1 to 100; defaults to 50"`
}

// libraryMCPClientArtifactVersionCreateInput exposes only a conflict fence,
// idempotency key, and new immutable text. The active endpoint and durable
// store derive client identity, subject, creator, provenance, and the format
// from the current text/Markdown head; callers cannot switch an artifact into
// another media type or mutate its grants and metadata.
type libraryMCPClientArtifactVersionCreateInput struct {
	RequestID                 string `json:"requestId" jsonschema:"Opaque idempotency key generated by this MCP client"`
	ArtifactID                string `json:"artifactId" jsonschema:"ID of a direct artifact owned by this exact MCP client"`
	ExpectedArtifactVersionID string `json:"expectedArtifactVersionId" jsonschema:"Exact current immutable artifact version ID"`
	ExpectedDigest            string `json:"expectedDigest" jsonschema:"Exact SHA-256 digest of the current immutable artifact version"`
	Body                      string `json:"body" jsonschema:"New immutable text or Markdown body"`
}

// libraryMCPClientSkillCreateInput deliberately omits creator identity,
// binding/scope selectors, credential references, and a lease ID. The
// endpoint registration and the server-side current lease derive every one of
// those authorization facts at the atomic store boundary.
type libraryMCPClientSkillCreateInput struct {
	RequestID             string   `json:"requestId" jsonschema:"Opaque idempotency key generated by this MCP client"`
	Name                  string   `json:"name" jsonschema:"Short Library skill name"`
	Slug                  string   `json:"slug,omitempty" jsonschema:"Optional lowercase skill slug; generated from name when omitted"`
	Description           string   `json:"description,omitempty" jsonschema:"Optional concise skill description"`
	Content               string   `json:"content" jsonschema:"Immutable Markdown skill instructions"`
	RequestedCapabilities []string `json:"requestedCapabilities,omitempty" jsonschema:"Requested capability intent only; this never grants authority"`
}

// libraryMCPClientSkillUpdateInput deliberately exposes only immutable
// version content/intent plus a compare-and-swap pair. The endpoint and store
// derive the client identity, subject, lease, and origin authorization facts;
// callers cannot select a scope, binding, grant, or metadata field.
type libraryMCPClientSkillUpdateInput struct {
	RequestID             string   `json:"requestId" jsonschema:"Opaque idempotency key generated by this MCP client"`
	SkillID               string   `json:"skillId" jsonschema:"ID of a still-unbound skill originally created by this MCP client"`
	ExpectedVersionID     string   `json:"expectedVersionId" jsonschema:"Exact current immutable skill version ID"`
	ExpectedVersionDigest string   `json:"expectedVersionDigest" jsonschema:"Exact SHA-256 digest of the current immutable skill version"`
	Content               string   `json:"content" jsonschema:"New immutable Markdown skill instructions"`
	RequestedCapabilities []string `json:"requestedCapabilities,omitempty" jsonschema:"Requested capability intent only; this never grants authority"`
}

type libraryMCPClientArtifactCursorWire struct {
	CreatedAt  string `json:"createdAt"`
	ArtifactID string `json:"artifactId"`
}

func decodeLibraryMCPClientArtifactCursor(raw string) (LibraryMCPClientArtifactCursor, error) {
	if raw == "" {
		return LibraryMCPClientArtifactCursor{}, nil
	}
	data, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return LibraryMCPClientArtifactCursor{}, err
	}
	var wire libraryMCPClientArtifactCursorWire
	if err := json.Unmarshal(data, &wire); err != nil || wire.CreatedAt == "" || wire.ArtifactID == "" {
		return LibraryMCPClientArtifactCursor{}, errors.New("invalid artifact page cursor")
	}
	createdAt, err := time.Parse(time.RFC3339Nano, wire.CreatedAt)
	if err != nil {
		return LibraryMCPClientArtifactCursor{}, err
	}
	if err := validateLibraryOpaqueRef("artifact page cursor", wire.ArtifactID, false); err != nil {
		return LibraryMCPClientArtifactCursor{}, err
	}
	return LibraryMCPClientArtifactCursor{CreatedAt: createdAt.UTC(), ArtifactID: wire.ArtifactID}, nil
}

func encodeLibraryMCPClientArtifactCursor(cursor LibraryMCPClientArtifactCursor) string {
	if cursor.CreatedAt.IsZero() || cursor.ArtifactID == "" {
		return ""
	}
	data, err := json.Marshal(libraryMCPClientArtifactCursorWire{CreatedAt: cursor.CreatedAt.UTC().Format(time.RFC3339Nano), ArtifactID: cursor.ArtifactID})
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(data)
}

// librarySkillActivationInput is intentionally empty. The activation context
// is the endpoint's verified MCP-client registration, so accepting a caller's
// binding/scope/agent-surface selector would turn a host hint into an access
// control input.
type librarySkillActivationInput struct{}

// libraryArtifactBelongsToMCPClient preserves the narrow direct-ownership
// predicate for existing callers/tests. Shared reads go through
// libraryMCPClientArtifactAccess, which separately requires a live immutable
// grant and never advances it to an artifact's latest head.
func libraryArtifactBelongsToMCPClient(ctx context.Context, store LibraryStore, artifact LibraryArtifact, client MCPClient) bool {
	return libraryArtifactDirectlyOwnedBySurface(ctx, store, artifact, client.Subject, client.ID)
}

package engine

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
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
	"library_skill_upload_blob",
	"library_skill_import_bundle",
	"library_skill_list",
	"library_skill_read",
	"library_skill_file_read",
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
	"library_memory_propose",
	"library_memory_recall",
	"library_memory_read",
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
			mcp.WithDescription("Create one portable Synaxis Library skill and automatically attach its tracking activation binding to this exact MCP client, only while this client's owner/admin-issued authoring window is active. The binding carries instructions and a capability ceiling only; it does not grant credentials, tools, OAuth scopes, publication, or authority."),
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
				Content: input.Content, RequestedCapabilities: input.RequestedCapabilities, Files: input.Files,
			})
			if err != nil {
				return libraryMCPClientSkillAuthoringErrorResult(err, "could not create skill"), nil
			}
			return libraryMCPClientSkillAuthoringResultJSON(result)
		},
	)

	// Staged uploads let a client send one large binary per call instead of
	// inlining every file into a create. The staging receipt is bound to this
	// client and epoch, expires with the lease, and consumes one authoring
	// write; it never becomes an independently readable blob.
	s.AddTool(
		mcp.NewTool(
			"library_skill_upload_blob",
			mcp.WithDescription("Stage one bundle file (up to 4 MiB, allowlisted type derived from the path extension) under this client's active authoring window, for a later library_skill_create or library_skill_update that references its blobId in files. Consumes one of the window's bounded upload slots (separate from its three create/update writes); an exact retry with the same requestId replays without consuming another. The blob is data only: Synaxis never executes or renders it, and the blobId is usable only by this client until the window expires."),
			mcp.WithInputSchema[libraryMCPClientSkillBlobUploadInput](),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			var input libraryMCPClientSkillBlobUploadInput
			if err := request.BindArguments(&input); err != nil {
				return mcp.NewToolResultError("invalid skill blob upload input"), nil
			}
			blobStore, supported := store.(LibraryMCPClientSkillBlobStore)
			if !supported {
				return mcp.NewToolResultError("skill authoring is not currently available"), nil
			}
			result, err := blobStore.StageLibraryMCPClientSkillBlob(ctx, client, LibraryMCPClientSkillBlobUploadRequest{
				RequestID: input.RequestID, Path: input.Path, DataBase64: input.DataBase64,
			})
			if err != nil {
				return libraryMCPClientSkillAuthoringErrorResult(err, "could not stage skill file"), nil
			}
			return mcp.NewToolResultJSON(struct {
				BlobID           string `json:"blobId"`
				Digest           string `json:"digest"`
				ContentType      string `json:"contentType"`
				SizeBytes        int64  `json:"sizeBytes"`
				ExpiresAt        string `json:"expiresAt"`
				RemainingUploads int    `json:"remainingUploads"`
				RemainingCreates int    `json:"remainingCreates"`
				Replayed         bool   `json:"replayed"`
			}{
				BlobID: result.BlobID, Digest: result.Digest, ContentType: result.ContentType, SizeBytes: result.SizeBytes,
				ExpiresAt: result.ExpiresAt.UTC().Format(time.RFC3339Nano), RemainingUploads: result.Lease.RemainingUploads,
				RemainingCreates: result.Lease.RemainingCreates, Replayed: result.Replayed,
			})
		},
	)

	// A .skill package (the skill-creator zip: <slug>/SKILL.md plus files) is
	// one authoring write. The Engine unpacks it with the same traversal,
	// symlink, duplicate, type, and size rules as inline files, so an archive
	// can never place a file outside the bundle or smuggle an unlisted type.
	s.AddTool(
		mcp.NewTool(
			"library_skill_import_bundle",
			mcp.WithDescription("Import a base64 .skill zip (SKILL.md at the root or inside one top-level folder) as a new skill, or, when skillId with the exact current expectedVersionId and expectedVersionDigest is given, as the next immutable version of a skill this client may revise. Requires this client's active authoring window and consumes one authoring write. SKILL.md front matter must carry name and description. Files are stored as data and never executed; nothing here grants credentials, tools, or authority."),
			mcp.WithInputSchema[libraryMCPClientSkillImportBundleInput](),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			var input libraryMCPClientSkillImportBundleInput
			if err := request.BindArguments(&input); err != nil {
				return mcp.NewToolResultError("invalid skill bundle import input"), nil
			}
			authoringStore, supported := store.(LibraryMCPClientSkillAuthoringStore)
			if !supported {
				return mcp.NewToolResultError("skill authoring is not currently available"), nil
			}
			files, err := libraryMCPClientSkillFileInputsFromBundle(input.BundleBase64)
			if err != nil {
				return libraryMCPClientSkillAuthoringErrorResult(err, "could not read skill bundle"), nil
			}
			if strings.TrimSpace(input.SkillID) == "" {
				result, err := authoringStore.CreateLibraryMCPClientSkillWithAuthoringLease(ctx, client, LibraryMCPClientSkillAuthoringRequest{
					RequestID: input.RequestID, Name: input.Name, Slug: input.Slug, Description: input.Description,
					RequestedCapabilities: input.RequestedCapabilities, Files: files,
				})
				if err != nil {
					return libraryMCPClientSkillAuthoringErrorResult(err, "could not import skill bundle"), nil
				}
				return libraryMCPClientSkillAuthoringResultJSON(result)
			}
			result, err := authoringStore.UpdateLibraryMCPClientSkillWithAuthoringLease(ctx, client, LibraryMCPClientSkillAuthoringUpdateRequest{
				RequestID: input.RequestID, SkillID: input.SkillID, ExpectedVersionID: input.ExpectedVersionID,
				ExpectedVersionDigest: input.ExpectedVersionDigest, RequestedCapabilities: input.RequestedCapabilities, Files: files,
			})
			if err != nil {
				return libraryMCPClientSkillAuthoringErrorResult(err, "could not import skill bundle"), nil
			}
			return libraryMCPClientSkillAuthoringResultJSON(result)
		},
	)

	// Discovery is intentionally as narrow as the update operation: an agent
	// may see only its own authoring-eligible, lease-created skills or the one
	// exact owner/admin-delegated target while the same bounded authoring window
	// is active. New creates retain exactly their automatic client-surface
	// binding; only legacy no-binding skills remain compatible. That gives a
	// later turn the exact version ID/digest pair required for a conflict-safe
	// update without turning this endpoint into a general Library inventory.
	s.AddTool(
		mcp.NewTool(
			"library_skill_authoring_list",
			mcp.WithDescription("List only this MCP client's authoring-eligible skills: skills it created through its authoring lease, or the one exact skill an owner/admin temporarily delegated to it. The current owner/admin-issued authoring window must be active. Newer created skills retain their exact automatic client-surface binding; legacy no-binding skills remain compatible. Returns metadata and the exact latest immutable version ID/digest needed for library_skill_update; never returns instructions, credentials, authority, or other clients' skills."),
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
				SkillID              string `json:"skillId"`
				Slug                 string `json:"slug"`
				Name                 string `json:"name"`
				Description          string `json:"description,omitempty"`
				LatestVersionID      string `json:"latestVersionId"`
				LatestVersion        int    `json:"latestVersion"`
				LatestVersionDigest  string `json:"latestVersionDigest"`
				LatestManifestDigest string `json:"latestManifestDigest"`
				UpdatedAt            string `json:"updatedAt"`
			}
			out := make([]authoredSkill, 0, len(items))
			for _, item := range items {
				out = append(out, authoredSkill{
					SkillID: item.SkillID, Slug: item.Slug, Name: item.Name, Description: item.Description,
					LatestVersionID: item.LatestVersionID, LatestVersion: item.LatestVersion,
					LatestVersionDigest: item.LatestVersionDigest, LatestManifestDigest: item.LatestManifestDigest,
					UpdatedAt: item.UpdatedAt.UTC().Format(time.RFC3339Nano),
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
			mcp.WithDescription("Append one immutable version to a Library skill this exact MCP client created, or to the one exact skill an owner/admin temporarily delegated to it. The owner/admin-issued authoring window must be active; the client binding and selected head must still match the lease. Supply the exact current version ID and digest from library_skill_authoring_list or a prior result. This consumes one bounded authoring write and cannot change names, bindings, publication, credentials, OAuth scopes, tools, or authority."),
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
				RequestedCapabilities: input.RequestedCapabilities, Files: input.Files,
			})
			if err != nil {
				return libraryMCPClientSkillAuthoringErrorResult(err, "could not update skill"), nil
			}
			return libraryMCPClientSkillAuthoringResultJSON(result)
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
			// MCP structuredContent must be a JSON object. Strict clients reject
			// a bare array, so wrap the rows in the same envelope the root
			// library_skill_list and library_artifact_list tools use.
			return mcp.NewToolResultJSON(struct {
				Skills []skillSummary `json:"skills"`
			}{Skills: out})
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
			mcp.WithDescription("Read the immutable version of a portable Library skill assigned to this exact MCP client. Only this client's explicit agent-surface bindings are returned. Instructions and capability constraints are context only; they grant no credentials, tools, scopes, permissions, or authority."),
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
				Skill           skillMetadata                  `json:"skill"`
				Version         version                        `json:"version"`
				Manifest        LibrarySkillManifestProjection `json:"manifest"`
				Bindings        []binding                      `json:"bindings"`
				AuthorityNotice string                         `json:"authorityNotice"`
			}{
				Skill: skillMetadata{ID: skill.ID, Slug: skill.Slug, Name: skill.Name, Description: skill.Description},
				Version: version{
					ID: selected.VersionID, Version: selected.Version, Content: selected.Content, Digest: selected.Digest,
					RequestedCapabilities: append([]string(nil), selected.RequestedCapabilities...),
				},
				Manifest:        libraryResolvedSkillManifestProjection(ctx, store, *selected),
				Bindings:        outBindings,
				AuthorityNotice: "Requested capabilities and bindings describe intent and applicability only. They do not grant credentials, scopes, or tool authority. Bundle files are data Synaxis never executes; fetch them with library_skill_file_read and verify each digest.",
			})
		},
	)

	// One file of one exact selected version. The client must name the
	// version its activation selected; a version that is not currently
	// selected for this surface reads as not found, so the endpoint cannot
	// become an inventory of unassigned versions.
	s.AddTool(
		mcp.NewTool(
			"library_skill_file_read",
			mcp.WithDescription("Read one bundle file (with its SHA-256 digest, size, and media type) from the exact immutable version of a skill assigned to this MCP client, as listed by library_skill_read or a v2 activation manifest. Text files return utf8; binaries return base64. Verify the digest before use. Files are data only: Synaxis never executes them and they grant no credentials, tools, or authority."),
			mcp.WithInputSchema[librarySkillFileReadInput](),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			if !available(ctx) {
				return denyUnavailable()
			}
			var input librarySkillFileReadInput
			if err := request.BindArguments(&input); err != nil || strings.TrimSpace(input.SkillID) == "" || strings.TrimSpace(input.VersionID) == "" {
				return mcp.NewToolResultError("skillId, versionId, and path are required"), nil
			}
			filePath, err := normalizeLibrarySkillPath(strings.TrimSpace(input.Path))
			if err != nil {
				return mcp.NewToolResultError("skill file not found"), nil
			}
			resolution, err := ResolveLibrarySkillsForAgentSurface(ctx, store, client.ID)
			if err != nil {
				return mcp.NewToolResultError("could not read assigned skill"), nil
			}
			selectedVersion := ""
			for _, resolved := range resolution.Skills {
				if resolved.SkillID == input.SkillID && resolved.VersionID == input.VersionID {
					selectedVersion = resolved.VersionID
					break
				}
			}
			if selectedVersion == "" {
				return mcp.NewToolResultError("skill file not found"), nil
			}
			bundleStore, supported := store.(LibrarySkillBundleStore)
			if !supported {
				return mcp.NewToolResultError("skill files are not available from this store"), nil
			}
			data, file, found, err := bundleStore.LibrarySkillFileBytes(ctx, input.SkillID, selectedVersion, filePath)
			if err != nil {
				return mcp.NewToolResultError("skill file is unavailable"), nil
			}
			if !found {
				return mcp.NewToolResultError("skill file not found"), nil
			}
			audit("library_skill_file_read")
			return mcp.NewToolResultJSON(newLibrarySkillFileReadResult(input.SkillID, selectedVersion, file, data))
		},
	)

	s.AddTool(
		mcp.NewTool(
			"library_skill_resolve",
			mcp.WithDescription("Resolve only skills explicitly assigned to this exact MCP client. The agent surface is derived from the endpoint; caller-supplied scopes and binding IDs are ignored. Returned instructions and constraints are context only and grant no authority."),
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
			mcp.WithDescription("Call with no arguments at task start, or when assigned procedures may have changed, to request this verified MCP client's deterministic Synaxis Library activation bundle. No arguments (or contractVersion synaxis.library.activation.v1) returns the unchanged v1 shape; contractVersion synaxis.library.activation.v2 also returns each skill's bundle manifest (file paths and digests, never file bytes) for library_skill_file_read. It contains immutable instructions and constraints only; it does not inject into a host, execute a skill, or grant credentials, tools, permissions, OAuth scopes, capabilities, or authority."),
			mcp.WithInputSchema[librarySkillActivationInput](),
			mcp.WithOutputSchema[LibrarySkillActivationBundle](),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			if !available(ctx) {
				return denyUnavailable()
			}
			var input librarySkillActivationInput
			if err := request.BindArguments(&input); err != nil {
				return mcp.NewToolResultError("invalid activation input"), nil
			}
			contract, err := normalizeLibrarySkillActivationContract(input.ContractVersion)
			if err != nil {
				return mcp.NewToolResultError("unsupported activation contract; use synaxis.library.activation.v1 or synaxis.library.activation.v2"), nil
			}
			bundle, err := BuildLibrarySkillActivationBundleForAgentSurfaceContract(ctx, store, client.ID, contract)
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

	if memoryStore, supported := store.(LibraryMemoryStore); supported {
		registerMCPClientMemoryTools(s, memoryStore, sink, client, live)
	}
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
	Name                  string   `json:"name,omitempty" jsonschema:"Short Library skill name; taken from SKILL.md front matter when omitted with files"`
	Slug                  string   `json:"slug,omitempty" jsonschema:"Optional lowercase skill slug; generated from name when omitted"`
	Description           string   `json:"description,omitempty" jsonschema:"Optional concise skill description; taken from SKILL.md front matter when omitted with files"`
	Content               string   `json:"content,omitempty" jsonschema:"Immutable SKILL.md Markdown instructions (shorthand for a files entry named SKILL.md)"`
	RequestedCapabilities []string `json:"requestedCapabilities,omitempty" jsonschema:"Requested capability intent only; this never grants authority"`
	// Files turns the version into a bundle. Inline entries carry utf8 or
	// base64 content; staged entries name a blobId from library_skill_upload_blob.
	Files []LibrarySkillFileInput `json:"files,omitempty" jsonschema:"Optional bundle files: {path, contentType?, encoding: utf8|base64, content} inline, or {path, blobId} staged; SKILL.md front matter must then carry name and description"`
}

// libraryMCPClientSkillBlobUploadInput stages one file's bytes. The path
// decides the media type; the lease, expiry, and blob identity are derived.
type libraryMCPClientSkillBlobUploadInput struct {
	RequestID  string `json:"requestId" jsonschema:"Opaque idempotency key generated by this MCP client"`
	Path       string `json:"path" jsonschema:"Relative bundle path the file will occupy, for example assets/template.xlsx; decides the media type"`
	DataBase64 string `json:"dataBase64" jsonschema:"Standard base64 of the file bytes (at most 4 MiB decoded)"`
}

// libraryMCPClientSkillImportBundleInput imports a whole .skill zip as one
// authoring write. Without skillId it creates; with the exact current version
// pair it appends a version.
type libraryMCPClientSkillImportBundleInput struct {
	RequestID             string   `json:"requestId" jsonschema:"Opaque idempotency key generated by this MCP client"`
	BundleBase64          string   `json:"bundleBase64" jsonschema:"Standard base64 of a .skill zip: SKILL.md at the root or inside one top-level folder"`
	Name                  string   `json:"name,omitempty" jsonschema:"Optional skill name; defaults to SKILL.md front matter name"`
	Slug                  string   `json:"slug,omitempty" jsonschema:"Optional lowercase skill slug"`
	Description           string   `json:"description,omitempty" jsonschema:"Optional description; defaults to SKILL.md front matter description"`
	RequestedCapabilities []string `json:"requestedCapabilities,omitempty" jsonschema:"Requested capability intent only; this never grants authority"`
	SkillID               string   `json:"skillId,omitempty" jsonschema:"When set, append a version to this authoring-eligible skill instead of creating one"`
	ExpectedVersionID     string   `json:"expectedVersionId,omitempty" jsonschema:"Required with skillId: exact current immutable skill version ID"`
	ExpectedVersionDigest string   `json:"expectedVersionDigest,omitempty" jsonschema:"Required with skillId: exact SHA-256 digest of the current SKILL.md"`
}

// librarySkillFileReadInput names one file of one exact immutable version.
type librarySkillFileReadInput struct {
	SkillID   string `json:"skillId" jsonschema:"Skill ID"`
	VersionID string `json:"versionId" jsonschema:"Exact immutable version ID (the one selected for this client)"`
	Path      string `json:"path" jsonschema:"Relative bundle path, for example scripts/build.py"`
}

// libraryMCPClientSkillUpdateInput deliberately exposes only immutable
// version content/intent plus a compare-and-swap pair. The endpoint and store
// derive the client identity, subject, lease, and origin authorization facts;
// callers cannot select a scope, binding, grant, or metadata field.
type libraryMCPClientSkillUpdateInput struct {
	RequestID             string                  `json:"requestId" jsonschema:"Opaque idempotency key generated by this MCP client"`
	SkillID               string                  `json:"skillId" jsonschema:"ID of an authoring-eligible skill originally created by this MCP client"`
	ExpectedVersionID     string                  `json:"expectedVersionId" jsonschema:"Exact current immutable skill version ID"`
	ExpectedVersionDigest string                  `json:"expectedVersionDigest" jsonschema:"Exact SHA-256 digest of the current immutable skill version"`
	Content               string                  `json:"content,omitempty" jsonschema:"New immutable SKILL.md Markdown instructions (shorthand for a files entry named SKILL.md)"`
	RequestedCapabilities []string                `json:"requestedCapabilities,omitempty" jsonschema:"Requested capability intent only; this never grants authority"`
	Files                 []LibrarySkillFileInput `json:"files,omitempty" jsonschema:"Optional bundle files, as for library_skill_create; the whole manifest of the new version is exactly SKILL.md plus these entries"`
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

// librarySkillActivationInput carries only the contract negotiation. The
// activation context is the endpoint's verified MCP-client registration, so
// accepting a caller's binding/scope/agent-surface selector would turn a host
// hint into an access control input.
type librarySkillActivationInput struct {
	ContractVersion string `json:"contractVersion,omitempty" jsonschema:"synaxis.library.activation.v1 (default, unchanged) or synaxis.library.activation.v2 (adds bundle manifests)"`
}

// libraryMCPClientSkillAuthoringResultJSON is the shared create/update/import
// result. It carries IDs, digests, and lease state only: never instructions,
// file bytes, or authority.
func libraryMCPClientSkillAuthoringResultJSON(result LibraryMCPClientSkillAuthoringResult) (*mcp.CallToolResult, error) {
	return mcp.NewToolResultJSON(struct {
		SkillID          string `json:"skillId"`
		SkillVersionID   string `json:"skillVersionId"`
		BindingID        string `json:"bindingId,omitempty"`
		Digest           string `json:"digest"`
		ManifestDigest   string `json:"manifestDigest"`
		FileCount        int    `json:"fileCount"`
		RemainingCreates int    `json:"remainingCreates"`
		ExpiresAt        string `json:"expiresAt"`
		Replayed         bool   `json:"replayed"`
	}{
		SkillID: result.Skill.ID, SkillVersionID: result.Version.ID, BindingID: result.BindingID, Digest: result.Version.Digest,
		ManifestDigest: result.Version.ManifestDigest, FileCount: len(result.Version.Files),
		RemainingCreates: result.Lease.RemainingCreates, ExpiresAt: result.Lease.ExpiresAt.UTC().Format(time.RFC3339Nano), Replayed: result.Replayed,
	})
}

// libraryMCPClientSkillAuthoringErrorResult keeps the neutral "unavailable"
// answer for every authorization condition so the endpoint is not a Library
// oracle, while bundle validation failures name the offending caller-supplied
// path or rule, which the caller already knows.
func libraryMCPClientSkillAuthoringErrorResult(err error, fallback string) *mcp.CallToolResult {
	switch {
	case errors.Is(err, ErrLibraryMCPClientSkillAuthoringRequestConflict):
		return mcp.NewToolResultError("skill authoring request conflicts with a prior request")
	case errors.Is(err, ErrLibrarySkillBundleInvalid),
		errors.Is(err, ErrLibrarySkillBundleTooLarge),
		errors.Is(err, ErrLibrarySkillFileUnsupported),
		errors.Is(err, ErrLibrarySkillBlobNotFound):
		return mcp.NewToolResultError(err.Error())
	case errors.Is(err, ErrLibraryMCPClientSkillAuthoringUnavailable),
		errors.Is(err, ErrLibraryMCPClientSkillAuthoringClientUnavailable),
		errors.Is(err, ErrLibraryMCPClientSkillAuthoringLeaseActive),
		errors.Is(err, ErrLibrarySkillExists),
		errors.Is(err, ErrLibrarySkillNotFound),
		errors.Is(err, ErrLibrarySkillVersionNotFound),
		errors.Is(err, ErrLibraryBuiltInManaged),
		errors.Is(err, ErrMCPClientNotFound),
		errors.Is(err, ErrMCPClientRevoked):
		// Match a duplicate global slug, a foreign skill, and a closed window;
		// the subject-bound client must not gain a Library membership oracle.
		return mcp.NewToolResultError("skill authoring is not currently available")
	default:
		return mcp.NewToolResultError(fallback)
	}
}

// libraryMCPClientSkillFileInputsFromBundle unpacks a .skill zip into the
// same inline file inputs a create accepts, so import and inline creation
// share one validation and persistence path.
func libraryMCPClientSkillFileInputsFromBundle(bundleBase64 string) ([]LibrarySkillFileInput, error) {
	encoded := strings.TrimSpace(bundleBase64)
	if encoded == "" || len(encoded) > base64.StdEncoding.EncodedLen(libraryMaxSkillBundleZipBytes)+4 {
		return nil, fmt.Errorf("%w: bundleBase64 is required and at most %d bytes decoded", ErrLibrarySkillBundleTooLarge, libraryMaxSkillBundleZipBytes)
	}
	archive, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("%w: bundleBase64 is not standard base64", ErrLibrarySkillBundleInvalid)
	}
	files, err := parseLibrarySkillBundleZip(archive)
	if err != nil {
		return nil, err
	}
	inputs := make([]LibrarySkillFileInput, 0, len(files))
	for _, file := range files {
		if file.Path == LibrarySkillInstructionsPath {
			inputs = append(inputs, LibrarySkillFileInput{Path: file.Path, Encoding: LibrarySkillFileEncodingUTF8, Content: string(file.Data)})
			continue
		}
		inputs = append(inputs, LibrarySkillFileInput{Path: file.Path, Encoding: LibrarySkillFileEncodingBase64, Content: base64.StdEncoding.EncodeToString(file.Data)})
	}
	return inputs, nil
}

// librarySkillFileReadResult is the shared one-file read projection. Text
// types are returned as utf8; everything else as base64.
type librarySkillFileReadResult struct {
	SkillID     string `json:"skillId"`
	VersionID   string `json:"versionId"`
	Path        string `json:"path"`
	ContentType string `json:"contentType"`
	SizeBytes   int64  `json:"sizeBytes"`
	Digest      string `json:"digest"`
	Encoding    string `json:"encoding"`
	Content     string `json:"content"`
}

func newLibrarySkillFileReadResult(skillID, versionID string, file LibrarySkillFile, data []byte) librarySkillFileReadResult {
	result := librarySkillFileReadResult{
		SkillID: skillID, VersionID: versionID, Path: file.Path, ContentType: file.ContentType,
		SizeBytes: file.SizeBytes, Digest: file.Digest, Encoding: LibrarySkillFileEncodingBase64,
		Content: base64.StdEncoding.EncodeToString(data),
	}
	if LibrarySkillFileIsText(file.ContentType) {
		result.Encoding, result.Content = LibrarySkillFileEncodingUTF8, string(data)
	}
	return result
}

// libraryResolvedSkillManifestProjection renders a selected version's
// manifest for a read tool, inlining small text files through the bundle
// store when the store supports it.
func libraryResolvedSkillManifestProjection(ctx context.Context, store LibraryStore, resolved LibraryResolvedSkill) LibrarySkillManifestProjection {
	version := LibrarySkillVersion{
		ID: resolved.VersionID, SkillID: resolved.SkillID, Content: resolved.Content, Digest: resolved.Digest,
		Files: resolved.Files, ManifestDigest: resolved.ManifestDigest,
	}
	if materialized, err := librarySkillVersionWithManifest(version); err == nil {
		version = materialized
	}
	return libraryStoredSkillManifestProjection(ctx, store, version)
}

func libraryStoredSkillManifestProjection(ctx context.Context, store LibraryStore, version LibrarySkillVersion) LibrarySkillManifestProjection {
	bundleStore, supported := store.(LibrarySkillBundleStore)
	var fileBytes func(LibrarySkillFile) ([]byte, error)
	if supported {
		fileBytes = func(file LibrarySkillFile) ([]byte, error) {
			data, _, found, err := bundleStore.LibrarySkillFileBytes(ctx, version.SkillID, version.ID, file.Path)
			if err != nil {
				return nil, err
			}
			if !found {
				return nil, ErrLibrarySkillFileNotFound
			}
			return data, nil
		}
	}
	return librarySkillManifestProjection(version, fileBytes)
}

// libraryArtifactBelongsToMCPClient preserves the narrow direct-ownership
// predicate for existing callers/tests. Shared reads go through
// libraryMCPClientArtifactAccess, which separately requires a live immutable
// grant and never advances it to an artifact's latest head.
func libraryArtifactBelongsToMCPClient(ctx context.Context, store LibraryStore, artifact LibraryArtifact, client MCPClient) bool {
	return libraryArtifactDirectlyOwnedBySurface(ctx, store, artifact, client.Subject, client.ID)
}

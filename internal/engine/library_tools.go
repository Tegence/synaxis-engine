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

// RegisterLibraryArtifactTools registers the small, portable direct-agent
// artifact surface plus read-only skill introspection/resolution. Artifact
// creation remains intentionally independent of skills: every create produces
// agent_direct run provenance and no tool can approve or publish an artifact.
// Platform remains the only public-link control plane.
func RegisterLibraryArtifactTools(s *server.MCPServer, store LibraryStore, sink AuditSink) {
	if s == nil || store == nil {
		return
	}
	s.AddTool(
		mcp.NewTool(
			"library_skill_list",
			mcp.WithDescription("List a bounded, metadata-only page of portable Synaxis Library skills. Use library_skill_read for immutable instructions. Skills describe requested capabilities but do not grant credentials or authority."),
			mcp.WithInputSchema[libraryRootMCPPageInput](),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			var input libraryRootMCPPageInput
			if err := request.BindArguments(&input); err != nil {
				return mcp.NewToolResultError("invalid skill page"), nil
			}
			cursor, err := decodeLibraryMCPRootPageCursor(input.Cursor, libraryMCPRootPageKindSkills)
			if err != nil {
				return mcp.NewToolResultError("invalid skill page"), nil
			}
			if _, err := normalizeLibraryMCPRootPageLimit(input.Limit); err != nil {
				return mcp.NewToolResultError("invalid skill page"), nil
			}
			page, err := store.LibraryMCPRootSkillPage(ctx, cursor, input.Limit)
			if err != nil {
				return mcp.NewToolResultError("could not list skills"), nil
			}
			type skillSummary struct {
				ID          string `json:"id"`
				Slug        string `json:"slug"`
				Name        string `json:"name"`
				Description string `json:"description,omitempty"`
				Version     int    `json:"latestVersion"`
				VersionID   string `json:"latestVersionId"`
			}
			out := make([]skillSummary, 0, len(page.Skills))
			for _, skill := range page.Skills {
				out = append(out, skillSummary{ID: skill.ID, Slug: skill.Slug, Name: skill.Name, Description: skill.Description, Version: skill.LatestVersion, VersionID: skill.LatestVersionID})
			}
			if sink != nil {
				sink.LogCall(CallRecord{Account: "engine", Tool: "library_skill_list", OK: true})
			}
			return mcp.NewToolResultJSON(struct {
				Skills     []skillSummary `json:"skills"`
				NextCursor string         `json:"nextCursor,omitempty"`
			}{Skills: out, NextCursor: encodeLibraryMCPRootPageCursor(page.NextCursor, libraryMCPRootPageKindSkills)})
		},
	)
	s.AddTool(
		mcp.NewTool(
			"library_skill_read",
			mcp.WithDescription("Read the latest immutable instructions for a portable Synaxis Library skill. Returned capabilities are intent only; runtime authority remains enforced by connection policy."),
			mcp.WithInputSchema[librarySkillReadInput](),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			var input librarySkillReadInput
			if err := request.BindArguments(&input); err != nil || strings.TrimSpace(input.SkillID) == "" {
				return mcp.NewToolResultError("skillId is required"), nil
			}
			skill, found := store.LibrarySkill(ctx, input.SkillID)
			if !found {
				return mcp.NewToolResultError("skill not found"), nil
			}
			versions, err := store.LibrarySkillVersions(ctx, skill.ID)
			if err != nil || len(versions) == 0 {
				return mcp.NewToolResultError("skill content is unavailable"), nil
			}
			bindings, err := store.LibrarySkillBindings(ctx, skill.ID)
			if err != nil {
				return mcp.NewToolResultError("skill bindings are unavailable"), nil
			}
			latest := versions[len(versions)-1]
			if sink != nil {
				sink.LogCall(CallRecord{Account: "engine", Tool: "library_skill_read", OK: true})
			}
			return mcp.NewToolResultJSON(struct {
				Skill           LibrarySkill          `json:"skill"`
				Version         LibrarySkillVersion   `json:"version"`
				Bindings        []LibrarySkillBinding `json:"bindings"`
				AuthorityNotice string                `json:"authorityNotice"`
			}{
				Skill: skill, Version: latest, Bindings: bindings,
				AuthorityNotice: "Requested capabilities and bindings describe intent and applicability only. They do not grant credentials, scopes, or tool authority.",
			})
		},
	)
	s.AddTool(
		mcp.NewTool(
			"library_skill_resolve",
			mcp.WithDescription("Resolve portable Library skill instructions for opaque runtime context that the host independently trusts. Scope fields select context only, never credentials or access. The result is read-only and grants no permissions, OAuth scopes, tools, or authority."),
			mcp.WithInputSchema[librarySkillResolveInput](),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			var input librarySkillResolveInput
			if err := request.BindArguments(&input); err != nil {
				return mcp.NewToolResultError("invalid skill resolution context"), nil
			}
			resolution, err := ResolveLibrarySkills(ctx, store, LibrarySkillResolutionRequest{
				ExplicitBindingID: input.BindingID,
				FolderID:          input.FolderID,
				RepositoryID:      input.RepositoryID,
				NamespaceID:       input.NamespaceID,
				WorkspaceID:       input.WorkspaceID,
			})
			if err != nil {
				if errors.Is(err, ErrLibraryBindingNotFound) {
					return mcp.NewToolResultError("binding not found"), nil
				}
				return mcp.NewToolResultError("could not resolve skills"), nil
			}
			if sink != nil {
				sink.LogCall(CallRecord{Account: "engine", Tool: "library_skill_resolve", OK: true})
			}
			return mcp.NewToolResultJSON(resolution)
		},
	)
	s.AddTool(
		mcp.NewTool(
			"library_artifact_create",
			mcp.WithDescription("Create a private text or markdown artifact in Synaxis Library. This does not publish it."),
			mcp.WithInputSchema[libraryArtifactCreateInput](),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
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
			if input.SourceArtifactID != "" && !librarySurfaceMayUseArtifactVersion(ctx, store, input.SourceArtifactID, input.SourceArtifactVersionID, input.SourceArtifactDigest, libraryRootMCPActorRef, libraryRootMCPSurfaceRef, "") {
				// The root resource has no durable MCP-client registration, so it
				// can cite only artifacts created by this exact root agent surface.
				// Shared grants intentionally require /mcp/clients/{slug}.
				return mcp.NewToolResultError("source artifact not found"), nil
			}
			// Validate caller-controlled content before the store derives the root
			// MCP provenance and commits every record together.
			if err := validateLibraryArtifact(LibraryArtifact{
				Title: input.Title, Summary: input.Summary, Origin: LibraryArtifactOriginAgentDirect,
			}); err != nil {
				return mcp.NewToolResultError("invalid artifact input"), nil
			}
			if err := validateLibraryArtifactVersion(LibraryArtifactVersion{ArtifactID: "pending", Format: input.Format, Body: input.Body}); err != nil {
				return mcp.NewToolResultError("invalid artifact input"), nil
			}
			run, artifact, version, err := store.CreateLibraryRootMCPArtifactWithInitialVersion(ctx, LibraryArtifact{
				Title: input.Title, Summary: input.Summary, Origin: LibraryArtifactOriginAgentDirect,
				SourceArtifactID: input.SourceArtifactID, SourceArtifactVersionID: input.SourceArtifactVersionID, SourceArtifactDigest: input.SourceArtifactDigest,
			}, LibraryArtifactVersion{Format: input.Format, Body: input.Body})
			if err != nil {
				if errors.Is(err, ErrLibraryArtifactNotFound) || errors.Is(err, ErrLibraryArtifactVersionNotFound) {
					return mcp.NewToolResultError("source artifact not found"), nil
				}
				return mcp.NewToolResultError("could not create artifact"), nil
			}
			if sink != nil {
				sink.LogCall(CallRecord{Account: "engine", Tool: "library_artifact_create", OK: true})
			}
			return mcp.NewToolResultJSON(struct {
				ArtifactID string `json:"artifactId"`
				VersionID  string `json:"artifactVersionId"`
				Digest     string `json:"digest"`
				RunID      string `json:"runId"`
			}{artifact.ID, version.ID, version.Digest, run.ID})
		},
	)
	s.AddTool(
		mcp.NewTool(
			"library_artifact_read",
			mcp.WithDescription("Read the latest private version of a Synaxis Library artifact by artifact ID."),
			mcp.WithInputSchema[libraryArtifactReadInput](),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			var input libraryArtifactReadInput
			if err := request.BindArguments(&input); err != nil || strings.TrimSpace(input.ArtifactID) == "" {
				return mcp.NewToolResultError("artifactId is required"), nil
			}
			artifact, found := store.LibraryArtifact(ctx, input.ArtifactID)
			if !found {
				return mcp.NewToolResultError("artifact not found"), nil
			}
			versions, err := store.LibraryArtifactVersions(ctx, artifact.ID)
			if err != nil || len(versions) == 0 {
				return mcp.NewToolResultError("artifact content is unavailable"), nil
			}
			version := versions[len(versions)-1]
			if version.Format == LibraryArtifactFormatImage {
				mediaStore, supported := store.(LibraryArtifactMediaStore)
				if !supported {
					return mcp.NewToolResultError("artifact media is unavailable"), nil
				}
				result, err := libraryArtifactImageReadResult(ctx, mediaStore, artifact, version, "")
				if err != nil {
					return mcp.NewToolResultError("artifact media is unavailable"), nil
				}
				if sink != nil {
					sink.LogCall(CallRecord{Account: "engine", Tool: "library_artifact_read", OK: true})
				}
				return result, nil
			}
			if sink != nil {
				sink.LogCall(CallRecord{Account: "engine", Tool: "library_artifact_read", OK: true})
			}
			return mcp.NewToolResultJSON(struct {
				ArtifactID string `json:"artifactId"`
				Title      string `json:"title"`
				Format     string `json:"format"`
				Body       string `json:"body"`
				Digest     string `json:"digest"`
			}{artifact.ID, artifact.Title, version.Format, version.Body, version.Digest})
		},
	)
	s.AddTool(
		mcp.NewTool(
			"library_artifact_list",
			mcp.WithDescription("List a bounded, metadata-only page of private Synaxis Library artifacts. Use library_artifact_read for a body."),
			mcp.WithInputSchema[libraryRootMCPPageInput](),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			var input libraryRootMCPPageInput
			if err := request.BindArguments(&input); err != nil {
				return mcp.NewToolResultError("invalid artifact page"), nil
			}
			cursor, err := decodeLibraryMCPRootPageCursor(input.Cursor, libraryMCPRootPageKindArtifacts)
			if err != nil {
				return mcp.NewToolResultError("invalid artifact page"), nil
			}
			if _, err := normalizeLibraryMCPRootPageLimit(input.Limit); err != nil {
				return mcp.NewToolResultError("invalid artifact page"), nil
			}
			page, err := store.LibraryMCPRootArtifactPage(ctx, cursor, input.Limit)
			if err != nil {
				return mcp.NewToolResultError("could not list artifacts"), nil
			}
			if sink != nil {
				sink.LogCall(CallRecord{Account: "engine", Tool: "library_artifact_list", OK: true})
			}
			type artifactSummary struct {
				ID        string `json:"id"`
				Title     string `json:"title"`
				Summary   string `json:"summary,omitempty"`
				Origin    string `json:"origin"`
				CreatedAt string `json:"createdAt"`
			}
			out := make([]artifactSummary, 0, len(page.Artifacts))
			for _, artifact := range page.Artifacts {
				out = append(out, artifactSummary{
					ID: artifact.ID, Title: artifact.Title, Summary: artifact.Summary, Origin: artifact.Origin,
					CreatedAt: artifact.CreatedAt.UTC().Format(time.RFC3339Nano),
				})
			}
			return mcp.NewToolResultJSON(struct {
				Artifacts  []artifactSummary `json:"artifacts"`
				NextCursor string            `json:"nextCursor,omitempty"`
			}{Artifacts: out, NextCursor: encodeLibraryMCPRootPageCursor(page.NextCursor, libraryMCPRootPageKindArtifacts)})
		},
	)
	registerLibraryArtifactImageCreateTool(s, store, sink)
	registerLibraryArtifactImageDownloadTool(s, store, sink)
}

// libraryRootMCPPageInput is shared by the root-only skill and artifact
// metadata lists. It deliberately offers no body/provenance expansion flag;
// callers must use the existing explicit read-by-ID tools for content.
type libraryRootMCPPageInput struct {
	Cursor string `json:"cursor,omitempty" jsonschema:"Opaque cursor returned by the same root Library list tool"`
	Limit  int    `json:"limit,omitempty" jsonschema:"Optional page size from 1 to 100; defaults to 50"`
}

const (
	libraryMCPRootPageKindSkills    = "skills"
	libraryMCPRootPageKindArtifacts = "artifacts"
)

type libraryMCPRootPageCursorWire struct {
	Kind      string `json:"kind"`
	CreatedAt string `json:"createdAt"`
	ID        string `json:"id"`
}

func decodeLibraryMCPRootPageCursor(raw, expectedKind string) (LibraryMCPRootPageCursor, error) {
	if raw == "" {
		return LibraryMCPRootPageCursor{}, nil
	}
	data, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return LibraryMCPRootPageCursor{}, err
	}
	var wire libraryMCPRootPageCursorWire
	if err := json.Unmarshal(data, &wire); err != nil || wire.Kind != expectedKind || wire.CreatedAt == "" || wire.ID == "" {
		return LibraryMCPRootPageCursor{}, errors.New("invalid root MCP page cursor")
	}
	createdAt, err := time.Parse(time.RFC3339Nano, wire.CreatedAt)
	if err != nil {
		return LibraryMCPRootPageCursor{}, err
	}
	cursor := LibraryMCPRootPageCursor{CreatedAt: createdAt.UTC(), ID: wire.ID}
	if err := validateLibraryMCPRootPageCursor(cursor); err != nil {
		return LibraryMCPRootPageCursor{}, err
	}
	return cursor, nil
}

func encodeLibraryMCPRootPageCursor(cursor LibraryMCPRootPageCursor, kind string) string {
	if cursor.CreatedAt.IsZero() || cursor.ID == "" {
		return ""
	}
	data, err := json.Marshal(libraryMCPRootPageCursorWire{
		Kind: kind, CreatedAt: cursor.CreatedAt.UTC().Format(time.RFC3339Nano), ID: cursor.ID,
	})
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(data)
}

type libraryArtifactCreateInput struct {
	Title                   string `json:"title" jsonschema:"Short artifact title"`
	Summary                 string `json:"summary,omitempty" jsonschema:"Optional concise artifact summary"`
	Format                  string `json:"format,omitempty" jsonschema:"Artifact body format: markdown or text; defaults to markdown"`
	Body                    string `json:"body" jsonschema:"Artifact content"`
	SourceArtifactID        string `json:"sourceArtifactId,omitempty" jsonschema:"Optional exact source artifact ID; requires sourceArtifactVersionId and sourceArtifactDigest"`
	SourceArtifactVersionID string `json:"sourceArtifactVersionId,omitempty" jsonschema:"Optional immutable source artifact version ID"`
	SourceArtifactDigest    string `json:"sourceArtifactDigest,omitempty" jsonschema:"Optional SHA-256 digest for the exact source version"`
}

type libraryArtifactReadInput struct {
	ArtifactID string `json:"artifactId" jsonschema:"Opaque Library artifact ID"`
}

type librarySkillReadInput struct {
	SkillID string `json:"skillId" jsonschema:"Opaque Library skill ID"`
}

// librarySkillResolveInput deliberately has no permissions, token, connector,
// or credential fields. Scope IDs are opaque context supplied by the caller's
// trusted runtime integration; the resolver itself never treats them as
// authorization.
type librarySkillResolveInput struct {
	BindingID    string `json:"bindingId,omitempty" jsonschema:"Optional explicit Library binding ID from independently trusted host context; overrides scope fields and grants no access"`
	FolderID     string `json:"folderId,omitempty" jsonschema:"Opaque folder context independently trusted by the host; not a credential or access selector"`
	RepositoryID string `json:"repositoryId,omitempty" jsonschema:"Opaque repository context independently trusted by the host; not a credential or access selector"`
	NamespaceID  string `json:"namespaceId,omitempty" jsonschema:"Opaque generic namespace context independently trusted by the host; not a credential namespace or access selector"`
	WorkspaceID  string `json:"workspaceId,omitempty" jsonschema:"Opaque workspace context independently trusted by the host; not a credential or access selector"`
}

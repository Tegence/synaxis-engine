package engine

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// libraryArtifactImageCreateInput is deliberately byte-transport-only: it
// accepts no URL, filename, blob ID, actor identity, or caller-provided
// provenance. MCP arguments are JSON, so bounded canonical standard base64
// is the V1 transport. The value is never retained in a Library record or
// echoed from a tool result.
type libraryArtifactImageCreateInput struct {
	Title                   string `json:"title" jsonschema:"Short artifact title"`
	Summary                 string `json:"summary,omitempty" jsonschema:"Optional concise artifact summary"`
	MIMEType                string `json:"mimeType" jsonschema:"Declared image MIME type: image/png, image/jpeg, or image/svg+xml"`
	DataBase64              string `json:"dataBase64" jsonschema:"Canonical standard base64 image bytes; no data URL, whitespace, or URL-safe alphabet"`
	AltText                 string `json:"altText,omitempty" jsonschema:"Optional concise private accessibility description"`
	SourceArtifactID        string `json:"sourceArtifactId,omitempty" jsonschema:"Optional exact source artifact ID; requires sourceArtifactVersionId and sourceArtifactDigest"`
	SourceArtifactVersionID string `json:"sourceArtifactVersionId,omitempty" jsonschema:"Optional immutable source artifact version ID"`
	SourceArtifactDigest    string `json:"sourceArtifactDigest,omitempty" jsonschema:"Optional SHA-256 digest for the exact source version"`
}

// libraryArtifactImageVersionCreateInput intentionally contains only an
// immutable head fence and replacement canonical image payload. It cannot
// rename an artifact, alter provenance, select storage, advance a grant, or
// turn a private image revision into a publication.
type libraryArtifactImageVersionCreateInput struct {
	RequestID                 string `json:"requestId" jsonschema:"Unique opaque request ID for safe retry replay"`
	ArtifactID                string `json:"artifactId" jsonschema:"Opaque Library image artifact ID owned by this exact MCP client"`
	ExpectedArtifactVersionID string `json:"expectedArtifactVersionId" jsonschema:"Exact current immutable image version ID"`
	ExpectedDigest            string `json:"expectedDigest" jsonschema:"SHA-256 digest of the exact current image version"`
	MIMEType                  string `json:"mimeType" jsonschema:"Declared replacement MIME type: image/png, image/jpeg, or image/svg+xml"`
	DataBase64                string `json:"dataBase64" jsonschema:"Canonical standard base64 replacement image bytes; no data URL, whitespace, or URL-safe alphabet"`
	AltText                   string `json:"altText,omitempty" jsonschema:"Optional concise private accessibility description for this immutable version"`
}

// libraryArtifactImageDownloadInput intentionally accepts only an exact
// parent artifact/version pair. It has no blob ID, storage locator, URL, MIME
// override, or presentation mode: authorization remains entirely on the
// immutable parent version.
type libraryArtifactImageDownloadInput struct {
	ArtifactID        string `json:"artifactId" jsonschema:"Opaque Library image artifact ID"`
	ArtifactVersionID string `json:"artifactVersionId" jsonschema:"Exact immutable image artifact version ID"`
}

func normalizeLibraryArtifactImageCreateInput(input libraryArtifactImageCreateInput) (libraryArtifactImageCanonical, string, error) {
	image, err := normalizeLibraryArtifactImage(input.MIMEType, input.DataBase64)
	if err != nil {
		return libraryArtifactImageCanonical{}, "", err
	}
	altText, err := normalizeLibraryArtifactImageAltText(input.AltText)
	if err != nil {
		return libraryArtifactImageCanonical{}, "", err
	}
	return image, altText, nil
}

func normalizeLibraryArtifactImageVersionCreateInput(input libraryArtifactImageVersionCreateInput) (LibraryMCPClientImageArtifactVersionCreateRequest, error) {
	image, altText, err := normalizeLibraryArtifactImageCreateInput(libraryArtifactImageCreateInput{
		MIMEType: input.MIMEType, DataBase64: input.DataBase64, AltText: input.AltText,
	})
	if err != nil {
		return LibraryMCPClientImageArtifactVersionCreateRequest{}, err
	}
	request, _, err := normalizeLibraryMCPClientImageArtifactVersionCreateRequest(LibraryMCPClientImageArtifactVersionCreateRequest{
		RequestID:                 input.RequestID,
		ArtifactID:                input.ArtifactID,
		ExpectedArtifactVersionID: input.ExpectedArtifactVersionID,
		ExpectedDigest:            input.ExpectedDigest,
		Image:                     image,
		AltText:                   altText,
	})
	return request, err
}

func libraryArtifactImageReadResult(ctx context.Context, mediaStore LibraryArtifactMediaStore, artifact LibraryArtifact, version LibraryArtifactVersion, access string) (*mcp.CallToolResult, error) {
	media, found, err := mediaStore.LibraryArtifactMedia(ctx, artifact.ID, version.ID)
	if err != nil || !found || validateLibraryArtifactMediaForVersion(version, media) != nil {
		return nil, libraryArtifactMediaUnavailableError(err)
	}
	type metadata struct {
		ArtifactID        string               `json:"artifactId"`
		ArtifactVersionID string               `json:"artifactVersionId"`
		Version           int                  `json:"version"`
		Access            string               `json:"access,omitempty"`
		Title             string               `json:"title"`
		Format            string               `json:"format"`
		Digest            string               `json:"digest"`
		Media             LibraryArtifactMedia `json:"media"`
		DownloadOnly      bool                 `json:"downloadOnly"`
	}
	result := metadata{
		ArtifactID: artifact.ID, ArtifactVersionID: version.ID, Version: version.Version, Access: access,
		Title: artifact.Title, Format: version.Format, Digest: version.Digest, Media: media,
		DownloadOnly: media.DeliveryMode == libraryArtifactImageDeliveryDownloadOnly,
	}
	if media.DeliveryMode == libraryArtifactImageDeliveryDownloadOnly {
		// SVG is never returned as MCP ImageContent. An authorized caller may
		// request this exact version via library_artifact_image_download, which
		// returns a bounded base64 attachment payload rather than raw markup.
		return mcp.NewToolResultJSON(result)
	}
	bytes, found, err := mediaStore.LibraryArtifactRasterBytes(ctx, artifact.ID, version.ID)
	if err != nil || !found || validateLibraryArtifactMediaBytes(media, bytes) != nil {
		return nil, libraryArtifactMediaUnavailableError(err)
	}
	encoded := base64.StdEncoding.EncodeToString(bytes)
	text, err := json.Marshal(result)
	if err != nil {
		return nil, errors.New("encode image artifact metadata")
	}
	return mcp.NewToolResultImage(string(text), encoded, media.MIMEType), nil
}

// libraryArtifactImageDownloadResult is the only MCP result builder that can
// return SVG bytes. The enclosing root/client tool has already authorized the
// exact parent version. The payload stays in canonical bounded base64 so MCP
// never emits raw SVG markup, ImageContent, a blob ID, or a storage URL.
func libraryArtifactImageDownloadResult(ctx context.Context, mediaStore LibraryArtifactMediaStore, artifact LibraryArtifact, version LibraryArtifactVersion, access string) (*mcp.CallToolResult, error) {
	media, found, err := mediaStore.LibraryArtifactMedia(ctx, artifact.ID, version.ID)
	if err != nil || !found || validateLibraryArtifactMediaForVersion(version, media) != nil {
		return nil, libraryArtifactMediaUnavailableError(err)
	}
	bytes, found, err := mediaStore.LibraryArtifactImageBytes(ctx, artifact.ID, version.ID)
	if err != nil || !found || validateLibraryArtifactMediaBytes(media, bytes) != nil {
		return nil, libraryArtifactMediaUnavailableError(err)
	}
	encoded := base64.StdEncoding.EncodeToString(bytes)
	if len(encoded) > libraryArtifactImageMaxEncodedBytes {
		return nil, libraryArtifactMediaUnavailableError(nil)
	}
	type download struct {
		ArtifactID        string               `json:"artifactId"`
		ArtifactVersionID string               `json:"artifactVersionId"`
		Version           int                  `json:"version"`
		Access            string               `json:"access,omitempty"`
		Title             string               `json:"title"`
		Format            string               `json:"format"`
		Digest            string               `json:"digest"`
		Media             LibraryArtifactMedia `json:"media"`
		DataBase64        string               `json:"dataBase64"`
	}
	return mcp.NewToolResultJSON(download{
		ArtifactID: artifact.ID, ArtifactVersionID: version.ID, Version: version.Version, Access: access,
		Title: artifact.Title, Format: version.Format, Digest: version.Digest, Media: media, DataBase64: encoded,
	})
}

func registerLibraryArtifactImageCreateTool(s *server.MCPServer, store LibraryStore, sink AuditSink) {
	mediaStore, supported := store.(LibraryArtifactMediaStore)
	if !supported {
		return
	}
	s.AddTool(
		mcp.NewTool(
			"library_artifact_image_create",
			mcp.WithDescription("Create one private immutable PNG, JPEG, or safely sanitized SVG artifact in Synaxis Library. SVG is download-only; this does not publish or grant authority."),
			mcp.WithInputSchema[libraryArtifactImageCreateInput](),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			var input libraryArtifactImageCreateInput
			if err := request.BindArguments(&input); err != nil {
				return mcp.NewToolResultError("invalid image artifact input"), nil
			}
			image, altText, err := normalizeLibraryArtifactImageCreateInput(input)
			if err != nil {
				return mcp.NewToolResultError("invalid image artifact input"), nil
			}
			if err := validateLibraryArtifactSourceReference(input.SourceArtifactID, input.SourceArtifactVersionID, input.SourceArtifactDigest, true); err != nil {
				return mcp.NewToolResultError("invalid source artifact reference"), nil
			}
			if input.SourceArtifactID != "" && !librarySurfaceMayUseArtifactVersion(ctx, store, input.SourceArtifactID, input.SourceArtifactVersionID, input.SourceArtifactDigest, libraryRootMCPActorRef, libraryRootMCPSurfaceRef, "") {
				return mcp.NewToolResultError("source artifact not found"), nil
			}
			if err := validateLibraryArtifact(LibraryArtifact{Title: input.Title, Summary: input.Summary, Origin: LibraryArtifactOriginAgentDirect}); err != nil {
				return mcp.NewToolResultError("invalid image artifact input"), nil
			}
			run, artifact, version, err := mediaStore.CreateLibraryRootMCPImageArtifactWithInitialVersion(ctx, LibraryArtifact{
				Title: input.Title, Summary: input.Summary, Origin: LibraryArtifactOriginAgentDirect,
				SourceArtifactID: input.SourceArtifactID, SourceArtifactVersionID: input.SourceArtifactVersionID, SourceArtifactDigest: input.SourceArtifactDigest,
			}, image, altText)
			if err != nil {
				if errors.Is(err, ErrLibraryArtifactNotFound) || errors.Is(err, ErrLibraryArtifactVersionNotFound) {
					return mcp.NewToolResultError("source artifact not found"), nil
				}
				return mcp.NewToolResultError("could not create image artifact"), nil
			}
			if sink != nil {
				sink.LogCall(CallRecord{Account: "engine", Tool: "library_artifact_image_create", OK: true})
			}
			return mcp.NewToolResultJSON(struct {
				ArtifactID string `json:"artifactId"`
				VersionID  string `json:"artifactVersionId"`
				Digest     string `json:"digest"`
				RunID      string `json:"runId"`
				MIMEType   string `json:"mimeType"`
			}{artifact.ID, version.ID, version.Digest, run.ID, image.MIMEType})
		},
	)
}

func registerLibraryArtifactImageDownloadTool(s *server.MCPServer, store LibraryStore, sink AuditSink) {
	mediaStore, supported := store.(LibraryArtifactMediaStore)
	if !supported {
		return
	}
	s.AddTool(
		mcp.NewTool(
			"library_artifact_image_download",
			mcp.WithDescription("Download one exact private immutable image artifact version as bounded canonical base64. SVG is an attachment payload only: this never returns raw SVG markup, ImageContent, or a URL."),
			mcp.WithInputSchema[libraryArtifactImageDownloadInput](),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			var input libraryArtifactImageDownloadInput
			if err := request.BindArguments(&input); err != nil || strings.TrimSpace(input.ArtifactID) == "" || strings.TrimSpace(input.ArtifactVersionID) == "" {
				return mcp.NewToolResultError("artifactId and artifactVersionId are required"), nil
			}
			artifact, found := store.LibraryArtifact(ctx, input.ArtifactID)
			if !found {
				return mcp.NewToolResultError("artifact not found"), nil
			}
			version, found := store.LibraryArtifactVersion(ctx, artifact.ID, input.ArtifactVersionID)
			if !found || version.Format != LibraryArtifactFormatImage {
				return mcp.NewToolResultError("artifact not found"), nil
			}
			result, err := libraryArtifactImageDownloadResult(ctx, mediaStore, artifact, version, "")
			if err != nil {
				return mcp.NewToolResultError("artifact media is unavailable"), nil
			}
			if sink != nil {
				sink.LogCall(CallRecord{Account: "engine", Tool: "library_artifact_image_download", OK: true})
			}
			return result, nil
		},
	)
}

func registerMCPClientLibraryArtifactImageCreateTool(s *server.MCPServer, store LibraryStore, sink AuditSink, client MCPClient, available func(context.Context) bool, denyUnavailable func() (*mcp.CallToolResult, error), audit func(string)) bool {
	mediaStore, supported := store.(LibraryArtifactMediaStore)
	if !supported {
		return false
	}
	s.AddTool(
		mcp.NewTool(
			"library_artifact_image_create",
			mcp.WithDescription("Create one private immutable PNG, JPEG, or safely sanitized SVG artifact owned by this MCP client. SVG is download-only; this does not publish or grant authority."),
			mcp.WithInputSchema[libraryArtifactImageCreateInput](),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			if !available(ctx) {
				return denyUnavailable()
			}
			var input libraryArtifactImageCreateInput
			if err := request.BindArguments(&input); err != nil {
				return mcp.NewToolResultError("invalid image artifact input"), nil
			}
			image, altText, err := normalizeLibraryArtifactImageCreateInput(input)
			if err != nil {
				return mcp.NewToolResultError("invalid image artifact input"), nil
			}
			if err := validateLibraryArtifactSourceReference(input.SourceArtifactID, input.SourceArtifactVersionID, input.SourceArtifactDigest, true); err != nil {
				return mcp.NewToolResultError("invalid source artifact reference"), nil
			}
			if input.SourceArtifactID != "" && !librarySurfaceMayUseArtifactVersion(ctx, store, input.SourceArtifactID, input.SourceArtifactVersionID, input.SourceArtifactDigest, client.Subject, client.ID, client.ID) {
				return mcp.NewToolResultError("source artifact not found"), nil
			}
			if err := validateLibraryArtifact(LibraryArtifact{Title: input.Title, Summary: input.Summary, Origin: LibraryArtifactOriginAgentDirect}); err != nil {
				return mcp.NewToolResultError("invalid image artifact input"), nil
			}
			run, artifact, version, err := mediaStore.CreateLibraryMCPClientImageArtifactWithInitialVersion(ctx, client, LibraryArtifact{
				Title: input.Title, Summary: input.Summary, Origin: LibraryArtifactOriginAgentDirect,
				SourceArtifactID: input.SourceArtifactID, SourceArtifactVersionID: input.SourceArtifactVersionID, SourceArtifactDigest: input.SourceArtifactDigest,
			}, image, altText)
			if err != nil {
				if errors.Is(err, ErrLibraryArtifactNotFound) || errors.Is(err, ErrLibraryArtifactVersionNotFound) {
					return mcp.NewToolResultError("source artifact not found"), nil
				}
				if errors.Is(err, ErrMCPClientNotFound) || errors.Is(err, ErrMCPClientRevoked) {
					return denyUnavailable()
				}
				return mcp.NewToolResultError("could not create image artifact"), nil
			}
			audit("library_artifact_image_create")
			return mcp.NewToolResultJSON(struct {
				ArtifactID string `json:"artifactId"`
				VersionID  string `json:"artifactVersionId"`
				Digest     string `json:"digest"`
				RunID      string `json:"runId"`
				MIMEType   string `json:"mimeType"`
			}{artifact.ID, version.ID, version.Digest, run.ID, image.MIMEType})
		},
	)
	return true
}

// registerMCPClientLibraryArtifactImageVersionCreateTool is deliberately
// subject-bound only. It appends an immutable canonical image version to an
// artifact with direct provenance from this exact MCP client; grants, shared
// subject identities, and host-attested outputs never authorize revision.
func registerMCPClientLibraryArtifactImageVersionCreateTool(s *server.MCPServer, store LibraryStore, client MCPClient, available func(context.Context) bool, denyUnavailable func() (*mcp.CallToolResult, error), audit func(string)) bool {
	mediaStore, supported := store.(LibraryArtifactMediaStore)
	if !supported {
		return false
	}
	s.AddTool(
		mcp.NewTool(
			"library_artifact_image_version_create",
			mcp.WithDescription("Append one immutable canonical PNG, JPEG, or safely sanitized SVG version to a private direct image artifact owned by this exact MCP client. Supply a unique requestId and the exact current version ID and digest from library_artifact_read or library_artifact_list. SVG stays download-only. This never overwrites prior bytes, advances a grant, publishes content, or grants credentials, tools, permissions, OAuth scopes, or authority."),
			mcp.WithInputSchema[libraryArtifactImageVersionCreateInput](),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			if !available(ctx) {
				return denyUnavailable()
			}
			var input libraryArtifactImageVersionCreateInput
			if err := request.BindArguments(&input); err != nil {
				return mcp.NewToolResultError("invalid image artifact version input"), nil
			}
			update, err := normalizeLibraryArtifactImageVersionCreateInput(input)
			if err != nil {
				return mcp.NewToolResultError("invalid image artifact version input"), nil
			}
			result, err := mediaStore.CreateLibraryMCPClientImageArtifactVersion(ctx, client, update)
			if err != nil {
				switch {
				case errors.Is(err, ErrLibraryMCPClientArtifactVersionConflict):
					return mcp.NewToolResultError("artifact version conflict; read the current artifact and retry"), nil
				case errors.Is(err, ErrLibraryMCPClientArtifactVersionRequestConflict):
					return mcp.NewToolResultError("artifact version request conflicts with a prior request"), nil
				case errors.Is(err, ErrLibraryArtifactNotFound), errors.Is(err, ErrLibraryArtifactVersionNotFound):
					return mcp.NewToolResultError("artifact not found"), nil
				case errors.Is(err, ErrMCPClientNotFound), errors.Is(err, ErrMCPClientRevoked):
					return denyUnavailable()
				default:
					return mcp.NewToolResultError("could not create image artifact version"), nil
				}
			}
			audit("library_artifact_image_version_create")
			return mcp.NewToolResultJSON(struct {
				ArtifactID        string `json:"artifactId"`
				ArtifactVersionID string `json:"artifactVersionId"`
				Version           int    `json:"version"`
				Digest            string `json:"digest"`
				MIMEType          string `json:"mimeType"`
				Replayed          bool   `json:"replayed"`
			}{
				ArtifactID: result.Version.ArtifactID, ArtifactVersionID: result.Version.ID, Version: result.Version.Version,
				Digest: result.Version.Digest, MIMEType: update.Image.MIMEType, Replayed: result.Replayed,
			})
		},
	)
	return true
}

func registerMCPClientLibraryArtifactImageDownloadTool(s *server.MCPServer, store LibraryStore, client MCPClient, available func(context.Context) bool, denyUnavailable func() (*mcp.CallToolResult, error), audit func(string)) bool {
	mediaStore, supported := store.(LibraryArtifactMediaStore)
	if !supported {
		return false
	}
	s.AddTool(
		mcp.NewTool(
			"library_artifact_image_download",
			mcp.WithDescription("Download one exact private image artifact version this MCP client owns or has been granted, as bounded canonical base64. SVG remains an attachment payload only: never raw markup, ImageContent, or a URL."),
			mcp.WithInputSchema[libraryArtifactImageDownloadInput](),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			if !available(ctx) {
				return denyUnavailable()
			}
			var input libraryArtifactImageDownloadInput
			if err := request.BindArguments(&input); err != nil || strings.TrimSpace(input.ArtifactID) == "" || strings.TrimSpace(input.ArtifactVersionID) == "" {
				return mcp.NewToolResultError("artifactId and artifactVersionId are required"), nil
			}
			artifact, found := store.LibraryArtifact(ctx, input.ArtifactID)
			if !found {
				return mcp.NewToolResultError("artifact not found"), nil
			}
			access, allowed := libraryMCPClientArtifactAccess(ctx, store, artifact, client)
			if !allowed || access.Version.ID != input.ArtifactVersionID || access.Version.Format != LibraryArtifactFormatImage {
				// Match an unknown ID so exact-version probes cannot reveal whether
				// another private artifact or a revoked grant exists.
				return mcp.NewToolResultError("artifact not found"), nil
			}
			result, err := libraryArtifactImageDownloadResult(ctx, mediaStore, access.Artifact, access.Version, access.Mode)
			if err != nil {
				return mcp.NewToolResultError("artifact media is unavailable"), nil
			}
			audit("library_artifact_image_download")
			return result, nil
		},
	)
	return true
}

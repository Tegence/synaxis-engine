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

var (
	// ErrLibraryMCPClientArtifactVersionConflict means the caller's immutable
	// head fence no longer matches. It is intentionally distinct from an
	// ownership failure so an owning client can re-read its current head and
	// retry without any mutable overwrite operation.
	ErrLibraryMCPClientArtifactVersionConflict = errors.New("library MCP client artifact version conflict")
	// ErrLibraryMCPClientArtifactVersionRequestConflict prevents an MCP client
	// from reusing one opaque request ID for a different immutable append.
	ErrLibraryMCPClientArtifactVersionRequestConflict = errors.New("library MCP client artifact version request conflicts with an existing request")
)

const (
	libraryMCPClientArtifactVersionOperationTextCreate = "text_create"
	libraryMCPClientArtifactVersionRequestIDMax        = 256
)

// LibraryMCPClientArtifactVersionCreateRequest contains the only
// caller-controlled fields for a subject-bound artifact revision. In
// particular, it deliberately omits provenance, review, grant, publication,
// and creator fields. The store derives those authorization-sensitive facts
// from the live durable MCP client while it appends the immutable version.
type LibraryMCPClientArtifactVersionCreateRequest struct {
	RequestID                 string
	ArtifactID                string
	ExpectedArtifactVersionID string
	ExpectedDigest            string
	Body                      string
}

// LibraryMCPClientArtifactVersionCreateResult returns the immutable output
// version plus whether storage replayed a previous successful request. A
// replay never creates another version, even after a newer head exists.
type LibraryMCPClientArtifactVersionCreateResult struct {
	Version  LibraryArtifactVersion
	Replayed bool
}

// libraryMCPClientArtifactVersionRequestRecord is deliberately generic across
// client-owned artifact revision types. It contains only one-way request and
// canonical-payload hashes plus structural IDs, allowing a future media
// revision primitive to use another operation value without storing raw MCP
// request IDs, bodies, image bytes, or metadata a second time.
type libraryMCPClientArtifactVersionRequestRecord struct {
	MCPClientID       string    `json:"mcpClientId"`
	MCPClientEpoch    string    `json:"mcpClientEpoch"`
	ArtifactID        string    `json:"artifactId"`
	Operation         string    `json:"operation"`
	RequestIDHash     string    `json:"requestIdHash"`
	PayloadDigest     string    `json:"payloadDigest"`
	ArtifactVersionID string    `json:"artifactVersionId"`
	CreatedAt         time.Time `json:"createdAt"`
}

// LibraryMCPClientArtifactVersionStore is the narrow write facet for a
// subject-bound client's own direct text/Markdown artifacts. It is kept out of
// LibraryStore so Console callers retain their existing generic version path
// and cannot accidentally obtain the client-derived ownership operation.
//
// Implementations must, in one native lock/transaction, reload the active
// exact client/subject/epoch, prove direct-agent ownership, compare the latest
// immutable head with the supplied version/digest, and append the new version.
// Existing grants are intentionally not touched: each remains pinned to its
// original immutable version.
type LibraryMCPClientArtifactVersionStore interface {
	CreateLibraryMCPClientArtifactVersion(context.Context, MCPClient, LibraryMCPClientArtifactVersionCreateRequest) (LibraryMCPClientArtifactVersionCreateResult, error)
}

func normalizeLibraryMCPClientArtifactVersionCreateRequest(request LibraryMCPClientArtifactVersionCreateRequest) (LibraryMCPClientArtifactVersionCreateRequest, string, error) {
	if !validLibraryMCPClientArtifactVersionRequestID(request.RequestID) {
		return LibraryMCPClientArtifactVersionCreateRequest{}, "", errors.New("a valid request id is required")
	}
	request.ArtifactID = strings.TrimSpace(request.ArtifactID)
	request.ExpectedArtifactVersionID = strings.TrimSpace(request.ExpectedArtifactVersionID)
	request.ExpectedDigest = strings.ToLower(strings.TrimSpace(request.ExpectedDigest))
	if err := validateLibraryOpaqueRef("artifact", request.ArtifactID, false); err != nil {
		return LibraryMCPClientArtifactVersionCreateRequest{}, "", err
	}
	if err := validateLibraryOpaqueRef("expected artifact version", request.ExpectedArtifactVersionID, false); err != nil {
		return LibraryMCPClientArtifactVersionCreateRequest{}, "", err
	}
	if err := validateLibraryDigest("expected artifact", request.ExpectedDigest, false); err != nil {
		return LibraryMCPClientArtifactVersionCreateRequest{}, "", err
	}
	// The current immutable head supplies the actual format while the store
	// holds its native lock. Validate the caller's body here against either
	// allowed textual format without exposing a media type-change option.
	if err := validateLibraryArtifactVersion(LibraryArtifactVersion{
		ArtifactID: request.ArtifactID,
		Format:     LibraryArtifactFormatMarkdown,
		Body:       request.Body,
	}); err != nil {
		return LibraryMCPClientArtifactVersionCreateRequest{}, "", err
	}
	canonical, err := json.Marshal(struct {
		ExpectedArtifactVersionID string `json:"expectedArtifactVersionId"`
		ExpectedDigest            string `json:"expectedDigest"`
		Body                      string `json:"body"`
	}{
		ExpectedArtifactVersionID: request.ExpectedArtifactVersionID,
		ExpectedDigest:            request.ExpectedDigest,
		Body:                      request.Body,
	})
	if err != nil {
		return LibraryMCPClientArtifactVersionCreateRequest{}, "", fmt.Errorf("encode MCP client artifact revision payload: %w", err)
	}
	return request, libraryDigest(string(canonical)), nil
}

func validLibraryMCPClientArtifactVersionRequestID(value string) bool {
	if value == "" || len(value) > libraryMCPClientArtifactVersionRequestIDMax || strings.TrimSpace(value) != value || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character == 0x7f {
			return false
		}
	}
	return true
}

func libraryMCPClientArtifactVersionRequestIDHash(clientID, epoch, artifactID, operation, requestID string) string {
	return libraryDigest("library-mcp-client-artifact-version:v1\x00" + clientID + "\x00" + epoch + "\x00" + artifactID + "\x00" + operation + "\x00" + requestID)
}

func copyLibraryMCPClientArtifactVersionRequestRecord(record libraryMCPClientArtifactVersionRequestRecord) libraryMCPClientArtifactVersionRequestRecord {
	return record
}

func copyLibraryMCPClientArtifactVersionRequestRecords(in []*libraryMCPClientArtifactVersionRequestRecord) []*libraryMCPClientArtifactVersionRequestRecord {
	out := make([]*libraryMCPClientArtifactVersionRequestRecord, len(in))
	for i, record := range in {
		if record != nil {
			copy := copyLibraryMCPClientArtifactVersionRequestRecord(*record)
			out[i] = &copy
		}
	}
	return out
}

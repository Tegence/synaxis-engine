package engine

import (
	"encoding/json"
	"fmt"
	"strings"
)

const libraryMCPClientArtifactVersionOperationImageCreate = "image_create"

// LibraryMCPClientImageArtifactVersionCreateRequest contains the bounded
// caller-controlled facts for appending one immutable image artifact version.
// It deliberately omits title, provenance, creator, review, grants,
// publication, storage, and delivery controls. The Store derives those facts
// from the current durable client and canonical image bytes while it holds its
// native transaction/lock.
type LibraryMCPClientImageArtifactVersionCreateRequest struct {
	RequestID                 string
	ArtifactID                string
	ExpectedArtifactVersionID string
	ExpectedDigest            string
	Image                     libraryArtifactImageCanonical
	AltText                   string
}

// normalizeLibraryMCPClientImageArtifactVersionCreateRequest verifies the
// structural head fence and creates a stable payload digest for durable retry
// replay. The image digest, not its base64 transport, is included in the
// canonical payload: the accepted canonical bytes are authenticated again by
// validateLibraryArtifactImageCanonical before persistence.
func normalizeLibraryMCPClientImageArtifactVersionCreateRequest(request LibraryMCPClientImageArtifactVersionCreateRequest) (LibraryMCPClientImageArtifactVersionCreateRequest, string, error) {
	if !validLibraryMCPClientArtifactVersionRequestID(request.RequestID) {
		return LibraryMCPClientImageArtifactVersionCreateRequest{}, "", fmt.Errorf("a valid request id is required")
	}
	request.ArtifactID = strings.TrimSpace(request.ArtifactID)
	request.ExpectedArtifactVersionID = strings.TrimSpace(request.ExpectedArtifactVersionID)
	request.ExpectedDigest = strings.ToLower(strings.TrimSpace(request.ExpectedDigest))
	if err := validateLibraryOpaqueRef("artifact", request.ArtifactID, false); err != nil {
		return LibraryMCPClientImageArtifactVersionCreateRequest{}, "", err
	}
	if err := validateLibraryOpaqueRef("expected artifact version", request.ExpectedArtifactVersionID, false); err != nil {
		return LibraryMCPClientImageArtifactVersionCreateRequest{}, "", err
	}
	if err := validateLibraryDigest("expected artifact", request.ExpectedDigest, false); err != nil {
		return LibraryMCPClientImageArtifactVersionCreateRequest{}, "", err
	}
	request.Image.Bytes = append([]byte(nil), request.Image.Bytes...)
	if err := validateLibraryArtifactImageCanonical(request.Image); err != nil {
		return LibraryMCPClientImageArtifactVersionCreateRequest{}, "", err
	}
	altText, err := normalizeLibraryArtifactImageAltText(request.AltText)
	if err != nil {
		return LibraryMCPClientImageArtifactVersionCreateRequest{}, "", err
	}
	request.AltText = altText
	canonical, err := json.Marshal(struct {
		ExpectedArtifactVersionID string `json:"expectedArtifactVersionId"`
		ExpectedDigest            string `json:"expectedDigest"`
		MIMEType                  string `json:"mimeType"`
		Digest                    string `json:"digest"`
		SizeBytes                 int64  `json:"sizeBytes"`
		Width                     int    `json:"width"`
		Height                    int    `json:"height"`
		DeliveryMode              string `json:"deliveryMode"`
		AltText                   string `json:"altText"`
	}{
		ExpectedArtifactVersionID: request.ExpectedArtifactVersionID,
		ExpectedDigest:            request.ExpectedDigest,
		MIMEType:                  request.Image.MIMEType,
		Digest:                    request.Image.Digest,
		SizeBytes:                 request.Image.SizeBytes,
		Width:                     request.Image.Width,
		Height:                    request.Image.Height,
		DeliveryMode:              request.Image.DeliveryMode,
		AltText:                   request.AltText,
	})
	if err != nil {
		return LibraryMCPClientImageArtifactVersionCreateRequest{}, "", fmt.Errorf("encode MCP client image artifact revision payload: %w", err)
	}
	return request, libraryDigest(string(canonical)), nil
}

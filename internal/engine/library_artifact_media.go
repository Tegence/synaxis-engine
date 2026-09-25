package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

// normalizeLibraryArtifactImageAltText keeps private image metadata small,
// deterministic, and safe to pass through JSON/MCP. It intentionally accepts
// an empty value: alt text is strongly encouraged, but an image creator must
// not invent accessibility text it cannot support.
func normalizeLibraryArtifactImageAltText(value string) (string, error) {
	if !utf8.ValidString(value) {
		return "", ErrLibraryArtifactMediaInvalid
	}
	value = strings.TrimSpace(value)
	if len(value) > libraryMaxDescriptionBytes {
		return "", ErrLibraryArtifactMediaTooLarge
	}
	return value, nil
}

// validateLibraryArtifactImageCanonical checks the durable facts the Store
// relies on after the MCP boundary has parsed and canonicalized the incoming
// media. It does not re-encode JPEG bytes: repeated JPEG encoding is lossy and
// would make an already accepted immutable digest unstable. The only callers
// are Engine-internal, and all untrusted ingress goes through
// normalizeLibraryArtifactImage first.
func validateLibraryArtifactImageCanonical(image libraryArtifactImageCanonical) error {
	if len(image.Bytes) == 0 || len(image.Bytes) > libraryArtifactImageMaxDecodedBytes || image.SizeBytes != int64(len(image.Bytes)) {
		return ErrLibraryArtifactMediaInvalid
	}
	sum := sha256.Sum256(image.Bytes)
	if image.Digest != hex.EncodeToString(sum[:]) {
		return ErrLibraryArtifactMediaInvalid
	}
	if err := validateLibraryDigest("image", image.Digest, false); err != nil {
		return ErrLibraryArtifactMediaInvalid
	}
	switch image.MIMEType {
	case libraryArtifactImageMIMEPNG, libraryArtifactImageMIMEJPEG:
		if image.DeliveryMode != libraryArtifactImageDeliveryInline {
			return ErrLibraryArtifactMediaInvalid
		}
		return validateLibraryArtifactImageDimensions(image.Width, image.Height)
	case libraryArtifactImageMIMESVG:
		if image.DeliveryMode != libraryArtifactImageDeliveryDownloadOnly {
			return ErrLibraryArtifactMediaInvalid
		}
		// An SVG with neither explicit dimensions nor a viewBox is valid in the
		// static download profile. If dimensions were present, preserve the same
		// raster-equivalent safety cap used by the SVG parser.
		if image.Width == 0 && image.Height == 0 {
			return nil
		}
		return validateLibraryArtifactImageDimensions(image.Width, image.Height)
	default:
		return ErrLibraryArtifactMediaUnsupported
	}
}

func libraryArtifactMediaFromCanonical(versionID string, image libraryArtifactImageCanonical, altText string) (LibraryArtifactMedia, error) {
	if err := validateLibraryArtifactImageCanonical(image); err != nil {
		return LibraryArtifactMedia{}, err
	}
	altText, err := normalizeLibraryArtifactImageAltText(altText)
	if err != nil {
		return LibraryArtifactMedia{}, err
	}
	return LibraryArtifactMedia{
		ArtifactVersionID: versionID,
		MIMEType:          image.MIMEType,
		Digest:            image.Digest,
		SizeBytes:         image.SizeBytes,
		Width:             image.Width,
		Height:            image.Height,
		AltText:           altText,
		DeliveryMode:      image.DeliveryMode,
	}, nil
}

func validateLibraryArtifactMedia(media LibraryArtifactMedia) error {
	if err := validateLibraryOpaqueRef("artifact media version", media.ArtifactVersionID, false); err != nil {
		return err
	}
	if err := validateLibraryDigest("artifact media", media.Digest, false); err != nil {
		return err
	}
	if media.SizeBytes <= 0 || media.SizeBytes > libraryArtifactImageMaxDecodedBytes {
		return ErrLibraryArtifactMediaInvalid
	}
	if _, err := normalizeLibraryArtifactImageAltText(media.AltText); err != nil {
		return err
	}
	switch media.MIMEType {
	case libraryArtifactImageMIMEPNG, libraryArtifactImageMIMEJPEG:
		if media.DeliveryMode != libraryArtifactImageDeliveryInline {
			return ErrLibraryArtifactMediaInvalid
		}
		return validateLibraryArtifactImageDimensions(media.Width, media.Height)
	case libraryArtifactImageMIMESVG:
		if media.DeliveryMode != libraryArtifactImageDeliveryDownloadOnly {
			return ErrLibraryArtifactMediaInvalid
		}
		if media.Width == 0 && media.Height == 0 {
			return nil
		}
		return validateLibraryArtifactImageDimensions(media.Width, media.Height)
	default:
		return ErrLibraryArtifactMediaUnsupported
	}
}

// validateLibraryArtifactMediaBytes binds an already-authorized byte payload
// back to its private media metadata. Store read paths and MCP response
// builders use it before returning any binary content, so a corrupt database
// row cannot be delivered merely because its parent version still exists.
func validateLibraryArtifactMediaBytes(media LibraryArtifactMedia, data []byte) error {
	if err := validateLibraryArtifactMedia(media); err != nil {
		return err
	}
	if len(data) == 0 || int64(len(data)) != media.SizeBytes {
		return ErrLibraryArtifactMediaInvalid
	}
	sum := sha256.Sum256(data)
	if media.Digest != hex.EncodeToString(sum[:]) {
		return ErrLibraryArtifactMediaInvalid
	}
	// Metadata is not evidence of a byte stream's MIME type. In particular,
	// an SVG row relabeled as inline PNG would otherwise retain a valid
	// digest/version and could reach MCP ImageContent. Re-parse the stored
	// bytes as their declared media class before any FileStore/PgStore read
	// returns them.
	return validateLibraryArtifactImageContent(media, data)
}

// normalizedLibraryArtifactImageVersion is deliberately distinct from the
// text/Markdown normalizer. Generic artifact-version writers cannot create an
// image format because they do not own an immutable media blob transaction.
func normalizedLibraryArtifactImageVersion(version LibraryArtifactVersion, image libraryArtifactImageCanonical) (LibraryArtifactVersion, error) {
	if version.ArtifactID == "" || version.Body != "" || (version.Format != "" && version.Format != LibraryArtifactFormatImage) {
		return LibraryArtifactVersion{}, errors.New("invalid image artifact version")
	}
	if err := validateLibraryOpaqueRef("created by", version.CreatedBy, true); err != nil {
		return LibraryArtifactVersion{}, err
	}
	if err := validateLibraryArtifactImageCanonical(image); err != nil {
		return LibraryArtifactVersion{}, err
	}
	version.Format = LibraryArtifactFormatImage
	version.Digest = image.Digest
	version.SizeBytes = image.SizeBytes
	version.RedactionStatus = LibraryRedactionPending
	version.ReviewedBy = ""
	version.ReviewedAt = time.Time{}
	version.PublicationClaimedAt = time.Time{}
	if version.CreatedAt.IsZero() {
		version.CreatedAt = time.Now().UTC()
	}
	return version, nil
}

func validateLibraryArtifactMediaForVersion(version LibraryArtifactVersion, media LibraryArtifactMedia) error {
	if version.Format != LibraryArtifactFormatImage || version.Body != "" || media.ArtifactVersionID != version.ID || media.Digest != version.Digest || media.SizeBytes != version.SizeBytes {
		return ErrLibraryArtifactMediaInvalid
	}
	return validateLibraryArtifactMedia(media)
}

// prepareLibraryMCPClientImageArtifact mirrors the text artifact provenance
// helper while pinning the run's output digest to the canonical media digest.
// Existing text run digests are intentionally unchanged for compatibility.
func prepareLibraryMCPClientImageArtifact(client MCPClient, artifact LibraryArtifact, image libraryArtifactImageCanonical) (LibraryRun, LibraryArtifact, LibraryArtifactVersion, error) {
	if err := validateLibraryOpaqueRef("agent surface", client.ID, false); err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
	}
	if err := validateLibraryOpaqueRef("client subject", client.Subject, false); err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
	}
	if artifact.Origin != LibraryArtifactOriginAgentDirect || artifact.ID != "" || artifact.RunID != "" || artifact.CreatedBy != "" || artifact.AgentSurfaceID != "" {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, errors.New("MCP client artifact must derive direct provenance")
	}
	if err := validateLibraryArtifactImageCanonical(image); err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
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

	version, err := normalizedLibraryArtifactImageVersion(LibraryArtifactVersion{
		ID: newLibraryArtifactVersionID(), ArtifactID: artifact.ID, Version: 1,
		CreatedBy: client.Subject, CreatedAt: artifact.CreatedAt,
	}, image)
	if err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
	}
	run, err := normalizedLibraryRun(LibraryRun{
		ID:                      artifact.RunID,
		Origin:                  LibraryRunOriginAgentDirect,
		ActorRef:                client.Subject,
		SurfaceRef:              client.ID,
		Status:                  "succeeded",
		InputDigest:             libraryDigest(artifact.Title + "\n" + version.Digest),
		OutputDigest:            version.Digest,
		SourceArtifactID:        artifact.SourceArtifactID,
		SourceArtifactVersionID: artifact.SourceArtifactVersionID,
		SourceArtifactDigest:    artifact.SourceArtifactDigest,
		StartedAt:               artifact.CreatedAt,
		CompletedAt:             artifact.CreatedAt,
	})
	if err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
	}
	return run, artifact, version, nil
}

func prepareLibraryRootMCPImageArtifact(artifact LibraryArtifact, image libraryArtifactImageCanonical) (LibraryRun, LibraryArtifact, LibraryArtifactVersion, error) {
	if artifact.Origin != LibraryArtifactOriginAgentDirect || artifact.ID != "" || artifact.RunID != "" || artifact.CreatedBy != "" || artifact.AgentSurfaceID != "" {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, errors.New("root MCP artifact must derive direct provenance")
	}
	if err := validateLibraryArtifactImageCanonical(image); err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
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

	version, err := normalizedLibraryArtifactImageVersion(LibraryArtifactVersion{
		ID: newLibraryArtifactVersionID(), ArtifactID: artifact.ID, Version: 1,
		CreatedBy: libraryRootMCPActorRef, CreatedAt: artifact.CreatedAt,
	}, image)
	if err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
	}
	run, err := normalizedLibraryRun(LibraryRun{
		ID:                      artifact.RunID,
		Origin:                  LibraryRunOriginAgentDirect,
		ActorRef:                libraryRootMCPActorRef,
		SurfaceRef:              libraryRootMCPSurfaceRef,
		Status:                  "succeeded",
		InputDigest:             libraryDigest(artifact.Title + "\n" + version.Digest),
		OutputDigest:            version.Digest,
		SourceArtifactID:        artifact.SourceArtifactID,
		SourceArtifactVersionID: artifact.SourceArtifactVersionID,
		SourceArtifactDigest:    artifact.SourceArtifactDigest,
		StartedAt:               artifact.CreatedAt,
		CompletedAt:             artifact.CreatedAt,
	})
	if err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
	}
	return run, artifact, version, nil
}

// prepareLibraryHumanImageArtifact is the Console counterpart of the MCP
// image helpers: a human run derived from the authenticated actor, an image
// artifact, and its first canonical image version. The run's output digest is
// the canonical media digest, exactly as for agent-created images.
func prepareLibraryHumanImageArtifact(artifact LibraryArtifact, image libraryArtifactImageCanonical, changelog string, provenance *LibraryVersionProvenance) (LibraryRun, LibraryArtifact, LibraryArtifactVersion, error) {
	if artifact.Origin != LibraryArtifactOriginHuman || artifact.ID != "" || artifact.RunID != "" || artifact.AgentSurfaceID != "" {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, errors.New("human image artifact must derive its run provenance")
	}
	if err := validateLibraryOpaqueRef("created by", artifact.CreatedBy, false); err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
	}
	if err := validateLibraryArtifactImageCanonical(image); err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
	}
	if err := validateLibraryChangelog(changelog); err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
	}
	if err := validateLibraryVersionProvenance(provenance); err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
	}

	artifact.ID = newLibraryArtifactID()
	artifact.RunID = newLibraryRunID()
	if artifact.CreatedAt.IsZero() {
		artifact.CreatedAt = time.Now().UTC()
	}
	if err := validateLibraryArtifact(artifact); err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
	}

	version, err := normalizedLibraryArtifactImageVersion(LibraryArtifactVersion{
		ID: newLibraryArtifactVersionID(), ArtifactID: artifact.ID, Version: 1,
		Changelog: changelog, Provenance: copyLibraryVersionProvenance(provenance),
		CreatedBy: artifact.CreatedBy, CreatedAt: artifact.CreatedAt,
	}, image)
	if err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
	}
	run, err := normalizedLibraryRun(LibraryRun{
		ID:                      artifact.RunID,
		Origin:                  LibraryRunOriginHuman,
		ActorRef:                artifact.CreatedBy,
		SurfaceRef:              libraryHumanConsoleSurfaceRef,
		Status:                  "succeeded",
		InputDigest:             libraryDigest(artifact.Title + "\n" + version.Digest),
		OutputDigest:            version.Digest,
		SourceArtifactID:        artifact.SourceArtifactID,
		SourceArtifactVersionID: artifact.SourceArtifactVersionID,
		SourceArtifactDigest:    artifact.SourceArtifactDigest,
		StartedAt:               artifact.CreatedAt,
		CompletedAt:             artifact.CreatedAt,
	})
	if err != nil {
		return LibraryRun{}, LibraryArtifact{}, LibraryArtifactVersion{}, err
	}
	return run, artifact, version, nil
}

// normalizeLibraryHumanImageArtifactVersionCreateRequest validates the
// Console's bounded inputs before a store re-reads the artifact head under
// its own lock. It never chooses the version number or format itself.
func normalizeLibraryHumanImageArtifactVersionCreateRequest(request LibraryHumanImageArtifactVersionCreateRequest) (LibraryHumanImageArtifactVersionCreateRequest, error) {
	if err := validateLibraryOpaqueRef("artifact", request.ArtifactID, false); err != nil {
		return LibraryHumanImageArtifactVersionCreateRequest{}, err
	}
	if err := validateLibraryOpaqueRef("created by", request.CreatedBy, false); err != nil {
		return LibraryHumanImageArtifactVersionCreateRequest{}, err
	}
	request.Image.Bytes = append([]byte(nil), request.Image.Bytes...)
	if err := validateLibraryArtifactImageCanonical(request.Image); err != nil {
		return LibraryHumanImageArtifactVersionCreateRequest{}, err
	}
	altText, err := normalizeLibraryArtifactImageAltText(request.AltText)
	if err != nil {
		return LibraryHumanImageArtifactVersionCreateRequest{}, err
	}
	request.AltText = altText
	if err := validateLibraryChangelog(request.Changelog); err != nil {
		return LibraryHumanImageArtifactVersionCreateRequest{}, err
	}
	if err := validateLibraryVersionProvenance(request.Provenance); err != nil {
		return LibraryHumanImageArtifactVersionCreateRequest{}, err
	}
	request.Provenance = copyLibraryVersionProvenance(request.Provenance)
	return request, nil
}

func libraryArtifactMediaUnavailableError(err error) error {
	if err == nil {
		return errors.New("library artifact media is unavailable")
	}
	return fmt.Errorf("library artifact media: %w", err)
}

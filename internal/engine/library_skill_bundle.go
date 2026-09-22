package engine

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// A Library skill version is a manifest: SKILL.md at the root plus any number
// of relative files (references, scripts, assets, examples). Every file is
// data. Synaxis stores, digests, and delivers bytes; it never executes a
// script, renders an asset, or lets a file confer authority.
//
// SKILL.md keeps its historical representation: LibrarySkillVersion.Content is
// its body and LibrarySkillVersion.Digest is its SHA-256, so every existing
// version ID, digest, pin, attestation, and v1 activation stays valid. Other
// files live in a content-addressed blob store keyed by SHA-256 and are
// referenced from the manifest by digest.

const (
	// LibrarySkillInstructionsPath is the mandatory root document of a bundle.
	LibrarySkillInstructionsPath = "SKILL.md"

	// librarySkillManifestDigestPrefix versions the canonical manifest material
	// so a later manifest shape can never collide with this one.
	librarySkillManifestDigestPrefix = "synaxis.library.skill-manifest.v1\n"

	// Bundle limits are Engine policy, never caller arguments. The per-version
	// total is aligned with the Platform BFF's 8 MiB response buffer so a
	// Console download of the whole bundle always fits.
	libraryMaxSkillFileBytes      = 4 << 20
	libraryMaxSkillBundleBytes    = 8 << 20
	libraryMaxSkillFiles          = 256
	libraryMaxSkillPathBytes      = 255
	libraryMaxSkillPathSegments   = 16
	libraryMaxSkillInlineText     = 64 << 10
	libraryMaxSkillBundleZipBytes = libraryMaxSkillBundleBytes

	LibrarySkillFileEncodingUTF8   = "utf8"
	LibrarySkillFileEncodingBase64 = "base64"
)

var (
	ErrLibrarySkillBundleInvalid   = errors.New("invalid library skill bundle")
	ErrLibrarySkillFileNotFound    = errors.New("library skill file not found")
	ErrLibrarySkillBlobNotFound    = errors.New("library skill blob not found")
	ErrLibrarySkillBundleTooLarge  = errors.New("library skill bundle exceeds the size limit")
	ErrLibrarySkillFileUnsupported = errors.New("library skill file type is not allowed")
)

// LibrarySkillFile is one manifest entry. It carries metadata and the file's
// SHA-256 only; bytes are read separately through the bundle store facet.
type LibrarySkillFile struct {
	Path        string `json:"path"`
	ContentType string `json:"contentType"`
	SizeBytes   int64  `json:"sizeBytes"`
	Digest      string `json:"digest"`
}

// LibrarySkillFileContent is a file with its bytes, used only at the ingress
// boundary (Console JSON, MCP tool input, zip import) before normalization.
type LibrarySkillFileContent struct {
	Path        string
	ContentType string
	Data        []byte
}

// LibrarySkillFileInput is the wire shape shared by the Console and the MCP
// tools. An inline file carries UTF-8 text or base64 bytes; a staged file
// names a blobId returned by library_skill_upload_blob under the same lease.
type LibrarySkillFileInput struct {
	Path        string `json:"path" jsonschema:"Relative path inside the bundle, for example references/guide.md"`
	ContentType string `json:"contentType,omitempty" jsonschema:"Optional media type; must match the type derived from the file extension"`
	Encoding    string `json:"encoding,omitempty" jsonschema:"utf8 (default) or base64 for inline content"`
	Content     string `json:"content,omitempty" jsonschema:"Inline file content in the declared encoding"`
	BlobID      string `json:"blobId,omitempty" jsonschema:"Blob staged earlier with library_skill_upload_blob under this lease; replaces content"`
}

// LibrarySkillBundle is a normalized, immutable version body: the sorted
// manifest (SKILL.md included), its deterministic digest, and the bytes of
// every non-SKILL.md file keyed by digest. SKILL.md bytes are the version's
// Content and are deliberately not duplicated here.
type LibrarySkillBundle struct {
	Files          []LibrarySkillFile
	ManifestDigest string
	Blobs          map[string][]byte
	// SkillDescription, when set, updates the skill record's description in
	// the same save or transaction as the version, so a SKILL.md whose front
	// matter describes the skill afresh can never disagree with the record.
	// Only the owner/admin Console sets it; leased MCP writes never do.
	SkillDescription *string
}

// librarySkillBlobRef is a staged-blob reference that a store resolves under
// its own lock. It is never a bearer capability: only the staging client and
// epoch can turn it into bytes.
type librarySkillBlobRef struct {
	Path   string
	BlobID string
}

// librarySkillFileTypes maps the allowlisted extensions to their canonical
// media type. A file whose extension is absent here is rejected rather than
// stored as application/octet-stream.
var librarySkillFileTypes = map[string]string{
	".md":       "text/markdown",
	".markdown": "text/markdown",
	".txt":      "text/plain",
	".json":     "application/json",
	".yaml":     "application/yaml",
	".yml":      "application/yaml",
	".csv":      "text/csv",
	".py":       "text/x-python",
	".sh":       "application/x-sh",
	".xlsx":     "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
	".docx":     "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
	".pptx":     "application/vnd.openxmlformats-officedocument.presentationml.presentation",
	".pdf":      "application/pdf",
	".png":      "image/png",
	".jpg":      "image/jpeg",
	".jpeg":     "image/jpeg",
	".svg":      "image/svg+xml",
}

// librarySkillTextTypes are delivered as UTF-8 text in read projections. SVG
// is text but is always treated as an attachment and never rendered.
var librarySkillTextTypes = map[string]bool{
	"text/markdown":    true,
	"text/plain":       true,
	"application/json": true,
	"application/yaml": true,
	"text/csv":         true,
	"text/x-python":    true,
	"application/x-sh": true,
}

// LibrarySkillFileIsText reports whether a content type is delivered inline
// as UTF-8 text. Binary and SVG files are always base64 attachments.
func LibrarySkillFileIsText(contentType string) bool {
	return librarySkillTextTypes[contentType]
}

func librarySkillFileDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// normalizeLibrarySkillPath applies the bundle path rules. Paths are relative,
// use forward slashes, contain no traversal or control characters, and keep
// their exact case; case-insensitive uniqueness is enforced across the bundle.
func normalizeLibrarySkillPath(raw string) (string, error) {
	if raw == "" {
		return "", fmt.Errorf("%w: empty path", ErrLibrarySkillBundleInvalid)
	}
	if !utf8.ValidString(raw) {
		return "", fmt.Errorf("%w: path is not valid UTF-8", ErrLibrarySkillBundleInvalid)
	}
	if len(raw) > libraryMaxSkillPathBytes {
		return "", fmt.Errorf("%w: path exceeds %d bytes", ErrLibrarySkillBundleInvalid, libraryMaxSkillPathBytes)
	}
	for _, character := range raw {
		if character < 0x20 || character == 0x7f {
			return "", fmt.Errorf("%w: path contains a control character", ErrLibrarySkillBundleInvalid)
		}
	}
	if strings.ContainsAny(raw, `\:`) {
		return "", fmt.Errorf("%w: path %q must use forward slashes and no drive letter", ErrLibrarySkillBundleInvalid, raw)
	}
	if strings.HasPrefix(raw, "/") {
		return "", fmt.Errorf("%w: path %q is absolute", ErrLibrarySkillBundleInvalid, raw)
	}
	if strings.HasSuffix(raw, "/") {
		return "", fmt.Errorf("%w: path %q names a directory", ErrLibrarySkillBundleInvalid, raw)
	}
	segments := strings.Split(raw, "/")
	if len(segments) > libraryMaxSkillPathSegments {
		return "", fmt.Errorf("%w: path %q is nested too deeply", ErrLibrarySkillBundleInvalid, raw)
	}
	for _, segment := range segments {
		switch {
		case segment == "":
			return "", fmt.Errorf("%w: path %q has an empty segment", ErrLibrarySkillBundleInvalid, raw)
		case segment == "." || segment == "..":
			return "", fmt.Errorf("%w: path %q contains a traversal segment", ErrLibrarySkillBundleInvalid, raw)
		case strings.TrimSpace(segment) != segment:
			return "", fmt.Errorf("%w: path %q has leading or trailing whitespace", ErrLibrarySkillBundleInvalid, raw)
		}
	}
	if path.Clean(raw) != raw {
		return "", fmt.Errorf("%w: path %q is not canonical", ErrLibrarySkillBundleInvalid, raw)
	}
	return raw, nil
}

// librarySkillPathKey is the case-insensitive identity used to reject paths
// that differ only by case, which would collide on common file systems.
func librarySkillPathKey(normalized string) string {
	return strings.ToLower(normalized)
}

// librarySkillContentTypeForPath derives the canonical media type from the
// extension. It is the only source of a file's type; a caller-supplied type
// may confirm it but never override it.
func librarySkillContentTypeForPath(normalized string) (string, error) {
	extension := strings.ToLower(path.Ext(normalized))
	contentType, ok := librarySkillFileTypes[extension]
	if !ok {
		return "", fmt.Errorf("%w: %q", ErrLibrarySkillFileUnsupported, normalized)
	}
	return contentType, nil
}

func normalizeLibrarySkillContentType(declared string) string {
	value := strings.ToLower(strings.TrimSpace(declared))
	if index := strings.IndexByte(value, ';'); index >= 0 {
		value = strings.TrimSpace(value[:index])
	}
	return value
}

// validateLibrarySkillFileBytes verifies that the bytes are what the media
// type claims. Text must be UTF-8 without NUL; binaries must carry their
// signature; SVG must be well-formed XML without active content. Bytes are
// never rewritten so an imported bundle round-trips exactly.
func validateLibrarySkillFileBytes(normalized, contentType string, data []byte) error {
	if int64(len(data)) > libraryMaxSkillFileBytes {
		return fmt.Errorf("%w: %q exceeds %d bytes", ErrLibrarySkillBundleTooLarge, normalized, libraryMaxSkillFileBytes)
	}
	if LibrarySkillFileIsText(contentType) {
		if !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0 {
			return fmt.Errorf("%w: %q is not UTF-8 text", ErrLibrarySkillBundleInvalid, normalized)
		}
		if contentType == "application/json" && len(bytes.TrimSpace(data)) > 0 && !json.Valid(data) {
			return fmt.Errorf("%w: %q is not valid JSON", ErrLibrarySkillBundleInvalid, normalized)
		}
		return nil
	}
	switch contentType {
	case "image/png":
		if !bytes.HasPrefix(data, []byte("\x89PNG\r\n\x1a\n")) {
			return fmt.Errorf("%w: %q is not a PNG image", ErrLibrarySkillBundleInvalid, normalized)
		}
	case "image/jpeg":
		if !bytes.HasPrefix(data, []byte{0xff, 0xd8, 0xff}) {
			return fmt.Errorf("%w: %q is not a JPEG image", ErrLibrarySkillBundleInvalid, normalized)
		}
	case "application/pdf":
		if !bytes.HasPrefix(data, []byte("%PDF-")) {
			return fmt.Errorf("%w: %q is not a PDF document", ErrLibrarySkillBundleInvalid, normalized)
		}
	case "image/svg+xml":
		return validateLibrarySkillSVG(normalized, data)
	default:
		// Office Open XML packages are ZIP containers. The signature check keeps
		// an arbitrary binary from being labelled as a spreadsheet; the package
		// itself is never opened or rendered by Synaxis.
		if !bytes.HasPrefix(data, []byte("PK\x03\x04")) {
			return fmt.Errorf("%w: %q is not an Office Open XML package", ErrLibrarySkillBundleInvalid, normalized)
		}
		if _, err := zip.NewReader(bytes.NewReader(data), int64(len(data))); err != nil {
			return fmt.Errorf("%w: %q is not a readable Office Open XML package", ErrLibrarySkillBundleInvalid, normalized)
		}
	}
	return nil
}

// validateLibrarySkillSVG accepts only a static SVG document. It rejects
// DOCTYPE declarations, scripts, event handlers, foreignObject, and script
// URLs, and it returns an error rather than rewriting the bytes.
func validateLibrarySkillSVG(normalized string, data []byte) error {
	if !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0 {
		return fmt.Errorf("%w: %q is not UTF-8 SVG", ErrLibrarySkillBundleInvalid, normalized)
	}
	decoder := xml.NewDecoder(bytes.NewReader(data))
	decoder.Strict = true
	rootSeen := false
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("%w: %q is not well-formed SVG", ErrLibrarySkillBundleInvalid, normalized)
		}
		switch element := token.(type) {
		case xml.Directive:
			return fmt.Errorf("%w: %q contains an XML directive", ErrLibrarySkillBundleInvalid, normalized)
		case xml.ProcInst:
			if strings.ToLower(element.Target) != "xml" {
				return fmt.Errorf("%w: %q contains a processing instruction", ErrLibrarySkillBundleInvalid, normalized)
			}
		case xml.StartElement:
			name := strings.ToLower(element.Name.Local)
			if !rootSeen {
				if name != "svg" {
					return fmt.Errorf("%w: %q root element is not svg", ErrLibrarySkillBundleInvalid, normalized)
				}
				rootSeen = true
			}
			if name == "script" || name == "foreignobject" {
				return fmt.Errorf("%w: %q contains active content", ErrLibrarySkillBundleInvalid, normalized)
			}
			for _, attribute := range element.Attr {
				attributeName := strings.ToLower(attribute.Name.Local)
				value := strings.ToLower(strings.TrimSpace(attribute.Value))
				if strings.HasPrefix(attributeName, "on") || strings.HasPrefix(value, "javascript:") || strings.HasPrefix(value, "data:text/html") {
					return fmt.Errorf("%w: %q contains active content", ErrLibrarySkillBundleInvalid, normalized)
				}
			}
		}
	}
	if !rootSeen {
		return fmt.Errorf("%w: %q has no svg element", ErrLibrarySkillBundleInvalid, normalized)
	}
	return nil
}

// librarySkillManifestDigest is deterministic over the sorted manifest. The
// material is a JSON array of {path, contentType, sizeBytes, digest} objects
// in that key order, without whitespace or HTML escaping, prefixed by the
// manifest contract label. Identical files uploaded in any order produce the
// same digest.
func librarySkillManifestDigest(files []LibrarySkillFile) (string, error) {
	sorted := append([]LibrarySkillFile(nil), files...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Path < sorted[j].Path })
	type entry struct {
		Path        string `json:"path"`
		ContentType string `json:"contentType"`
		SizeBytes   int64  `json:"sizeBytes"`
		Digest      string `json:"digest"`
	}
	material := make([]entry, 0, len(sorted))
	for _, file := range sorted {
		material = append(material, entry{Path: file.Path, ContentType: file.ContentType, SizeBytes: file.SizeBytes, Digest: file.Digest})
	}
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(material); err != nil {
		return "", fmt.Errorf("encode library skill manifest: %w", err)
	}
	encoded := bytes.TrimRight(buffer.Bytes(), "\n")
	return libraryDigest(librarySkillManifestDigestPrefix + string(encoded)), nil
}

// legacyLibrarySkillManifest is the one-file manifest every pre-bundle
// version is equivalent to: SKILL.md with the content's byte length and the
// existing content digest.
func legacyLibrarySkillManifest(content, digest string) []LibrarySkillFile {
	return []LibrarySkillFile{{
		Path: LibrarySkillInstructionsPath, ContentType: "text/markdown",
		SizeBytes: int64(len(content)), Digest: digest,
	}}
}

// librarySkillVersionWithManifest fills the manifest of a version read from
// a store that predates bundles. It is idempotent and never changes Content
// or Digest, so legacy version IDs and digests stay valid unchanged.
func librarySkillVersionWithManifest(version LibrarySkillVersion) (LibrarySkillVersion, error) {
	if version.Digest == "" {
		version.Digest = libraryDigest(version.Content)
	}
	if len(version.Files) == 0 {
		version.Files = legacyLibrarySkillManifest(version.Content, version.Digest)
	}
	if err := validateLibrarySkillManifest(version.Files, version.Content, version.Digest); err != nil {
		return LibrarySkillVersion{}, err
	}
	digest, err := librarySkillManifestDigest(version.Files)
	if err != nil {
		return LibrarySkillVersion{}, err
	}
	version.ManifestDigest = digest
	return version, nil
}

// validateLibrarySkillManifest checks structural manifest invariants for a
// stored or incoming version: sorted unique paths, SKILL.md present with the
// content's size and digest, allowlisted types, and the per-file caps.
func validateLibrarySkillManifest(files []LibrarySkillFile, content, contentDigest string) error {
	if len(files) == 0 {
		return fmt.Errorf("%w: manifest is empty", ErrLibrarySkillBundleInvalid)
	}
	if len(files) > libraryMaxSkillFiles {
		return fmt.Errorf("%w: at most %d files are allowed", ErrLibrarySkillBundleTooLarge, libraryMaxSkillFiles)
	}
	seen := make(map[string]struct{}, len(files))
	var total int64
	instructionsSeen := false
	for index, file := range files {
		normalized, err := normalizeLibrarySkillPath(file.Path)
		if err != nil {
			return err
		}
		if normalized != file.Path {
			return fmt.Errorf("%w: path %q is not normalized", ErrLibrarySkillBundleInvalid, file.Path)
		}
		if index > 0 && files[index-1].Path >= file.Path {
			return fmt.Errorf("%w: manifest is not sorted", ErrLibrarySkillBundleInvalid)
		}
		key := librarySkillPathKey(normalized)
		if _, duplicate := seen[key]; duplicate {
			return fmt.Errorf("%w: duplicate path %q", ErrLibrarySkillBundleInvalid, file.Path)
		}
		seen[key] = struct{}{}
		expectedType, err := librarySkillContentTypeForPath(normalized)
		if err != nil {
			return err
		}
		if file.ContentType != expectedType {
			return fmt.Errorf("%w: %q content type %q does not match its extension", ErrLibrarySkillBundleInvalid, file.Path, file.ContentType)
		}
		if file.SizeBytes < 0 || file.SizeBytes > libraryMaxSkillFileBytes {
			return fmt.Errorf("%w: %q size is out of range", ErrLibrarySkillBundleTooLarge, file.Path)
		}
		if err := validateLibraryDigest("skill file", file.Digest, false); err != nil {
			return fmt.Errorf("%w: %q: %v", ErrLibrarySkillBundleInvalid, file.Path, err)
		}
		total += file.SizeBytes
		if file.Path == LibrarySkillInstructionsPath {
			instructionsSeen = true
			if file.SizeBytes != int64(len(content)) || file.Digest != contentDigest {
				return fmt.Errorf("%w: SKILL.md manifest entry does not match the instructions", ErrLibrarySkillBundleInvalid)
			}
		}
	}
	if !instructionsSeen {
		return fmt.Errorf("%w: SKILL.md is required at the bundle root", ErrLibrarySkillBundleInvalid)
	}
	if total > libraryMaxSkillBundleBytes {
		return fmt.Errorf("%w: bundle exceeds %d bytes", ErrLibrarySkillBundleTooLarge, libraryMaxSkillBundleBytes)
	}
	return nil
}

// normalizeLibrarySkillBundle turns raw ingress files plus the SKILL.md
// shorthand into an immutable bundle. SKILL.md may arrive as content, as a
// file entry, or both when identical. The result is sorted, digested, and
// validated; blob bytes are keyed by digest so identical files dedupe.
func normalizeLibrarySkillBundle(content string, files []LibrarySkillFileContent) (string, LibrarySkillBundle, error) {
	entries := make([]LibrarySkillFile, 0, len(files)+1)
	blobs := make(map[string][]byte, len(files))
	seen := make(map[string]struct{}, len(files)+1)
	instructions := content
	instructionsFromFile := false
	for _, file := range files {
		normalized, err := normalizeLibrarySkillPath(file.Path)
		if err != nil {
			return "", LibrarySkillBundle{}, err
		}
		key := librarySkillPathKey(normalized)
		if _, duplicate := seen[key]; duplicate {
			return "", LibrarySkillBundle{}, fmt.Errorf("%w: duplicate path %q", ErrLibrarySkillBundleInvalid, file.Path)
		}
		seen[key] = struct{}{}
		if key == librarySkillPathKey(LibrarySkillInstructionsPath) {
			if normalized != LibrarySkillInstructionsPath {
				return "", LibrarySkillBundle{}, fmt.Errorf("%w: the instructions file must be named exactly SKILL.md", ErrLibrarySkillBundleInvalid)
			}
			if !utf8.Valid(file.Data) {
				return "", LibrarySkillBundle{}, fmt.Errorf("%w: SKILL.md is not UTF-8 text", ErrLibrarySkillBundleInvalid)
			}
			text := string(file.Data)
			if content != "" && content != text {
				return "", LibrarySkillBundle{}, fmt.Errorf("%w: content and the SKILL.md file entry disagree", ErrLibrarySkillBundleInvalid)
			}
			instructions = text
			instructionsFromFile = true
			continue
		}
		contentType, err := librarySkillContentTypeForPath(normalized)
		if err != nil {
			return "", LibrarySkillBundle{}, err
		}
		if declared := normalizeLibrarySkillContentType(file.ContentType); declared != "" && declared != contentType {
			return "", LibrarySkillBundle{}, fmt.Errorf("%w: %q declares %q but its extension means %q", ErrLibrarySkillBundleInvalid, normalized, declared, contentType)
		}
		if err := validateLibrarySkillFileBytes(normalized, contentType, file.Data); err != nil {
			return "", LibrarySkillBundle{}, err
		}
		digest := librarySkillFileDigest(file.Data)
		entries = append(entries, LibrarySkillFile{Path: normalized, ContentType: contentType, SizeBytes: int64(len(file.Data)), Digest: digest})
		if _, stored := blobs[digest]; !stored {
			blobs[digest] = append([]byte(nil), file.Data...)
		}
	}
	if strings.TrimSpace(instructions) == "" {
		if instructionsFromFile {
			return "", LibrarySkillBundle{}, fmt.Errorf("%w: SKILL.md is empty", ErrLibrarySkillBundleInvalid)
		}
		return "", LibrarySkillBundle{}, fmt.Errorf("%w: SKILL.md is required at the bundle root", ErrLibrarySkillBundleInvalid)
	}
	if len(instructions) > libraryMaxContentBytes {
		return "", LibrarySkillBundle{}, fmt.Errorf("%w: SKILL.md exceeds %d bytes", ErrLibrarySkillBundleTooLarge, libraryMaxContentBytes)
	}
	if !utf8.ValidString(instructions) || strings.IndexByte(instructions, 0) >= 0 {
		return "", LibrarySkillBundle{}, fmt.Errorf("%w: SKILL.md is not UTF-8 text", ErrLibrarySkillBundleInvalid)
	}
	contentDigest := libraryDigest(instructions)
	entries = append(entries, legacyLibrarySkillManifest(instructions, contentDigest)...)
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	if err := validateLibrarySkillManifest(entries, instructions, contentDigest); err != nil {
		return "", LibrarySkillBundle{}, err
	}
	manifestDigest, err := librarySkillManifestDigest(entries)
	if err != nil {
		return "", LibrarySkillBundle{}, err
	}
	return instructions, LibrarySkillBundle{Files: entries, ManifestDigest: manifestDigest, Blobs: blobs}, nil
}

// decodeLibrarySkillFileInputs splits wire inputs into inline files and
// staged-blob references. Inline content is decoded here; references are
// resolved later by a store under its lock, where the staging client and
// epoch can be verified.
func decodeLibrarySkillFileInputs(inputs []LibrarySkillFileInput) ([]LibrarySkillFileContent, []librarySkillBlobRef, error) {
	if len(inputs) > libraryMaxSkillFiles {
		return nil, nil, fmt.Errorf("%w: at most %d files are allowed", ErrLibrarySkillBundleTooLarge, libraryMaxSkillFiles)
	}
	inline := make([]LibrarySkillFileContent, 0, len(inputs))
	refs := make([]librarySkillBlobRef, 0)
	seen := make(map[string]struct{}, len(inputs))
	for _, input := range inputs {
		normalized, err := normalizeLibrarySkillPath(strings.TrimSpace(input.Path))
		if err != nil {
			return nil, nil, err
		}
		key := librarySkillPathKey(normalized)
		if _, duplicate := seen[key]; duplicate {
			return nil, nil, fmt.Errorf("%w: duplicate path %q", ErrLibrarySkillBundleInvalid, normalized)
		}
		seen[key] = struct{}{}
		blobID := strings.TrimSpace(input.BlobID)
		if blobID != "" {
			if input.Content != "" || input.Encoding != "" {
				return nil, nil, fmt.Errorf("%w: %q must supply either content or blobId", ErrLibrarySkillBundleInvalid, normalized)
			}
			if err := validateLibraryOpaqueRef("skill blob", blobID, false); err != nil {
				return nil, nil, fmt.Errorf("%w: %q: %v", ErrLibrarySkillBundleInvalid, normalized, err)
			}
			refs = append(refs, librarySkillBlobRef{Path: normalized, BlobID: blobID})
			continue
		}
		var data []byte
		switch strings.ToLower(strings.TrimSpace(input.Encoding)) {
		case "", LibrarySkillFileEncodingUTF8:
			if !utf8.ValidString(input.Content) {
				return nil, nil, fmt.Errorf("%w: %q content is not UTF-8", ErrLibrarySkillBundleInvalid, normalized)
			}
			data = []byte(input.Content)
		case LibrarySkillFileEncodingBase64:
			if len(input.Content) > base64.StdEncoding.EncodedLen(libraryMaxSkillFileBytes)+4 {
				return nil, nil, fmt.Errorf("%w: %q exceeds %d bytes", ErrLibrarySkillBundleTooLarge, normalized, libraryMaxSkillFileBytes)
			}
			decoded, err := base64.StdEncoding.DecodeString(input.Content)
			if err != nil {
				return nil, nil, fmt.Errorf("%w: %q content is not standard base64", ErrLibrarySkillBundleInvalid, normalized)
			}
			data = decoded
		default:
			return nil, nil, fmt.Errorf("%w: %q encoding must be utf8 or base64", ErrLibrarySkillBundleInvalid, normalized)
		}
		if int64(len(data)) > libraryMaxSkillFileBytes {
			return nil, nil, fmt.Errorf("%w: %q exceeds %d bytes", ErrLibrarySkillBundleTooLarge, normalized, libraryMaxSkillFileBytes)
		}
		inline = append(inline, LibrarySkillFileContent{Path: normalized, ContentType: input.ContentType, Data: data})
	}
	return inline, refs, nil
}

// librarySkillFileInputsPayloadMaterial is the caller-controlled bundle part of
// an idempotency payload digest. Inline files contribute their digest; staged
// references contribute the opaque blob ID, so an exact retry hashes the same
// and a changed file or reference conflicts.
func librarySkillFileInputsPayloadMaterial(inline []LibrarySkillFileContent, refs []librarySkillBlobRef) []string {
	material := make([]string, 0, len(inline)+len(refs))
	for _, file := range inline {
		material = append(material, file.Path+"\x00"+normalizeLibrarySkillContentType(file.ContentType)+"\x00sha256:"+librarySkillFileDigest(file.Data))
	}
	for _, ref := range refs {
		material = append(material, ref.Path+"\x00\x00blob:"+ref.BlobID)
	}
	sort.Strings(material)
	return material
}

// librarySkillFrontMatter is the parsed head of SKILL.md. Only the top-level
// scalar keys the Engine needs are interpreted; everything else is ignored
// exactly as the Console importer ignores it.
type librarySkillFrontMatter struct {
	Present     bool
	Name        string
	Description string
	Body        string
}

// parseLibrarySkillFrontMatter reads a YAML-like front matter block. It
// supports `key: value`, single- and double-quoted scalars, and `|`/`>` block
// scalars for top-level keys, and never evaluates anything.
func parseLibrarySkillFrontMatter(content string) librarySkillFrontMatter {
	text := strings.TrimPrefix(content, "\ufeff")
	lines := strings.Split(text, "\n")
	trim := func(line string) string { return strings.TrimRight(line, "\r") }
	if len(lines) == 0 || strings.TrimSpace(trim(lines[0])) != "---" {
		return librarySkillFrontMatter{Body: content}
	}
	end := -1
	for index := 1; index < len(lines); index++ {
		if strings.TrimSpace(trim(lines[index])) == "---" {
			end = index
			break
		}
	}
	if end < 0 {
		return librarySkillFrontMatter{Body: content}
	}
	result := librarySkillFrontMatter{Present: true, Body: strings.Join(lines[end+1:], "\n")}
	block := lines[1:end]
	values := map[string]string{}
	for index := 0; index < len(block); index++ {
		line := trim(block[index])
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if line != strings.TrimLeft(line, " \t") {
			// Indented lines belong to a nested mapping or list; skip them.
			continue
		}
		colon := strings.Index(line, ":")
		if colon <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:colon])
		value := strings.TrimSpace(line[colon+1:])
		if value == "|" || value == ">" || value == "|-" || value == ">-" {
			var collected []string
			for index+1 < len(block) {
				next := trim(block[index+1])
				if strings.TrimSpace(next) != "" && next == strings.TrimLeft(next, " \t") {
					break
				}
				collected = append(collected, strings.TrimLeft(next, " \t"))
				index++
			}
			if strings.HasPrefix(value, "|") {
				values[key] = strings.TrimSpace(strings.Join(collected, "\n"))
			} else {
				values[key] = strings.TrimSpace(strings.Join(collected, " "))
			}
			continue
		}
		values[key] = unquoteLibrarySkillScalar(value)
	}
	result.Name = values["name"]
	result.Description = values["description"]
	return result
}

func unquoteLibrarySkillScalar(value string) string {
	if len(value) >= 2 {
		first, last := value[0], value[len(value)-1]
		if first == '"' && last == '"' {
			if unquoted, err := strconv.Unquote(value); err == nil {
				return unquoted
			}
			return strings.ReplaceAll(value[1:len(value)-1], `\"`, `"`)
		}
		if first == '\'' && last == '\'' {
			return strings.ReplaceAll(value[1:len(value)-1], "''", "'")
		}
	}
	return value
}

func librarySkillNormalizedText(value string) string {
	return strings.Join(strings.Fields(value), " ")
}

// librarySkillFrontMatterNameAgrees accepts the Agent Skills convention where
// front matter `name` is the skill identifier (slug) as well as the display
// name, compared case- and whitespace-insensitively.
func librarySkillFrontMatterNameAgrees(frontMatterName string, skill LibrarySkill) bool {
	candidate := librarySkillNormalizedText(frontMatterName)
	if candidate == "" {
		return false
	}
	if strings.EqualFold(candidate, librarySkillNormalizedText(skill.Name)) || candidate == skill.Slug {
		return true
	}
	return librarySlugFromName(candidate) != "" && librarySlugFromName(candidate) == skill.Slug
}

// validateLibrarySkillFrontMatter enforces the agreement rule. A bundle-
// authored version must carry front matter with name and description that
// match the skill record; a legacy single-document version may omit front
// matter but, when present, it must still agree.
func validateLibrarySkillFrontMatter(skill LibrarySkill, content string, required bool) error {
	frontMatter := parseLibrarySkillFrontMatter(content)
	if !frontMatter.Present {
		if required {
			return fmt.Errorf("%w: SKILL.md front matter with name and description is required", ErrLibrarySkillBundleInvalid)
		}
		return nil
	}
	if frontMatter.Name == "" || frontMatter.Description == "" {
		if required {
			return fmt.Errorf("%w: SKILL.md front matter must include name and description", ErrLibrarySkillBundleInvalid)
		}
	}
	if frontMatter.Name != "" && !librarySkillFrontMatterNameAgrees(frontMatter.Name, skill) {
		return fmt.Errorf("%w: SKILL.md front matter name %q does not match the skill", ErrLibrarySkillBundleInvalid, frontMatter.Name)
	}
	if frontMatter.Description != "" && librarySkillNormalizedText(frontMatter.Description) != librarySkillNormalizedText(skill.Description) {
		return fmt.Errorf("%w: SKILL.md front matter description does not match the skill", ErrLibrarySkillBundleInvalid)
	}
	return nil
}

// applyLibrarySkillFrontMatterDefaults fills a create request's missing name
// and description from SKILL.md front matter so an imported bundle needs no
// duplicated metadata. It never overrides a value the caller supplied.
func applyLibrarySkillFrontMatterDefaults(name, description *string, content string) {
	frontMatter := parseLibrarySkillFrontMatter(content)
	if !frontMatter.Present {
		return
	}
	if strings.TrimSpace(*name) == "" && frontMatter.Name != "" {
		*name = strings.TrimSpace(frontMatter.Name)
	}
	if strings.TrimSpace(*description) == "" && frontMatter.Description != "" {
		*description = strings.TrimSpace(frontMatter.Description)
	}
}

// parseLibrarySkillBundleZip reads a .skill package (the skill-creator
// format: one top-level folder containing SKILL.md) or a flat zip with
// SKILL.md at its root. It refuses traversal, absolute, symlink, encrypted,
// duplicate, and oversize entries before any byte is kept, and it ignores
// macOS resource forks that common zip tools add.
func parseLibrarySkillBundleZip(data []byte) ([]LibrarySkillFileContent, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: empty archive", ErrLibrarySkillBundleInvalid)
	}
	if int64(len(data)) > libraryMaxSkillBundleZipBytes {
		return nil, fmt.Errorf("%w: archive exceeds %d bytes", ErrLibrarySkillBundleTooLarge, libraryMaxSkillBundleZipBytes)
	}
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("%w: not a zip archive", ErrLibrarySkillBundleInvalid)
	}
	type rawEntry struct {
		name string
		data []byte
	}
	var entries []rawEntry
	var total int64
	for _, file := range reader.File {
		name := file.Name
		if strings.HasPrefix(name, "__MACOSX/") || path.Base(name) == ".DS_Store" {
			continue
		}
		if strings.HasSuffix(name, "/") || file.FileInfo().IsDir() {
			if _, err := normalizeLibrarySkillPath(strings.TrimSuffix(name, "/")); err != nil && name != "/" {
				return nil, err
			}
			continue
		}
		if file.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("%w: %q is a symbolic link", ErrLibrarySkillBundleInvalid, name)
		}
		if file.Flags&0x1 != 0 {
			return nil, fmt.Errorf("%w: %q is encrypted", ErrLibrarySkillBundleInvalid, name)
		}
		if _, err := normalizeLibrarySkillPath(name); err != nil {
			return nil, err
		}
		if len(entries) >= libraryMaxSkillFiles {
			return nil, fmt.Errorf("%w: at most %d files are allowed", ErrLibrarySkillBundleTooLarge, libraryMaxSkillFiles)
		}
		if file.UncompressedSize64 > uint64(libraryMaxSkillFileBytes) {
			return nil, fmt.Errorf("%w: %q exceeds %d bytes", ErrLibrarySkillBundleTooLarge, name, libraryMaxSkillFileBytes)
		}
		content, err := file.Open()
		if err != nil {
			return nil, fmt.Errorf("%w: %q cannot be read", ErrLibrarySkillBundleInvalid, name)
		}
		payload, err := io.ReadAll(io.LimitReader(content, libraryMaxSkillFileBytes+1))
		content.Close()
		if err != nil {
			return nil, fmt.Errorf("%w: %q cannot be read", ErrLibrarySkillBundleInvalid, name)
		}
		if int64(len(payload)) > libraryMaxSkillFileBytes {
			return nil, fmt.Errorf("%w: %q exceeds %d bytes", ErrLibrarySkillBundleTooLarge, name, libraryMaxSkillFileBytes)
		}
		total += int64(len(payload))
		if total > libraryMaxSkillBundleBytes {
			return nil, fmt.Errorf("%w: bundle exceeds %d bytes", ErrLibrarySkillBundleTooLarge, libraryMaxSkillBundleBytes)
		}
		entries = append(entries, rawEntry{name: name, data: payload})
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("%w: archive has no files", ErrLibrarySkillBundleInvalid)
	}
	prefix := ""
	rootHasInstructions := false
	for _, entry := range entries {
		if entry.name == LibrarySkillInstructionsPath {
			rootHasInstructions = true
			break
		}
	}
	if !rootHasInstructions {
		first := entries[0].name
		slash := strings.Index(first, "/")
		if slash <= 0 {
			return nil, fmt.Errorf("%w: SKILL.md is required at the bundle root", ErrLibrarySkillBundleInvalid)
		}
		prefix = first[:slash+1]
		found := false
		for _, entry := range entries {
			if !strings.HasPrefix(entry.name, prefix) {
				return nil, fmt.Errorf("%w: SKILL.md is required at the bundle root", ErrLibrarySkillBundleInvalid)
			}
			if entry.name == prefix+LibrarySkillInstructionsPath {
				found = true
			}
		}
		if !found {
			return nil, fmt.Errorf("%w: SKILL.md is required at the bundle root", ErrLibrarySkillBundleInvalid)
		}
	}
	files := make([]LibrarySkillFileContent, 0, len(entries))
	seen := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		relative := strings.TrimPrefix(entry.name, prefix)
		normalized, err := normalizeLibrarySkillPath(relative)
		if err != nil {
			return nil, err
		}
		key := librarySkillPathKey(normalized)
		if _, duplicate := seen[key]; duplicate {
			return nil, fmt.Errorf("%w: duplicate path %q", ErrLibrarySkillBundleInvalid, normalized)
		}
		seen[key] = struct{}{}
		files = append(files, LibrarySkillFileContent{Path: normalized, Data: entry.data})
	}
	return files, nil
}

// buildLibrarySkillBundleZip writes a deterministic .skill package for one
// immutable version: entries sorted by path under a single <slug>/ folder,
// fixed timestamps from the version, deflate for text and store for already
// compressed types. Repeated exports of the same version are identical.
func buildLibrarySkillBundleZip(slug string, version LibrarySkillVersion, fileBytes func(LibrarySkillFile) ([]byte, error)) ([]byte, error) {
	if slug == "" || !librarySlugPattern.MatchString(slug) {
		return nil, fmt.Errorf("%w: invalid skill slug", ErrLibrarySkillBundleInvalid)
	}
	files := append([]LibrarySkillFile(nil), version.Files...)
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	modified := version.CreatedAt.UTC()
	for _, file := range files {
		data, err := fileBytes(file)
		if err != nil {
			return nil, err
		}
		if int64(len(data)) != file.SizeBytes || librarySkillFileDigest(data) != file.Digest {
			return nil, fmt.Errorf("%w: %q bytes do not match the manifest", ErrLibrarySkillBundleInvalid, file.Path)
		}
		header := &zip.FileHeader{Name: slug + "/" + file.Path, Method: zip.Deflate, Modified: modified}
		if !LibrarySkillFileIsText(file.ContentType) && file.ContentType != "image/svg+xml" {
			header.Method = zip.Store
		}
		header.SetMode(0o644)
		entry, err := writer.CreateHeader(header)
		if err != nil {
			return nil, fmt.Errorf("write library skill bundle entry %q: %w", file.Path, err)
		}
		if _, err := entry.Write(data); err != nil {
			return nil, fmt.Errorf("write library skill bundle entry %q: %w", file.Path, err)
		}
	}
	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("close library skill bundle: %w", err)
	}
	return buffer.Bytes(), nil
}

// LibrarySkillFileProjection is the read-side view of one manifest entry.
// Text files up to the inline limit carry their UTF-8 body; everything else
// is fetched on demand through library_skill_file_read or the Console route.
type LibrarySkillFileProjection struct {
	Path        string `json:"path"`
	ContentType string `json:"contentType"`
	SizeBytes   int64  `json:"sizeBytes"`
	Digest      string `json:"digest"`
	Text        string `json:"text,omitempty"`
}

// LibrarySkillManifestProjection is the manifest as MCP read tools return it.
type LibrarySkillManifestProjection struct {
	ManifestDigest string                       `json:"manifestDigest"`
	Files          []LibrarySkillFileProjection `json:"files"`
}

// LibrarySkillBundleStore is the narrow persistence facet for bundle bytes.
// Ordinary Library list/detail code cannot read file bytes merely by holding
// LibraryStore; a caller must name the exact skill, version, and path.
type LibrarySkillBundleStore interface {
	CreateLibrarySkillWithInitialBundle(ctx context.Context, skill LibrarySkill, version LibrarySkillVersion, bundle LibrarySkillBundle) (LibrarySkill, LibrarySkillVersion, error)
	CreateLibrarySkillBundleVersion(ctx context.Context, version LibrarySkillVersion, bundle LibrarySkillBundle) (LibrarySkillVersion, error)
	LibrarySkillFileBytes(ctx context.Context, skillID, versionID, filePath string) ([]byte, LibrarySkillFile, bool, error)
	// UpdateLibrarySkillDescription changes the skill record's description
	// only. Name, slug, versions, bindings, and authority are untouched; the
	// Engine-managed guide is refused.
	UpdateLibrarySkillDescription(ctx context.Context, skillID, description string) (LibrarySkill, error)
}

// validateLibrarySkillDescriptionUpdate applies the record's own description
// rule to an in-place edit.
func validateLibrarySkillDescriptionUpdate(description string) error {
	if len(description) > libraryMaxDescriptionBytes || !utf8.ValidString(description) {
		return fmt.Errorf("skill description must be valid UTF-8 of at most %d bytes", libraryMaxDescriptionBytes)
	}
	return nil
}

// librarySkillManifestProjection renders the manifest for a read tool,
// inlining small text files through the supplied byte reader. A reader error
// leaves the entry metadata-only rather than failing the whole read.
func librarySkillManifestProjection(version LibrarySkillVersion, fileBytes func(LibrarySkillFile) ([]byte, error)) LibrarySkillManifestProjection {
	projection := LibrarySkillManifestProjection{ManifestDigest: version.ManifestDigest, Files: make([]LibrarySkillFileProjection, 0, len(version.Files))}
	for _, file := range version.Files {
		entry := LibrarySkillFileProjection{Path: file.Path, ContentType: file.ContentType, SizeBytes: file.SizeBytes, Digest: file.Digest}
		if file.Path == LibrarySkillInstructionsPath {
			if len(version.Content) <= libraryMaxSkillInlineText {
				entry.Text = version.Content
			}
		} else if LibrarySkillFileIsText(file.ContentType) && file.SizeBytes <= libraryMaxSkillInlineText && fileBytes != nil {
			if data, err := fileBytes(file); err == nil && utf8.Valid(data) {
				entry.Text = string(data)
			}
		}
		projection.Files = append(projection.Files, entry)
	}
	return projection
}

// librarySkillFileByPath finds one manifest entry by exact path.
func librarySkillFileByPath(version LibrarySkillVersion, filePath string) (LibrarySkillFile, bool) {
	for _, file := range version.Files {
		if file.Path == filePath {
			return file, true
		}
	}
	return LibrarySkillFile{}, false
}

func copyLibrarySkillFiles(files []LibrarySkillFile) []LibrarySkillFile {
	if files == nil {
		return nil
	}
	return append([]LibrarySkillFile(nil), files...)
}

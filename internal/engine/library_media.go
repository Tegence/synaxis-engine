package engine

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"image/jpeg"
	"image/png"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// The image-artifact input is intentionally small. The encoded cap is sized
// for the bounded decoded payload, rather than accepting an unbounded base64
// string and discovering the limit after allocation.
const (
	libraryArtifactImageMIMEPNG  = "image/png"
	libraryArtifactImageMIMEJPEG = "image/jpeg"
	libraryArtifactImageMIMESVG  = "image/svg+xml"

	// MCP routes cap JSON request bodies at 1 MiB. Keeping the decoded image
	// below 512 KiB guarantees canonical base64 plus its small JSON envelope
	// remains below that existing transport boundary without weakening it.
	libraryArtifactImageMaxDecodedBytes = 512 << 10
	libraryArtifactImageMaxEncodedBytes = ((libraryArtifactImageMaxDecodedBytes + 2) / 3) * 4
	libraryArtifactImageMaxDimension    = 4096
	libraryArtifactImageMaxPixels       = 8_000_000

	libraryArtifactSVGMaxBytes      = 256 << 10
	libraryArtifactSVGMaxNodes      = 1024
	libraryArtifactSVGMaxDepth      = 64
	libraryArtifactSVGMaxAttrBytes  = 64 << 10
	libraryArtifactSVGMaxCoordinate = 1_000_000

	libraryArtifactImageDeliveryInline       = "inline"
	libraryArtifactImageDeliveryDownloadOnly = "download_only"

	libraryArtifactSVGNamespace = "http://www.w3.org/2000/svg"
)

var (
	// ErrLibraryArtifactMediaInvalid is deliberately content-free. Callers can
	// return it from a JSON/MCP boundary without reflecting image bytes, SVG
	// source, or an untrusted MIME string into logs or responses.
	ErrLibraryArtifactMediaInvalid = errors.New("invalid library artifact media")
	// ErrLibraryArtifactMediaTooLarge distinguishes a policy limit from a
	// malformed payload without exposing the size or payload itself.
	ErrLibraryArtifactMediaTooLarge = errors.New("library artifact media is too large")
	// ErrLibraryArtifactMediaUnsupported is used for a media class that the
	// deliberately narrow V1 profile does not accept.
	ErrLibraryArtifactMediaUnsupported = errors.New("unsupported library artifact media")
)

// libraryArtifactImageCanonical is the boundary result used by the later
// Store/tool integration. Bytes are canonicalized before the digest is
// calculated; SVG is never an inline-preview candidate in V1.
//
// This type intentionally carries no caller-provided base64, filename, or raw
// error context. That prevents those untrusted values from becoming durable
// metadata or accidental audit payloads.
type libraryArtifactImageCanonical struct {
	MIMEType     string
	Bytes        []byte
	Digest       string
	SizeBytes    int64
	Width        int
	Height       int
	DeliveryMode string
}

// normalizeLibraryArtifactImage is the MCP-facing boundary: it only accepts
// canonical standard base64 (no data URL, whitespace, URL alphabet, or loose
// padding), then checks the declared MIME against the decoded bytes.
func normalizeLibraryArtifactImage(declaredMIME, dataBase64 string) (libraryArtifactImageCanonical, error) {
	raw, err := decodeCanonicalLibraryArtifactImageBase64(dataBase64)
	if err != nil {
		return libraryArtifactImageCanonical{}, err
	}
	return canonicalizeLibraryArtifactImage(declaredMIME, raw)
}

// decodeCanonicalLibraryArtifactImageBase64 decodes exactly one RFC 4648
// standard-base64 representation. Re-encoding is intentional: DecodeString
// alone accepts several spellings that would make an immutable request digest
// depend on transport quirks.
func decodeCanonicalLibraryArtifactImageBase64(encoded string) ([]byte, error) {
	if encoded == "" {
		return nil, ErrLibraryArtifactMediaInvalid
	}
	if len(encoded) > libraryArtifactImageMaxEncodedBytes {
		return nil, ErrLibraryArtifactMediaTooLarge
	}
	for i := 0; i < len(encoded); i++ {
		ch := encoded[i]
		if (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '+' || ch == '/' || ch == '=' {
			continue
		}
		return nil, ErrLibraryArtifactMediaInvalid
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(raw) == 0 {
		return nil, ErrLibraryArtifactMediaInvalid
	}
	if len(raw) > libraryArtifactImageMaxDecodedBytes {
		return nil, ErrLibraryArtifactMediaTooLarge
	}
	if base64.StdEncoding.EncodeToString(raw) != encoded {
		return nil, ErrLibraryArtifactMediaInvalid
	}
	return raw, nil
}

// canonicalizeLibraryArtifactImage also accepts already-decoded bytes for
// trusted future Console/upload transport. It applies the same bounded parser
// and canonicalizer, so transport cannot change the media security contract.
func canonicalizeLibraryArtifactImage(declaredMIME string, raw []byte) (libraryArtifactImageCanonical, error) {
	if len(raw) == 0 {
		return libraryArtifactImageCanonical{}, ErrLibraryArtifactMediaInvalid
	}
	if len(raw) > libraryArtifactImageMaxDecodedBytes {
		return libraryArtifactImageCanonical{}, ErrLibraryArtifactMediaTooLarge
	}

	var (
		canonical []byte
		width     int
		height    int
		delivery  = libraryArtifactImageDeliveryInline
		err       error
	)
	switch declaredMIME {
	case libraryArtifactImageMIMEPNG:
		canonical, width, height, err = canonicalizeLibraryArtifactPNG(raw)
	case libraryArtifactImageMIMEJPEG:
		canonical, width, height, err = canonicalizeLibraryArtifactJPEG(raw)
	case libraryArtifactImageMIMESVG:
		canonical, width, height, err = canonicalizeLibraryArtifactSVG(raw)
		delivery = libraryArtifactImageDeliveryDownloadOnly
	default:
		return libraryArtifactImageCanonical{}, ErrLibraryArtifactMediaUnsupported
	}
	if err != nil {
		return libraryArtifactImageCanonical{}, err
	}
	if len(canonical) == 0 {
		return libraryArtifactImageCanonical{}, ErrLibraryArtifactMediaInvalid
	}
	if len(canonical) > libraryArtifactImageMaxDecodedBytes {
		return libraryArtifactImageCanonical{}, ErrLibraryArtifactMediaTooLarge
	}
	sum := sha256.Sum256(canonical)
	return libraryArtifactImageCanonical{
		MIMEType:     declaredMIME,
		Bytes:        canonical,
		Digest:       hex.EncodeToString(sum[:]),
		SizeBytes:    int64(len(canonical)),
		Width:        width,
		Height:       height,
		DeliveryMode: delivery,
	}, nil
}

func canonicalizeLibraryArtifactPNG(raw []byte) ([]byte, int, int, error) {
	if len(raw) < 8 || !bytes.Equal(raw[:8], []byte{'\x89', 'P', 'N', 'G', '\r', '\n', '\x1a', '\n'}) {
		return nil, 0, 0, ErrLibraryArtifactMediaInvalid
	}
	config, err := png.DecodeConfig(bytes.NewReader(raw))
	if err != nil {
		return nil, 0, 0, ErrLibraryArtifactMediaInvalid
	}
	if err := validateLibraryArtifactImageDimensions(config.Width, config.Height); err != nil {
		return nil, 0, 0, err
	}
	image, err := png.Decode(bytes.NewReader(raw))
	if err != nil {
		return nil, 0, 0, ErrLibraryArtifactMediaInvalid
	}
	if image.Bounds().Dx() != config.Width || image.Bounds().Dy() != config.Height {
		return nil, 0, 0, ErrLibraryArtifactMediaInvalid
	}
	var out bytes.Buffer
	if err := png.Encode(&out, image); err != nil {
		return nil, 0, 0, ErrLibraryArtifactMediaInvalid
	}
	return out.Bytes(), config.Width, config.Height, nil
}

func canonicalizeLibraryArtifactJPEG(raw []byte) ([]byte, int, int, error) {
	if len(raw) < 4 || raw[0] != 0xff || raw[1] != 0xd8 {
		return nil, 0, 0, ErrLibraryArtifactMediaInvalid
	}
	config, err := jpeg.DecodeConfig(bytes.NewReader(raw))
	if err != nil {
		return nil, 0, 0, ErrLibraryArtifactMediaInvalid
	}
	if err := validateLibraryArtifactImageDimensions(config.Width, config.Height); err != nil {
		return nil, 0, 0, err
	}
	image, err := jpeg.Decode(bytes.NewReader(raw))
	if err != nil {
		return nil, 0, 0, ErrLibraryArtifactMediaInvalid
	}
	if image.Bounds().Dx() != config.Width || image.Bounds().Dy() != config.Height {
		return nil, 0, 0, ErrLibraryArtifactMediaInvalid
	}
	var out bytes.Buffer
	// Re-encoding with a fixed quality strips EXIF/XMP/comments and gives the
	// immutable blob one stable representation. JPEG's source compression is
	// intentionally not preserved because metadata must never become content.
	if err := jpeg.Encode(&out, image, &jpeg.Options{Quality: 90}); err != nil {
		return nil, 0, 0, ErrLibraryArtifactMediaInvalid
	}
	return out.Bytes(), config.Width, config.Height, nil
}

// validateLibraryArtifactImageContent verifies that persisted canonical bytes
// still match their declared media type and dimensions. It deliberately does
// not re-encode JPEG on every read: JPEG's fixed-quality canonicalizer is a
// write-time transform and a second lossy encode need not be byte-identical.
// PNG/JPEG are fully decoded after their bounded config is read; SVG must
// reproduce the static canonical representation exactly.
func validateLibraryArtifactImageContent(media LibraryArtifactMedia, raw []byte) error {
	switch media.MIMEType {
	case libraryArtifactImageMIMEPNG:
		if media.DeliveryMode != libraryArtifactImageDeliveryInline {
			return ErrLibraryArtifactMediaInvalid
		}
		return validateLibraryArtifactPNGContent(raw, media.Width, media.Height)
	case libraryArtifactImageMIMEJPEG:
		if media.DeliveryMode != libraryArtifactImageDeliveryInline {
			return ErrLibraryArtifactMediaInvalid
		}
		return validateLibraryArtifactJPEGContent(raw, media.Width, media.Height)
	case libraryArtifactImageMIMESVG:
		if media.DeliveryMode != libraryArtifactImageDeliveryDownloadOnly {
			return ErrLibraryArtifactMediaInvalid
		}
		canonical, width, height, err := canonicalizeLibraryArtifactSVG(raw)
		if err != nil {
			return err
		}
		if width != media.Width || height != media.Height || !bytes.Equal(canonical, raw) {
			return ErrLibraryArtifactMediaInvalid
		}
		return nil
	default:
		return ErrLibraryArtifactMediaUnsupported
	}
}

func validateLibraryArtifactPNGContent(raw []byte, expectedWidth, expectedHeight int) error {
	if len(raw) < 8 || !bytes.Equal(raw[:8], []byte{'\x89', 'P', 'N', 'G', '\r', '\n', '\x1a', '\n'}) {
		return ErrLibraryArtifactMediaInvalid
	}
	config, err := png.DecodeConfig(bytes.NewReader(raw))
	if err != nil {
		return ErrLibraryArtifactMediaInvalid
	}
	if err := validateLibraryArtifactImageDimensions(config.Width, config.Height); err != nil {
		return err
	}
	if config.Width != expectedWidth || config.Height != expectedHeight {
		return ErrLibraryArtifactMediaInvalid
	}
	decoded, err := png.Decode(bytes.NewReader(raw))
	if err != nil || decoded.Bounds().Dx() != config.Width || decoded.Bounds().Dy() != config.Height {
		return ErrLibraryArtifactMediaInvalid
	}
	return nil
}

func validateLibraryArtifactJPEGContent(raw []byte, expectedWidth, expectedHeight int) error {
	if len(raw) < 4 || raw[0] != 0xff || raw[1] != 0xd8 {
		return ErrLibraryArtifactMediaInvalid
	}
	config, err := jpeg.DecodeConfig(bytes.NewReader(raw))
	if err != nil {
		return ErrLibraryArtifactMediaInvalid
	}
	if err := validateLibraryArtifactImageDimensions(config.Width, config.Height); err != nil {
		return err
	}
	if config.Width != expectedWidth || config.Height != expectedHeight {
		return ErrLibraryArtifactMediaInvalid
	}
	decoded, err := jpeg.Decode(bytes.NewReader(raw))
	if err != nil || decoded.Bounds().Dx() != config.Width || decoded.Bounds().Dy() != config.Height {
		return ErrLibraryArtifactMediaInvalid
	}
	return nil
}

func validateLibraryArtifactImageDimensions(width, height int) error {
	if width <= 0 || height <= 0 {
		return ErrLibraryArtifactMediaInvalid
	}
	if width > libraryArtifactImageMaxDimension || height > libraryArtifactImageMaxDimension {
		return ErrLibraryArtifactMediaTooLarge
	}
	if uint64(width)*uint64(height) > uint64(libraryArtifactImageMaxPixels) {
		return ErrLibraryArtifactMediaTooLarge
	}
	return nil
}

type librarySVGOpenElement struct {
	name string
	text strings.Builder
}

// canonicalizeLibraryArtifactSVG accepts a small static SVG profile, then
// writes a namespace-normalized, attribute-sorted representation. It is not a
// renderer and its result is explicitly download-only. The parser rejects
// dynamic/foreign-content features rather than trying to recognize dangerous
// substrings with regular expressions.
func canonicalizeLibraryArtifactSVG(raw []byte) ([]byte, int, int, error) {
	if len(raw) == 0 || len(raw) > libraryArtifactSVGMaxBytes {
		if len(raw) > libraryArtifactSVGMaxBytes {
			return nil, 0, 0, ErrLibraryArtifactMediaTooLarge
		}
		return nil, 0, 0, ErrLibraryArtifactMediaInvalid
	}
	if !utf8.Valid(raw) {
		return nil, 0, 0, ErrLibraryArtifactMediaInvalid
	}

	decoder := xml.NewDecoder(bytes.NewReader(raw))
	decoder.Strict = true
	var out bytes.Buffer
	var stack []librarySVGOpenElement
	rootSeen := false
	rootClosed := false
	nodes := 0
	width, height := 0, 0

	for {
		token, err := decoder.Token()
		if err == io.EOF {
			if !rootSeen || !rootClosed || len(stack) != 0 {
				return nil, 0, 0, ErrLibraryArtifactMediaInvalid
			}
			break
		}
		if err != nil {
			return nil, 0, 0, ErrLibraryArtifactMediaInvalid
		}

		switch value := token.(type) {
		case xml.StartElement:
			if rootClosed || len(stack) >= libraryArtifactSVGMaxDepth {
				return nil, 0, 0, ErrLibraryArtifactMediaInvalid
			}
			nodes++
			if nodes > libraryArtifactSVGMaxNodes {
				return nil, 0, 0, ErrLibraryArtifactMediaTooLarge
			}
			if len(stack) == 0 {
				if rootSeen || value.Name.Local != "svg" || value.Name.Space != libraryArtifactSVGNamespace {
					return nil, 0, 0, ErrLibraryArtifactMediaInvalid
				}
				rootSeen = true
				attributes, err := canonicalLibrarySVGAttributes("svg", value.Attr, true)
				if err != nil {
					return nil, 0, 0, err
				}
				width, height, err = libraryArtifactSVGDimensions(attributes)
				if err != nil {
					return nil, 0, 0, err
				}
				writeLibrarySVGStart(&out, "svg", attributes, true)
				stack = append(stack, librarySVGOpenElement{name: "svg"})
				continue
			}
			if value.Name.Space != libraryArtifactSVGNamespace || !librarySVGElementAllowed(value.Name.Local) {
				return nil, 0, 0, ErrLibraryArtifactMediaInvalid
			}
			parent := stack[len(stack)-1].name
			if parent == "title" || parent == "desc" {
				return nil, 0, 0, ErrLibraryArtifactMediaInvalid
			}
			attributes, err := canonicalLibrarySVGAttributes(value.Name.Local, value.Attr, false)
			if err != nil {
				return nil, 0, 0, err
			}
			writeLibrarySVGStart(&out, value.Name.Local, attributes, false)
			stack = append(stack, librarySVGOpenElement{name: value.Name.Local})
		case xml.EndElement:
			if len(stack) == 0 {
				return nil, 0, 0, ErrLibraryArtifactMediaInvalid
			}
			current := &stack[len(stack)-1]
			if value.Name.Space != libraryArtifactSVGNamespace || value.Name.Local != current.name {
				return nil, 0, 0, ErrLibraryArtifactMediaInvalid
			}
			if current.name == "title" || current.name == "desc" {
				writeLibrarySVGText(&out, normalizeLibrarySVGText(current.text.String()))
			}
			out.WriteString("</")
			out.WriteString(current.name)
			out.WriteByte('>')
			stack = stack[:len(stack)-1]
			if len(stack) == 0 {
				rootClosed = true
			}
		case xml.CharData:
			if len(stack) == 0 {
				if strings.TrimSpace(string(value)) != "" {
					return nil, 0, 0, ErrLibraryArtifactMediaInvalid
				}
				continue
			}
			current := &stack[len(stack)-1]
			if current.name != "title" && current.name != "desc" {
				if strings.TrimSpace(string(value)) != "" {
					return nil, 0, 0, ErrLibraryArtifactMediaInvalid
				}
				continue
			}
			if current.text.Len()+len(value) > libraryArtifactSVGMaxAttrBytes {
				return nil, 0, 0, ErrLibraryArtifactMediaTooLarge
			}
			current.text.Write([]byte(value))
		case xml.Comment, xml.Directive, xml.ProcInst:
			// Comments and processing/directive constructs are unnecessary for a
			// static artifact. Rejecting all of them fails closed on DOCTYPE and
			// custom entities without maintaining a string blacklist.
			return nil, 0, 0, ErrLibraryArtifactMediaInvalid
		default:
			return nil, 0, 0, ErrLibraryArtifactMediaInvalid
		}
	}
	if len(out.Bytes()) > libraryArtifactSVGMaxBytes {
		return nil, 0, 0, ErrLibraryArtifactMediaTooLarge
	}
	return out.Bytes(), width, height, nil
}

func librarySVGElementAllowed(element string) bool {
	switch element {
	case "g", "path", "rect", "circle", "ellipse", "line", "polyline", "polygon", "title", "desc":
		return true
	default:
		// This intentionally rejects script, foreignObject, image, use, a,
		// style, animation, filter, mask, font, and unknown namespaces/tags.
		return false
	}
}

func canonicalLibrarySVGAttributes(element string, attributes []xml.Attr, root bool) (map[string]string, error) {
	out := make(map[string]string, len(attributes))
	for _, attribute := range attributes {
		if librarySVGNamespaceAttribute(attribute) {
			if !root || attribute.Value != libraryArtifactSVGNamespace {
				return nil, ErrLibraryArtifactMediaInvalid
			}
			continue
		}
		if attribute.Name.Space != "" {
			return nil, ErrLibraryArtifactMediaInvalid
		}
		name := attribute.Name.Local
		if strings.HasPrefix(strings.ToLower(name), "on") || !librarySVGAttributeAllowed(element, name) {
			return nil, ErrLibraryArtifactMediaInvalid
		}
		if _, exists := out[name]; exists {
			return nil, ErrLibraryArtifactMediaInvalid
		}
		canonical, err := canonicalLibrarySVGAttributeValue(name, attribute.Value)
		if err != nil {
			return nil, err
		}
		out[name] = canonical
	}
	return out, nil
}

func librarySVGNamespaceAttribute(attribute xml.Attr) bool {
	// encoding/xml has represented xmlns attributes in each of these forms
	// across token paths. Only the default declaration is accepted; a prefix
	// declaration is deliberately rejected even if it is otherwise unused.
	if attribute.Name.Space == "" && attribute.Name.Local == "xmlns" {
		return true
	}
	if attribute.Name.Space == "xmlns" && (attribute.Name.Local == "" || attribute.Name.Local == "xmlns") {
		return true
	}
	return attribute.Name.Space == "http://www.w3.org/2000/xmlns/" && (attribute.Name.Local == "" || attribute.Name.Local == "xmlns")
}

func librarySVGAttributeAllowed(element, name string) bool {
	if element != "title" && element != "desc" && librarySVGGlobalAttribute(name) {
		return true
	}
	switch element {
	case "svg":
		return name == "width" || name == "height" || name == "viewBox"
	case "path":
		return name == "d"
	case "rect":
		return name == "x" || name == "y" || name == "width" || name == "height" || name == "rx" || name == "ry"
	case "circle":
		return name == "cx" || name == "cy" || name == "r"
	case "ellipse":
		return name == "cx" || name == "cy" || name == "rx" || name == "ry"
	case "line":
		return name == "x1" || name == "x2" || name == "y1" || name == "y2"
	case "polyline", "polygon":
		return name == "points"
	default:
		return false
	}
}

func librarySVGGlobalAttribute(name string) bool {
	switch name {
	case "fill", "fill-opacity", "fill-rule", "stroke", "stroke-opacity", "stroke-width", "stroke-linecap", "stroke-linejoin", "stroke-miterlimit", "stroke-dasharray", "stroke-dashoffset", "opacity":
		return true
	default:
		return false
	}
}

func canonicalLibrarySVGAttributeValue(name, value string) (string, error) {
	if len(value) > libraryArtifactSVGMaxAttrBytes {
		return "", ErrLibraryArtifactMediaTooLarge
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return "", ErrLibraryArtifactMediaInvalid
	}
	switch name {
	case "fill", "stroke":
		return canonicalLibrarySVGPaint(value)
	case "fill-opacity", "stroke-opacity", "opacity":
		return canonicalLibrarySVGOpacity(value)
	case "fill-rule":
		if value == "nonzero" || value == "evenodd" {
			return value, nil
		}
		return "", ErrLibraryArtifactMediaInvalid
	case "stroke-linecap":
		if value == "butt" || value == "round" || value == "square" {
			return value, nil
		}
		return "", ErrLibraryArtifactMediaInvalid
	case "stroke-linejoin":
		if value == "miter" || value == "round" || value == "bevel" {
			return value, nil
		}
		return "", ErrLibraryArtifactMediaInvalid
	case "stroke-dasharray":
		if value == "none" {
			return value, nil
		}
		values, err := parseLibrarySVGNumberList(value, 128)
		if err != nil || len(values) == 0 {
			return "", ErrLibraryArtifactMediaInvalid
		}
		for _, item := range values {
			if item < 0 {
				return "", ErrLibraryArtifactMediaInvalid
			}
		}
		return joinLibrarySVGNumbers(values, " "), nil
	case "stroke-width", "stroke-dashoffset", "stroke-miterlimit", "x", "y", "cx", "cy", "x1", "x2", "y1", "y2", "r", "rx", "ry", "width", "height":
		value, err := parseLibrarySVGNumber(value)
		if err != nil {
			return "", err
		}
		if (name == "stroke-width" || name == "stroke-miterlimit" || name == "r" || name == "rx" || name == "ry" || name == "width" || name == "height") && value < 0 {
			return "", ErrLibraryArtifactMediaInvalid
		}
		return formatLibrarySVGNumber(value), nil
	case "viewBox":
		values, err := parseLibrarySVGNumberList(value, 4)
		if err != nil || len(values) != 4 || values[2] <= 0 || values[3] <= 0 {
			return "", ErrLibraryArtifactMediaInvalid
		}
		return joinLibrarySVGNumbers(values, " "), nil
	case "points":
		values, err := parseLibrarySVGNumberList(value, 4096)
		if err != nil || len(values) < 4 || len(values)%2 != 0 {
			return "", ErrLibraryArtifactMediaInvalid
		}
		var out strings.Builder
		for index := 0; index < len(values); index += 2 {
			if index > 0 {
				out.WriteByte(' ')
			}
			out.WriteString(formatLibrarySVGNumber(values[index]))
			out.WriteByte(',')
			out.WriteString(formatLibrarySVGNumber(values[index+1]))
		}
		return out.String(), nil
	case "d":
		return canonicalLibrarySVGPath(value)
	default:
		return "", ErrLibraryArtifactMediaInvalid
	}
}

func canonicalLibrarySVGPaint(value string) (string, error) {
	if value == "none" {
		return value, nil
	}
	if value == "currentColor" {
		return value, nil
	}
	if len(value) != 4 && len(value) != 5 && len(value) != 7 && len(value) != 9 {
		return "", ErrLibraryArtifactMediaInvalid
	}
	if value[0] != '#' {
		return "", ErrLibraryArtifactMediaInvalid
	}
	for index := 1; index < len(value); index++ {
		character := value[index]
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f') || (character >= 'A' && character <= 'F')) {
			return "", ErrLibraryArtifactMediaInvalid
		}
	}
	return strings.ToLower(value), nil
}

func canonicalLibrarySVGOpacity(value string) (string, error) {
	parsed, err := parseLibrarySVGNumber(value)
	if err != nil || parsed < 0 || parsed > 1 {
		return "", ErrLibraryArtifactMediaInvalid
	}
	return formatLibrarySVGNumber(parsed), nil
}

func libraryArtifactSVGDimensions(attributes map[string]string) (int, int, error) {
	widthRaw, hasWidth := attributes["width"]
	heightRaw, hasHeight := attributes["height"]
	if hasWidth != hasHeight {
		return 0, 0, ErrLibraryArtifactMediaInvalid
	}
	if hasWidth {
		width, err := parseLibrarySVGNumber(widthRaw)
		if err != nil || width <= 0 {
			return 0, 0, ErrLibraryArtifactMediaInvalid
		}
		height, err := parseLibrarySVGNumber(heightRaw)
		if err != nil || height <= 0 {
			return 0, 0, ErrLibraryArtifactMediaInvalid
		}
		return validateLibrarySVGDimensions(width, height)
	}
	viewBox, found := attributes["viewBox"]
	if !found {
		return 0, 0, nil
	}
	values, err := parseLibrarySVGNumberList(viewBox, 4)
	if err != nil || len(values) != 4 {
		return 0, 0, ErrLibraryArtifactMediaInvalid
	}
	return validateLibrarySVGDimensions(values[2], values[3])
}

func validateLibrarySVGDimensions(width, height float64) (int, int, error) {
	if width <= 0 || height <= 0 || width > libraryArtifactImageMaxDimension || height > libraryArtifactImageMaxDimension || width*height > libraryArtifactImageMaxPixels {
		return 0, 0, ErrLibraryArtifactMediaTooLarge
	}
	return int(math.Ceil(width)), int(math.Ceil(height)), nil
}

func parseLibrarySVGNumber(value string) (float64, error) {
	index := skipLibrarySVGWhitespace(value, 0)
	parsed, next, err := parseLibrarySVGNumberAt(value, index)
	if err != nil {
		return 0, err
	}
	if skipLibrarySVGWhitespace(value, next) != len(value) {
		return 0, ErrLibraryArtifactMediaInvalid
	}
	return parsed, nil
}

func parseLibrarySVGNumberList(value string, maximum int) ([]float64, error) {
	if maximum <= 0 {
		return nil, ErrLibraryArtifactMediaInvalid
	}
	values := make([]float64, 0, 4)
	index := skipLibrarySVGWhitespace(value, 0)
	for index < len(value) {
		if len(values) >= maximum {
			return nil, ErrLibraryArtifactMediaTooLarge
		}
		parsed, next, err := parseLibrarySVGNumberAt(value, index)
		if err != nil {
			return nil, err
		}
		values = append(values, parsed)
		if next == len(value) {
			break
		}
		separatorStart := next
		index = skipLibrarySVGWhitespace(value, next)
		if index < len(value) && value[index] == ',' {
			index++
			index = skipLibrarySVGWhitespace(value, index)
		} else if index == separatorStart {
			// The static profile requires an explicit comma or whitespace between
			// generic number-list values. Path data has its own grammar below.
			return nil, ErrLibraryArtifactMediaInvalid
		}
		if index == len(value) {
			return nil, ErrLibraryArtifactMediaInvalid
		}
	}
	return values, nil
}

func parseLibrarySVGNumberAt(value string, index int) (float64, int, error) {
	if index >= len(value) {
		return 0, index, ErrLibraryArtifactMediaInvalid
	}
	start := index
	if value[index] == '+' || value[index] == '-' {
		index++
	}
	digits := 0
	for index < len(value) && value[index] >= '0' && value[index] <= '9' {
		index++
		digits++
	}
	if index < len(value) && value[index] == '.' {
		index++
		for index < len(value) && value[index] >= '0' && value[index] <= '9' {
			index++
			digits++
		}
	}
	if digits == 0 {
		return 0, index, ErrLibraryArtifactMediaInvalid
	}
	if index < len(value) && (value[index] == 'e' || value[index] == 'E') {
		index++
		if index < len(value) && (value[index] == '+' || value[index] == '-') {
			index++
		}
		exponentDigits := 0
		for index < len(value) && value[index] >= '0' && value[index] <= '9' {
			index++
			exponentDigits++
		}
		if exponentDigits == 0 {
			return 0, index, ErrLibraryArtifactMediaInvalid
		}
	}
	parsed, err := strconv.ParseFloat(value[start:index], 64)
	if err != nil || math.IsNaN(parsed) || math.IsInf(parsed, 0) || math.Abs(parsed) > libraryArtifactSVGMaxCoordinate {
		return 0, index, ErrLibraryArtifactMediaInvalid
	}
	return parsed, index, nil
}

func skipLibrarySVGWhitespace(value string, index int) int {
	for index < len(value) {
		switch value[index] {
		case ' ', '\t', '\r', '\n':
			index++
		default:
			return index
		}
	}
	return index
}

func formatLibrarySVGNumber(value float64) string {
	if value == 0 {
		return "0"
	}
	return strconv.FormatFloat(value, 'g', -1, 64)
}

func joinLibrarySVGNumbers(values []float64, separator string) string {
	var out strings.Builder
	for index, value := range values {
		if index > 0 {
			out.WriteString(separator)
		}
		out.WriteString(formatLibrarySVGNumber(value))
	}
	return out.String()
}

func canonicalLibrarySVGPath(value string) (string, error) {
	if len(value) > libraryArtifactSVGMaxAttrBytes {
		return "", ErrLibraryArtifactMediaTooLarge
	}
	var out strings.Builder
	index := 0
	command := byte(0)
	commandHasGroup := false
	pathStarted := false
	segments := 0
	for {
		index = skipLibrarySVGWhitespaceAndCommas(value, index)
		if index == len(value) {
			if command != 0 && !commandHasGroup {
				return "", ErrLibraryArtifactMediaInvalid
			}
			break
		}
		if isLibrarySVGPathCommand(value[index]) {
			if command != 0 && !commandHasGroup {
				return "", ErrLibraryArtifactMediaInvalid
			}
			if !pathStarted && value[index] != 'M' && value[index] != 'm' {
				return "", ErrLibraryArtifactMediaInvalid
			}
			pathStarted = true
			command = value[index]
			commandHasGroup = false
			index++
			if librarySVGPathCommandArity(command) == 0 {
				writeLibrarySVGPathSegment(&out, command, nil)
				command = 0
			}
			continue
		}
		if command == 0 {
			return "", ErrLibraryArtifactMediaInvalid
		}
		arity := librarySVGPathCommandArity(command)
		if arity == 0 {
			return "", ErrLibraryArtifactMediaInvalid
		}
		values := make([]float64, 0, arity)
		for argument := 0; argument < arity; argument++ {
			before := index
			index = skipLibrarySVGWhitespaceAndCommas(value, index)
			if index == len(value) || isLibrarySVGPathCommand(value[index]) {
				return "", ErrLibraryArtifactMediaInvalid
			}
			if argument > 0 && index == before && value[index] != '+' && value[index] != '-' {
				return "", ErrLibraryArtifactMediaInvalid
			}
			parsed, next, err := parseLibrarySVGNumberAt(value, index)
			if err != nil {
				return "", err
			}
			values = append(values, parsed)
			index = next
		}
		if command == 'A' || command == 'a' {
			if (values[3] != 0 && values[3] != 1) || (values[4] != 0 && values[4] != 1) {
				return "", ErrLibraryArtifactMediaInvalid
			}
		}
		segments++
		if segments > libraryArtifactSVGMaxNodes*8 {
			return "", ErrLibraryArtifactMediaTooLarge
		}
		writeLibrarySVGPathSegment(&out, command, values)
		commandHasGroup = true
	}
	if out.Len() == 0 {
		return "", ErrLibraryArtifactMediaInvalid
	}
	return out.String(), nil
}

func skipLibrarySVGWhitespaceAndCommas(value string, index int) int {
	for index < len(value) {
		switch value[index] {
		case ' ', '\t', '\r', '\n', ',':
			index++
		default:
			return index
		}
	}
	return index
}

func isLibrarySVGPathCommand(value byte) bool {
	switch value {
	case 'M', 'm', 'Z', 'z', 'L', 'l', 'H', 'h', 'V', 'v', 'C', 'c', 'S', 's', 'Q', 'q', 'T', 't', 'A', 'a':
		return true
	default:
		return false
	}
}

func librarySVGPathCommandArity(command byte) int {
	switch command {
	case 'M', 'm', 'L', 'l', 'T', 't':
		return 2
	case 'H', 'h', 'V', 'v':
		return 1
	case 'C', 'c':
		return 6
	case 'S', 's', 'Q', 'q':
		return 4
	case 'A', 'a':
		return 7
	case 'Z', 'z':
		return 0
	default:
		return -1
	}
}

func writeLibrarySVGPathSegment(out *strings.Builder, command byte, values []float64) {
	if out.Len() > 0 {
		out.WriteByte(' ')
	}
	out.WriteByte(command)
	for _, value := range values {
		out.WriteByte(' ')
		out.WriteString(formatLibrarySVGNumber(value))
	}
}

func normalizeLibrarySVGText(value string) string {
	return strings.Join(strings.Fields(value), " ")
}

func writeLibrarySVGStart(out *bytes.Buffer, element string, attributes map[string]string, root bool) {
	out.WriteByte('<')
	out.WriteString(element)
	if root {
		out.WriteString(" xmlns=\"")
		out.WriteString(libraryArtifactSVGNamespace)
		out.WriteByte('"')
	}
	keys := make([]string, 0, len(attributes))
	for key := range attributes {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		out.WriteByte(' ')
		out.WriteString(key)
		out.WriteString("=\"")
		// Attribute values have already passed the static lexical validators;
		// XML escaping remains defense in depth if that profile changes later.
		writeLibrarySVGText(out, attributes[key])
		out.WriteByte('"')
	}
	out.WriteByte('>')
}

func writeLibrarySVGText(out *bytes.Buffer, value string) {
	// bytes.Buffer never returns an error, and EscapeText only writes to the
	// supplied writer. Keeping this at the final output edge prevents a future
	// attribute/text validator regression from becoming markup injection.
	_ = xml.EscapeText(out, []byte(value))
}

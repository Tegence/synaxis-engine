package engine

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"strings"
	"testing"
)

func TestNormalizeLibraryArtifactImageRequiresCanonicalBase64(t *testing.T) {
	pngBytes := testLibraryMediaPNG(t, 2, 3)
	encoded := base64.StdEncoding.EncodeToString(pngBytes)
	canonical, err := normalizeLibraryArtifactImage(libraryArtifactImageMIMEPNG, encoded)
	if err != nil {
		t.Fatalf("normalize valid PNG: %v", err)
	}
	if canonical.MIMEType != libraryArtifactImageMIMEPNG || canonical.Width != 2 || canonical.Height != 3 {
		t.Fatalf("unexpected canonical image metadata: %+v", canonical)
	}
	if canonical.DeliveryMode != libraryArtifactImageDeliveryInline {
		t.Fatalf("PNG delivery mode = %q, want inline", canonical.DeliveryMode)
	}
	sum := sha256.Sum256(canonical.Bytes)
	if canonical.Digest != hex.EncodeToString(sum[:]) || canonical.SizeBytes != int64(len(canonical.Bytes)) {
		t.Fatalf("canonical digest/size do not describe canonical bytes: %+v", canonical)
	}

	for name, input := range map[string]string{
		"data URL":     "data:image/png;base64," + encoded,
		"whitespace":   encoded[:8] + "\n" + encoded[8:],
		"URL alphabet": "-w==",
		"no padding":   "TQ",
		"bad pad bits": "TR==",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := decodeCanonicalLibraryArtifactImageBase64(input)
			if !errors.Is(err, ErrLibraryArtifactMediaInvalid) {
				t.Fatalf("decode error = %v, want invalid-media error", err)
			}
		})
	}

	over := strings.Repeat("A", libraryArtifactImageMaxEncodedBytes+1)
	if _, err := decodeCanonicalLibraryArtifactImageBase64(over); !errors.Is(err, ErrLibraryArtifactMediaTooLarge) {
		t.Fatalf("oversized encoding error = %v, want too-large error", err)
	}
	decodedOver := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0}, libraryArtifactImageMaxDecodedBytes+1))
	if _, err := decodeCanonicalLibraryArtifactImageBase64(decodedOver); !errors.Is(err, ErrLibraryArtifactMediaTooLarge) {
		t.Fatalf("oversized decoded payload error = %v, want too-large error", err)
	}
}

func TestCanonicalizeLibraryArtifactImageMIMEAndRasterLimits(t *testing.T) {
	pngBytes := testLibraryMediaPNG(t, 2, 3)
	if _, err := canonicalizeLibraryArtifactImage(libraryArtifactImageMIMEJPEG, pngBytes); !errors.Is(err, ErrLibraryArtifactMediaInvalid) {
		t.Fatalf("mismatched MIME error = %v, want invalid-media error", err)
	}
	if _, err := canonicalizeLibraryArtifactImage("image/gif", pngBytes); !errors.Is(err, ErrLibraryArtifactMediaUnsupported) {
		t.Fatalf("unsupported MIME error = %v, want unsupported-media error", err)
	}

	oversized := testLibraryMediaPNG(t, libraryArtifactImageMaxDimension+1, 1)
	if _, err := canonicalizeLibraryArtifactImage(libraryArtifactImageMIMEPNG, oversized); !errors.Is(err, ErrLibraryArtifactMediaTooLarge) {
		t.Fatalf("oversized dimensions error = %v, want too-large error", err)
	}
}

func TestCanonicalizeLibraryArtifactJPEGStripsAPPMetadata(t *testing.T) {
	imageValue := image.NewNRGBA(image.Rect(0, 0, 3, 2))
	imageValue.SetNRGBA(1, 1, color.NRGBA{R: 100, G: 20, B: 200, A: 255})
	var encoded bytes.Buffer
	if err := jpeg.Encode(&encoded, imageValue, &jpeg.Options{Quality: 80}); err != nil {
		t.Fatalf("encode JPEG fixture: %v", err)
	}
	secret := []byte("Exif\x00\x00LIBRARY-MEDIA-SECRET")
	if len(secret)+2 > 0xffff {
		t.Fatal("test APP1 payload unexpectedly large")
	}
	withAPP := make([]byte, 0, encoded.Len()+len(secret)+4)
	withAPP = append(withAPP, encoded.Bytes()[:2]...)
	withAPP = append(withAPP, 0xff, 0xe1, byte((len(secret)+2)>>8), byte(len(secret)+2))
	withAPP = append(withAPP, secret...)
	withAPP = append(withAPP, encoded.Bytes()[2:]...)

	canonical, err := canonicalizeLibraryArtifactImage(libraryArtifactImageMIMEJPEG, withAPP)
	if err != nil {
		t.Fatalf("canonicalize JPEG: %v", err)
	}
	if canonical.Width != 3 || canonical.Height != 2 || canonical.DeliveryMode != libraryArtifactImageDeliveryInline {
		t.Fatalf("unexpected JPEG canonical metadata: %+v", canonical)
	}
	if bytes.Contains(canonical.Bytes, secret) {
		t.Fatal("canonical JPEG retained APP/EXIF metadata")
	}
	if _, err := jpeg.Decode(bytes.NewReader(canonical.Bytes)); err != nil {
		t.Fatalf("canonical JPEG no longer decodes: %v", err)
	}
}

func TestCanonicalizeLibraryArtifactRejectsWebPWithoutDecoder(t *testing.T) {
	if _, err := canonicalizeLibraryArtifactImage("image/webp", []byte("RIFF-not-a-decoded-webp")); !errors.Is(err, ErrLibraryArtifactMediaUnsupported) {
		t.Fatalf("WebP error = %v, want unsupported-media error", err)
	}
}

func TestCanonicalizeLibraryArtifactSVGUsesStaticDownloadOnlyProfile(t *testing.T) {
	source := []byte(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0, 0, 24, 24" fill="#ABC">
  <title> Safe &amp; Sound </title>
  <path stroke="#Ff0" stroke-width=" 2 " d="M0 0 L24 24 Z"/>
</svg>`)
	canonical, err := canonicalizeLibraryArtifactImage(libraryArtifactImageMIMESVG, source)
	if err != nil {
		t.Fatalf("canonicalize SVG: %v", err)
	}
	if canonical.DeliveryMode != libraryArtifactImageDeliveryDownloadOnly || canonical.Width != 24 || canonical.Height != 24 {
		t.Fatalf("unexpected SVG delivery/dimensions: %+v", canonical)
	}
	if bytes.Contains(canonical.Bytes, []byte("#ABC")) || !bytes.Contains(canonical.Bytes, []byte("#abc")) {
		t.Fatalf("SVG color was not canonicalized: %s", canonical.Bytes)
	}
	if !bytes.Contains(canonical.Bytes, []byte(`<title>Safe &amp; Sound</title>`)) {
		t.Fatalf("SVG title was not safely canonicalized: %s", canonical.Bytes)
	}
	again, err := canonicalizeLibraryArtifactImage(libraryArtifactImageMIMESVG, canonical.Bytes)
	if err != nil {
		t.Fatalf("re-canonicalize SVG: %v", err)
	}
	if !bytes.Equal(canonical.Bytes, again.Bytes) || canonical.Digest != again.Digest {
		t.Fatalf("SVG canonicalization is not stable:\nfirst:  %s\nsecond: %s", canonical.Bytes, again.Bytes)
	}
}

func TestCanonicalizeLibraryArtifactSVGRejectsDynamicAndForeignContent(t *testing.T) {
	malicious := map[string]string{
		"doctype":        `<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg xmlns="http://www.w3.org/2000/svg"><title>&xxe;</title></svg>`,
		"PI":             `<?danger now?><svg xmlns="http://www.w3.org/2000/svg"></svg>`,
		"script":         `<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`,
		"foreign object": `<svg xmlns="http://www.w3.org/2000/svg"><foreignObject/></svg>`,
		"image":          `<svg xmlns="http://www.w3.org/2000/svg"><image href="https://example.invalid/p.png"/></svg>`,
		"use":            `<svg xmlns="http://www.w3.org/2000/svg"><use href="#x"/></svg>`,
		"link":           `<svg xmlns="http://www.w3.org/2000/svg"><a href="https://example.invalid"><path d="M0 0"/></a></svg>`,
		"style":          `<svg xmlns="http://www.w3.org/2000/svg"><path d="M0 0" style="fill:url(data:image/png;base64,AAA)"/></svg>`,
		"event":          `<svg xmlns="http://www.w3.org/2000/svg"><path d="M0 0" onclick="alert(1)"/></svg>`,
		"paint URL":      `<svg xmlns="http://www.w3.org/2000/svg"><path d="M0 0" fill="url(https://example.invalid/LEAK-ME)"/></svg>`,
		"filter":         `<svg xmlns="http://www.w3.org/2000/svg"><filter/></svg>`,
		"mask":           `<svg xmlns="http://www.w3.org/2000/svg"><mask/></svg>`,
		"font":           `<svg xmlns="http://www.w3.org/2000/svg"><font/></svg>`,
		"unsafe ns":      `<svg xmlns="https://example.invalid/svg"><path d="M0 0"/></svg>`,
		"prefix ns":      `<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><path d="M0 0"/></svg>`,
		"missing moveto": `<svg xmlns="http://www.w3.org/2000/svg"><path d="L 0 0"/></svg>`,
	}
	for name, source := range malicious {
		t.Run(name, func(t *testing.T) {
			_, err := canonicalizeLibraryArtifactImage(libraryArtifactImageMIMESVG, []byte(source))
			if !errors.Is(err, ErrLibraryArtifactMediaInvalid) {
				t.Fatalf("SVG error = %v, want invalid-media error", err)
			}
			if strings.Contains(err.Error(), "LEAK-ME") {
				t.Fatalf("SVG error reflected untrusted source: %q", err)
			}
		})
	}
}

func TestCanonicalizeLibraryArtifactSVGBounds(t *testing.T) {
	nodes := `<svg xmlns="http://www.w3.org/2000/svg">` + strings.Repeat(`<g></g>`, libraryArtifactSVGMaxNodes) + `</svg>`
	if _, err := canonicalizeLibraryArtifactImage(libraryArtifactImageMIMESVG, []byte(nodes)); !errors.Is(err, ErrLibraryArtifactMediaTooLarge) {
		t.Fatalf("too many SVG nodes error = %v, want too-large error", err)
	}
	largeDimensions := []byte(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 5000 1"></svg>`)
	if _, err := canonicalizeLibraryArtifactImage(libraryArtifactImageMIMESVG, largeDimensions); !errors.Is(err, ErrLibraryArtifactMediaTooLarge) {
		t.Fatalf("large SVG dimensions error = %v, want too-large error", err)
	}
	oversized := bytes.Repeat([]byte("a"), libraryArtifactSVGMaxBytes+1)
	if _, _, _, err := canonicalizeLibraryArtifactSVG(oversized); !errors.Is(err, ErrLibraryArtifactMediaTooLarge) {
		t.Fatalf("oversized SVG source error = %v, want too-large error", err)
	}
}

func testLibraryMediaPNG(t *testing.T, width, height int) []byte {
	t.Helper()
	value := image.NewNRGBA(image.Rect(0, 0, width, height))
	value.SetNRGBA(0, 0, color.NRGBA{R: 20, G: 60, B: 180, A: 255})
	var out bytes.Buffer
	if err := png.Encode(&out, value); err != nil {
		t.Fatalf("encode PNG fixture: %v", err)
	}
	return out.Bytes()
}

package engine

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"narthex/backend/pkg/libraryruntime"
)

// testSkillBundleFrontMatter is a SKILL.md head in the Agent Skills layout.
func testSkillBundleFrontMatter(name, description, body string) string {
	return "---\nname: " + name + "\ndescription: " + description + "\n---\n\n" + body
}

// testOOXMLBlob builds a real, readable ZIP container of about the requested
// size so the bundle validator accepts it as an Office Open XML package. It
// is synthetic: no customer workbook is committed to the repository.
func testOOXMLBlob(t *testing.T, size int) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	entry, err := writer.Create("xl/worksheets/sheet1.xml")
	if err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, size)
	for index := range payload {
		payload[index] = byte('a' + (index*7+index/13)%26)
	}
	if _, err := entry.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

// testElevenFileBundle mirrors the shape of the commit-poc-loe skill: SKILL.md,
// three references, one example, five scripts (one nested), and a 200 KB
// workbook template.
func testElevenFileBundle(t *testing.T, name, description string) []LibrarySkillFileContent {
	t.Helper()
	return []LibrarySkillFileContent{
		{Path: "SKILL.md", Data: []byte(testSkillBundleFrontMatter(name, description, "# Builder\n\nUse `scripts/build.py` with `assets/template.xlsx`.\n"))},
		{Path: "references/content-guide.md", Data: []byte("# Content guide\n\nWrite each section plainly.\n")},
		{Path: "references/spec-schema.md", Data: []byte("# Spec schema\n\n| field | rule |\n|---|---|\n| title | required |\n")},
		{Path: "references/standard-rules.md", Data: []byte("# Standard rules\n\n1. Every number lives in the same cell.\n")},
		{Path: "examples/aires_spec.json", Data: []byte(`{"title":"Example","rows":[{"role":"engineer","days":12}]}`)},
		{Path: "scripts/build.py", Data: []byte("import json\n\nprint(json.dumps({'ok': True}))\n")},
		{Path: "scripts/recalc.py", Data: []byte("print('recalculate')\n")},
		{Path: "scripts/verify.py", Data: []byte("print('verify')\n")},
		{Path: "scripts/dev_make_template.py", Data: []byte("print('template')\n")},
		{Path: "scripts/office/soffice.py", Data: []byte("print('soffice')\n")},
		{Path: "assets/template.xlsx", Data: testOOXMLBlob(t, 200<<10)},
	}
}

func testSkillBundleZip(t *testing.T, prefix string, files []LibrarySkillFileContent) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for _, file := range files {
		entry, err := writer.Create(prefix + file.Path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write(file.Data); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func TestLibrarySkillBundleRoundTripsElevenFilesThroughFileStore(t *testing.T) {
	ctx := context.Background()
	store := newLibraryFileStore(t)
	files := testElevenFileBundle(t, "commit-poc-loe", "Build a PoC level-of-effort workbook on the standard template.")
	content, bundle, err := normalizeLibrarySkillBundle("", files)
	if err != nil {
		t.Fatalf("normalize bundle: %v", err)
	}
	if len(bundle.Files) != 11 || bundle.Files[0].Path != "SKILL.md" && bundle.Files[0].Path < "SKILL.md" {
		t.Fatalf("manifest = %+v", bundle.Files)
	}
	if len(bundle.Blobs) != 10 {
		t.Fatalf("blobs = %d, want 10 (SKILL.md stays on the version)", len(bundle.Blobs))
	}
	skill := LibrarySkill{Slug: "commit-poc-loe", Name: "Commit PoC LOE", Description: "Build a PoC level-of-effort workbook on the standard template.", CreatedBy: "usr_owner"}
	if err := validateLibrarySkillFrontMatter(skill, content, true); err != nil {
		t.Fatalf("front matter agreement: %v", err)
	}
	created, version, err := store.CreateLibrarySkillWithInitialBundle(ctx, skill, LibrarySkillVersion{Content: content, CreatedBy: "usr_owner"}, bundle)
	if err != nil {
		t.Fatalf("create bundle: %v", err)
	}
	if version.ManifestDigest != bundle.ManifestDigest || version.Digest != libraryDigest(content) || len(version.Files) != 11 {
		t.Fatalf("stored version = %+v", version)
	}

	// Every byte and digest survives, including the 200 KB workbook.
	expected := make(map[string][]byte, len(files))
	for _, file := range files {
		expected[file.Path] = file.Data
	}
	for _, entry := range version.Files {
		data, file, found, err := store.LibrarySkillFileBytes(ctx, created.ID, version.ID, entry.Path)
		if err != nil || !found {
			t.Fatalf("read %s: found=%t err=%v", entry.Path, found, err)
		}
		if !bytes.Equal(data, expected[entry.Path]) || file.Digest != librarySkillFileDigest(expected[entry.Path]) || file.SizeBytes != int64(len(expected[entry.Path])) {
			t.Fatalf("%s did not round-trip: size=%d digest=%s", entry.Path, file.SizeBytes, file.Digest)
		}
	}
	if _, _, found, err := store.LibrarySkillFileBytes(ctx, created.ID, version.ID, "scripts/missing.py"); found || err != nil {
		t.Fatalf("missing file found=%t err=%v", found, err)
	}

	// The exported .skill package re-imports to the identical manifest.
	archive, err := buildLibrarySkillBundleZip(created.Slug, version, func(file LibrarySkillFile) ([]byte, error) {
		data, _, _, err := store.LibrarySkillFileBytes(ctx, created.ID, version.ID, file.Path)
		return data, err
	})
	if err != nil {
		t.Fatalf("export bundle: %v", err)
	}
	again, err := buildLibrarySkillBundleZip(created.Slug, version, func(file LibrarySkillFile) ([]byte, error) {
		data, _, _, err := store.LibrarySkillFileBytes(ctx, created.ID, version.ID, file.Path)
		return data, err
	})
	if err != nil || !bytes.Equal(archive, again) {
		t.Fatalf("bundle export is not deterministic (err=%v)", err)
	}
	reader, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range reader.File {
		if !strings.HasPrefix(entry.Name, "commit-poc-loe/") {
			t.Fatalf("zip entry %q is not under the slug folder", entry.Name)
		}
	}
	imported, err := parseLibrarySkillBundleZip(archive)
	if err != nil {
		t.Fatalf("re-import: %v", err)
	}
	importedContent, importedBundle, err := normalizeLibrarySkillBundle("", imported)
	if err != nil {
		t.Fatalf("normalize re-import: %v", err)
	}
	if importedContent != content || importedBundle.ManifestDigest != bundle.ManifestDigest {
		t.Fatalf("re-imported manifest digest %s != %s", importedBundle.ManifestDigest, bundle.ManifestDigest)
	}
	for _, file := range imported {
		if !bytes.Equal(file.Data, expected[file.Path]) {
			t.Fatalf("%s changed across export/import", file.Path)
		}
	}

	// The next version appends a bundle, reuses identical blobs, and leaves the
	// first version's manifest untouched.
	files[1].Data = []byte("# Content guide\n\nRevised.\n")
	content2, bundle2, err := normalizeLibrarySkillBundle("", files)
	if err != nil {
		t.Fatal(err)
	}
	version2, err := store.CreateLibrarySkillBundleVersion(ctx, LibrarySkillVersion{SkillID: created.ID, Content: content2, CreatedBy: "usr_owner"}, bundle2)
	if err != nil {
		t.Fatalf("create bundle version: %v", err)
	}
	if version2.Version != 2 || version2.ManifestDigest == version.ManifestDigest {
		t.Fatalf("second version = %+v", version2)
	}
	store.mu.Lock()
	blobCount := len(store.librarySkillBlobs)
	store.mu.Unlock()
	if blobCount != 11 {
		t.Fatalf("blob store holds %d blobs, want 11 (10 original + 1 revised guide)", blobCount)
	}
	first, found := store.LibrarySkillVersion(ctx, created.ID, version.ID)
	if !found || first.ManifestDigest != version.ManifestDigest {
		t.Fatalf("first version changed: %+v", first)
	}
}

func TestLibrarySkillManifestDigestIsOrderIndependent(t *testing.T) {
	files := testElevenFileBundle(t, "order", "Order test.")
	_, forward, err := normalizeLibrarySkillBundle("", files)
	if err != nil {
		t.Fatal(err)
	}
	reversed := make([]LibrarySkillFileContent, 0, len(files))
	for index := len(files) - 1; index >= 0; index-- {
		reversed = append(reversed, files[index])
	}
	_, backward, err := normalizeLibrarySkillBundle("", reversed)
	if err != nil {
		t.Fatal(err)
	}
	if forward.ManifestDigest != backward.ManifestDigest {
		t.Fatalf("manifest digest depends on upload order: %s vs %s", forward.ManifestDigest, backward.ManifestDigest)
	}
	for index := range forward.Files {
		if forward.Files[index] != backward.Files[index] {
			t.Fatalf("manifest entry %d differs: %+v vs %+v", index, forward.Files[index], backward.Files[index])
		}
	}
	// A legacy single document is exactly the one-file manifest.
	legacy, err := librarySkillVersionWithManifest(LibrarySkillVersion{Content: "# Legacy", Digest: libraryDigest("# Legacy")})
	if err != nil {
		t.Fatal(err)
	}
	_, single, err := normalizeLibrarySkillBundle("# Legacy", nil)
	if err != nil {
		t.Fatal(err)
	}
	if legacy.ManifestDigest != single.ManifestDigest || len(legacy.Files) != 1 || legacy.Files[0].Path != "SKILL.md" {
		t.Fatalf("legacy manifest %+v (%s) != single-file manifest (%s)", legacy.Files, legacy.ManifestDigest, single.ManifestDigest)
	}
}

func TestLibrarySkillBundleRejectsUnsafePathsTypesAndCaps(t *testing.T) {
	instructions := testSkillBundleFrontMatter("safe", "Safe.", "# Safe\n")
	badPaths := []string{
		"/etc/passwd", "../escape.md", "references/../../escape.md", "refs\\guide.md", "C:/guide.md",
		"references//guide.md", "references/", "", "bad\x00name.md", "bad\nname.md", " leading.md", "./guide.md",
		strings.Repeat("a", 250) + "/deep.md", strings.Repeat("d/", 17) + "x.md",
	}
	for _, path := range badPaths {
		_, _, err := normalizeLibrarySkillBundle(instructions, []LibrarySkillFileContent{{Path: path, Data: []byte("x")}})
		if !errors.Is(err, ErrLibrarySkillBundleInvalid) {
			t.Fatalf("path %q accepted: %v", path, err)
		}
	}
	cases := []struct {
		name  string
		files []LibrarySkillFileContent
		want  error
	}{
		{"case duplicate", []LibrarySkillFileContent{{Path: "references/Guide.md", Data: []byte("a")}, {Path: "references/guide.md", Data: []byte("b")}}, ErrLibrarySkillBundleInvalid},
		{"exact duplicate", []LibrarySkillFileContent{{Path: "references/guide.md", Data: []byte("a")}, {Path: "references/guide.md", Data: []byte("a")}}, ErrLibrarySkillBundleInvalid},
		{"instructions case duplicate", []LibrarySkillFileContent{{Path: "skill.md", Data: []byte("# x")}}, ErrLibrarySkillBundleInvalid},
		{"unsupported type", []LibrarySkillFileContent{{Path: "scripts/run.exe", Data: []byte("MZ")}}, ErrLibrarySkillFileUnsupported},
		{"no extension", []LibrarySkillFileContent{{Path: "scripts/run", Data: []byte("x")}}, ErrLibrarySkillFileUnsupported},
		{"type mismatch", []LibrarySkillFileContent{{Path: "assets/x.png", Data: []byte("not a png")}}, ErrLibrarySkillBundleInvalid},
		{"declared type mismatch", []LibrarySkillFileContent{{Path: "references/a.md", ContentType: "text/plain", Data: []byte("x")}}, ErrLibrarySkillBundleInvalid},
		{"invalid utf8 text", []LibrarySkillFileContent{{Path: "references/a.md", Data: []byte{0xff, 0xfe}}}, ErrLibrarySkillBundleInvalid},
		{"invalid json", []LibrarySkillFileContent{{Path: "examples/a.json", Data: []byte("{")}}, ErrLibrarySkillBundleInvalid},
		{"svg script", []LibrarySkillFileContent{{Path: "assets/a.svg", Data: []byte(`<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`)}}, ErrLibrarySkillBundleInvalid},
		{"svg handler", []LibrarySkillFileContent{{Path: "assets/a.svg", Data: []byte(`<svg xmlns="http://www.w3.org/2000/svg" onload="x()"/>`)}}, ErrLibrarySkillBundleInvalid},
		{"svg doctype", []LibrarySkillFileContent{{Path: "assets/a.svg", Data: []byte(`<!DOCTYPE svg><svg xmlns="http://www.w3.org/2000/svg"/>`)}}, ErrLibrarySkillBundleInvalid},
		{"file over cap", []LibrarySkillFileContent{{Path: "assets/big.txt", Data: bytes.Repeat([]byte("a"), libraryMaxSkillFileBytes+1)}}, ErrLibrarySkillBundleTooLarge},
		{"bundle over cap", []LibrarySkillFileContent{
			{Path: "assets/one.txt", Data: bytes.Repeat([]byte("a"), 3<<20)},
			{Path: "assets/two.txt", Data: bytes.Repeat([]byte("b"), 3<<20)},
			{Path: "assets/three.txt", Data: bytes.Repeat([]byte("c"), 3<<20)},
		}, ErrLibrarySkillBundleTooLarge},
	}
	for _, tc := range cases {
		_, _, err := normalizeLibrarySkillBundle(instructions, tc.files)
		if !errors.Is(err, tc.want) {
			t.Fatalf("%s: err=%v want %v", tc.name, err, tc.want)
		}
	}
	// A valid static SVG is accepted verbatim.
	svg := []byte(`<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1 1"><rect width="1" height="1"/></svg>`)
	_, ok, err := normalizeLibrarySkillBundle(instructions, []LibrarySkillFileContent{{Path: "assets/ok.svg", Data: svg}})
	if err != nil || len(ok.Blobs) != 1 {
		t.Fatalf("static svg rejected: %v", err)
	}
	// Too many files.
	many := make([]LibrarySkillFileContent, 0, libraryMaxSkillFiles+1)
	for index := 0; index <= libraryMaxSkillFiles; index++ {
		many = append(many, LibrarySkillFileContent{Path: fmt.Sprintf("references/f%d.md", index), Data: []byte("x")})
	}
	if _, _, err := normalizeLibrarySkillBundle(instructions, many); !errors.Is(err, ErrLibrarySkillBundleTooLarge) {
		t.Fatalf("file count cap: %v", err)
	}
	// SKILL.md is mandatory and must be text; content and a SKILL.md entry must agree.
	if _, _, err := normalizeLibrarySkillBundle("", []LibrarySkillFileContent{{Path: "references/a.md", Data: []byte("x")}}); !errors.Is(err, ErrLibrarySkillBundleInvalid) {
		t.Fatalf("missing SKILL.md: %v", err)
	}
	if _, _, err := normalizeLibrarySkillBundle("# A", []LibrarySkillFileContent{{Path: "SKILL.md", Data: []byte("# B")}}); !errors.Is(err, ErrLibrarySkillBundleInvalid) {
		t.Fatalf("disagreeing SKILL.md: %v", err)
	}
	// Front matter rules.
	skill := LibrarySkill{Slug: "safe", Name: "Safe skill", Description: "Safe."}
	if err := validateLibrarySkillFrontMatter(skill, "# No front matter", true); !errors.Is(err, ErrLibrarySkillBundleInvalid) {
		t.Fatalf("bundle without front matter accepted: %v", err)
	}
	if err := validateLibrarySkillFrontMatter(skill, "# No front matter", false); err != nil {
		t.Fatalf("legacy content rejected: %v", err)
	}
	if err := validateLibrarySkillFrontMatter(skill, testSkillBundleFrontMatter("safe", "Safe.", "# ok"), true); err != nil {
		t.Fatalf("slug name rejected: %v", err)
	}
	if err := validateLibrarySkillFrontMatter(skill, testSkillBundleFrontMatter("\"Safe Skill\"", "'Safe.'", "# ok"), true); err != nil {
		t.Fatalf("quoted display name rejected: %v", err)
	}
	if err := validateLibrarySkillFrontMatter(skill, testSkillBundleFrontMatter("other", "Safe.", "# ok"), true); !errors.Is(err, ErrLibrarySkillBundleInvalid) {
		t.Fatalf("mismatched name accepted: %v", err)
	}
	if err := validateLibrarySkillFrontMatter(skill, testSkillBundleFrontMatter("safe", "Different.", "# ok"), true); !errors.Is(err, ErrLibrarySkillBundleInvalid) {
		t.Fatalf("mismatched description accepted: %v", err)
	}
	if err := validateLibrarySkillFrontMatter(skill, "---\nname: safe\n---\n# ok", true); !errors.Is(err, ErrLibrarySkillBundleInvalid) {
		t.Fatalf("missing description accepted: %v", err)
	}
	folded := "---\nname: safe\ndescription: >\n  Safe.\nmetadata:\n  version: \"1\"\n---\n# ok"
	if err := validateLibrarySkillFrontMatter(skill, folded, true); err != nil {
		t.Fatalf("block scalar description rejected: %v", err)
	}
}

func TestLibrarySkillBundleZipImportRejectsTraversalSymlinksAndDuplicates(t *testing.T) {
	instructions := []byte(testSkillBundleFrontMatter("zipped", "Zipped.", "# Zipped\n"))
	build := func(entries func(*zip.Writer)) []byte {
		var buffer bytes.Buffer
		writer := zip.NewWriter(&buffer)
		entries(writer)
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		return buffer.Bytes()
	}
	write := func(writer *zip.Writer, name string, data []byte) {
		entry, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct {
		name    string
		archive []byte
		want    error
	}{
		{"zip slip", build(func(w *zip.Writer) { write(w, "SKILL.md", instructions); write(w, "../escape.md", []byte("x")) }), ErrLibrarySkillBundleInvalid},
		{"absolute", build(func(w *zip.Writer) { write(w, "SKILL.md", instructions); write(w, "/etc/x.md", []byte("x")) }), ErrLibrarySkillBundleInvalid},
		{"nested traversal", build(func(w *zip.Writer) {
			write(w, "skill/SKILL.md", instructions)
			write(w, "skill/refs/../../x.md", []byte("x"))
		}), ErrLibrarySkillBundleInvalid},
		{"duplicate by case", build(func(w *zip.Writer) {
			write(w, "SKILL.md", instructions)
			write(w, "refs/A.md", []byte("x"))
			write(w, "refs/a.md", []byte("y"))
		}), ErrLibrarySkillBundleInvalid},
		{"no SKILL.md", build(func(w *zip.Writer) { write(w, "refs/a.md", []byte("x")) }), ErrLibrarySkillBundleInvalid},
		{"two roots", build(func(w *zip.Writer) { write(w, "one/SKILL.md", instructions); write(w, "two/refs/a.md", []byte("x")) }), ErrLibrarySkillBundleInvalid},
		{"empty", nil, ErrLibrarySkillBundleInvalid},
		{"not a zip", []byte("plain text"), ErrLibrarySkillBundleInvalid},
		{"symlink", build(func(w *zip.Writer) {
			write(w, "SKILL.md", instructions)
			header := &zip.FileHeader{Name: "refs/link.md", Method: zip.Store}
			header.SetMode(os.ModeSymlink | 0o777)
			entry, err := w.CreateHeader(header)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = entry.Write([]byte("../SKILL.md"))
		}), ErrLibrarySkillBundleInvalid},
		{"encrypted flag", build(func(w *zip.Writer) {
			write(w, "SKILL.md", instructions)
			header := &zip.FileHeader{Name: "refs/secret.md", Method: zip.Store, Flags: 0x1}
			entry, err := w.CreateHeader(header)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = entry.Write([]byte("x"))
		}), ErrLibrarySkillBundleInvalid},
		{"oversize entry", build(func(w *zip.Writer) {
			write(w, "SKILL.md", instructions)
			write(w, "assets/big.txt", bytes.Repeat([]byte("a"), libraryMaxSkillFileBytes+1))
		}), ErrLibrarySkillBundleTooLarge},
	}
	for _, tc := range cases {
		_, err := parseLibrarySkillBundleZip(tc.archive)
		if !errors.Is(err, tc.want) {
			t.Fatalf("%s: err=%v want %v", tc.name, err, tc.want)
		}
	}
	// A skill-creator package (one top-level folder) and a flat archive both
	// import; macOS resource forks and directory entries are ignored.
	packaged := build(func(w *zip.Writer) {
		write(w, "zipped/", nil)
		write(w, "zipped/SKILL.md", instructions)
		write(w, "zipped/refs/a.md", []byte("x"))
		write(w, "__MACOSX/zipped/._SKILL.md", []byte("junk"))
		write(w, "zipped/.DS_Store", []byte("junk"))
	})
	files, err := parseLibrarySkillBundleZip(packaged)
	if err != nil || len(files) != 2 || files[0].Path != "SKILL.md" || files[1].Path != "refs/a.md" {
		t.Fatalf("packaged import files=%+v err=%v", files, err)
	}
	flat := build(func(w *zip.Writer) { write(w, "SKILL.md", instructions); write(w, "refs/a.md", []byte("x")) })
	if files, err := parseLibrarySkillBundleZip(flat); err != nil || len(files) != 2 {
		t.Fatalf("flat import files=%+v err=%v", files, err)
	}
}

// TestLibrarySkillLegacyVersionsMigrateToOneFileManifest proves the FileStore
// migration: a store written before bundles loads every version as the
// equivalent one-file manifest with its content and digest unchanged, and the
// Engine-managed seed skill v1 keeps its exact identity and expected digest.
func TestLibrarySkillLegacyVersionsMigrateToOneFileManifest(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "accounts.json")
	legacy := map[string]any{
		"accounts": []any{},
		"library_skills": []map[string]any{{
			"id": "libsk_legacy", "slug": "legacy-skill", "name": "Legacy skill", "description": "Written before bundles.",
			"createdBy": "usr_owner", "createdAt": "2026-01-01T00:00:00Z", "updatedAt": "2026-01-01T00:00:00Z",
		}},
		"library_skill_versions": []map[string]any{{
			"id": "libskv_legacy_v1", "skillId": "libsk_legacy", "version": 1, "content": "# Legacy instructions\n",
			"digest": libraryDigest("# Legacy instructions\n"), "requestedCapabilities": []string{"repository.read"},
			"createdBy": "usr_owner", "createdAt": "2026-01-01T00:00:00Z",
		}},
	}
	raw, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := LoadFileStore(path)
	if err != nil {
		t.Fatalf("load legacy store: %v", err)
	}
	if err := ReconcileBuiltInLibrary(ctx, store); err != nil {
		t.Fatalf("reconcile seed skill: %v", err)
	}
	version, found := store.LibrarySkillVersion(ctx, "libsk_legacy", "libskv_legacy_v1")
	if !found {
		t.Fatal("legacy version disappeared")
	}
	if version.Content != "# Legacy instructions\n" || version.Digest != libraryDigest("# Legacy instructions\n") || version.ID != "libskv_legacy_v1" {
		t.Fatalf("legacy identity changed: %+v", version)
	}
	wantManifest, err := librarySkillManifestDigest(legacyLibrarySkillManifest(version.Content, version.Digest))
	if err != nil {
		t.Fatal(err)
	}
	if len(version.Files) != 1 || version.Files[0] != (LibrarySkillFile{Path: "SKILL.md", ContentType: "text/markdown", SizeBytes: int64(len(version.Content)), Digest: version.Digest}) || version.ManifestDigest != wantManifest {
		t.Fatalf("legacy manifest = %+v (%s)", version.Files, version.ManifestDigest)
	}
	seed, found := store.LibrarySkillVersion(ctx, usingSynaxisSkillID, usingSynaxisSkillVersionID)
	if !found || seed.Digest != usingSynaxisExpectedContentDigest || seed.Content != usingSynaxisSkillContent {
		t.Fatalf("seed skill v1 changed: found=%t digest=%s", found, seed.Digest)
	}
	if len(seed.Files) != 1 || seed.Files[0].Digest != usingSynaxisExpectedContentDigest || seed.ManifestDigest == "" {
		t.Fatalf("seed manifest = %+v (%s)", seed.Files, seed.ManifestDigest)
	}
	// The migrated manifest is persisted on the next save and survives a reload.
	if _, _, err := store.CreateLibrarySkillWithInitialVersion(ctx, LibrarySkill{Slug: "after", Name: "After", CreatedBy: "usr_owner"}, LibrarySkillVersion{Content: "# After", CreatedBy: "usr_owner"}); err != nil {
		t.Fatal(err)
	}
	reloaded, err := LoadFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	again, found := reloaded.LibrarySkillVersion(ctx, "libsk_legacy", "libskv_legacy_v1")
	if !found || again.ManifestDigest != wantManifest || again.Digest != version.Digest {
		t.Fatalf("reloaded legacy version = %+v", again)
	}
	data, file, found, err := reloaded.LibrarySkillFileBytes(ctx, "libsk_legacy", "libskv_legacy_v1", "SKILL.md")
	if err != nil || !found || string(data) != version.Content || file.Digest != version.Digest {
		t.Fatalf("legacy SKILL.md bytes: found=%t err=%v", found, err)
	}
}

// TestMCPClientSkillBundleAuthoringIsIdempotentAndLeaseBounded exercises the
// leased MCP path end to end on the FileStore: staged uploads with their own
// bounded budget, inline files, blob references, exact replays,
// changed-payload conflicts, front-matter enforcement, and quota exhaustion
// that leaves no partial version behind.
func TestMCPClientSkillBundleAuthoringIsIdempotentAndLeaseBounded(t *testing.T) {
	ctx := context.Background()
	store := newLibraryFileStore(t)
	client := newAuthoringLeaseMCPClient(t, store, "usr_bundle")
	if _, err := store.GrantMCPClientSkillAuthoringLease(ctx, client.ID, MCPClientPrecondition{ID: client.ID, Revision: client.Revision}, "usr_owner"); err != nil {
		t.Fatal(err)
	}
	workbook := testOOXMLBlob(t, 200<<10)
	upload := LibraryMCPClientSkillBlobUploadRequest{RequestID: "upload-1", Path: "assets/template.xlsx", DataBase64: base64.StdEncoding.EncodeToString(workbook)}
	staged, err := store.StageLibraryMCPClientSkillBlob(ctx, client, upload)
	if err != nil {
		t.Fatalf("stage blob: %v", err)
	}
	// An upload consumes an upload slot, never one of the three authoring writes.
	if staged.Replayed || staged.Lease.RemainingCreates != libraryMCPClientSkillAuthoringLeaseMaxCreates || staged.Lease.RemainingUploads != libraryMCPClientSkillAuthoringLeaseMaxUploads-1 ||
		staged.Digest != librarySkillFileDigest(workbook) || staged.ContentType != "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" || staged.SizeBytes != int64(len(workbook)) {
		t.Fatalf("staged = %+v", staged)
	}
	replayed, err := store.StageLibraryMCPClientSkillBlob(ctx, client, upload)
	if err != nil || !replayed.Replayed || replayed.BlobID != staged.BlobID || replayed.Lease.RemainingUploads != libraryMCPClientSkillAuthoringLeaseMaxUploads-1 {
		t.Fatalf("upload replay = %+v err=%v", replayed, err)
	}
	changed := upload
	changed.DataBase64 = base64.StdEncoding.EncodeToString(testOOXMLBlob(t, 1024))
	if _, err := store.StageLibraryMCPClientSkillBlob(ctx, client, changed); !errors.Is(err, ErrLibraryMCPClientSkillAuthoringRequestConflict) {
		t.Fatalf("changed upload replay err=%v", err)
	}
	if _, err := store.StageLibraryMCPClientSkillBlob(ctx, client, LibraryMCPClientSkillBlobUploadRequest{RequestID: "bad", Path: "SKILL.md", DataBase64: base64.StdEncoding.EncodeToString([]byte("# x"))}); !errors.Is(err, ErrLibrarySkillBundleInvalid) {
		t.Fatalf("SKILL.md upload err=%v", err)
	}

	instructions := testSkillBundleFrontMatter("bundle-skill", "A bundled skill.", "# Bundle\n")
	create := LibraryMCPClientSkillAuthoringRequest{
		RequestID: "create-1", Name: "Bundle skill", Description: "A bundled skill.", Content: instructions,
		RequestedCapabilities: []string{"repository.read"},
		Files: []LibrarySkillFileInput{
			{Path: "references/guide.md", Content: "# Guide\n"},
			{Path: "scripts/build.py", Encoding: "base64", Content: base64.StdEncoding.EncodeToString([]byte("print('build')\n"))},
			{Path: "assets/template.xlsx", BlobID: staged.BlobID},
		},
	}
	created, err := store.CreateLibraryMCPClientSkillWithAuthoringLease(ctx, client, create)
	if err != nil {
		t.Fatalf("leased bundle create: %v", err)
	}
	if created.Replayed || created.Lease.RemainingCreates != 2 || len(created.Version.Files) != 4 || created.Version.ManifestDigest == "" || created.Version.Digest != libraryDigest(instructions) {
		t.Fatalf("created = %+v", created)
	}
	data, file, found, err := store.LibrarySkillFileBytes(ctx, created.Skill.ID, created.Version.ID, "assets/template.xlsx")
	if err != nil || !found || !bytes.Equal(data, workbook) || file.Digest != staged.Digest {
		t.Fatalf("staged blob did not land in the version: found=%t err=%v", found, err)
	}
	again, err := store.CreateLibraryMCPClientSkillWithAuthoringLease(ctx, client, create)
	if err != nil || !again.Replayed || again.Version.ID != created.Version.ID || again.Lease.RemainingCreates != 2 {
		t.Fatalf("create replay = %+v err=%v", again, err)
	}
	items, _, err := store.ListLibraryMCPClientAuthoredSkillsWithAuthoringLease(ctx, client)
	if err != nil || len(items) != 1 || items[0].LatestManifestDigest != created.Version.ManifestDigest || items[0].LatestVersionDigest != created.Version.Digest {
		t.Fatalf("authoring list = %+v err=%v", items, err)
	}

	// A foreign blob reference, a missing front matter, and a mismatched name
	// are rejected before any write and without consuming quota.
	other := newAuthoringLeaseMCPClient(t, store, "usr_other")
	if _, err := store.GrantMCPClientSkillAuthoringLease(ctx, other.ID, MCPClientPrecondition{ID: other.ID, Revision: other.Revision}, "usr_owner"); err != nil {
		t.Fatal(err)
	}
	foreign := LibraryMCPClientSkillAuthoringRequest{
		RequestID: "foreign-1", Name: "Foreign", Description: "Foreign.", Content: testSkillBundleFrontMatter("foreign", "Foreign.", "# f"),
		Files: []LibrarySkillFileInput{{Path: "assets/template.xlsx", BlobID: staged.BlobID}},
	}
	if _, err := store.CreateLibraryMCPClientSkillWithAuthoringLease(ctx, other, foreign); !errors.Is(err, ErrLibrarySkillBundleInvalid) {
		t.Fatalf("foreign blob reference err=%v", err)
	}
	noFrontMatter := LibraryMCPClientSkillAuthoringRequest{
		RequestID: "nofm-1", Name: "No front matter", Description: "x", Content: "# plain",
		Files: []LibrarySkillFileInput{{Path: "references/guide.md", Content: "# Guide\n"}},
	}
	if _, err := store.CreateLibraryMCPClientSkillWithAuthoringLease(ctx, other, noFrontMatter); !errors.Is(err, ErrLibrarySkillBundleInvalid) {
		t.Fatalf("bundle without front matter err=%v", err)
	}
	otherLease, _, err := store.MCPClientSkillAuthoringLease(ctx, other.ID)
	if err != nil || otherLease.RemainingCreates != libraryMCPClientSkillAuthoringLeaseMaxCreates || otherLease.RemainingUploads != libraryMCPClientSkillAuthoringLeaseMaxUploads {
		t.Fatalf("rejected bundle writes consumed quota: %+v err=%v", otherLease, err)
	}

	// Update appends a bundle version with the exact head fence; the old
	// version keeps its manifest.
	update := LibraryMCPClientSkillAuthoringUpdateRequest{
		RequestID: "update-1", SkillID: created.Skill.ID, ExpectedVersionID: created.Version.ID, ExpectedVersionDigest: created.Version.Digest,
		Content: instructions, RequestedCapabilities: []string{"repository.read"},
		Files: []LibrarySkillFileInput{{Path: "references/guide.md", Content: "# Guide v2\n"}},
	}
	updated, err := store.UpdateLibraryMCPClientSkillWithAuthoringLease(ctx, client, update)
	if err != nil || updated.Version.Version != 2 || len(updated.Version.Files) != 2 || updated.Lease.RemainingCreates != 1 {
		t.Fatalf("leased bundle update = %+v err=%v", updated, err)
	}
	// The last authoring write closes the window for uploads too.
	if _, err := store.CreateLibraryMCPClientSkillWithAuthoringLease(ctx, client, LibraryMCPClientSkillAuthoringRequest{RequestID: "create-last", Name: "Last write", Content: "# last"}); err != nil {
		t.Fatalf("last create: %v", err)
	}
	if _, err := store.StageLibraryMCPClientSkillBlob(ctx, client, LibraryMCPClientSkillBlobUploadRequest{RequestID: "upload-late", Path: "assets/late.xlsx", DataBase64: base64.StdEncoding.EncodeToString(workbook)}); !errors.Is(err, ErrLibraryMCPClientSkillAuthoringUnavailable) {
		t.Fatalf("upload after exhaustion err=%v", err)
	}
	versions, err := store.LibrarySkillVersions(ctx, created.Skill.ID)
	if err != nil || len(versions) != 2 || versions[0].ManifestDigest != created.Version.ManifestDigest {
		t.Fatalf("versions after exhaustion = %+v err=%v", versions, err)
	}

	// Exhausting the authoring writes while blobs are still staged leaves no
	// partial version: the create that would reference them fails closed and
	// the slug stays free.
	third := newAuthoringLeaseMCPClient(t, store, "usr_third")
	if _, err := store.GrantMCPClientSkillAuthoringLease(ctx, third.ID, MCPClientPrecondition{ID: third.ID, Revision: third.Revision}, "usr_owner"); err != nil {
		t.Fatal(err)
	}
	var blobIDs []string
	for index := 0; index < 3; index++ {
		result, err := store.StageLibraryMCPClientSkillBlob(ctx, third, LibraryMCPClientSkillBlobUploadRequest{
			RequestID: fmt.Sprintf("multi-%d", index), Path: fmt.Sprintf("assets/part%d.txt", index), DataBase64: base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("part %d", index))),
		})
		if err != nil {
			t.Fatalf("stage part %d: %v", index, err)
		}
		blobIDs = append(blobIDs, result.BlobID)
	}
	for index := 0; index < libraryMCPClientSkillAuthoringLeaseMaxCreates; index++ {
		if _, err := store.CreateLibraryMCPClientSkillWithAuthoringLease(ctx, third, LibraryMCPClientSkillAuthoringRequest{
			RequestID: fmt.Sprintf("filler-%d", index), Name: fmt.Sprintf("Filler %d", index), Content: "# filler",
		}); err != nil {
			t.Fatalf("filler create %d: %v", index, err)
		}
	}
	partial := LibraryMCPClientSkillAuthoringRequest{
		RequestID: "partial-1", Name: "Partial", Description: "Partial.", Content: testSkillBundleFrontMatter("partial", "Partial.", "# p"),
		Files: []LibrarySkillFileInput{{Path: "assets/part0.txt", BlobID: blobIDs[0]}, {Path: "assets/part1.txt", BlobID: blobIDs[1]}, {Path: "assets/part2.txt", BlobID: blobIDs[2]}},
	}
	if _, err := store.CreateLibraryMCPClientSkillWithAuthoringLease(ctx, third, partial); !errors.Is(err, ErrLibraryMCPClientSkillAuthoringUnavailable) {
		t.Fatalf("create after exhaustion err=%v", err)
	}
	skills, err := store.LibrarySkills(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, skill := range skills {
		if skill.Slug == "partial" {
			t.Fatal("exhausted lease left a partial skill behind")
		}
	}

	// The upload budget is bounded on its own: the slot after the last one is
	// refused, while the authoring writes are still available.
	fourth := newAuthoringLeaseMCPClient(t, store, "usr_fourth")
	if _, err := store.GrantMCPClientSkillAuthoringLease(ctx, fourth.ID, MCPClientPrecondition{ID: fourth.ID, Revision: fourth.Revision}, "usr_owner"); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < libraryMCPClientSkillAuthoringLeaseMaxUploads; index++ {
		if _, err := store.StageLibraryMCPClientSkillBlob(ctx, fourth, LibraryMCPClientSkillBlobUploadRequest{
			RequestID: fmt.Sprintf("budget-%d", index), Path: fmt.Sprintf("assets/b%d.txt", index), DataBase64: base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("b %d", index))),
		}); err != nil {
			t.Fatalf("budget upload %d: %v", index, err)
		}
	}
	if _, err := store.StageLibraryMCPClientSkillBlob(ctx, fourth, LibraryMCPClientSkillBlobUploadRequest{RequestID: "budget-overflow", Path: "assets/overflow.txt", DataBase64: base64.StdEncoding.EncodeToString([]byte("over"))}); !errors.Is(err, ErrLibraryMCPClientSkillAuthoringUnavailable) {
		t.Fatalf("upload past the budget err=%v", err)
	}
	fourthLease, _, err := store.MCPClientSkillAuthoringLease(ctx, fourth.ID)
	if err != nil || fourthLease.RemainingUploads != 0 || fourthLease.RemainingCreates != libraryMCPClientSkillAuthoringLeaseMaxCreates || fourthLease.Status != LibraryMCPClientSkillAuthoringLeaseStatusActive {
		t.Fatalf("lease after upload budget = %+v err=%v", fourthLease, err)
	}
}

// TestMCPClientSkillBundleToolsRoundTripImportReadAndActivation drives the
// subject-bound MCP tools: import a .skill package, read its manifest and
// files, and confirm v1 activation is unchanged while v2 adds the manifest.
func TestMCPClientSkillBundleToolsRoundTripImportReadAndActivation(t *testing.T) {
	ctx := context.Background()
	store, gateway := newMCPClientGateway(t)
	client := newAuthoringLeaseMCPClient(t, store, "usr_tools")
	if err := gateway.RefreshMCPClients(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GrantMCPClientSkillAuthoringLease(ctx, client.ID, MCPClientPrecondition{ID: client.ID, Revision: client.Revision}, "usr_owner"); err != nil {
		t.Fatal(err)
	}
	mcpServer := clientLibraryServer(t, gateway, client.Slug)
	files := testElevenFileBundle(t, "commit-poc-loe", "Build a PoC level-of-effort workbook on the standard template.")
	archive := testSkillBundleZip(t, "commit-poc-loe/", files)

	imported := callLibraryTool(t, mcpServer, "library_skill_import_bundle", map[string]any{
		"requestId": "import-1", "bundleBase64": base64.StdEncoding.EncodeToString(archive),
	})
	if strings.Contains(imported, `"isError":true`) {
		t.Fatalf("import bundle: %s", imported)
	}
	var importResult struct {
		SkillID        string `json:"skillId"`
		SkillVersionID string `json:"skillVersionId"`
		Digest         string `json:"digest"`
		ManifestDigest string `json:"manifestDigest"`
		FileCount      int    `json:"fileCount"`
		Replayed       bool   `json:"replayed"`
	}
	if err := json.Unmarshal([]byte(libraryToolJSONText(t, imported)), &importResult); err != nil {
		t.Fatal(err)
	}
	if importResult.FileCount != 11 || importResult.ManifestDigest == "" || importResult.Replayed {
		t.Fatalf("import result = %+v", importResult)
	}
	skill, found := store.LibrarySkill(ctx, importResult.SkillID)
	if !found || skill.Slug != "commit-poc-loe" || skill.Name != "commit-poc-loe" || !strings.HasPrefix(skill.Description, "Build a PoC") {
		t.Fatalf("imported skill metadata came from front matter: %+v found=%t", skill, found)
	}
	replay := callLibraryTool(t, mcpServer, "library_skill_import_bundle", map[string]any{
		"requestId": "import-1", "bundleBase64": base64.StdEncoding.EncodeToString(archive),
	})
	if !strings.Contains(replay, `"replayed":true`) {
		t.Fatalf("import replay = %s", replay)
	}
	slipped := testSkillBundleZip(t, "", append([]LibrarySkillFileContent{{Path: "../escape.md", Data: []byte("x")}}, files...))
	if got := callLibraryTool(t, mcpServer, "library_skill_import_bundle", map[string]any{"requestId": "import-slip", "bundleBase64": base64.StdEncoding.EncodeToString(slipped)}); !strings.Contains(got, `"isError":true`) || !strings.Contains(got, "traversal") {
		t.Fatalf("zip slip accepted: %s", got)
	}

	// The automatic client binding assigns the skill, so the read tools see it.
	read := libraryToolJSONText(t, callLibraryTool(t, mcpServer, "library_skill_read", map[string]any{"skillId": importResult.SkillID}))
	var readResult struct {
		Version  struct{ ID, Digest string }    `json:"version"`
		Manifest LibrarySkillManifestProjection `json:"manifest"`
	}
	if err := json.Unmarshal([]byte(read), &readResult); err != nil {
		t.Fatal(err)
	}
	if readResult.Manifest.ManifestDigest != importResult.ManifestDigest || len(readResult.Manifest.Files) != 11 {
		t.Fatalf("read manifest = %+v", readResult.Manifest)
	}
	for _, entry := range readResult.Manifest.Files {
		if LibrarySkillFileIsText(entry.ContentType) && entry.Text == "" {
			t.Fatalf("small text file %s was not inlined", entry.Path)
		}
		if entry.Path == "assets/template.xlsx" && entry.Text != "" {
			t.Fatal("binary was inlined into the manifest projection")
		}
	}
	fileRead := libraryToolJSONText(t, callLibraryTool(t, mcpServer, "library_skill_file_read", map[string]any{
		"skillId": importResult.SkillID, "versionId": importResult.SkillVersionID, "path": "assets/template.xlsx",
	}))
	var fileResult librarySkillFileReadResult
	if err := json.Unmarshal([]byte(fileRead), &fileResult); err != nil {
		t.Fatal(err)
	}
	decoded, err := base64.StdEncoding.DecodeString(fileResult.Content)
	if err != nil || fileResult.Encoding != "base64" || !bytes.Equal(decoded, files[10].Data) || fileResult.Digest != librarySkillFileDigest(files[10].Data) {
		t.Fatalf("file read = %+v err=%v", fileResult.Digest, err)
	}
	textRead := libraryToolJSONText(t, callLibraryTool(t, mcpServer, "library_skill_file_read", map[string]any{
		"skillId": importResult.SkillID, "versionId": importResult.SkillVersionID, "path": "scripts/build.py",
	}))
	if !strings.Contains(textRead, `"encoding":"utf8"`) || !strings.Contains(textRead, "print(json.dumps") {
		t.Fatalf("text file read = %s", textRead)
	}
	for _, bad := range []map[string]any{
		{"skillId": importResult.SkillID, "versionId": importResult.SkillVersionID, "path": "../SKILL.md"},
		{"skillId": importResult.SkillID, "versionId": "libskv_unknown", "path": "SKILL.md"},
		{"skillId": "libsk_unknown", "versionId": importResult.SkillVersionID, "path": "SKILL.md"},
	} {
		if got := callLibraryTool(t, mcpServer, "library_skill_file_read", bad); !strings.Contains(got, "skill file not found") {
			t.Fatalf("file read %v = %s", bad, got)
		}
	}

	// v1 activation is byte-for-byte the pre-bundle contract; v2 adds manifests.
	v1 := libraryToolJSONText(t, callLibraryTool(t, mcpServer, "library_skill_activation", nil))
	if strings.Contains(v1, `"manifest"`) || !strings.Contains(v1, `"contractVersion":"synaxis.library.activation.v1"`) {
		t.Fatalf("v1 activation changed: %s", v1)
	}
	v1Verified, err := libraryruntime.DecodeAndVerifyActivationBundle(strings.NewReader(v1), libraryruntime.Limits{})
	if err != nil {
		t.Fatalf("v1 activation verification: %v", err)
	}
	var v1Bundle libraryruntime.ActivationBundle
	if err := json.Unmarshal([]byte(v1), &v1Bundle); err != nil {
		t.Fatal(err)
	}
	if len(v1Bundle.HostResponsibilities) != 3 {
		t.Fatalf("v1 host responsibilities = %v", v1Bundle.HostResponsibilities)
	}
	explicit := libraryToolJSONText(t, callLibraryTool(t, mcpServer, "library_skill_activation", map[string]any{"contractVersion": "synaxis.library.activation.v1"}))
	if explicit != v1 {
		t.Fatal("explicit v1 request differs from the default")
	}
	v2 := libraryToolJSONText(t, callLibraryTool(t, mcpServer, "library_skill_activation", map[string]any{"contractVersion": "synaxis.library.activation.v2"}))
	v2Verified, err := libraryruntime.DecodeAndVerifyActivationBundle(strings.NewReader(v2), libraryruntime.Limits{})
	if err != nil {
		t.Fatalf("v2 activation verification: %v", err)
	}
	if v2Verified.BundleDigest() == v1Verified.BundleDigest() {
		t.Fatal("v2 bundle digest equals the v1 digest; manifests are not covered")
	}
	manifestSeen := false
	for _, selected := range v2Verified.Skills() {
		if selected.Manifest == nil {
			t.Fatalf("v2 selection %s has no manifest", selected.SkillID)
		}
		if selected.SkillID == importResult.SkillID {
			manifestSeen = true
			if selected.Manifest.ManifestDigest != importResult.ManifestDigest || len(selected.Manifest.Files) != 11 {
				t.Fatalf("v2 manifest = %+v", selected.Manifest)
			}
		}
	}
	if !manifestSeen {
		t.Fatal("imported skill missing from v2 activation")
	}
	if _, err := libraryruntime.BuildContext(v2Verified, libraryruntime.Limits{}); err != nil {
		t.Fatalf("v2 context: %v", err)
	}
	if got := callLibraryTool(t, mcpServer, "library_skill_activation", map[string]any{"contractVersion": "synaxis.library.activation.v9"}); !strings.Contains(got, "unsupported activation contract") {
		t.Fatalf("unknown contract = %s", got)
	}

	// The authoring list reports the manifest digest a bundle update fences on.
	list := libraryToolJSONText(t, callLibraryTool(t, mcpServer, "library_skill_authoring_list", nil))
	if !strings.Contains(list, `"latestManifestDigest":"`+importResult.ManifestDigest+`"`) {
		t.Fatalf("authoring list = %s", list)
	}

	// An inline update with a staged blob through the tools.
	staged := libraryToolJSONText(t, callLibraryTool(t, mcpServer, "library_skill_upload_blob", map[string]any{
		"requestId": "upload-1", "path": "assets/template.xlsx", "dataBase64": base64.StdEncoding.EncodeToString(files[10].Data),
	}))
	var stagedResult struct {
		BlobID string `json:"blobId"`
		Digest string `json:"digest"`
	}
	if err := json.Unmarshal([]byte(staged), &stagedResult); err != nil || stagedResult.BlobID == "" {
		t.Fatalf("upload result = %s err=%v", staged, err)
	}
	updated := callLibraryTool(t, mcpServer, "library_skill_update", map[string]any{
		"requestId": "update-1", "skillId": importResult.SkillID, "expectedVersionId": importResult.SkillVersionID, "expectedVersionDigest": importResult.Digest,
		"content": string(files[0].Data),
		"files": []map[string]any{
			{"path": "references/content-guide.md", "content": "# Revised guide\n"},
			{"path": "assets/template.xlsx", "blobId": stagedResult.BlobID},
		},
	})
	if strings.Contains(updated, `"isError":true`) || !strings.Contains(updated, `"fileCount":3`) {
		t.Fatalf("bundle update = %s", updated)
	}
}

// TestLibrarySkillBundleConsoleRoutesCreateDownloadAndServeFiles covers the
// owner/admin HTTP surface: a bundle create, the per-file attachment route,
// and the deterministic .skill download.
func TestLibrarySkillBundleConsoleRoutesCreateDownloadAndServeFiles(t *testing.T) {
	mux, token, _ := newLibraryConsole(t)
	do := func(method, target string, body []byte) *httptest.ResponseRecorder {
		t.Helper()
		var reader io.Reader
		if body != nil {
			reader = bytes.NewReader(body)
		}
		request := httptest.NewRequest(method, target, reader)
		request.Header.Set("Authorization", "Bearer "+token)
		if body != nil {
			request.Header.Set("Content-Type", "application/json")
		}
		recorder := httptest.NewRecorder()
		mux.ServeHTTP(recorder, request)
		return recorder
	}
	files := testElevenFileBundle(t, "commit-poc-loe", "Build a PoC level-of-effort workbook on the standard template.")
	inputs := make([]map[string]any, 0, len(files))
	for _, file := range files {
		if file.Path == "SKILL.md" || LibrarySkillFileIsText(librarySkillContentTypeOrEmpty(file.Path)) {
			inputs = append(inputs, map[string]any{"path": file.Path, "content": string(file.Data)})
			continue
		}
		inputs = append(inputs, map[string]any{"path": file.Path, "encoding": "base64", "content": base64.StdEncoding.EncodeToString(file.Data)})
	}
	body, _ := json.Marshal(map[string]any{"name": "Commit PoC LOE", "files": inputs, "origin": "imported"})
	response := do(http.MethodPost, "/api/library/skills", body)
	if response.Code != http.StatusCreated {
		t.Fatalf("bundle create status=%d body=%s", response.Code, response.Body)
	}
	var created struct {
		Skill   LibrarySkill        `json:"skill"`
		Version LibrarySkillVersion `json:"version"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if len(created.Version.Files) != 11 || created.Version.ManifestDigest == "" || created.Skill.Description == "" || created.Version.Provenance == nil || created.Version.Provenance.Origin != LibraryVersionOriginImported {
		t.Fatalf("created = %+v", created)
	}
	base := "/api/library/skills/" + created.Skill.ID + "/versions/" + created.Version.ID
	response = do(http.MethodGet, base+"/files/assets/template.xlsx", nil)
	if response.Code != http.StatusOK || !bytes.Equal(response.Body.Bytes(), files[10].Data) {
		t.Fatalf("file route status=%d len=%d", response.Code, response.Body.Len())
	}
	if !strings.HasPrefix(response.Header().Get("Content-Disposition"), "attachment") || response.Header().Get("X-Content-Type-Options") != "nosniff" || response.Header().Get("X-Synaxis-File-Digest") != librarySkillFileDigest(files[10].Data) {
		t.Fatalf("file route headers = %v", response.Header())
	}
	if response := do(http.MethodGet, base+"/files/scripts/missing.py", nil); response.Code != http.StatusNotFound {
		t.Fatalf("missing file status=%d", response.Code)
	}
	if response := do(http.MethodGet, base+"/files/..%2FSKILL.md", nil); response.Code != http.StatusNotFound {
		t.Fatalf("traversal file route status=%d body=%s", response.Code, response.Body)
	}
	response = do(http.MethodGet, base+"/bundle", nil)
	if response.Code != http.StatusOK || response.Header().Get("Content-Type") != "application/zip" || response.Header().Get("X-Synaxis-Manifest-Digest") != created.Version.ManifestDigest {
		t.Fatalf("bundle route status=%d type=%s", response.Code, response.Header().Get("Content-Type"))
	}
	reimported, err := parseLibrarySkillBundleZip(response.Body.Bytes())
	if err != nil || len(reimported) != 11 {
		t.Fatalf("downloaded bundle re-import files=%d err=%v", len(reimported), err)
	}
	for _, file := range reimported {
		for _, original := range files {
			if original.Path == file.Path && !bytes.Equal(original.Data, file.Data) {
				t.Fatalf("%s changed across download", file.Path)
			}
		}
	}
	// The version list carries the manifest, and a bundle version can follow.
	response = do(http.MethodGet, "/api/library/skills/"+created.Skill.ID+"/versions", nil)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"manifestDigest":"`+created.Version.ManifestDigest+`"`) {
		t.Fatalf("versions list status=%d body=%s", response.Code, response.Body)
	}
	body, _ = json.Marshal(map[string]any{"bundleBase64": base64.StdEncoding.EncodeToString(testSkillBundleZip(t, "commit-poc-loe/", files)), "changelog": "Re-imported package"})
	response = do(http.MethodPost, "/api/library/skills/"+created.Skill.ID+"/versions", body)
	if response.Code != http.StatusCreated || !strings.Contains(response.Body.String(), `"version":2`) {
		t.Fatalf("bundle version status=%d body=%s", response.Code, response.Body)
	}
	// A blob reference is an MCP-lease concept and is refused by the Console.
	body, _ = json.Marshal(map[string]any{"name": "Refs", "files": []map[string]any{{"path": "SKILL.md", "content": testSkillBundleFrontMatter("refs", "Refs.", "# r")}, {"path": "assets/a.xlsx", "blobId": "libblob_x"}}})
	if response := do(http.MethodPost, "/api/library/skills", body); response.Code != http.StatusBadRequest {
		t.Fatalf("blob reference status=%d body=%s", response.Code, response.Body)
	}
	// A legacy single-document create still works and reads as a one-file manifest.
	body, _ = json.Marshal(map[string]any{"name": "Plain", "content": "# Plain instructions"})
	if response := do(http.MethodPost, "/api/library/skills", body); response.Code != http.StatusCreated || !strings.Contains(response.Body.String(), `"path":"SKILL.md"`) {
		t.Fatalf("legacy create status=%d body=%s", response.Code, response.Body)
	}

	// The description is the one editable piece of skill metadata: on its own
	// through PATCH, or together with a version whose SKILL.md front matter
	// describes the skill afresh. Name and slug never change.
	body, _ = json.Marshal(map[string]any{"description": "Build a PoC LOE workbook from a spec."})
	response = do(http.MethodPatch, "/api/library/skills/"+created.Skill.ID, body)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"description":"Build a PoC LOE workbook from a spec."`) {
		t.Fatalf("patch description status=%d body=%s", response.Code, response.Body)
	}
	revised := testSkillBundleFrontMatter("commit-poc-loe", "Build a PoC LOE workbook from a spec, then verify it.", "# Builder v3\n")
	body, _ = json.Marshal(map[string]any{
		"content": revised, "description": "Build a PoC LOE workbook from a spec, then verify it.",
		"files": []map[string]any{{"path": "references/guide.md", "content": "# Guide\n"}},
	})
	response = do(http.MethodPost, "/api/library/skills/"+created.Skill.ID+"/versions", body)
	if response.Code != http.StatusCreated || !strings.Contains(response.Body.String(), `"version":3`) {
		t.Fatalf("version with description status=%d body=%s", response.Code, response.Body)
	}
	response = do(http.MethodGet, "/api/library/skills/"+created.Skill.ID, nil)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"description":"Build a PoC LOE workbook from a spec, then verify it."`) || !strings.Contains(response.Body.String(), `"name":"Commit PoC LOE"`) {
		t.Fatalf("skill after described version status=%d body=%s", response.Code, response.Body)
	}
	// A version whose front matter disagrees with the (possibly updated)
	// description is still refused, and the managed guide cannot be edited.
	body, _ = json.Marshal(map[string]any{
		"content": testSkillBundleFrontMatter("commit-poc-loe", "Something else entirely.", "# v4\n"),
		"files":   []map[string]any{{"path": "references/guide.md", "content": "# Guide\n"}},
	})
	if response := do(http.MethodPost, "/api/library/skills/"+created.Skill.ID+"/versions", body); response.Code != http.StatusBadRequest {
		t.Fatalf("disagreeing front matter status=%d body=%s", response.Code, response.Body)
	}
	body, _ = json.Marshal(map[string]any{"description": "not allowed"})
	if response := do(http.MethodPatch, "/api/library/skills/"+usingSynaxisSkillID, body); response.Code != http.StatusConflict && response.Code != http.StatusNotFound {
		t.Fatalf("managed guide patch status=%d body=%s", response.Code, response.Body)
	}
}

func librarySkillContentTypeOrEmpty(path string) string {
	contentType, err := librarySkillContentTypeForPath(path)
	if err != nil {
		return ""
	}
	return contentType
}

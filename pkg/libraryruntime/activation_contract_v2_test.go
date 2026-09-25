package libraryruntime

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// v2FixtureBundle is the canonical v2 fixture: one bundled skill whose
// manifest lists SKILL.md plus a reference and a workbook. Digests are
// computed here so the committed JSON can never drift from the adapter.
func v2FixtureBundle(t *testing.T) ActivationBundle {
	t.Helper()
	instructions := "---\nname: release-notes\ndescription: Summarize verified changes.\n---\n\nSummarize verified changes. Do not invent deployment status.\n"
	files := []ManifestFile{
		{Path: "SKILL.md", ContentType: "text/markdown", SizeBytes: int64(len(instructions)), Digest: digestString(instructions)},
		{Path: "assets/template.xlsx", ContentType: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", SizeBytes: 203467, Digest: digestString("workbook-bytes-stand-in")},
		{Path: "references/guide.md", ContentType: "text/markdown", SizeBytes: 12, Digest: digestString("# Guide\n\nHi\n")},
	}
	manifestValue, err := manifestDigest(files)
	if err != nil {
		t.Fatal(err)
	}
	bundle := ActivationBundle{
		ContractVersion: ActivationContractVersionV2,
		AgentSurface:    AgentSurface{Kind: "mcp_client", ID: "mcpcli_example"},
		Skills: []Skill{{
			SkillID: "skill_release_notes", SkillSlug: "release-notes", SkillName: "Release Notes",
			VersionID: "version_2", Version: 2, Instructions: instructions, ContentDigest: digestString(instructions),
			Binding:     Binding{ID: "binding_example", Mode: "pin", Priority: 100},
			Constraints: Constraints{RequestedCapabilities: []string{"repo.read"}, CapabilityCeiling: []string{"repo.read"}},
			Manifest:    &Manifest{ManifestDigest: manifestValue, Files: files},
		}},
		AuthorityNotice:      activationAuthorityNotice,
		HostResponsibilities: activationHostResponsibilitiesFor(ActivationContractVersionV2),
	}
	digest, err := activationDigest(bundle)
	if err != nil {
		t.Fatal(err)
	}
	bundle.BundleDigest = digest
	return bundle
}

func TestActivationBundleV2SchemaFixturesAndAdapter(t *testing.T) {
	t.Parallel()
	bundle := v2FixtureBundle(t)
	encoded, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded, '\n')
	fixturePath := filepath.Join("testdata", "activation-bundle.v2.valid.json")
	if os.Getenv("SYNAXIS_WRITE_FIXTURES") == "1" {
		if err := os.WriteFile(fixturePath, encoded, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	stored, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("read v2 fixture (set SYNAXIS_WRITE_FIXTURES=1 to generate): %v", err)
	}
	if !bytes.Equal(stored, encoded) {
		t.Fatal("committed v2 fixture differs from the adapter's canonical bundle; regenerate it with SYNAXIS_WRITE_FIXTURES=1")
	}

	compiler := jsonschema.NewCompiler()
	v2Schema, err := compiler.Compile("activation-bundle.v2.schema.json")
	if err != nil {
		t.Fatalf("compile v2 schema: %v", err)
	}
	v1Schema, err := compiler.Compile("activation-bundle.v1.schema.json")
	if err != nil {
		t.Fatalf("compile v1 schema: %v", err)
	}
	instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(stored))
	if err != nil {
		t.Fatal(err)
	}
	if err := v2Schema.Validate(instance); err != nil {
		t.Fatalf("v2 fixture fails the v2 schema: %v", err)
	}
	if err := v1Schema.Validate(instance); err == nil {
		t.Fatal("v2 fixture must not validate as v1 (a v1 host must reject it)")
	}
	verified, err := DecodeAndVerifyActivationBundle(bytes.NewReader(stored), Limits{})
	if err != nil {
		t.Fatalf("adapter rejects the v2 fixture: %v", err)
	}
	selected := verified.Skills()[0]
	if selected.Manifest == nil || len(selected.Manifest.Files) != 3 || selected.Manifest.Files[0].Path != "SKILL.md" {
		t.Fatalf("verified manifest = %+v", selected.Manifest)
	}
	context, err := BuildContext(verified, Limits{})
	if err != nil {
		t.Fatalf("v2 context: %v", err)
	}
	if context.ContractVersion != ActivationContractVersionV2 || context.Skills[0].Manifest == nil {
		t.Fatalf("context = %+v", context)
	}

	// Tampering with any manifest field, dropping the manifest, or presenting
	// the v2 responsibilities under a v1 contract is rejected.
	tamper := func(name string, mutate func(*ActivationBundle)) {
		t.Helper()
		copy := v2FixtureBundle(t)
		mutate(&copy)
		raw, err := json.Marshal(copy)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecodeAndVerifyActivationBundle(bytes.NewReader(raw), Limits{}); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
	tamper("changed file digest", func(b *ActivationBundle) { b.Skills[0].Manifest.Files[1].Digest = digestString("other") })
	tamper("changed file size", func(b *ActivationBundle) { b.Skills[0].Manifest.Files[1].SizeBytes++ })
	tamper("unsorted files", func(b *ActivationBundle) {
		files := b.Skills[0].Manifest.Files
		files[1], files[2] = files[2], files[1]
	})
	tamper("missing SKILL.md", func(b *ActivationBundle) { b.Skills[0].Manifest.Files = b.Skills[0].Manifest.Files[1:] })
	tamper("traversal path", func(b *ActivationBundle) { b.Skills[0].Manifest.Files[2].Path = "../guide.md" })
	tamper("manifest dropped", func(b *ActivationBundle) { b.Skills[0].Manifest = nil })
	tamper("manifest digest stale", func(b *ActivationBundle) { b.Skills[0].Manifest.ManifestDigest = digestString("stale") })
	tamper("v1 contract with manifest", func(b *ActivationBundle) {
		b.ContractVersion = ActivationContractVersion
		b.HostResponsibilities = activationHostResponsibilitiesFor(ActivationContractVersion)
	})
	tamper("v2 with v1 responsibilities", func(b *ActivationBundle) {
		b.HostResponsibilities = activationHostResponsibilitiesFor(ActivationContractVersion)
	})
	tamper("unknown contract", func(b *ActivationBundle) { b.ContractVersion = "synaxis.library.activation.v3" })
}

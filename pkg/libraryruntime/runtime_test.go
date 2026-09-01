package libraryruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

type fakeHostAuthKey struct{}

type fakeHostGrantProvider struct {
	grants []string
	calls  int
}

func (provider *fakeHostGrantProvider) GrantedCapabilities(ctx context.Context, request GrantRequest) ([]string, error) {
	if subject, _ := ctx.Value(fakeHostAuthKey{}).(string); subject != "host-session-alice" {
		return nil, errors.New("missing host-authenticated session")
	}
	if request.AgentSurface.Kind != "mcp_client" || request.AgentSurface.ID != "mcpcli_alice" ||
		request.Skill.SkillID != "skill_release_notes" || request.Skill.VersionID != "version_12" || request.Skill.BindingID != "binding_client_alice" ||
		request.Tool.Tool == "" || len(request.Tool.RequiredCapabilities) == 0 {
		return nil, errors.New("host received an incomplete tool mapping")
	}
	provider.calls++
	return append([]string(nil), provider.grants...), nil
}

func TestReferenceHostFlowSelectionContextCeilingAndEvidence(t *testing.T) {
	skill := Skill{
		SkillID:      "skill_release_notes",
		SkillSlug:    "release-notes",
		SkillName:    "Release Notes",
		VersionID:    "version_12",
		Version:      12,
		Instructions: "Summarize verified changes. Do not invent deployment status.",
		Binding:      Binding{ID: "binding_client_alice", Mode: "pin", Priority: 100},
		Constraints: Constraints{
			RequestedCapabilities: []string{"repo.read", "repo.write"},
			CapabilityCeiling:     []string{"repo.read"},
		},
	}
	skill.ContentDigest = digestString(skill.Instructions)
	activation := fixtureActivation(t, []Skill{skill})
	payload, err := json.Marshal(activation)
	if err != nil {
		t.Fatalf("marshal fixture activation: %v", err)
	}

	verified, err := DecodeAndVerifyActivationBundle(bytes.NewReader(payload), Limits{})
	if err != nil {
		t.Fatalf("DecodeAndVerifyActivationBundle: %v", err)
	}
	selected, found := verified.Skill(skill.Reference())
	if !found || selected.VersionID != "version_12" || selected.ContentDigest != skill.ContentDigest {
		t.Fatalf("verified selection = %+v, found=%v; want immutable version_12 selection", selected, found)
	}
	contextValue, err := BuildContext(verified, Limits{})
	if err != nil {
		t.Fatalf("BuildContext: %v", err)
	}
	if len(contextValue.Skills) != 1 || contextValue.Skills[0].Reference != skill.Reference() {
		t.Fatalf("context selections = %+v; want exact activation tuple", contextValue.Skills)
	}
	if !strings.Contains(contextValue.Document, skill.Instructions) || !strings.Contains(contextValue.Document, activation.BundleDigest) {
		t.Fatalf("canonical context does not contain verified selection and bundle digest: %s", contextValue.Document)
	}
	repeatedContext, err := BuildContext(verified, Limits{})
	if err != nil {
		t.Fatalf("repeat BuildContext: %v", err)
	}
	if repeatedContext.Document != contextValue.Document {
		t.Fatalf("context document changed without an activation change:\nfirst=%s\nsecond=%s", contextValue.Document, repeatedContext.Document)
	}

	provider := &fakeHostGrantProvider{grants: []string{"repo.read", "repo.write", "secrets.read"}}
	interceptor := ToolInterceptor{Grants: provider}
	hostContext := context.WithValue(context.Background(), fakeHostAuthKey{}, "host-session-alice")
	readAuthorization, err := interceptor.Authorize(hostContext, verified, skill.Reference(), ToolCall{
		Tool:                 "repository.get_file",
		RequiredCapabilities: []string{"repo.read"},
	})
	if err != nil {
		t.Fatalf("Authorize(repo.read): %v", err)
	}
	if got, want := readAuthorization.EffectiveCapabilities(), []string{"repo.read"}; !sameStrings(got, want) {
		t.Fatalf("read effective capabilities=%v, want %v", got, want)
	}
	if _, err := interceptor.Authorize(hostContext, verified, skill.Reference(), ToolCall{
		Tool:                 "repository.write_file",
		RequiredCapabilities: []string{"repo.write"},
	}); !errors.Is(err, ErrToolDenied) {
		t.Fatalf("Authorize(repo.write) error=%v, want capability-ceiling denial", err)
	}
	if provider.calls != 2 {
		t.Fatalf("grant provider calls=%d, want one fresh grant lookup per tool call", provider.calls)
	}

	input := []byte(`{"path":"notes.md","secret":"must-not-appear-in-evidence"}`)
	evidence, err := readAuthorization.SkillRunEvidence(input)
	if err != nil {
		t.Fatalf("SkillRunEvidence: %v", err)
	}
	if evidence.ContractVersion != SkillRunEvidenceContractVersion || evidence.Origin != SkillRunOrigin ||
		evidence.SkillID != skill.SkillID || evidence.SkillVersionID != skill.VersionID || evidence.BindingID != skill.Binding.ID ||
		evidence.AgentSurfaceID != activation.AgentSurface.ID || evidence.ActivationBundleDigest != activation.BundleDigest ||
		evidence.InputDigest != digestBytes(input) || !sameStrings(evidence.EffectiveCapabilities, []string{"repo.read"}) {
		t.Fatalf("immutable run evidence input=%+v; want exact selected tuple and per-call capability", evidence)
	}
	encodedEvidence, err := json.Marshal(evidence)
	if err != nil {
		t.Fatalf("marshal run evidence: %v", err)
	}
	if strings.Contains(string(encodedEvidence), "must-not-appear-in-evidence") || strings.Contains(string(encodedEvidence), `"path"`) {
		t.Fatalf("run evidence leaked raw tool input: %s", encodedEvidence)
	}
	completed, err := evidence.Complete([]byte(`{"content":"release note"}`))
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if completed.OutputDigest != digestBytes([]byte(`{"content":"release note"}`)) || completed.InputDigest != evidence.InputDigest {
		t.Fatalf("completed evidence=%+v; want immutable input digest and output digest", completed)
	}
}

func TestActivationVerifierRejectsTamperedInstructionAndUnknownFields(t *testing.T) {
	skill := Skill{
		SkillID:      "skill_safe",
		SkillSlug:    "safe",
		SkillName:    "Safe",
		VersionID:    "version_1",
		Version:      1,
		Instructions: "Read only.",
		Binding:      Binding{ID: "binding_safe", Mode: "pin", Priority: 0},
		Constraints: Constraints{
			RequestedCapabilities: []string{"repo.read"},
			CapabilityCeiling:     []string{},
		},
	}
	skill.ContentDigest = digestString(skill.Instructions)
	activation := fixtureActivation(t, []Skill{skill})
	activation.Skills[0].Instructions = "Write everything."
	payload, err := json.Marshal(activation)
	if err != nil {
		t.Fatalf("marshal tampered activation: %v", err)
	}
	if _, err := DecodeAndVerifyActivationBundle(bytes.NewReader(payload), Limits{}); !errors.Is(err, ErrActivationIntegrity) {
		t.Fatalf("tampered activation error=%v, want integrity failure", err)
	}

	valid := fixtureActivation(t, []Skill{skill})
	validPayload, err := json.Marshal(valid)
	if err != nil {
		t.Fatalf("marshal valid activation: %v", err)
	}
	unknownFieldPayload := append(validPayload[:len(validPayload)-1], []byte(`,"credential":"nope"}`)...)
	if _, err := DecodeAndVerifyActivationBundle(bytes.NewReader(unknownFieldPayload), Limits{}); !errors.Is(err, ErrActivationIntegrity) {
		t.Fatalf("unknown authority-like field error=%v, want integrity failure", err)
	}
}

func fixtureActivation(t *testing.T, skills []Skill) ActivationBundle {
	t.Helper()
	activation := ActivationBundle{
		ContractVersion:      ActivationContractVersion,
		AgentSurface:         AgentSurface{Kind: "mcp_client", ID: "mcpcli_alice"},
		Skills:               cloneSkills(skills),
		AuthorityNotice:      activationAuthorityNotice,
		HostResponsibilities: append([]string(nil), activationHostResponsibilities...),
	}
	digest, err := activationDigest(activation)
	if err != nil {
		t.Fatalf("activationDigest: %v", err)
	}
	activation.BundleDigest = digest
	return activation
}

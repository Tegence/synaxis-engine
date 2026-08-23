package engine

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOpenAICompatibleSkillDraftGeneratorUsesServerSideEndpoint(t *testing.T) {
	var gotAuthorization string
	var gotRequest openAICompatibleDraftRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/chat/completions" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		gotAuthorization = r.Header.Get("Authorization")
		if err := json.NewDecoder(r.Body).Decode(&gotRequest); err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"model":"provider-model","choices":[{"message":{"role":"assistant","content":"{\"name\":\"Incident responder\",\"description\":\"Triage safely\",\"content\":\"# Triage\",\"requested_capabilities\":[\"alerts.read\"]}"}}]}`))
	}))
	defer server.Close()

	generator, err := newOpenAICompatibleSkillDraftGenerator(server.URL+"/v1", "server-only-test-key", "configured-model", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	result, err := generator.GenerateSkillDraft(context.Background(), SkillDraftGenerationRequest{
		Name: "Incident responder", Prompt: "Create a safe incident response skill.", RequestedCapabilities: []string{"alerts.read"},
	})
	if err != nil {
		t.Fatalf("GenerateSkillDraft: %v", err)
	}
	if gotAuthorization != "Bearer server-only-test-key" || gotRequest.Model != "configured-model" || result.Model != "provider-model" {
		t.Fatalf("auth=%q request=%+v result=%+v", gotAuthorization, gotRequest, result)
	}
	if result.Content != "# Triage" || len(result.RequestedCapabilities) != 1 || result.RequestedCapabilities[0] != "alerts.read" {
		t.Fatalf("result=%+v", result)
	}
}

func TestOpenAICompatibleSkillDraftGeneratorNormalizesEndpointSafely(t *testing.T) {
	for _, test := range []struct {
		name  string
		input string
		want  string
	}{
		{name: "OpenAI base", input: "https://api.example", want: "https://api.example/v1/chat/completions"},
		{name: "version base", input: "https://api.example/v1", want: "https://api.example/v1/chat/completions"},
		{name: "custom version base", input: "https://api.example/openai/v1", want: "https://api.example/openai/v1/chat/completions"},
		{name: "full endpoint", input: "https://api.example/v1/chat/completions", want: "https://api.example/v1/chat/completions"},
	} {
		t.Run(test.name, func(t *testing.T) {
			generator, err := newOpenAICompatibleSkillDraftGenerator(test.input, "key", "model", &http.Client{})
			if err != nil {
				t.Fatal(err)
			}
			if generator.endpoint != test.want {
				t.Fatalf("endpoint=%q want=%q", generator.endpoint, test.want)
			}
		})
	}
	for _, endpoint := range []string{"https://api.example/v1?mode=test", "https://user:pass@api.example/v1", "http://api.example/v1"} {
		if _, err := newOpenAICompatibleSkillDraftGenerator(endpoint, "key", "model", &http.Client{}); err == nil {
			t.Fatalf("unsafe endpoint %q was accepted", endpoint)
		}
	}
}

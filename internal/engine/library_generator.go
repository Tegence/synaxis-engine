package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	libraryDraftGenerationTimeout = 30 * time.Second
	libraryDraftResponseMaxBytes  = 1 << 20
)

// OpenAICompatibleSkillDraftGenerator calls a server-side OpenAI-compatible
// chat-completions endpoint. The API key is held only by the Engine process;
// browser requests can supply a task brief but never a provider credential.
type OpenAICompatibleSkillDraftGenerator struct {
	endpoint string
	apiKey   string
	model    string
	client   *http.Client
}

// NewOpenAICompatibleSkillDraftGenerator constructs the production generator
// seam. endpoint may be either an API base URL or a full /chat/completions
// URL. Empty values are rejected so an accidentally half-configured Engine
// never looks like it can generate a draft.
func NewOpenAICompatibleSkillDraftGenerator(endpoint, apiKey, model string) (*OpenAICompatibleSkillDraftGenerator, error) {
	return newOpenAICompatibleSkillDraftGenerator(endpoint, apiKey, model, nil)
}

func newOpenAICompatibleSkillDraftGenerator(endpoint, apiKey, model string, client *http.Client) (*OpenAICompatibleSkillDraftGenerator, error) {
	endpoint = strings.TrimRight(strings.TrimSpace(endpoint), "/")
	apiKey = strings.TrimSpace(apiKey)
	model = strings.TrimSpace(model)
	if endpoint == "" || apiKey == "" || model == "" {
		return nil, errors.New("draft generator endpoint, API key, and model are required")
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.RawFragment != "" || parsed.RawPath != "" {
		return nil, errors.New("draft generator endpoint must be an absolute URL without credentials")
	}
	if parsed.Scheme != "https" && parsed.Hostname() != "localhost" && parsed.Hostname() != "127.0.0.1" && parsed.Hostname() != "::1" {
		return nil, errors.New("draft generator endpoint must use HTTPS")
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	switch {
	case strings.HasSuffix(parsed.Path, "/chat/completions"):
		// A complete provider endpoint was supplied.
	case parsed.Path == "":
		parsed.Path = "/v1/chat/completions"
	case strings.HasSuffix(parsed.Path, "/v1"):
		parsed.Path += "/chat/completions"
	default:
		// Some compatible services use a nonstandard version prefix (for
		// example /openai/v1). Treat a path as their API base rather than
		// duplicating OpenAI's /v1 segment.
		parsed.Path += "/chat/completions"
	}
	endpoint = parsed.String()
	if client == nil {
		client = &http.Client{Timeout: libraryDraftGenerationTimeout}
	}
	return &OpenAICompatibleSkillDraftGenerator{endpoint: endpoint, apiKey: apiKey, model: model, client: client}, nil
}

func (g *OpenAICompatibleSkillDraftGenerator) GenerateSkillDraft(ctx context.Context, request SkillDraftGenerationRequest) (SkillDraftGeneration, error) {
	if g == nil || g.client == nil || g.endpoint == "" || g.apiKey == "" || g.model == "" {
		return SkillDraftGeneration{}, ErrLibraryDraftGeneratorUnavailable
	}
	if strings.TrimSpace(request.Prompt) == "" || len(request.Prompt) > libraryMaxContentBytes {
		return SkillDraftGeneration{}, errors.New("draft prompt is required and too long")
	}
	capabilities, err := normalizeLibraryCapabilities(request.RequestedCapabilities)
	if err != nil {
		return SkillDraftGeneration{}, err
	}
	payload := openAICompatibleDraftRequest{
		Model: g.model,
		Messages: []openAICompatibleMessage{
			{Role: "system", Content: "You create portable Synaxis skills. Return only one JSON object with string fields name, description, content and an array requested_capabilities. A skill is markdown instructions, not executable code. Do not claim to grant credentials, permissions, or tool access."},
			{Role: "user", Content: formatDraftGenerationPrompt(request, capabilities)},
		},
		ResponseFormat: map[string]string{"type": "json_object"},
		Temperature:    0.2,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return SkillDraftGeneration{}, fmt.Errorf("encode draft request: %w", err)
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, g.endpoint, bytes.NewReader(body))
	if err != nil {
		return SkillDraftGeneration{}, fmt.Errorf("build draft request: %w", err)
	}
	httpRequest.Header.Set("Authorization", "Bearer "+g.apiKey)
	httpRequest.Header.Set("Content-Type", "application/json")
	response, err := g.client.Do(httpRequest)
	if err != nil {
		return SkillDraftGeneration{}, fmt.Errorf("request draft generation: %w", err)
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, libraryDraftResponseMaxBytes+1))
	if err != nil {
		return SkillDraftGeneration{}, fmt.Errorf("read draft generation response: %w", err)
	}
	if len(responseBody) > libraryDraftResponseMaxBytes {
		return SkillDraftGeneration{}, errors.New("draft generation response exceeds limit")
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		// Never reflect provider payloads: they may include request IDs, policy
		// metadata, or echoed user prompts.
		return SkillDraftGeneration{}, fmt.Errorf("draft generator returned HTTP %d", response.StatusCode)
	}
	var decoded openAICompatibleDraftResponse
	if err := json.Unmarshal(responseBody, &decoded); err != nil {
		return SkillDraftGeneration{}, fmt.Errorf("decode draft generation response: %w", err)
	}
	if len(decoded.Choices) == 0 || strings.TrimSpace(decoded.Choices[0].Message.Content) == "" {
		return SkillDraftGeneration{}, errors.New("draft generator returned no candidate")
	}
	var candidate struct {
		Name                  string   `json:"name"`
		Description           string   `json:"description"`
		Content               string   `json:"content"`
		RequestedCapabilities []string `json:"requested_capabilities"`
	}
	if err := json.Unmarshal([]byte(decoded.Choices[0].Message.Content), &candidate); err != nil {
		return SkillDraftGeneration{}, errors.New("draft generator returned invalid candidate JSON")
	}
	if candidate.Name == "" {
		candidate.Name = request.Name
	}
	if candidate.Description == "" {
		candidate.Description = request.Description
	}
	if len(candidate.RequestedCapabilities) == 0 {
		candidate.RequestedCapabilities = capabilities
	}
	normalized, err := normalizeLibraryCapabilities(candidate.RequestedCapabilities)
	if err != nil {
		return SkillDraftGeneration{}, err
	}
	model := strings.TrimSpace(decoded.Model)
	if model == "" {
		model = g.model
	}
	draft := LibrarySkillDraft{
		Name: candidate.Name, Description: candidate.Description, Content: candidate.Content,
		RequestedCapabilities: normalized, Origin: LibraryDraftOriginGenerated,
		Generator: "openai-compatible", Model: model, PromptDigest: libraryDigest(request.Prompt),
	}
	if err := validateLibrarySkillDraft(draft); err != nil {
		return SkillDraftGeneration{}, err
	}
	return SkillDraftGeneration{
		Name: candidate.Name, Description: candidate.Description, Content: candidate.Content,
		RequestedCapabilities: normalized, Generator: "openai-compatible", Model: model,
	}, nil
}

func formatDraftGenerationPrompt(request SkillDraftGenerationRequest, capabilities []string) string {
	return "Create a concise portable skill.\n" +
		"Requested name: " + strings.TrimSpace(request.Name) + "\n" +
		"Requested description: " + strings.TrimSpace(request.Description) + "\n" +
		"Requested capabilities (intent only): " + strings.Join(capabilities, ", ") + "\n" +
		"Task brief:\n" + strings.TrimSpace(request.Prompt)
}

type openAICompatibleDraftRequest struct {
	Model          string                    `json:"model"`
	Messages       []openAICompatibleMessage `json:"messages"`
	ResponseFormat map[string]string         `json:"response_format,omitempty"`
	Temperature    float64                   `json:"temperature"`
}

type openAICompatibleMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openAICompatibleDraftResponse struct {
	Model   string `json:"model"`
	Choices []struct {
		Message openAICompatibleMessage `json:"message"`
	} `json:"choices"`
}

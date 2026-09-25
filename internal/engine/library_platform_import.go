package engine

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// LibraryPlatformSkillDraftImport is the narrow, provider-neutral handoff
// from a hosted control plane to its isolated Engine. It intentionally has no
// workspace, connection, tool, binding, run, artifact, or publication field:
// an import only creates an editable draft. The raw prompt and provider
// credentials never cross this boundary.
//
// RequestedCapabilities is deliberately outside Candidate. It is the caller's
// stated capability intent, not model-authored content, and remains subject to
// the normal binding/runtime intersection before a skill can ever run.
type LibraryPlatformSkillDraftImport struct {
	RequestID             string                             `json:"requestId"`
	RequestedCapabilities []string                           `json:"requestedCapabilities"`
	Candidate             LibraryPlatformSkillDraftCandidate `json:"candidate"`
}

// LibraryPlatformSkillDraftCandidate is the typed, bounded result supplied by
// a Platform-side broker after it has completed provider work. Provider and
// Model are provenance labels only; neither is an Engine configuration value.
type LibraryPlatformSkillDraftCandidate struct {
	Name         string `json:"name"`
	Description  string `json:"description"`
	Content      string `json:"content"`
	Provider     string `json:"provider"`
	Model        string `json:"model"`
	PromptDigest string `json:"promptDigest"`
	// Rationale and Assumptions are optional generator review aids. They are
	// bounded like every other candidate field and never truncated.
	Rationale   string   `json:"rationale"`
	Assumptions []string `json:"assumptions"`
}

// librarySkillDraftImportRecord retains only hashes for request idempotency.
// Request IDs are opaque caller correlation values and never need to be kept
// in plaintext by an Engine. PayloadDigest detects accidental or malicious
// reuse of a request ID for a different candidate.
type librarySkillDraftImportRecord struct {
	RequestIDHash string `json:"request_id_hash"`
	PayloadDigest string `json:"payload_digest"`
	DraftID       string `json:"draft_id"`
}

type normalizedLibraryPlatformSkillDraftImport struct {
	draft  LibrarySkillDraft
	record librarySkillDraftImportRecord
}

var (
	ErrLibraryDraftImportConflict = errors.New("library skill draft import request conflicts with an existing request")
	libraryDraftImportLabel       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@:-]{0,159}$`)
)

const libraryDraftImportRequestIDMinBytes = 16

func normalizeLibraryPlatformSkillDraftImport(
	request LibraryPlatformSkillDraftImport,
	createdBy string,
) (normalizedLibraryPlatformSkillDraftImport, error) {
	requestID := request.RequestID
	if strings.TrimSpace(requestID) != requestID {
		return normalizedLibraryPlatformSkillDraftImport{}, errors.New("platform draft import request id is invalid")
	}
	if len(requestID) < libraryDraftImportRequestIDMinBytes || !validActorIdentifier(requestID) {
		return normalizedLibraryPlatformSkillDraftImport{}, errors.New("platform draft import request id is invalid")
	}
	if err := validateLibraryOpaqueRef("created by", createdBy, false); err != nil {
		return normalizedLibraryPlatformSkillDraftImport{}, err
	}
	if !libraryDraftImportLabel.MatchString(request.Candidate.Provider) {
		return normalizedLibraryPlatformSkillDraftImport{}, errors.New("platform draft import provider is invalid")
	}
	if !libraryDraftImportLabel.MatchString(request.Candidate.Model) {
		return normalizedLibraryPlatformSkillDraftImport{}, errors.New("platform draft import model is invalid")
	}
	if err := validateLibraryDigest("prompt", request.Candidate.PromptDigest, false); err != nil {
		return normalizedLibraryPlatformSkillDraftImport{}, err
	}
	capabilities, err := normalizeLibraryCapabilities(request.RequestedCapabilities)
	if err != nil {
		return normalizedLibraryPlatformSkillDraftImport{}, err
	}
	assumptions, err := normalizeLibraryDraftAssumptions(request.Candidate.Assumptions)
	if err != nil {
		return normalizedLibraryPlatformSkillDraftImport{}, err
	}
	draft := LibrarySkillDraft{
		Name:                  request.Candidate.Name,
		Description:           request.Candidate.Description,
		Content:               request.Candidate.Content,
		RequestedCapabilities: capabilities,
		Rationale:             request.Candidate.Rationale,
		Assumptions:           assumptions,
		Origin:                LibraryDraftOriginGenerated,
		// Generator is the existing portable-draft provenance field. For a
		// Platform import it carries the provider's bounded label, never a URL
		// or credential.
		Generator:    request.Candidate.Provider,
		Model:        request.Candidate.Model,
		PromptDigest: request.Candidate.PromptDigest,
		CreatedBy:    createdBy,
	}
	if err := validateLibrarySkillDraft(draft); err != nil {
		return normalizedLibraryPlatformSkillDraftImport{}, err
	}

	// Marshal a fixed private shape after capability normalization. This makes
	// an idempotent replay insensitive to ordering/duplicates in a caller's
	// intent list while detecting every actual candidate, provenance, or actor
	// change. It intentionally excludes the raw request ID because that is the
	// separate idempotency lookup key and excludes any raw prompt by design.
	payload, err := json.Marshal(struct {
		Name                  string   `json:"name"`
		Description           string   `json:"description"`
		Content               string   `json:"content"`
		RequestedCapabilities []string `json:"requestedCapabilities"`
		Rationale             string   `json:"rationale"`
		Assumptions           []string `json:"assumptions"`
		Provider              string   `json:"provider"`
		Model                 string   `json:"model"`
		PromptDigest          string   `json:"promptDigest"`
		CreatedBy             string   `json:"createdBy"`
	}{
		Name: draft.Name, Description: draft.Description, Content: draft.Content,
		RequestedCapabilities: draft.RequestedCapabilities, Rationale: draft.Rationale, Assumptions: draft.Assumptions,
		Provider: draft.Generator, Model: draft.Model, PromptDigest: draft.PromptDigest, CreatedBy: draft.CreatedBy,
	})
	if err != nil {
		return normalizedLibraryPlatformSkillDraftImport{}, fmt.Errorf("encode platform draft import: %w", err)
	}
	return normalizedLibraryPlatformSkillDraftImport{
		draft: draft,
		record: librarySkillDraftImportRecord{
			RequestIDHash: libraryDigest(requestID),
			PayloadDigest: libraryDigest(string(payload)),
		},
	}, nil
}

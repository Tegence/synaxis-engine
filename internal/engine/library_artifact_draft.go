package engine

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// LibraryPlatformArtifactDraftImport is the output-draft counterpart of the
// skill draft handoff. Platform has already performed the provider call; the
// Engine receives only a typed, bounded candidate plus the exact immutable
// source the broker showed the model, if any. An import creates an editable
// draft and nothing else.
type LibraryPlatformArtifactDraftImport struct {
	RequestID               string                                `json:"requestId"`
	Format                  string                                `json:"format"`
	SourceArtifactID        string                                `json:"sourceArtifactId"`
	SourceArtifactVersionID string                                `json:"sourceArtifactVersionId"`
	SourceArtifactDigest    string                                `json:"sourceArtifactDigest"`
	Candidate               LibraryPlatformArtifactDraftCandidate `json:"candidate"`
}

// LibraryPlatformArtifactDraftCandidate is the broker's validated result.
// Provider and Model are provenance labels, never Engine configuration.
type LibraryPlatformArtifactDraftCandidate struct {
	Title        string   `json:"title"`
	Summary      string   `json:"summary"`
	Content      string   `json:"content"`
	Provider     string   `json:"provider"`
	Model        string   `json:"model"`
	PromptDigest string   `json:"promptDigest"`
	Rationale    string   `json:"rationale"`
	Assumptions  []string `json:"assumptions"`
}

type normalizedLibraryPlatformArtifactDraftImport struct {
	draft  LibraryArtifactDraft
	record librarySkillDraftImportRecord
}

// normalizeLibraryPlatformArtifactDraftImport applies the same request-ID,
// label, and digest rules as the skill import, then validates the candidate
// as a draft. The idempotency payload covers every candidate, source, and
// actor field so a reused request ID with different content conflicts.
func normalizeLibraryPlatformArtifactDraftImport(
	request LibraryPlatformArtifactDraftImport,
	createdBy string,
) (normalizedLibraryPlatformArtifactDraftImport, error) {
	requestID := request.RequestID
	if strings.TrimSpace(requestID) != requestID {
		return normalizedLibraryPlatformArtifactDraftImport{}, errors.New("platform draft import request id is invalid")
	}
	if len(requestID) < libraryDraftImportRequestIDMinBytes || !validActorIdentifier(requestID) {
		return normalizedLibraryPlatformArtifactDraftImport{}, errors.New("platform draft import request id is invalid")
	}
	if err := validateLibraryOpaqueRef("created by", createdBy, false); err != nil {
		return normalizedLibraryPlatformArtifactDraftImport{}, err
	}
	if !libraryDraftImportLabel.MatchString(request.Candidate.Provider) {
		return normalizedLibraryPlatformArtifactDraftImport{}, errors.New("platform draft import provider is invalid")
	}
	if !libraryDraftImportLabel.MatchString(request.Candidate.Model) {
		return normalizedLibraryPlatformArtifactDraftImport{}, errors.New("platform draft import model is invalid")
	}
	if err := validateLibraryDigest("prompt", request.Candidate.PromptDigest, false); err != nil {
		return normalizedLibraryPlatformArtifactDraftImport{}, err
	}
	format := request.Format
	if format == "" {
		format = LibraryArtifactFormatMarkdown
	}
	draft, err := normalizedLibraryArtifactDraft(LibraryArtifactDraft{
		Title:                   request.Candidate.Title,
		Summary:                 request.Candidate.Summary,
		Content:                 request.Candidate.Content,
		Format:                  format,
		Rationale:               request.Candidate.Rationale,
		Assumptions:             request.Candidate.Assumptions,
		Origin:                  LibraryDraftOriginGenerated,
		Generator:               request.Candidate.Provider,
		Model:                   request.Candidate.Model,
		PromptDigest:            request.Candidate.PromptDigest,
		SourceArtifactID:        request.SourceArtifactID,
		SourceArtifactVersionID: request.SourceArtifactVersionID,
		// Platform may spell the digest with a "sha256:" prefix; the stored
		// citation always uses the bare hex form the Engine compares against.
		SourceArtifactDigest: normalizeLibraryDigestInput(request.SourceArtifactDigest),
		CreatedBy:            createdBy,
	})
	if err != nil {
		return normalizedLibraryPlatformArtifactDraftImport{}, err
	}

	payload, err := json.Marshal(struct {
		Title                   string   `json:"title"`
		Summary                 string   `json:"summary"`
		Content                 string   `json:"content"`
		Format                  string   `json:"format"`
		Rationale               string   `json:"rationale"`
		Assumptions             []string `json:"assumptions"`
		Provider                string   `json:"provider"`
		Model                   string   `json:"model"`
		PromptDigest            string   `json:"promptDigest"`
		SourceArtifactID        string   `json:"sourceArtifactId"`
		SourceArtifactVersionID string   `json:"sourceArtifactVersionId"`
		SourceArtifactDigest    string   `json:"sourceArtifactDigest"`
		CreatedBy               string   `json:"createdBy"`
	}{
		Title: draft.Title, Summary: draft.Summary, Content: draft.Content, Format: draft.Format,
		Rationale: draft.Rationale, Assumptions: draft.Assumptions,
		Provider: draft.Generator, Model: draft.Model, PromptDigest: draft.PromptDigest,
		SourceArtifactID: draft.SourceArtifactID, SourceArtifactVersionID: draft.SourceArtifactVersionID,
		SourceArtifactDigest: draft.SourceArtifactDigest, CreatedBy: draft.CreatedBy,
	})
	if err != nil {
		return normalizedLibraryPlatformArtifactDraftImport{}, fmt.Errorf("encode platform artifact draft import: %w", err)
	}
	return normalizedLibraryPlatformArtifactDraftImport{
		draft: draft,
		record: librarySkillDraftImportRecord{
			RequestIDHash: libraryDigest(requestID),
			PayloadDigest: libraryDigest(string(payload)),
		},
	}, nil
}

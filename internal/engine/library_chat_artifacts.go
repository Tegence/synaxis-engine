package engine

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

const (
	LibraryContentArtifact       = "artifact"
	LibraryContentChatReply      = "chat_reply"
	libraryChatArtifactsMax      = 32
	libraryChatClassificationMax = 100
)

// These references are immutable content identities, never user-supplied URLs.
type LibraryChatArtifactRef struct {
	ArtifactID        string `json:"artifactId"`
	ArtifactVersionID string `json:"artifactVersionId"`
	Digest            string `json:"digest"`
}
type LibraryChatArtifactCard struct {
	LibraryChatArtifactRef
	Title  string `json:"title"`
	Format string `json:"format"`
}
type LibraryChatReplyReference struct {
	ArtifactID        string `json:"artifactId"`
	ArtifactVersionID string `json:"artifactVersionId"`
	AgentSurfaceID    string `json:"agentSurfaceId"`
	Subject           string `json:"subject"`
}
type LibraryChatSaveRequest struct {
	LibraryChatReplyReference
	Title string `json:"title"`
}
type LibraryChatSaveResult struct {
	Artifact LibraryChatArtifactCard `json:"artifact"`
	Replayed bool                    `json:"replayed"`
}
type libraryChatSaveRecord struct {
	SourceArtifactID  string `json:"sourceArtifactId"`
	SourceVersionID   string `json:"sourceVersionId"`
	ArtifactID        string `json:"artifactId"`
	ArtifactVersionID string `json:"artifactVersionId"`
}

// Hosting-only classification and copy operations do not grant library access.
// Their callers supply authoritative run references; stores recheck ownership.
type LibraryChatArtifactStore interface {
	ClassifyLibraryChatReplies(context.Context, []LibraryChatReplyReference) (int, error)
	SaveLibraryChatReply(context.Context, LibraryChatSaveRequest) (LibraryChatSaveResult, error)
	LibraryChatArtifactCards(context.Context, string, string, []string) ([]LibraryChatArtifactCard, *LibraryChatArtifactCard, error)
}

func nonNilLibraryChatRefs(refs []LibraryChatArtifactRef) []LibraryChatArtifactRef {
	if refs == nil {
		return []LibraryChatArtifactRef{}
	}
	return refs
}

func libraryContentKind(kind string) string {
	if kind == "" {
		return LibraryContentArtifact
	}
	return kind
}
func validateLibraryChatArtifactFields(artifact LibraryArtifact) error {
	if artifact.ContentKind != "" && artifact.ContentKind != LibraryContentArtifact && artifact.ContentKind != LibraryContentChatReply {
		return errors.New("invalid artifact content kind")
	}
	if artifact.ContentKind == LibraryContentChatReply && artifact.Origin != LibraryArtifactOriginAgentDirect {
		return errors.New("chat replies require agent provenance")
	}
	if len(artifact.LinkedArtifacts) > libraryChatArtifactsMax || (len(artifact.LinkedArtifacts) > 0 && artifact.ContentKind != LibraryContentChatReply) {
		return errors.New("invalid linked artifacts")
	}
	seen := map[string]bool{}
	for _, ref := range artifact.LinkedArtifacts {
		if err := validateLibraryOpaqueRef("linked artifact", ref.ArtifactID, false); err != nil {
			return err
		}
		if err := validateLibraryOpaqueRef("linked version", ref.ArtifactVersionID, false); err != nil {
			return err
		}
		if err := validateLibraryDigest("linked artifact", ref.Digest, false); err != nil {
			return err
		}
		if seen[ref.ArtifactVersionID] {
			return errors.New("duplicate linked artifact version")
		}
		seen[ref.ArtifactVersionID] = true
	}
	return nil
}
func validateLibraryChatReplyReference(ref LibraryChatReplyReference) error {
	for label, id := range map[string]string{"artifact": ref.ArtifactID, "artifact version": ref.ArtifactVersionID, "agent surface": ref.AgentSurfaceID, "subject": ref.Subject} {
		if err := validateLibraryOpaqueRef(label, id, false); err != nil {
			return err
		}
	}
	return nil
}
func validateLibraryChatClassification(refs []LibraryChatReplyReference) error {
	if len(refs) == 0 || len(refs) > libraryChatClassificationMax {
		return fmt.Errorf("expected 1 to %d reply references", libraryChatClassificationMax)
	}
	for _, ref := range refs {
		if err := validateLibraryChatReplyReference(ref); err != nil {
			return err
		}
	}
	return nil
}
func validateLibraryChatSave(request LibraryChatSaveRequest) error {
	if err := validateLibraryChatReplyReference(request.LibraryChatReplyReference); err != nil {
		return err
	}
	return validateLibraryArtifact(LibraryArtifact{Title: strings.TrimSpace(request.Title), Origin: LibraryArtifactOriginAgentDirect, ContentKind: LibraryContentArtifact})
}
func libraryChatSourceMatches(artifact LibraryArtifact, version LibraryArtifactVersion, client MCPClient, ref LibraryChatReplyReference) bool {
	return artifact.ID == ref.ArtifactID && version.ArtifactID == artifact.ID && version.ID == ref.ArtifactVersionID &&
		artifact.AgentSurfaceID == ref.AgentSurfaceID && artifact.AgentSurfaceID == client.ID && artifact.CreatedBy == ref.Subject && client.Subject == ref.Subject &&
		artifact.Origin == LibraryArtifactOriginAgentDirect && artifact.RunID != "" && (version.Format == LibraryArtifactFormatMarkdown || version.Format == LibraryArtifactFormatText)
}
func libraryChatCard(artifact LibraryArtifact, version LibraryArtifactVersion) LibraryChatArtifactCard {
	return LibraryChatArtifactCard{LibraryChatArtifactRef: LibraryChatArtifactRef{ArtifactID: artifact.ID, ArtifactVersionID: version.ID, Digest: version.Digest}, Title: artifact.Title, Format: version.Format}
}
func prepareLibraryChatCopy(client MCPClient, source LibraryArtifact, version LibraryArtifactVersion, title string) (LibraryRun, LibraryArtifact, LibraryArtifactVersion, error) {
	return prepareLibraryMCPClientArtifact(client, LibraryArtifact{Title: strings.TrimSpace(title), Origin: LibraryArtifactOriginAgentDirect, ContentKind: LibraryContentArtifact,
		SourceArtifactID: source.ID, SourceArtifactVersionID: version.ID, SourceArtifactDigest: version.Digest}, LibraryArtifactVersion{Format: version.Format, Body: version.Body})
}

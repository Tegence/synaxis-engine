package engine

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode/utf8"
)

var (
	ErrCollaborationUnavailable = errors.New("collaboration access is unavailable")
	ErrCollaborationForbidden   = errors.New("this role cannot perform that action")
	ErrCollaborationConflict    = errors.New("the output changed; read the latest version before saving")
	ErrCollaborationInvalid     = errors.New("invalid collaboration request")
	ErrCollaborationCapacity    = errors.New("this output has reached its collaboration limit")
)

// Collaboration is separate from a pinned LibraryArtifactGrant. Its authority
// explicitly includes the current and future versions of exactly one output.
type LibraryCollaborationGrant struct {
	ID         string     `json:"id"`
	ArtifactID string     `json:"artifactId"`
	Kind       string     `json:"kind"` // subject, client, guest, external_agent
	Recipient  string     `json:"recipient,omitempty"`
	Label      string     `json:"label"`
	Role       string     `json:"role"` // view, comment, edit
	ExpiresAt  *time.Time `json:"expiresAt,omitempty"`
	CreatedAt  time.Time  `json:"createdAt"`
	RevokedAt  *time.Time `json:"revokedAt,omitempty"`
}

type libraryCollaborationGrantRecord struct {
	LibraryCollaborationGrant
	TokenHash   string `json:"tokenHash,omitempty"`
	ClientEpoch string `json:"clientEpoch,omitempty"`
	CreatedBy   string `json:"createdBy"`
	RevokedBy   string `json:"revokedBy,omitempty"`
}

type LibraryCollaborationComment struct {
	ID         string    `json:"id"`
	Author     string    `json:"author"`
	AuthorKind string    `json:"authorKind"`
	Body       string    `json:"body"`
	CreatedAt  time.Time `json:"createdAt"`
}

type LibraryCollaborationThread struct {
	ID         string                        `json:"id"`
	VersionID  string                        `json:"versionId"`
	Version    int                           `json:"version"`
	Quote      string                        `json:"quote,omitempty"`
	Comments   []LibraryCollaborationComment `json:"comments"`
	ResolvedAt *time.Time                    `json:"resolvedAt,omitempty"`
	ResolvedBy string                        `json:"resolvedBy,omitempty"`
}

// Actor is supplied only by authenticated ingress, never a request body.
// A capability actor supplies a grant ID and token, not a trusted identity.
type LibraryCollaborationActor struct {
	Kind    string
	Ref     string
	Epoch   string
	Subject string
	Token   string
}

type LibraryCollaborationRequest struct {
	Operation      string     `json:"operation"`
	ArtifactID     string     `json:"artifactId,omitempty"`
	GrantID        string     `json:"grantId,omitempty"`
	Kind           string     `json:"kind,omitempty"`
	Recipient      string     `json:"recipient,omitempty"`
	Label          string     `json:"label,omitempty"`
	Role           string     `json:"role,omitempty"`
	ExpiresAt      *time.Time `json:"expiresAt,omitempty"`
	RequestID      string     `json:"requestId,omitempty"`
	VersionID      string     `json:"versionId,omitempty"`
	ExpectedDigest string     `json:"expectedDigest,omitempty"`
	ThreadID       string     `json:"threadId,omitempty"`
	Quote          string     `json:"quote,omitempty"`
	Body           string     `json:"body,omitempty"`
	Resolved       bool       `json:"resolved,omitempty"`
}

type LibraryCollaborationResult struct {
	ArtifactID string                       `json:"artifactId"`
	Title      string                       `json:"title,omitempty"`
	Role       string                       `json:"role"`
	ExpiresAt  *time.Time                   `json:"expiresAt,omitempty"`
	Version    *LibraryArtifactVersion      `json:"version,omitempty"`
	Threads    []LibraryCollaborationThread `json:"threads,omitempty"`
	Grants     []LibraryCollaborationGrant  `json:"grants,omitempty"`
	Grant      *LibraryCollaborationGrant   `json:"grant,omitempty"`
	Token      string                       `json:"token,omitempty"`
	Replayed   bool                         `json:"replayed,omitempty"`
}

type LibraryCollaborationSummary struct {
	ArtifactID string     `json:"artifactId"`
	Title      string     `json:"title"`
	Role       string     `json:"role"`
	ExpiresAt  *time.Time `json:"expiresAt,omitempty"`
}

type LibraryCollaborationStore interface {
	Collaborate(context.Context, LibraryCollaborationActor, LibraryCollaborationRequest) (LibraryCollaborationResult, error)
	CollaborationArtifacts(context.Context, LibraryCollaborationActor) ([]LibraryCollaborationSummary, error)
}

type libraryCollaborationReceipt struct {
	Key       string `json:"key"`
	Digest    string `json:"digest"`
	VersionID string `json:"versionId,omitempty"`
}

type libraryCollaborationState struct {
	Grants   []libraryCollaborationGrantRecord `json:"grants"`
	Threads  []LibraryCollaborationThread      `json:"threads"`
	Receipts []libraryCollaborationReceipt     `json:"receipts"`
}

func collaborationHash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
func collaborationPrincipal(a LibraryCollaborationActor) string {
	return collaborationHash(a.Kind + "\x00" + a.Ref)
}
func collaborationRole(role string) int {
	switch role {
	case "view":
		return 1
	case "comment":
		return 2
	case "edit":
		return 3
	case "admin":
		return 4
	}
	return 0
}
func collaborationActive(g LibraryCollaborationGrant, now time.Time) bool {
	return g.RevokedAt == nil && (g.ExpiresAt == nil || now.Before(*g.ExpiresAt))
}
func collaborationText(s string, max int) bool {
	return strings.TrimSpace(s) != "" && len(s) <= max && utf8.ValidString(s) && !strings.ContainsRune(s, '\x00')
}

func collaborationAccess(state libraryCollaborationState, a LibraryCollaborationActor, now time.Time) (string, string, *time.Time, bool) {
	if a.Kind == "admin" && a.Ref != "" {
		return "admin", a.Ref, nil, true
	}
	var selected *LibraryCollaborationGrant
	for i := range state.Grants {
		g := &state.Grants[i]
		if !collaborationActive(g.LibraryCollaborationGrant, now) {
			continue
		}
		matches := g.Kind == a.Kind && g.Recipient == a.Ref && a.Ref != ""
		if a.Kind == "client" {
			matches = matches && g.ClientEpoch == a.Epoch
		}
		if a.Kind == "capability" {
			matches = (g.Kind == "guest" || g.Kind == "external_agent") && g.ID == a.Ref && len(a.Token) == 43 && subtle.ConstantTimeCompare([]byte(g.TokenHash), []byte(collaborationHash(a.Token))) == 1
		}
		if matches && (selected == nil || collaborationRole(g.Role) > collaborationRole(selected.Role)) {
			selected = &g.LibraryCollaborationGrant
		}
	}
	if selected == nil {
		return "", "", nil, false
	}
	author := selected.Label
	return selected.Role, author, selected.ExpiresAt, true
}

// applyCollaboration runs with the source artifact and live client locked in
// either store. It returns a new immutable version for the adapter to commit
// alongside discussion/access changes. No caller can advance a public snapshot.
func applyCollaboration(state *libraryCollaborationState, artifact LibraryArtifact, versions []LibraryArtifactVersion, actor LibraryCollaborationActor, req LibraryCollaborationRequest, now time.Time) (LibraryCollaborationResult, *LibraryArtifactVersion, bool, error) {
	result := LibraryCollaborationResult{ArtifactID: artifact.ID}
	role, author, expires, ok := collaborationAccess(*state, actor, now)
	if !ok {
		return result, nil, false, ErrCollaborationUnavailable
	}
	result.Role, result.ExpiresAt = role, expires
	head := libraryArtifactHead(versions)
	if head == nil {
		return result, nil, false, ErrCollaborationUnavailable
	}
	// Media revisions use their canonical image path; collaboration never treats
	// a blob locator as text. Text and Markdown cover the collaboration editor.
	if head.Format != LibraryArtifactFormatText && head.Format != LibraryArtifactFormatMarkdown {
		return result, nil, false, ErrLibraryArtifactFormatMismatch
	}
	result.Title = artifact.Title
	if req.Operation == "read" {
		v := *head
		v.ReviewComment = ""
		v.ReviewedBy = ""
		v.CreatedBy = ""
		v.Provenance = nil
		result.Version = &v
		result.Threads = state.Threads
		return result, nil, false, nil
	}
	if req.Operation == "grants" || req.Operation == "grant" || req.Operation == "revoke" {
		if role != "admin" {
			return result, nil, false, ErrCollaborationForbidden
		}
		if req.Operation == "grants" {
			result.Grants = make([]LibraryCollaborationGrant, 0, len(state.Grants))
			for _, g := range state.Grants {
				result.Grants = append(result.Grants, g.LibraryCollaborationGrant)
			}
			return result, nil, false, nil
		}
		if req.Operation == "revoke" {
			for i := range state.Grants {
				g := &state.Grants[i]
				if g.ID != req.GrantID {
					continue
				}
				if g.RevokedAt == nil {
					g.RevokedAt = &now
					g.RevokedBy = author
				}
				result.Grant = &g.LibraryCollaborationGrant
				return result, nil, true, nil
			}
			return result, nil, false, ErrCollaborationUnavailable
		}
		if len(state.Grants) >= 256 {
			return result, nil, false, ErrCollaborationCapacity
		}
		if collaborationRole(req.Role) < 1 || collaborationRole(req.Role) > 3 || !collaborationText(req.Label, 160) || (req.ExpiresAt != nil && !req.ExpiresAt.After(now)) {
			return result, nil, false, ErrCollaborationInvalid
		}
		switch req.Kind {
		case "subject", "client":
			if validateLibraryOpaqueRef("recipient", req.Recipient, false) != nil {
				return result, nil, false, ErrCollaborationInvalid
			}
		case "guest", "external_agent":
			if req.Recipient != "" {
				return result, nil, false, ErrCollaborationInvalid
			}
		default:
			return result, nil, false, ErrCollaborationInvalid
		}
		for _, g := range state.Grants {
			if req.Recipient != "" && g.Kind == req.Kind && g.Recipient == req.Recipient && collaborationActive(g.LibraryCollaborationGrant, now) {
				return result, nil, false, ErrCollaborationConflict
			}
		}
		g := libraryCollaborationGrantRecord{LibraryCollaborationGrant: LibraryCollaborationGrant{ID: "libcol_" + newEpoch(), ArtifactID: artifact.ID, Kind: req.Kind, Recipient: req.Recipient, Label: strings.TrimSpace(req.Label), Role: req.Role, ExpiresAt: req.ExpiresAt, CreatedAt: now}, CreatedBy: author}
		if req.Kind == "guest" || req.Kind == "external_agent" {
			raw := make([]byte, 32)
			if _, err := rand.Read(raw); err != nil {
				return result, nil, false, err
			}
			result.Token = base64.RawURLEncoding.EncodeToString(raw)
			g.TokenHash = collaborationHash(result.Token)
		}
		state.Grants = append(state.Grants, g)
		result.Grant = &g.LibraryCollaborationGrant
		return result, nil, true, nil
	}
	minimum := 2
	if req.Operation == "edit" || req.Operation == "resolve" {
		minimum = 3
	}
	if collaborationRole(role) < minimum {
		return result, nil, false, ErrCollaborationForbidden
	}
	if !validLibraryMCPClientArtifactVersionRequestID(req.RequestID) {
		return result, nil, false, ErrCollaborationInvalid
	}
	encoded, _ := json.Marshal(req)
	digest := collaborationHash(string(encoded))
	key := collaborationHash(actor.Kind + "\x00" + actor.Ref + "\x00" + req.RequestID)
	for _, receipt := range state.Receipts {
		if receipt.Key != key {
			continue
		}
		if receipt.Digest != digest {
			return result, nil, false, ErrCollaborationConflict
		}
		result.Replayed = true
		if receipt.VersionID != "" {
			for _, v := range versions {
				if v.ID == receipt.VersionID {
					v.ReviewComment = ""
					v.ReviewedBy = ""
					v.CreatedBy = ""
					v.Provenance = nil
					result.Version = &v
					break
				}
			}
		}
		return result, nil, false, nil
	}
	if len(state.Receipts) >= 4096 {
		return result, nil, false, ErrCollaborationCapacity
	}
	var newVersion *LibraryArtifactVersion
	switch req.Operation {
	case "comment":
		if len(state.Threads) >= 500 || !collaborationText(req.Body, 4096) || len(req.Quote) > 2048 || !utf8.ValidString(req.Quote) {
			return result, nil, false, ErrCollaborationInvalid
		}
		var anchor *LibraryArtifactVersion
		for i := range versions {
			if versions[i].ID == req.VersionID {
				anchor = &versions[i]
				break
			}
		}
		if anchor == nil || (req.Quote != "" && !strings.Contains(anchor.Body, req.Quote)) {
			return result, nil, false, ErrCollaborationInvalid
		}
		state.Threads = append(state.Threads, LibraryCollaborationThread{ID: "libcth_" + newEpoch(), VersionID: anchor.ID, Version: anchor.Version, Quote: req.Quote, Comments: []LibraryCollaborationComment{{ID: "libcom_" + newEpoch(), Author: author, AuthorKind: collaborationAuthorKind(*state, actor), Body: strings.TrimSpace(req.Body), CreatedAt: now}}})
	case "reply", "resolve":
		var thread *LibraryCollaborationThread
		for i := range state.Threads {
			if state.Threads[i].ID == req.ThreadID {
				thread = &state.Threads[i]
				break
			}
		}
		if thread == nil {
			return result, nil, false, ErrCollaborationUnavailable
		}
		if req.Operation == "reply" {
			if len(thread.Comments) >= 100 || !collaborationText(req.Body, 4096) {
				return result, nil, false, ErrCollaborationInvalid
			}
			thread.Comments = append(thread.Comments, LibraryCollaborationComment{ID: "libcom_" + newEpoch(), Author: author, AuthorKind: collaborationAuthorKind(*state, actor), Body: strings.TrimSpace(req.Body), CreatedAt: now})
		} else {
			thread.ResolvedAt = nil
			thread.ResolvedBy = ""
			if req.Resolved {
				thread.ResolvedAt = &now
				thread.ResolvedBy = author
			}
		}
	case "edit":
		if req.VersionID != head.ID || req.ExpectedDigest != head.Digest {
			return result, nil, false, ErrCollaborationConflict
		}
		v, err := normalizedLibraryArtifactVersion(LibraryArtifactVersion{ID: newLibraryArtifactVersionID(), ArtifactID: artifact.ID, Version: head.Version + 1, Format: head.Format, Body: req.Body, CreatedBy: actor.Kind + ":" + actor.Ref, Changelog: "Edited through collaboration by " + author, CreatedAt: now})
		if err != nil {
			return result, nil, false, ErrCollaborationInvalid
		}
		newVersion = &v
		display := copyLibraryArtifactVersion(v)
		display.CreatedBy = ""
		result.Version = &display
	default:
		return result, nil, false, ErrCollaborationInvalid
	}
	receipt := libraryCollaborationReceipt{Key: key, Digest: digest}
	if newVersion != nil {
		receipt.VersionID = newVersion.ID
	}
	state.Receipts = append(state.Receipts, receipt)
	return result, newVersion, true, nil
}

func collaborationAuthorKind(state libraryCollaborationState, actor LibraryCollaborationActor) string {
	if actor.Kind == "capability" {
		for _, g := range state.Grants {
			if g.ID == actor.Ref {
				return g.Kind
			}
		}
	}
	return actor.Kind
}
func cloneCollaborationState(state *libraryCollaborationState) libraryCollaborationState {
	var copy libraryCollaborationState
	if state != nil {
		b, _ := json.Marshal(state)
		_ = json.Unmarshal(b, &copy)
	}
	return copy
}
func collaborationClientValid(client MCPClient, actor LibraryCollaborationActor) bool {
	return client.Status == MCPClientStatusActive && client.Epoch != "" && client.Epoch == actor.Epoch && client.Subject != "" && client.Subject == actor.Subject && client.OAuthClientID != ""
}

// A collaboration operation needs only the head, its anchor, and a saved replay
// version. Avoid materializing an artifact's entire history on every guest read.
func collaborationVersionIDs(state libraryCollaborationState, actor LibraryCollaborationActor, req LibraryCollaborationRequest) []string {
	ids := make([]string, 0, 2)
	if req.VersionID != "" {
		ids = append(ids, req.VersionID)
	}
	key := collaborationHash(actor.Kind + "\x00" + actor.Ref + "\x00" + req.RequestID)
	for _, receipt := range state.Receipts {
		if receipt.Key == key && receipt.VersionID != "" && receipt.VersionID != req.VersionID {
			ids = append(ids, receipt.VersionID)
			break
		}
	}
	return ids
}

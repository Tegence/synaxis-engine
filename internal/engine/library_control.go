package engine

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// The control-plane artifact projection serves the subject-scoped Library
// routes under /control/v1/library. It is a metadata-only view: it carries the
// opaque agent-surface projection key so a hosting control plane can map an
// artifact to one of its subject-bound registrations, but it never includes an
// immutable version body. Bodies stay behind the separately authorized
// exact-version read.
const (
	libraryControlArtifactPageMax = 50

	LibraryControlArtifactAccessOwned   = "owned"
	LibraryControlArtifactAccessGranted = "granted"
)

// LibraryControlArtifactScope selects the artifacts one control page covers.
type LibraryControlArtifactScope struct {
	// AgentSurfaceIDs limits the page to artifacts owned by, or delegated by an
	// active exact-version grant to, these agent surfaces (subject-bound MCP
	// clients). An empty set selects nothing.
	AgentSurfaceIDs []string
	// Everything lists the whole catalog. It is a separate explicit switch so a
	// subject with no active registrations can never widen into the full
	// catalog through an empty surface set.
	Everything bool
}

// LibraryControlArtifactCursor is a keyset position over the artifact's
// update time (the newest immutable version's creation time) and ID. Stores
// validate the pair independently of the opaque wire token.
type LibraryControlArtifactCursor struct {
	UpdatedAt time.Time
	ID        string
}

// LibraryControlArtifact is one row of the control projection.
type LibraryControlArtifact struct {
	// Artifact is the metadata projection plus AgentSurfaceID. Provenance and
	// actor references are stripped exactly as in the other list projections.
	Artifact LibraryArtifact
	// Access is "owned" or "granted" relative to the scope's surfaces, and
	// empty on an unscoped page.
	Access string
	// LatestVersion is metadata only; its Body is always empty.
	LatestVersion LibraryArtifactVersion
	// GrantedVersion is the exact pinned version metadata when Access is
	// "granted". A grant never means "latest".
	GrantedVersion *LibraryArtifactVersion
	// UpdatedAt is the newest immutable version's creation time. Appending a
	// version moves the artifact to the top of the page.
	UpdatedAt time.Time
}

type LibraryControlArtifactPage struct {
	Artifacts  []LibraryControlArtifact
	NextCursor LibraryControlArtifactCursor
}

// LibraryControlArtifactStore is the narrow read facet behind
// GET /control/v1/library/artifacts. It is kept out of LibraryStore so the
// self-hosted console and MCP surfaces never gain a projection that exposes
// the agent-surface key.
type LibraryControlArtifactStore interface {
	// LibraryControlArtifactPage returns up to limit artifacts newest-updated
	// first, starting strictly after the cursor position, restricted to the
	// scope. When one of the scope's surfaces owns an artifact and another
	// holds a grant to it, the row reports "owned"; among several grants the
	// highest pinned version wins.
	LibraryControlArtifactPage(context.Context, LibraryControlArtifactScope, LibraryControlArtifactCursor, int) (LibraryControlArtifactPage, error)
}

func normalizeLibraryControlArtifactScope(scope LibraryControlArtifactScope) (LibraryControlArtifactScope, error) {
	if scope.Everything {
		if len(scope.AgentSurfaceIDs) != 0 {
			return LibraryControlArtifactScope{}, errors.New("a control artifact scope is either every artifact or a surface set")
		}
		return LibraryControlArtifactScope{Everything: true}, nil
	}
	seen := make(map[string]struct{}, len(scope.AgentSurfaceIDs))
	ids := make([]string, 0, len(scope.AgentSurfaceIDs))
	for _, id := range scope.AgentSurfaceIDs {
		id = strings.TrimSpace(id)
		if err := validateLibraryOpaqueRef("agent surface", id, false); err != nil {
			return LibraryControlArtifactScope{}, err
		}
		if _, duplicate := seen[id]; duplicate {
			continue
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return LibraryControlArtifactScope{AgentSurfaceIDs: ids}, nil
}

func validateLibraryControlArtifactCursor(cursor LibraryControlArtifactCursor) error {
	if cursor.UpdatedAt.IsZero() != (cursor.ID == "") {
		return errors.New("invalid control artifact page cursor")
	}
	if cursor.ID != "" {
		if err := validateLibraryOpaqueRef("control artifact page cursor", cursor.ID, false); err != nil {
			return err
		}
	}
	return nil
}

func normalizeLibraryControlArtifactPageLimit(limit int) (int, error) {
	if limit == 0 {
		return libraryControlArtifactPageMax, nil
	}
	if limit < 0 || limit > libraryControlArtifactPageMax {
		return 0, fmt.Errorf("control artifact page limit must be between 1 and %d", libraryControlArtifactPageMax)
	}
	return limit, nil
}

// libraryControlArtifactMetadata is the list projection plus the structural
// agent-surface key. It is the only projection that carries that key; every
// non-control DTO keeps omitting it.
func libraryControlArtifactMetadata(artifact LibraryArtifact) LibraryArtifact {
	metadata := libraryArtifactMetadata(artifact)
	metadata.AgentSurfaceID = artifact.AgentSurfaceID
	return metadata
}

func libraryControlArtifactAfter(cursor LibraryControlArtifactCursor, item LibraryControlArtifact) bool {
	if cursor.ID == "" {
		return true
	}
	return item.UpdatedAt.Before(cursor.UpdatedAt) || (item.UpdatedAt.Equal(cursor.UpdatedAt) && item.Artifact.ID < cursor.ID)
}

func sortLibraryControlArtifacts(items []LibraryControlArtifact) {
	sort.Slice(items, func(i, j int) bool {
		if !items[i].UpdatedAt.Equal(items[j].UpdatedAt) {
			return items[i].UpdatedAt.After(items[j].UpdatedAt)
		}
		return items[i].Artifact.ID > items[j].Artifact.ID
	})
}

// finishLibraryControlArtifactPage truncates an over-fetched, sorted slice to
// the page limit and derives the continuation cursor from the last row kept.
func finishLibraryControlArtifactPage(items []LibraryControlArtifact, limit int) LibraryControlArtifactPage {
	page := LibraryControlArtifactPage{Artifacts: items}
	if len(items) > limit {
		last := items[limit-1]
		page.NextCursor = LibraryControlArtifactCursor{UpdatedAt: last.UpdatedAt, ID: last.Artifact.ID}
		page.Artifacts = items[:limit]
	}
	if page.Artifacts == nil {
		page.Artifacts = []LibraryControlArtifact{}
	}
	return page
}

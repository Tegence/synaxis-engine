package engine

import (
	"context"
	"fmt"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
)

// syncSkillSource fetches the source's current state, upserts a Skill row
// per discovered file, creates a new SkillVersion for any file whose content
// digest changed since the last sync, prunes skills whose file disappeared,
// and recomputes drift for every skill under the source against the live
// tool set. It never returns a *fatal* error for a single skill going bad —
// mirroring the gateway's "one bad account is skipped, never fatal"
// tolerance — but it does return an error if the fetch itself fails, since
// without a fetch there is nothing to reconcile.
func syncSkillSource(ctx context.Context, store SkillStore, gw *Gateway, fetcher SkillSourceFetcher, src SkillSource) (SkillSource, error) {
	commit, author, files, err := fetcher.Fetch(ctx, src.URL, src.Token, src.Branch, src.Path)
	if err != nil {
		syncErr := err.Error()
		_ = store.UpdateSkillSourceSync(ctx, src.ID, time.Now().UTC(), src.LastSyncCommit, syncErr)
		src.LastSyncError = syncErr
		return src, err
	}

	live := gw.skillLiveTools()
	now := time.Now().UTC()
	keepIDs := make([]string, 0, len(files))
	for _, file := range files {
		sk, err := store.UpsertSkill(ctx, Skill{
			SourceID: src.ID,
			Name:     skillNameFromPath(file.Path),
			Path:     file.Path,
		})
		if err != nil {
			// One bad file must not fail the whole sync.
			continue
		}
		keepIDs = append(keepIDs, sk.ID)
		_ = syncSkillVersion(ctx, store, live, sk, file, commit, author, now)
		_ = refreshSkillDrift(ctx, store, live, sk.ID, now)
	}
	if err := store.PruneSkills(ctx, src.ID, keepIDs); err != nil {
		return src, fmt.Errorf("prune removed skills: %w", err)
	}

	if err := store.UpdateSkillSourceSync(ctx, src.ID, now, commit, ""); err != nil {
		return src, err
	}
	src.LastSyncedAt, src.LastSyncCommit, src.LastSyncError = now, commit, ""
	return src, nil
}

// syncSkillVersion creates a new SkillVersion only when the file's content
// actually changed since the last synced version (digest comparison) — a
// re-sync of an unchanged file is a no-op, not a fresh "vN".
func syncSkillVersion(ctx context.Context, store SkillStore, live map[string]mcp.Tool, sk Skill, file SkillFile, commit, author string, now time.Time) error {
	digest := digestContent(file.Content)
	nextVersion := 1
	if latest, ok := store.LatestSkillVersion(ctx, sk.ID); ok {
		if latest.Digest == digest {
			return nil // unchanged content, nothing to publish
		}
		nextVersion = latest.Version + 1
	}

	manifest, _ := parseSkillManifest(file.Content) // a missing/invalid manifest just yields an empty tool list; runSkillChecks reports it
	schemas := make(map[string]skillToolSchema, len(manifest.Tools))
	for _, name := range manifest.Tools {
		if tool, ok := live[name]; ok {
			schemas[name] = snapshotToolSchema(tool)
		}
	}

	_, err := store.CreateSkillVersion(ctx, SkillVersion{
		SkillID:       sk.ID,
		Version:       nextVersion,
		Commit:        commit,
		Author:        author,
		Digest:        digest,
		Content:       file.Content,
		ContextTokens: estimateTokens(file.Content),
		Tools:         manifest.Tools,
		ToolSchemas:   schemas,
		CreatedAt:     now,
	})
	return err
}

// refreshSkillDrift recomputes drift for a skill's latest version and
// persists the reconciled finding set (preserving DetectedAt for findings
// that already existed). Called both after every sync (so drift reflects a
// new publish immediately) and on demand from the "+ Run checks" endpoint
// (so an operator can re-check without waiting for the next source sync).
func refreshSkillDrift(ctx context.Context, store SkillStore, live map[string]mcp.Tool, skillID string, now time.Time) error {
	latest, ok := store.LatestSkillVersion(ctx, skillID)
	if !ok {
		return nil
	}
	fresh := computeSkillDrift(latest, live)
	existing, err := store.SkillDriftFindings(ctx, skillID)
	if err != nil {
		return err
	}
	return store.ReplaceSkillDriftFindings(ctx, skillID, reconcileDriftFindings(skillID, fresh, existing, now))
}

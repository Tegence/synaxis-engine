package engine

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// SkillFile is one skill markdown file discovered during a source sync.
type SkillFile struct {
	Path    string // repo-relative path, e.g. "skills/incident-triage.md"
	Content string
}

// SkillSourceFetcher fetches the current state of a git-backed skill source.
// It exists as an interface purely as a test seam — the same pattern as the
// `connector` interface in console.go and Gateway.listTools — so sync-logic
// tests never shell out to a real `git` binary or touch the network.
// Production wiring uses gitFetcher.
type SkillSourceFetcher interface {
	// Fetch returns the source's current HEAD commit + author and every
	// skill file found under path on branch.
	Fetch(ctx context.Context, gitURL, token, branch, path string) (commit, author string, files []SkillFile, err error)
}

// gitFetcher is the real SkillSourceFetcher.
//
// ASSUMPTION (report explicitly allows "shelling out to git if consistent
// with how the codebase already handles external processes"): nothing else
// in this codebase shells out to an external process today, but Go's
// standard library has no git-protocol client, and vendoring a full git
// implementation (or a third-party pure-Go git library) is out of scope for
// a lean v1 sync. Shelling out to the system `git` binary is the minimal
// correct choice. Every sync does a fresh shallow clone into a temp
// directory; see SkillVersion.Commit's doc comment for the per-file-
// precision simplification this implies (every skill in one sync shares that
// sync's source-HEAD commit/author, not a per-path git-blame).
type gitFetcher struct{}

func newGitFetcher() *gitFetcher { return &gitFetcher{} }

// gitFetchTimeout bounds one sync's clone + read work so a hung or
// enormous upstream repo cannot wedge a console request/background sync
// forever.
const gitFetchTimeout = 2 * time.Minute

func (f *gitFetcher) Fetch(ctx context.Context, gitURL, token, branch, path string) (string, string, []SkillFile, error) {
	gitURL = strings.TrimSpace(gitURL)
	if gitURL == "" {
		return "", "", nil, errors.New("skill source url is required")
	}
	if branch = strings.TrimSpace(branch); branch == "" {
		branch = "main"
	}
	cloneURL, err := withCloneCredentials(gitURL, token)
	if err != nil {
		return "", "", nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, gitFetchTimeout)
	defer cancel()
	dir, err := os.MkdirTemp("", "narthex-skill-src-")
	if err != nil {
		return "", "", nil, fmt.Errorf("create sync workdir: %w", err)
	}
	defer os.RemoveAll(dir)

	if out, err := exec.CommandContext(ctx, "git", "clone", "--depth", "1", "--branch", branch, "--single-branch", cloneURL, dir).CombinedOutput(); err != nil {
		return "", "", nil, fmt.Errorf("git clone: %w: %s", err, strings.TrimSpace(scrubGitOutput(string(out), token)))
	}
	commit, err := runGit(ctx, dir, "rev-parse", "HEAD")
	if err != nil {
		return "", "", nil, err
	}
	author, err := runGit(ctx, dir, "log", "-1", "--format=%an")
	if err != nil {
		return "", "", nil, err
	}
	files, err := scanSkillFiles(dir, path)
	if err != nil {
		return "", "", nil, fmt.Errorf("scan skill files: %w", err)
	}
	return strings.TrimSpace(commit), strings.TrimSpace(author), files, nil
}

// withCloneCredentials injects an optional access token into an https:// URL
// as userinfo (the common PAT convention: https://<token>@host/path). Non-
// https URLs (ssh, git://) are returned unchanged — token auth only applies
// to https remotes.
func withCloneCredentials(gitURL, token string) (string, error) {
	if token == "" {
		return gitURL, nil
	}
	u, err := url.Parse(gitURL)
	if err != nil || u.Scheme != "https" {
		return gitURL, nil
	}
	u.User = url.UserPassword("x-access-token", token)
	return u.String(), nil
}

// scrubGitOutput removes a credential embedded in a clone URL from git's
// error output so a bad/expired token is never written into a console error
// message or a log line.
func scrubGitOutput(out, token string) string {
	if token == "" {
		return out
	}
	return strings.ReplaceAll(out, token, "[redacted]")
}

func runGit(ctx context.Context, dir string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
	}
	return string(out), nil
}

// scanSkillFiles walks root/path for "*.md" files. A missing/empty skills
// directory is not an error — it just yields zero skills, matching the "one
// bad account is skipped, not fatal" tolerance the rest of the engine uses
// for external state.
func scanSkillFiles(root, path string) ([]SkillFile, error) {
	scanRoot := root
	if path = strings.TrimSpace(path); path != "" {
		scanRoot = filepath.Join(root, filepath.FromSlash(path))
	}
	if _, err := os.Stat(scanRoot); os.IsNotExist(err) {
		return nil, nil
	}
	var files []SkillFile
	err := filepath.WalkDir(scanRoot, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(strings.ToLower(d.Name()), ".md") {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		files = append(files, SkillFile{Path: filepath.ToSlash(rel), Content: string(b)})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return files, nil
}

// skillNameFromPath derives a skill's display name from its file path:
// "skills/incident-triage.md" -> "incident-triage".
func skillNameFromPath(path string) string {
	base := filepath.Base(path)
	return strings.TrimSuffix(base, filepath.Ext(base))
}

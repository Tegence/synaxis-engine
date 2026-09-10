package engine

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// requireGit skips the test when the `git` binary isn't on PATH, so this
// suite never fails a sandbox/CI image that happens not to ship it.
func requireGit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git binary not found on PATH; skipping gitFetcher integration test")
	}
}

// runGitCmd is a small test helper around exec.Command for building a local
// fixture repo — deliberately separate from the production runGit (which
// runs against an already-cloned working dir under a caller-supplied ctx).
func runGitCmd(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=Test", "GIT_AUTHOR_EMAIL=test@example.com",
		"GIT_COMMITTER_NAME=Test", "GIT_COMMITTER_EMAIL=test@example.com",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

// TestGitFetcherFetchesLocalRepo exercises the REAL gitFetcher (the one used
// in production, which shells out to `git clone`) against a purely local,
// network-free fixture repository — `git clone` accepts a local filesystem
// path as a remote, so this needs no network access and no test double.
func TestGitFetcherFetchesLocalRepo(t *testing.T) {
	requireGit(t)

	repoDir := t.TempDir()
	runGitCmd(t, repoDir, "init", "--initial-branch=main")
	skillsDir := filepath.Join(repoDir, "skills")
	if err := os.MkdirAll(skillsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skillsDir, "incident-triage.md"), []byte(incidentTriageManifestV1), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repoDir, "README.md"), []byte("# not a skill\n"), 0o644); err != nil {
		t.Fatal(err) // outside the "skills" path — must not be picked up
	}
	runGitCmd(t, repoDir, "add", ".")
	runGitCmd(t, repoDir, "commit", "-m", "add incident-triage skill")

	f := newGitFetcher()
	commit, author, files, err := f.Fetch(context.Background(), repoDir, "", "main", "skills")
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if commit == "" {
		t.Error("commit is empty")
	}
	if author != "Test" {
		t.Errorf("author = %q, want Test", author)
	}
	if len(files) != 1 {
		t.Fatalf("files = %v, want exactly the one file under skills/", files)
	}
	if files[0].Path != "skills/incident-triage.md" {
		t.Errorf("path = %q, want skills/incident-triage.md", files[0].Path)
	}
	if files[0].Content != incidentTriageManifestV1 {
		t.Errorf("content mismatch:\ngot:  %q\nwant: %q", files[0].Content, incidentTriageManifestV1)
	}
}

func TestGitFetcherMissingSkillsDirIsNotFatal(t *testing.T) {
	requireGit(t)

	repoDir := t.TempDir()
	runGitCmd(t, repoDir, "init", "--initial-branch=main")
	if err := os.WriteFile(filepath.Join(repoDir, "README.md"), []byte("# empty repo\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGitCmd(t, repoDir, "add", ".")
	runGitCmd(t, repoDir, "commit", "-m", "initial")

	f := newGitFetcher()
	_, _, files, err := f.Fetch(context.Background(), repoDir, "", "main", "skills")
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(files) != 0 {
		t.Fatalf("files = %v, want none (no skills/ directory in this repo)", files)
	}
}

func TestGitFetcherRequiresURL(t *testing.T) {
	f := newGitFetcher()
	if _, _, _, err := f.Fetch(context.Background(), "", "", "main", "skills"); err == nil {
		t.Fatal("expected an error for an empty url")
	}
}

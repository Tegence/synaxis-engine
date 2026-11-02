package engine

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Every surface the code marks with NoteDeprecated or deprecatedHandler must
// have a row in DEPRECATIONS.md (backend/DEPRECATIONS.md in the product
// repository, the root of the public engine export), so a compatibility path
// can never outlive the record of what replaces it and when it may go.
func TestDeprecatedSurfacesAreInTheLedger(t *testing.T) {
	root := filepath.Join("..", "..")
	ledger, err := os.ReadFile(filepath.Join(root, "DEPRECATIONS.md"))
	if err != nil {
		t.Fatal(err)
	}
	listed := map[string]bool{}
	for _, m := range regexp.MustCompile("`([a-z]+:[^`]+)`").FindAllStringSubmatch(string(ledger), -1) {
		listed[m[1]] = true
	}
	if len(listed) == 0 {
		t.Fatal("DEPRECATIONS.md lists no surfaces; each row names one as `kind:name`")
	}
	note := regexp.MustCompile(`(?:NoteDeprecated|deprecatedHandler)\("([^"]+)"`)
	var missing []string
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != root && (strings.HasPrefix(d.Name(), ".") || d.Name() == "testdata") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		for _, m := range note.FindAllSubmatch(src, -1) {
			if name := string(m[1]); !listed[name] {
				missing = append(missing, name+" ("+filepath.ToSlash(rel)+")")
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("these deprecated surfaces have no row in DEPRECATIONS.md:\n  %s", strings.Join(missing, "\n  "))
	}
}

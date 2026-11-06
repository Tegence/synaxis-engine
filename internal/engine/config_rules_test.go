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

// Every environment variable the Engine reads must have a row in the engine
// README's configuration table (backend/README.md in the product repository,
// README.md at the root of the public engine export). Operators discover
// settings from that table; a variable missing from it is a setting nobody can
// find, and the table is where the default and the hosted-mode rule live.
func TestEnvironmentVariablesAreDocumented(t *testing.T) {
	root := filepath.Join("..", "..")
	readme, err := os.ReadFile(filepath.Join(root, "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	documented := map[string]bool{}
	variable := regexp.MustCompile("`([A-Z][A-Z0-9_]+)`")
	for _, line := range strings.Split(string(readme), "\n") {
		if !strings.HasPrefix(line, "| `") {
			continue
		}
		for _, m := range variable.FindAllStringSubmatch(line, -1) {
			documented[m[1]] = true
		}
	}
	if len(documented) == 0 {
		t.Fatal("README.md has no configuration table rows of the form | `NAME` | …")
	}
	read := regexp.MustCompile(`(?:os\.Getenv|os\.LookupEnv|envOr|env)\("([A-Z][A-Z0-9_]+)"`)
	missing := map[string][]string{}
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
		for _, m := range read.FindAllSubmatch(src, -1) {
			if name := string(m[1]); !documented[name] {
				missing[name] = append(missing[name], filepath.ToSlash(rel))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(missing) == 0 {
		return
	}
	var lines []string
	for name, files := range missing {
		sort.Strings(files)
		lines = append(lines, name+" (read in "+strings.Join(files, ", ")+")")
	}
	sort.Strings(lines)
	t.Fatalf("these environment variables are read but have no row in README.md's configuration table:\n  %s",
		strings.Join(lines, "\n  "))
}

package engine

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// CI runs this package's PostgreSQL-backed suite as
//
//	go test ./internal/engine/ -run 'Pg|Postgres'
//
// (.github/workflows/ci.yml, "PgStore parity tests"). A test that opens the
// database through freshEnginePgSchemaDSN, directly or through a helper, but is
// named outside that pattern skips in the hermetic run and is never selected in
// the database run, so it never executes anywhere. This rule pins the naming
// convention the workflow depends on; change them together.
func TestPostgresBackedTestsMatchTheCIFilter(t *testing.T) {
	const fixtureEnv = "TEST_DATABASE_URL"
	ciFilter := regexp.MustCompile(`Pg|Postgres`)

	files, err := filepath.Glob("*_test.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	calls := map[string]map[string]bool{} // function -> package-level functions it calls
	usesDB := map[string]bool{}           // function -> reads the fixture environment variable
	var tests []string
	for _, name := range files {
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || fn.Body == nil {
				continue
			}
			fnName := fn.Name.Name
			calls[fnName] = map[string]bool{}
			ast.Inspect(fn.Body, func(node ast.Node) bool {
				switch x := node.(type) {
				case *ast.CallExpr:
					if id, ok := x.Fun.(*ast.Ident); ok {
						calls[fnName][id.Name] = true
					}
				case *ast.BasicLit:
					if x.Kind == token.STRING && strings.Contains(x.Value, fixtureEnv) {
						usesDB[fnName] = true
					}
				}
				return true
			})
			if strings.HasPrefix(fnName, "Test") {
				tests = append(tests, fnName)
			}
		}
	}
	if len(usesDB) == 0 {
		t.Fatalf("no test helper reads %s; update this rule alongside the fixture", fixtureEnv)
	}
	for changed := true; changed; {
		changed = false
		for fnName, callees := range calls {
			if usesDB[fnName] {
				continue
			}
			for callee := range callees {
				if usesDB[callee] {
					usesDB[fnName] = true
					changed = true
					break
				}
			}
		}
	}
	var misnamed []string
	for _, name := range tests {
		if usesDB[name] && !ciFilter.MatchString(name) {
			misnamed = append(misnamed, name)
		}
	}
	sort.Strings(misnamed)
	if len(misnamed) > 0 {
		t.Fatalf("these tests need PostgreSQL but their names do not match the CI filter %q, so CI never runs them:\n  %s",
			ciFilter, strings.Join(misnamed, "\n  "))
	}
}

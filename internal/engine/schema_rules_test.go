package engine

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// These tests enforce THE RULE in store_pg.go (below libraryMigrate) without a
// database: schema bootstrap re-adds a CHECK constraint only through
// engineReappliedChecks, and drops or renames a constraint elsewhere only
// after review, so the previous Engine release can still start over rows a
// newer release wrote. The Postgres behaviour itself is covered by
// schema_rollback_pg_test.go.

// ruleReappliedCheckConstraints are the CHECK constraints the rule was
// introduced for. Each must stay in engineReappliedChecks; drop one from this
// list only together with the constraint itself.
var ruleReappliedCheckConstraints = []string{
	"narthex_library_mcp_client_skill_authoring_audit_events_operation_check",
	"narthex_library_artifact_versions_format_check",
	"narthex_library_artifact_media_blobs_size_check",
	"narthex_library_mcp_client_skill_authoring_leases_kind_check",
}

// reapplyHelperFunction is the only function allowed to assemble an ADD,
// DROP or RENAME CONSTRAINT statement from fragments.
const reapplyHelperFunction = "reapplyCheckConstraint"

// reviewedConstraintRemovals are the constraints that schema bootstrap drops
// or renames outside reapplyCheckConstraint, each with the reason the
// previous release still starts after it (rules 4 and 7 of THE RULE). A
// name-guarded one-time CHECK add or an engineReappliedChecks constraint is
// never safe to remove this way, whatever this list says.
var reviewedConstraintRemovals = map[string]string{
	"narthex_library_memory_versions_source_digest_check":        "a short-lived development CHECK, dropped for good; no release adds the name again (rule 7)",
	"narthex_mcp_client_namespaces_connection_namespace_id_fkey": "a FOREIGN KEY re-added on every start with an unchanged target (rule 7), not a CHECK",
}

var (
	schemaIdentifier    = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	addConstraintClause = regexp.MustCompile(`(?i)\bADD\s+(CONSTRAINT|CHECK)\b`)
	constraintNameThen  = regexp.MustCompile(`^\s+("[^"]+"|[A-Za-z_][A-Za-z0-9_$]*)\s+([A-Za-z]+)`)
	alterTableTarget    = regexp.MustCompile(`(?i)\bALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?("[^"]+"|[A-Za-z_][A-Za-z0-9_.]*)`)
	alterTable          = regexp.MustCompile(`(?i)\bALTER\s+TABLE\b`)
	endIf               = regexp.MustCompile(`(?i)\bEND\s+IF\b`)
	doBlockStart        = regexp.MustCompile(`(?i)\bDO\s+\$`)
	// DROP CONSTRAINT [IF EXISTS] or RENAME CONSTRAINT; the constraint name
	// follows when the literal spells it out.
	constraintRemoval = regexp.MustCompile(`(?i)\b(DROP|RENAME)\s+CONSTRAINT\b(?:\s+IF\s+EXISTS\b)?`)
	leadingIdentifier = regexp.MustCompile(`^\s+("[^"]+"|[A-Za-z_][A-Za-z0-9_$]*)`)
)

func TestEngineSchemaReaddsChecksOnlyThroughRollbackSafeHelper(t *testing.T) {
	root := engineModuleRoot(t)
	var files []string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", "testdata", "vendor", "node_modules":
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatalf("no Go sources found under %s", root)
	}
	var all schemaCheckReaddReport
	for _, path := range files {
		source, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		relative, _ := filepath.Rel(root, path)
		report, err := scanSchemaCheckReadds(relative, string(source))
		if err != nil {
			t.Fatal(err)
		}
		all.merge(report)
	}
	if all.sqlLiterals == 0 {
		t.Fatal("found no SQL literals that add a constraint; the scan is not looking at the schema")
	}
	for _, violation := range all.violations {
		t.Error(violation)
	}
	// A drop or rename in one file can undo a guarded add in another, so
	// removals are checked against every scanned file at once.
	var reapplied []string
	for _, check := range engineReappliedChecks {
		reapplied = append(reapplied, check.constraint)
	}
	violations, unused := constraintRemovalViolations(all, reapplied, reviewedConstraintRemovals)
	for _, violation := range violations {
		t.Error(violation)
	}
	for _, name := range unused {
		t.Errorf("reviewedConstraintRemovals lists %s, which schema bootstrap no longer drops or renames; remove it", name)
	}

	// Keep the helper from being "simplified" back into a validating re-add.
	helper := strings.Join(all.helperLiterals, "\n")
	for _, required := range []string{"DROP CONSTRAINT IF EXISTS", " ADD CONSTRAINT ", ") NOT VALID", "COMMENT ON CONSTRAINT ", " VALIDATE CONSTRAINT "} {
		if !strings.Contains(helper, required) {
			t.Errorf("%s no longer contains %q", reapplyHelperFunction, required)
		}
	}
}

func TestEngineReappliedChecksAreWellFormed(t *testing.T) {
	stored := map[string]string{}
	for _, check := range engineReappliedChecks {
		if !schemaIdentifier.MatchString(check.table) || !schemaIdentifier.MatchString(check.constraint) {
			t.Errorf("%q on %q: table and constraint must be plain lowercase identifiers", check.constraint, check.table)
		}
		name := storedPgIdentifier(check.constraint)
		if previous, ok := stored[name]; ok {
			t.Errorf("%s and %s are the same constraint once PostgreSQL truncates them to %d bytes", previous, check.constraint, pgIdentifierMaxBytes)
		}
		stored[name] = check.constraint
		expression := strings.TrimSpace(check.expression)
		upper := strings.ToUpper(expression)
		switch {
		case expression == "":
			t.Errorf("%s has an empty CHECK expression", check.constraint)
		case strings.HasPrefix(upper, "CHECK") || strings.Contains(upper, "NOT VALID"):
			t.Errorf("%s: pass only the boolean expression; the helper adds CHECK (...) NOT VALID itself", check.constraint)
		case strings.Contains(expression, ";") || strings.Contains(expression, "--") || strings.Contains(expression, "/*"):
			t.Errorf("%s: the expression is interpolated as SQL and must be one expression: %s", check.constraint, expression)
		case strings.Contains(expression, `\`):
			t.Errorf("%s: a backslash would make the recorded comment depend on standard_conforming_strings: %s", check.constraint, expression)
		}
	}
	for _, name := range ruleReappliedCheckConstraints {
		if _, ok := stored[storedPgIdentifier(name)]; !ok {
			t.Errorf("%s is no longer re-added through engineReappliedChecks", name)
		}
	}
}

// A fresh install creates each listed constraint from its table's inline
// CHECK; every later start re-adds it from engineReappliedChecks. The two must
// agree, or a fresh install and an upgraded database would enforce different
// lists.
func TestEngineReappliedChecksMatchInlineDefinitions(t *testing.T) {
	schema := strings.Join([]string{accountsSchema, mcpClientsSchema, librarySchema, libraryMigrate}, "\n")
	for _, check := range engineReappliedChecks {
		inline := regexp.MustCompile(`(?s)CONSTRAINT\s+` + regexp.QuoteMeta(check.constraint) + `\s+CHECK\s*\(`)
		location := inline.FindStringIndex(schema)
		if location == nil {
			t.Errorf("%s has no inline CHECK in its CREATE TABLE", check.constraint)
			continue
		}
		body, ok := balancedParenthesesBody(schema[location[1]-1:])
		if !ok {
			t.Errorf("%s: unbalanced inline CHECK", check.constraint)
			continue
		}
		if normalizeSQLSpace(body) != normalizeSQLSpace(check.expression) {
			t.Errorf("%s: inline CHECK (%s) differs from the re-applied CHECK (%s)", check.constraint, body, check.expression)
		}
	}
}

// connection_scope is the list rule 3 of THE RULE names as not safe to widen:
// accountsMigrate rewrites an unknown scope to 'shared' on every start, so the
// previous release would silently widen access to accounts a newer release
// gave a new scope. Until the two-release procedure in the note above
// accountsMigrate is done, every list involved stays this one set.
func TestEngineConnectionScopeListIsPinned(t *testing.T) {
	const remedy = "connection_scope is not safe to widen across a rollback; follow the two-release procedure " +
		"in the note above accountsMigrate in store_pg.go before changing this pin"
	pinned := []string{"shared", "personal", "service"}
	lists := regexp.MustCompile(`(?i)\bconnection_scope\s+(?:NOT\s+)?IN\s*\(([^)]*)\)`).
		FindAllStringSubmatch(accountsSchema+"\n"+accountsMigrate, -1)
	// The inline CHECK, the guarded one-time add and the startup rewrite.
	if len(lists) != 3 {
		t.Fatalf("found %d connection_scope lists in accountsSchema and accountsMigrate, want 3. %s", len(lists), remedy)
	}
	for _, list := range lists {
		var values []string
		for _, value := range checkQuotedValue.FindAllString(list[1], -1) {
			values = append(values, strings.Trim(value, "'"))
		}
		if strings.Join(values, ",") != strings.Join(pinned, ",") {
			t.Errorf("%s lists %q, want %q. %s", list[0], values, pinned, remedy)
		}
	}
	for _, scope := range []ConnectionScope{ConnectionScopeShared, ConnectionScopePersonal, ConnectionScopeService} {
		if !slices.Contains(pinned, string(scope)) {
			t.Errorf("ConnectionScope %q is not in the pinned list %q. %s", scope, pinned, remedy)
		}
	}
	for _, value := range pinned {
		if got, err := normalizedConnectionScope(ConnectionScope(value)); err != nil || string(got) != value {
			t.Errorf("normalizedConnectionScope(%q) = %q, %v; want it accepted unchanged. %s", value, got, err, remedy)
		}
	}
}

// The recorded comment is what decides whether a start re-adds a listed
// constraint, so it must change exactly when the expression does.
func TestReappliedCheckAppliedComment(t *testing.T) {
	check := reappliedCheck{expression: "kind IN ('generic',\n\t'adoption')"}
	if got, want := check.appliedComment(), reappliedCheckCommentPrefix+"kind IN ('generic', 'adoption')"; got != want {
		t.Fatalf("appliedComment() = %q, want %q", got, want)
	}
	widened := reappliedCheck{expression: "kind IN ('generic','adoption','transfer')"}
	if check.appliedComment() == widened.appliedComment() {
		t.Fatal("a widened list records the same comment, so an upgraded database would keep the old list")
	}
	if got, want := quoteSQLLiteral("it's"), `'it''s'`; got != want {
		t.Fatalf("quoteSQLLiteral = %s, want %s", got, want)
	}
}

func TestPreviousCheckExpressions(t *testing.T) {
	for _, test := range []struct {
		expression string
		want       []string
	}{
		{`kind IN ('generic','adoption')`, []string{`kind IN ('adoption')`, `kind IN ('generic')`}},
		{`kind IN ('generic', 'adoption', 'transfer')`, []string{`kind IN ('adoption', 'transfer')`, `kind IN ('generic', 'transfer')`, `kind IN ('generic', 'adoption')`}},
		{`size_bytes > 0 AND size_bytes <= 524288`, []string{`size_bytes > 1 AND size_bytes <= 524288`, `size_bytes > 0 AND size_bytes <= 524289`}},
		{`kind = 'generic'`, nil},
	} {
		if got := previousCheckExpressions(test.expression); strings.Join(got, "|") != strings.Join(test.want, "|") {
			t.Errorf("previousCheckExpressions(%s) = %q, want %q", test.expression, got, test.want)
		}
	}
}

var (
	checkQuotedValue = regexp.MustCompile(`'[^']*'`)
	checkInteger     = regexp.MustCompile(`\b[0-9]+\b`)
)

// previousCheckExpressions derives expressions that a previous release could
// have applied in place of expression: each value of a list left out in turn,
// and each integer limit changed in turn.
func previousCheckExpressions(expression string) []string {
	var previous []string
	for _, value := range checkQuotedValue.FindAllStringIndex(expression, -1) {
		start, end := value[0], value[1]
		after := strings.TrimLeft(expression[end:], " ")
		before := strings.TrimRight(expression[:start], " ")
		switch {
		case strings.HasPrefix(after, ","):
			end = len(expression) - len(strings.TrimLeft(after[1:], " "))
		case strings.HasSuffix(before, ","):
			start = len(before) - 1
		default:
			continue // the only value of its list
		}
		previous = append(previous, expression[:start]+expression[end:])
	}
	for _, number := range checkInteger.FindAllStringIndex(expression, -1) {
		value, err := strconv.Atoi(expression[number[0]:number[1]])
		if err != nil {
			continue
		}
		previous = append(previous, expression[:number[0]]+strconv.Itoa(value+1)+expression[number[1]:])
	}
	return previous
}

func TestScanSchemaCheckReaddsCatchesUnsafeReadds(t *testing.T) {
	// The fixtures' own engineReappliedChecks and reviewedConstraintRemovals.
	fixtureReapplied := []string{"t_reapplied_check"}
	fixtureReviewed := map[string]string{"t_u_fkey": "fixture"}
	guardedAdd := "DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='t_kind_check' AND conrelid='t'::regclass) THEN\n" +
		"ALTER TABLE t ADD CONSTRAINT t_kind_check CHECK (kind IN ('a','b'));\nEND IF; END $$;"
	for _, test := range []struct {
		name   string
		source string
		want   []string // one violation mentioning each; nil = no violation
	}{
		{
			name: "plain validating re-add",
			source: "const s = `ALTER TABLE t DROP CONSTRAINT IF EXISTS t_kind_check; /* a\nb */\n" +
				"ALTER TABLE t ADD CONSTRAINT t_kind_check CHECK (kind IN ('a','b'));`",
			// The fixture starts at line 2; the re-add is two lines further on.
			want: []string{"fixture.go:4: CHECK constraint \"t_kind_check\"", "fixture.go:2: DROP CONSTRAINT t_kind_check is not reviewed"},
		},
		{
			name: "definition-guarded re-add",
			source: "const s = `DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='t_kind_check'\n" +
				"AND conrelid='t'::regclass AND pg_get_constraintdef(oid) LIKE '%b%') THEN\n" +
				"ALTER TABLE t DROP CONSTRAINT IF EXISTS t_kind_check;\n" +
				"ALTER TABLE t ADD CONSTRAINT t_kind_check CHECK (kind IN ('a','b'));\nEND IF; END $$;`",
			want: []string{"CHECK constraint \"t_kind_check\"", "DROP CONSTRAINT t_kind_check is not reviewed"},
		},
		{
			name: "one-time add guarded by name",
			source: "const s = `DO $$ BEGIN IF NOT EXISTS (\n  SELECT 1 FROM pg_constraint\n  WHERE conname = 't_kind_check'\n" +
				"  AND conrelid = 't'::regclass\n) THEN\n  ALTER TABLE t\n    ADD CONSTRAINT t_kind_check CHECK (kind IN ('a','b'));\nEND IF; END $$;`",
		},
		{
			name: "guard on another table",
			source: "const s = `DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='t_kind_check' AND conrelid='u'::regclass) THEN\n" +
				"ALTER TABLE t ADD CONSTRAINT t_kind_check CHECK (kind IN ('a','b'));\nEND IF; END $$;`",
			want: []string{"t_kind_check"},
		},
		{
			name: "guard for another constraint",
			source: "const s = `DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='t_other_check' AND conrelid='t'::regclass) THEN\n" +
				"ALTER TABLE t ADD CONSTRAINT t_kind_check CHECK (kind IN ('a','b'));\nEND IF; END $$;`",
			want: []string{"t_kind_check"},
		},
		{
			name: "add after the guard closed",
			source: "const s = `DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='t_kind_check' AND conrelid='t'::regclass) THEN\n" +
				"PERFORM 1; END IF;\nALTER TABLE t ADD CONSTRAINT t_kind_check CHECK (kind IN ('a','b')); END $$;`",
			want: []string{"t_kind_check"},
		},
		{
			name:   "unnamed check",
			source: "const s = `ALTER TABLE t ADD CHECK (n > 0);`",
			want:   []string{"ADD CHECK"},
		},
		{
			name:   "assembled from fragments outside the helper",
			source: "func f(name string) string { return \"ALTER TABLE t ADD CONSTRAINT \" + name + \" CHECK (n > 0)\" }",
			want:   []string{"fragments"},
		},
		{
			name:   "assembled inside the helper",
			source: "func reapplyCheckConstraint(name string) string { return \"ALTER TABLE t DROP CONSTRAINT IF EXISTS \" + name + \"; ALTER TABLE t ADD CONSTRAINT \" + name + \" CHECK (n > 0) NOT VALID\" }",
		},
		{
			name:   "commented out",
			source: "const s = `-- ALTER TABLE t ADD CONSTRAINT t_kind_check CHECK (kind IN ('a'));\n/* ADD CHECK (n > 0); ALTER TABLE t DROP CONSTRAINT t_kind_check */ SELECT 1;`",
		},
		{
			name: "reviewed foreign key re-add",
			source: "const s = `ALTER TABLE t DROP CONSTRAINT IF EXISTS t_u_fkey;\n" +
				"ALTER TABLE t ADD CONSTRAINT t_u_fkey FOREIGN KEY (u) REFERENCES u(id);`",
		},
		{
			name:   "not SQL",
			source: "const s = \"price: add constraint checks later\"",
		},
		// Rule 4: dropping or renaming a name-guarded CHECK turns its one-time
		// add into a validating re-add on every start.
		{
			name:   "drop before a name-guarded add",
			source: "const s = `ALTER TABLE t DROP CONSTRAINT IF EXISTS t_kind_check;\n" + guardedAdd + "`",
			want:   []string{"fixture.go:2: DROP CONSTRAINT t_kind_check removes the CHECK that fixture.go:4 adds once"},
		},
		{
			name: "drop inside the DO block before the guard",
			source: "const s = `DO $$ BEGIN ALTER TABLE t DROP CONSTRAINT IF EXISTS t_kind_check; " +
				"IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='t_kind_check' AND conrelid='t'::regclass) THEN\n" +
				"ALTER TABLE t ADD CONSTRAINT t_kind_check CHECK (kind IN ('a','b'));\nEND IF; END $$;`",
			want: []string{"DROP CONSTRAINT t_kind_check removes the CHECK that fixture.go:3 adds once"},
		},
		{
			name:   "drop in another schema const",
			source: "const a = `ALTER TABLE t DROP CONSTRAINT t_kind_check;`\nconst b = `" + guardedAdd + "`",
			want:   []string{"fixture.go:2: DROP CONSTRAINT t_kind_check removes the CHECK that fixture.go:4 adds once"},
		},
		{
			name:   "rename of a name-guarded add",
			source: "const s = `ALTER TABLE t RENAME CONSTRAINT t_kind_check TO t_kind_old;\n" + guardedAdd + "`",
			want:   []string{"RENAME CONSTRAINT t_kind_check removes the CHECK"},
		},
		{
			name:   "drop of a re-applied check",
			source: "const s = `ALTER TABLE t DROP CONSTRAINT IF EXISTS t_reapplied_check;`",
			want:   []string{"t_reapplied_check is in engineReappliedChecks"},
		},
		{
			name:   "drop by a name chosen at run time",
			source: "const s = `DO $$ BEGIN EXECUTE format('ALTER TABLE t DROP CONSTRAINT %I', 't_kind_check'); END $$;`",
			want:   []string{"DROP CONSTRAINT names its constraint at run time"},
		},
		{
			name:   "drop assembled from fragments outside the helper",
			source: "func f(name string) string { return \"ALTER TABLE t DROP CONSTRAINT IF EXISTS \" + name }",
			want:   []string{"DROP CONSTRAINT names its constraint at run time or from fragments"},
		},
		{
			name:   "unreviewed drop",
			source: "const s = `ALTER TABLE t DROP CONSTRAINT IF EXISTS t_other_check;`",
			want:   []string{"fixture.go:2: DROP CONSTRAINT t_other_check is not reviewed"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			report, err := scanSchemaCheckReadds("fixture.go", "package fixture\n"+test.source+"\n")
			if err != nil {
				t.Fatal(err)
			}
			removals, _ := constraintRemovalViolations(report, fixtureReapplied, fixtureReviewed)
			violations := append(append([]string(nil), report.violations...), removals...)
			if len(violations) != len(test.want) {
				t.Fatalf("violations = %q, want one mentioning each of %q", violations, test.want)
			}
			matched := make([]bool, len(violations))
			for _, want := range test.want {
				found := false
				for index, violation := range violations {
					if !matched[index] && strings.Contains(violation, want) {
						matched[index], found = true, true
						break
					}
				}
				if !found {
					t.Fatalf("no violation mentions %q: %q", want, violations)
				}
			}
		})
	}
}

func TestConstraintRemovalViolationsReportsUnusedReviews(t *testing.T) {
	report, err := scanSchemaCheckReadds("fixture.go", "package fixture\nconst s = `ALTER TABLE t DROP CONSTRAINT t_u_fkey;`\n")
	if err != nil {
		t.Fatal(err)
	}
	violations, unused := constraintRemovalViolations(report, nil, map[string]string{"t_u_fkey": "fixture", "t_gone_check": "fixture"})
	if len(violations) != 0 || strings.Join(unused, ",") != "t_gone_check" {
		t.Fatalf("violations = %q, unused = %q; want none and [t_gone_check]", violations, unused)
	}
}

type schemaCheckReaddReport struct {
	violations     []string
	helperLiterals []string
	sqlLiterals    int
	// guardedAdds are the name-guarded one-time CHECK adds, and removals the
	// DROP and RENAME CONSTRAINT clauses outside the helper. Rule 4 relates
	// them across files, so constraintRemovalViolations checks them once
	// every file is scanned.
	guardedAdds []constraintSite
	removals    []constraintSite
}

// constraintSite is one statement that adds or removes a constraint.
type constraintSite struct {
	verb string // DROP or RENAME, for a removal
	// name is the constraint as PostgreSQL stores it, or "" when a removal
	// names it at run time or from fragments.
	name string
	at   string // file:line
}

func (r *schemaCheckReaddReport) merge(other schemaCheckReaddReport) {
	r.violations = append(r.violations, other.violations...)
	r.helperLiterals = append(r.helperLiterals, other.helperLiterals...)
	r.sqlLiterals += other.sqlLiterals
	r.guardedAdds = append(r.guardedAdds, other.guardedAdds...)
	r.removals = append(r.removals, other.removals...)
}

// scanSchemaCheckReadds inspects every string literal in one Go source file.
// A CHECK may be added only as a one-time add guarded by its name alone inside
// a DO block, or by reapplyCheckConstraint, which assembles its statements
// from fragments. It also records each guarded add and each DROP or RENAME
// CONSTRAINT outside the helper for constraintRemovalViolations.
func scanSchemaCheckReadds(path, source string) (schemaCheckReaddReport, error) {
	var report schemaCheckReaddReport
	files := token.NewFileSet()
	file, err := parser.ParseFile(files, path, source, parser.SkipObjectResolution)
	if err != nil {
		return report, err
	}
	for _, declaration := range file.Decls {
		function := ""
		if decl, ok := declaration.(*ast.FuncDecl); ok {
			function = decl.Name.Name
		}
		ast.Inspect(declaration, func(node ast.Node) bool {
			literal, ok := node.(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING {
				return true
			}
			value, err := strconv.Unquote(literal.Value)
			if err != nil {
				return true
			}
			if function == reapplyHelperFunction {
				report.helperLiterals = append(report.helperLiterals, value)
				return true
			}
			sql := stripSQLComments(value)
			// Prose such as an error message is not SQL; any casing counts
			// once the literal alters a table.
			if !alterTable.MatchString(sql) && !strings.Contains(sql, "ADD CONSTRAINT") && !strings.Contains(sql, "ADD CHECK") &&
				!strings.Contains(sql, "DROP CONSTRAINT") && !strings.Contains(sql, "RENAME CONSTRAINT") {
				return true
			}
			position := files.Position(literal.Pos())
			at := func(offset int) string {
				return fmt.Sprintf("%s:%d", position.Filename, position.Line+strings.Count(sql[:offset], "\n"))
			}
			for _, match := range constraintRemoval.FindAllStringSubmatchIndex(sql, -1) {
				removal := constraintSite{verb: strings.ToUpper(sql[match[2]:match[3]]), at: at(match[0])}
				if name := leadingIdentifier.FindStringSubmatch(sql[match[1]:]); name != nil {
					removal.name = storedPgIdentifier(strings.Trim(name[1], `"`))
				}
				report.removals = append(report.removals, removal)
			}
			matches := addConstraintClause.FindAllStringSubmatchIndex(sql, -1)
			if len(matches) == 0 {
				return true
			}
			report.sqlLiterals++
			for _, match := range matches {
				violation, guarded := checkReaddClause(sql, match)
				if violation != "" {
					report.violations = append(report.violations, at(match[0])+": "+violation)
				}
				if guarded != "" {
					report.guardedAdds = append(report.guardedAdds, constraintSite{name: storedPgIdentifier(guarded), at: at(match[0])})
				}
			}
			return true
		})
	}
	return report, nil
}

// checkReaddClause returns why the ADD clause at match is unsafe, or, for a
// one-time add guarded by its name, that constraint's name.
func checkReaddClause(sql string, match []int) (violation, guarded string) {
	const remedy = "Schema bootstrap re-runs on every start, including the previous release over a newer database, " +
		"and a validating re-add fails there. List the constraint in engineReappliedChecks (THE RULE in store_pg.go), " +
		"or add it once in a DO block guarded by IF NOT EXISTS (SELECT 1 FROM pg_constraint " +
		"WHERE conname = '<constraint>' AND conrelid = '<table>'::regclass) and never drop or rename it."
	if strings.EqualFold(sql[match[2]:match[3]], "CHECK") {
		return "an unnamed ADD CHECK cannot be guarded or re-applied rollback-safely. " + remedy, ""
	}
	clause := constraintNameThen.FindStringSubmatch(sql[match[1]:])
	if clause == nil {
		return "ADD CONSTRAINT is assembled from fragments outside " + reapplyHelperFunction + ", so it cannot be checked. " + remedy, ""
	}
	name := strings.Trim(clause[1], `"`)
	switch strings.ToUpper(clause[2]) {
	case "CHECK":
	case "FOREIGN", "UNIQUE", "PRIMARY", "EXCLUDE":
		return "", ""
	default:
		return fmt.Sprintf("cannot tell what ADD CONSTRAINT %s adds. %s", name, remedy), ""
	}
	if guardedOneTimeCheckAdd(sql[:match[0]], name) {
		return "", name
	}
	return fmt.Sprintf("CHECK constraint %q is added outside engineReappliedChecks and is not a one-time add guarded by its name. %s", name, remedy), ""
}

// constraintRemovalViolations applies rule 4 to every scanned file at once. A
// DROP or RENAME CONSTRAINT outside reapplyCheckConstraint must spell out its
// constraint and must not remove a name-guarded one-time CHECK add, whose
// guard would then add it again, validating, on every start of this and every
// older release, or an engineReappliedChecks constraint, which the helper
// alone drops, in the transaction that re-adds it. Any other removal must be
// in reviewed. It also returns the reviewed names that nothing removes.
func constraintRemovalViolations(report schemaCheckReaddReport, reapplied []string, reviewed map[string]string) (violations, unused []string) {
	const remedy = "The previous release runs its own copy of the schema on every start. Change a CHECK by listing it " +
		"in engineReappliedChecks (THE RULE in store_pg.go), never by dropping or renaming it."
	guarded := map[string]string{}
	for _, add := range report.guardedAdds {
		if _, ok := guarded[add.name]; !ok {
			guarded[add.name] = add.at
		}
	}
	helper := map[string]bool{}
	for _, name := range reapplied {
		helper[storedPgIdentifier(name)] = true
	}
	review := map[string]string{}
	for name := range reviewed {
		review[storedPgIdentifier(name)] = name
	}
	used := map[string]bool{}
	for _, removal := range report.removals {
		if name, ok := review[removal.name]; ok {
			used[name] = true
		}
		addedAt, isGuarded := guarded[removal.name]
		_, isReviewed := review[removal.name]
		switch {
		case removal.name == "":
			violations = append(violations, fmt.Sprintf("%s: %s CONSTRAINT names its constraint at run time or from fragments outside %s, so it cannot be checked. %s",
				removal.at, removal.verb, reapplyHelperFunction, remedy))
		case isGuarded:
			violations = append(violations, fmt.Sprintf("%s: %s CONSTRAINT %s removes the CHECK that %s adds once under its name guard, so the guard adds it again, validating, on every start of this and every older release. %s",
				removal.at, removal.verb, removal.name, addedAt, remedy))
		case helper[removal.name]:
			violations = append(violations, fmt.Sprintf("%s: %s CONSTRAINT %s: %s is in engineReappliedChecks, and only %s drops it, in the transaction that re-adds it. %s",
				removal.at, removal.verb, removal.name, removal.name, reapplyHelperFunction, remedy))
		case !isReviewed:
			violations = append(violations, fmt.Sprintf("%s: %s CONSTRAINT %s is not reviewed. Check that the previous release, which may add the constraint again, still starts over this schema, then add it to reviewedConstraintRemovals with the reason. %s",
				removal.at, removal.verb, removal.name, remedy))
		}
	}
	for name := range reviewed {
		if !used[name] {
			unused = append(unused, name)
		}
	}
	sort.Strings(unused)
	return violations, unused
}

// guardedOneTimeCheckAdd reports whether before (the SQL preceding an ADD
// CONSTRAINT <name> CHECK) ends inside a DO block's IF branch that runs only
// when no constraint of that name exists on the ALTER TABLE's table. Such an
// add never runs again once the constraint exists, so an older binary skips
// it. A guard that also inspects the stored definition is a re-add.
func guardedOneTimeCheckAdd(before, name string) bool {
	guard := regexp.MustCompile(`(?is)\bIF\s+NOT\s+EXISTS\s*\(\s*SELECT\s+1\s+FROM\s+pg_constraint\s+` +
		`WHERE\s+conname\s*=\s*'` + regexp.QuoteMeta(name) + `'\s+AND\s+conrelid\s*=\s*'([a-z0-9_]+)'::regclass\s*\)\s*THEN\b`)
	locations := guard.FindAllStringSubmatchIndex(before, -1)
	if len(locations) == 0 {
		return false
	}
	last := locations[len(locations)-1]
	if !doBlockStart.MatchString(before[:last[0]]) {
		return false
	}
	branch := before[last[1]:]
	if endIf.MatchString(branch) {
		return false
	}
	targets := alterTableTarget.FindAllStringSubmatch(branch, -1)
	if len(targets) == 0 {
		return false
	}
	return strings.Trim(targets[len(targets)-1][1], `"`) == before[last[2]:last[3]]
}

// stripSQLComments blanks -- and /* */ comments outside single-quoted
// literals, keeping every newline so line numbers survive. Dollar-quoted DO
// bodies are PL/pgSQL, which shares SQL's comments, so they are scanned like
// the rest of the statement.
func stripSQLComments(sql string) string {
	var out strings.Builder
	quoted := false
	for index := 0; index < len(sql); index++ {
		switch {
		case sql[index] == '\'':
			quoted = !quoted
		case !quoted && strings.HasPrefix(sql[index:], "--"):
			end := strings.IndexByte(sql[index:], '\n')
			if end < 0 {
				return out.String()
			}
			index += end
		case !quoted && strings.HasPrefix(sql[index:], "/*"):
			end := strings.Index(sql[index+2:], "*/")
			if end < 0 {
				return out.String()
			}
			out.WriteByte(' ')
			out.WriteString(strings.Repeat("\n", strings.Count(sql[index:index+2+end], "\n")))
			index += end + 3
			continue
		}
		out.WriteByte(sql[index])
	}
	return out.String()
}

// balancedParenthesesBody returns what lies between s's leading "(" and its
// matching ")", skipping single-quoted literals.
func balancedParenthesesBody(s string) (string, bool) {
	if !strings.HasPrefix(s, "(") {
		return "", false
	}
	depth, quoted := 0, false
	for index := 0; index < len(s); index++ {
		switch {
		case s[index] == '\'':
			quoted = !quoted
		case quoted:
		case s[index] == '(':
			depth++
		case s[index] == ')':
			depth--
			if depth == 0 {
				return s[1:index], true
			}
		}
	}
	return "", false
}

func normalizeSQLSpace(sql string) string {
	return strings.Join(strings.Fields(sql), " ")
}

func engineModuleRoot(t *testing.T) string {
	t.Helper()
	directory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(directory, "go.mod")); err == nil {
			return directory
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			t.Fatal("no go.mod above the engine package")
		}
		directory = parent
	}
}

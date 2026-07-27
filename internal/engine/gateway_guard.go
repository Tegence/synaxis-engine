package engine

// Response-side guardrails for virtual connectors. The gateway is the only
// component that sees tool RESULTS before the model does, so the guard stage
// runs on the way back from the upstream, in this exact order:
//
//	upstream result → redact → size-cap → injection scan → audit LogCall → client
//
// LogCall runs AFTER the guards, so recorded payloads are post-redaction and
// post-truncation — a recorded payload can never contain what redaction
// removed. GUARDS ARE A CONNECTOR FEATURE: the default /mcp endpoint is a raw
// passthrough (its dispatch closure carries no auditScope, so no guards run
// there — see aggregateAccount in gateway.go).
//
// Guards cover every model-visible carrier of a tool result:
//
//   - TextContent items (value or pointer form);
//   - embedded text resources (EmbeddedResource wrapping TextResourceContents
//     — file/document contents are first-class model-readable text);
//   - the result-level structuredContent and _meta, guarded via their JSON
//     serialization (redacted, charged to the size budget, injection-scanned;
//     structuredContent is dropped whole if it overflows the budget, and
//     either carrier is dropped rather than passed through if it no longer
//     parses after redaction).
//
// Binary items (images, audio, blob resources) pass through untouched and
// don't count toward the size budget. Protocol errors (err != nil, no result)
// skip guards entirely; an isError tool result still has its text content
// redacted/capped/scanned like any other text (the CallRecord.Error field
// itself is never guarded — clampErr only).

import (
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
)

// compiledGuards is one connector's guard configuration, compiled once at
// connector build/rebuild time (buildConnector) and shared by every handler
// registered on that connector.
type compiledGuards struct {
	maxBytes      int              // VirtualConnector.MaxResultBytes; 0 = no cap
	redact        []*regexp.Regexp // compiled VirtualConnector.Redact patterns
	scanInjection bool
}

// compileGuards compiles vc's guard config. The console validates Redact
// patterns at create/update (400 on compile error) — it is the validation
// gate. The gateway layer therefore never fails a rebuild over a bad pattern
// (e.g. one written to the store before validation existed): log + skip it.
func compileGuards(vc VirtualConnector) compiledGuards {
	cg := compiledGuards{maxBytes: vc.MaxResultBytes, scanInjection: !vc.DisableInjectionScan}
	for _, p := range vc.Redact {
		re, err := regexp.Compile(p)
		if err != nil {
			log.Printf("engine: connector %q: invalid redact pattern %q skipped: %v", vc.Slug, p, err)
			continue
		}
		cg.redact = append(cg.redact, re)
	}
	return cg
}

const redactedMark = "[redacted]"

// injectionPatterns is a conservative, always-on scan of result text for
// instruction-shaped content aimed at the model (prompt injection riding in
// on tool output). Flag ONLY — the result is never modified. Matching any
// pattern marks the call "flagged:injection" in the audit log.
var injectionPatterns = []*regexp.Regexp{
	// The classic override: "ignore (all) previous/prior/above instructions".
	regexp.MustCompile(`(?i)ignore (all )?(previous|prior|above) instructions`),
	// System-prompt override: "disregard your/the system prompt/instructions".
	regexp.MustCompile(`(?i)disregard (your|the) (system prompt|instructions)`),
	// Imperative pivot addressed at the model: "you must/should now ...".
	regexp.MustCompile(`(?i)you (must|should) now`),
	// Inline instruction block: "new instructions:".
	regexp.MustCompile(`(?i)new instructions:`),
	// Fake system-role tag smuggled into result text.
	regexp.MustCompile(`(?i)<system>`),
	// Urgency addressed at the model, not the user: "IMPORTANT: you/assistant".
	regexp.MustCompile(`(?i)IMPORTANT: (you|assistant)`),
	// Concealment directive: output telling the model to hide things.
	regexp.MustCompile(`(?i)do not tell the user`),
}

// getGuardableText returns the model-visible text carried by a content item:
// mcp.TextContent, or an mcp.EmbeddedResource whose Resource is
// mcp.TextResourceContents (value and pointer forms of each satisfy
// mcp.Content). ok=false means the item carries no guardable text (images,
// audio, blob resources) and passes through untouched.
func getGuardableText(c mcp.Content) (string, bool) {
	switch t := c.(type) {
	case mcp.TextContent:
		return t.Text, true
	case *mcp.TextContent:
		if t != nil {
			return t.Text, true
		}
	case mcp.EmbeddedResource:
		switch r := t.Resource.(type) {
		case mcp.TextResourceContents:
			return r.Text, true
		case *mcp.TextResourceContents:
			if r != nil {
				return r.Text, true
			}
		}
	case *mcp.EmbeddedResource:
		if t != nil {
			return getGuardableText(*t)
		}
	}
	return "", false
}

// setGuardableText returns a copy of c with its guardable text replaced by s,
// preserving every other field (URI, MIMEType, annotations, _meta). Only
// meaningful for items where getGuardableText returned ok; anything else is
// returned unchanged.
func setGuardableText(c mcp.Content, s string) mcp.Content {
	switch t := c.(type) {
	case mcp.TextContent:
		t.Text = s
		return t
	case *mcp.TextContent:
		if t != nil {
			tc := *t
			tc.Text = s
			return tc
		}
	case mcp.EmbeddedResource:
		switch r := t.Resource.(type) {
		case mcp.TextResourceContents:
			r.Text = s
			t.Resource = r
		case *mcp.TextResourceContents:
			if r != nil {
				rc := *r
				rc.Text = s
				t.Resource = rc
			}
		}
		return t
	case *mcp.EmbeddedResource:
		if t != nil {
			return setGuardableText(*t, s)
		}
	}
	return c
}

// guardSerialized guards a non-Content carrier (structuredContent, result
// _meta) via its JSON serialization: every redact pattern runs over the
// serialized form and the injection patterns scan it, then the guarded JSON
// is decoded back into out (a pointer). It returns the guarded serialization's
// byte length, the redaction count, whether an injection pattern matched, and
// ok=false when the carrier could not be marshaled or no longer parses after
// redaction — callers must then drop/replace the carrier rather than pass
// unguarded data through.
func guardSerialized(v any, g compiledGuards, out any) (size, redactions int, flagged, ok bool) {
	b, err := json.Marshal(v)
	if err != nil {
		return 0, 0, false, false
	}
	s := string(b)
	for _, re := range g.redact {
		if n := len(re.FindAllStringIndex(s, -1)); n > 0 {
			redactions += n
			s = re.ReplaceAllString(s, redactedMark)
		}
	}
	if g.scanInjection {
		for _, re := range injectionPatterns {
			if re.MatchString(s) {
				flagged = true
				break
			}
		}
	}
	if err := json.Unmarshal([]byte(s), out); err != nil {
		return len(s), redactions, flagged, false
	}
	return len(s), redactions, flagged, true
}

// applyGuards runs the guard pipeline (redact → size-cap → injection scan)
// over a tool result's guardable text (text content items, embedded text
// resources) plus its structuredContent/_meta carriers, and returns the
// guarded result plus the
// comma-joined guard markers for the audit row ("truncated", "redacted:N",
// "flagged:injection"; "" = nothing fired). The input result is not mutated —
// a shallow copy with a fresh Content slice is returned when anything at all
// needs inspecting (cheap: content items are small headers over strings).
func applyGuards(res *mcp.CallToolResult, g compiledGuards) (*mcp.CallToolResult, string) {
	if res == nil {
		return res, ""
	}
	content := make([]mcp.Content, len(res.Content))
	copy(content, res.Content)

	// 1) Redact: every operator pattern, every guardable text item (plain
	// text and embedded text resources), count replacements.
	redactions := 0
	for i, c := range content {
		text, ok := getGuardableText(c)
		if !ok {
			continue
		}
		changed := false
		for _, re := range g.redact {
			if n := len(re.FindAllStringIndex(text, -1)); n > 0 {
				redactions += n
				text = re.ReplaceAllString(text, redactedMark)
				changed = true
			}
		}
		if changed {
			content[i] = setGuardableText(c, text)
		}
	}

	// 2) Size cap: total guardable-text bytes across items, in order. The
	// first item that overflows the remaining budget is truncated rune-safely
	// and gets the visible marker; every later guardable item is dropped
	// entirely. Binary items pass through untouched and are not charged.
	// `budget` carries what's left so structuredContent (step 4) is charged
	// against the same cap.
	truncated := false
	budget := g.maxBytes
	if g.maxBytes > 0 {
		kept := make([]mcp.Content, 0, len(content))
		for _, c := range content {
			text, ok := getGuardableText(c)
			if !ok {
				kept = append(kept, c)
				continue
			}
			if truncated {
				continue // budget already spent — drop the item
			}
			if len(text) <= budget {
				budget -= len(text)
				kept = append(kept, c)
				continue
			}
			text = text[:runeBoundary(text, budget)] +
				fmt.Sprintf("\n\n[narthex: result truncated at %d bytes]", g.maxBytes)
			truncated = true
			budget = 0
			kept = append(kept, setGuardableText(c, text))
		}
		content = kept
	}

	// 3) Injection scan (post-redaction/cap — what the model will see).
	// Flag only; never modify.
	flagged := false
	if g.scanInjection {
	scan:
		for _, c := range content {
			text, ok := getGuardableText(c)
			if !ok {
				continue
			}
			for _, re := range injectionPatterns {
				if re.MatchString(text) {
					flagged = true
					break scan
				}
			}
		}
	}

	// 4) Non-Content carriers. structuredContent and result _meta are parsed
	// off the upstream wire and re-serialized to the client verbatim, so they
	// are just as model-visible as text content and get the same treatment
	// via their JSON serialization. This runs BEFORE the audit LogCall (the
	// caller records the returned result), preserving the invariant that a
	// recorded payload never contains what redaction removed.
	structured := res.StructuredContent
	if structured != nil {
		var guarded any
		size, n, fl, ok := guardSerialized(structured, g, &guarded)
		redactions += n
		flagged = flagged || fl
		switch {
		case !ok:
			// Unserializable, or redaction broke the JSON structure (e.g. a
			// pattern matched across quotes) — never pass the raw value on.
			structured = map[string]any{"narthex": "structured content removed by redaction"}
		case g.maxBytes > 0 && size > budget:
			structured = nil // overflows the shared cap — drop it whole
			truncated = true
		default:
			if g.maxBytes > 0 {
				budget -= size
			}
			structured = guarded
		}
	}
	meta := res.Meta
	if meta != nil {
		var guarded mcp.Meta
		_, n, fl, ok := guardSerialized(meta, g, &guarded)
		redactions += n
		flagged = flagged || fl
		if ok {
			meta = &guarded
		} else {
			meta = nil // undecodable post-redaction — drop rather than leak
		}
	}

	var marks []string
	if truncated {
		marks = append(marks, "truncated")
	}
	if redactions > 0 {
		marks = append(marks, fmt.Sprintf("redacted:%d", redactions))
	}
	if flagged {
		marks = append(marks, "flagged:injection")
	}
	out := *res
	out.Content = content
	out.StructuredContent = structured
	out.Meta = meta
	return &out, strings.Join(marks, ",")
}

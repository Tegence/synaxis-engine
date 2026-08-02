package engine

// Flight recorder: per-endpoint payload recording layered over the shared
// dispatch closures, plus console-triggered replay of a recorded call.
//
// The cached per-tool closure (built in aggregateAccount) does the upstream
// call, the timing, and the single LogCall. What it CANNOT know is which
// endpoint the call entered through — the same closure serves /mcp and every
// /mcp/{slug} connector server. That context (connector slug, whether to
// record payloads, and any approval decision) travels down via an auditScope
// in ctx, injected by scopedHandler at the connector boundary. One LogCall
// per call, always written by the innermost closure, always stamped with the
// outermost endpoint's identity.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// auditScope is the per-request endpoint context for one tool call. It is a
// pointer on purpose: the approval wrapper sits between the scope injection
// and the dispatch closure and mutates decision on an approved call.
type auditScope struct {
	connector  string
	kind       string
	generation string
	record     bool
	decision   string          // set to "approved" by the approval wrapper before dispatch
	guards     *compiledGuards // response guardrails; nil only off-connector (/mcp injects no scope at all)
}

type auditScopeKey struct{}

func withAuditScope(ctx context.Context, sc *auditScope) context.Context {
	return context.WithValue(ctx, auditScopeKey{}, sc)
}

// auditScopeFrom returns the request's scope, or nil for calls on the default
// /mcp endpoint (which never injects one).
func auditScopeFrom(ctx context.Context) *auditScope {
	sc, _ := ctx.Value(auditScopeKey{}).(*auditScope)
	return sc
}

// scopedHandler wraps a connector-registered handler so every request through
// it carries a fresh auditScope naming the connector, its Record flag, and its
// compiled response guards (applied by the dispatch closure after the upstream
// call, before the audit row — see applyGuards in gateway_guard.go).
func (g *Gateway) scopedHandler(
	connector, kind, generation string,
	record bool,
	guards *compiledGuards,
	inner server.ToolHandlerFunc,
) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return inner(withAuditScope(ctx, &auditScope{
			connector: connector, kind: kind, generation: generation,
			record: record, guards: guards,
		}), req)
	}
}

// marshalPayload JSON-encodes one side of a recorded call, clamped to the
// payload cap (the store clamps again on write; clamping here also bounds the
// in-flight record).
func marshalPayload(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return `{"marshal_error":` + strconv.Quote(err.Error()) + `}`
	}
	return clampPayload(string(b), maxPayloadBytes)
}

// ErrReplayForceRequired is returned by Replay when the target tool is (or
// may be) mutating and the caller did not pass force. The console maps it to
// 409 so the UI can raise a confirm dialog and retry with {"force": true}.
var ErrReplayForceRequired = errors.New("mutating tool — force required")

// Replay re-issues audit record id's call through the account's live upstream
// dispatch path and writes a NEW audit row with Decision "replay". Rules:
//
//   - The original call must have a recorded Args payload — a summary-only row
//     carries no arguments to re-send.
//   - The tool must still be in the account's live cache (account gone, tool
//     disabled, or tool vanished upstream → error).
//   - A tool that isn't read-only per readOnlyTool (annotation-first, write-verb
//     veto) requires force=true (ErrReplayForceRequired otherwise). Note replay
//     bypasses connector approval gating — force IS the explicit human sign-off.
//   - The new row records Args and the fresh Result regardless of any Record
//     flag: an explicit replay is an explicit ask.
//
// The returned record is the new one (payloads included) so the console can
// diff old vs new results; its ID is not populated (PgStore's LogCall is
// fire-and-forget). A failed upstream call is still a successful replay — the
// returned record carries OK=false and the error.
func (g *Gateway) Replay(ctx context.Context, id int64, force bool) (CallRecord, error) {
	if g.audit == nil {
		return CallRecord{}, fmt.Errorf("no audit sink configured — nothing to replay")
	}
	orig, ok, err := g.audit.CallDetail(ctx, id)
	if err != nil {
		return CallRecord{}, err
	}
	if !ok {
		return CallRecord{}, fmt.Errorf("call %d not found", id)
	}
	if orig.Args == "" {
		return CallRecord{}, fmt.Errorf("call %d has no recorded payload (recording was off) — nothing to replay", id)
	}
	// A connector-attributed row is replayable only through the exact endpoint
	// incarnation that accepted it. Slug alone is unsafe: namespace deletion
	// followed by connector/namespace recreation could otherwise make an old
	// record cross a new authorization boundary. Legacy attributed rows lack
	// this identity and therefore fail closed.
	var replayGuards *compiledGuards
	if orig.Connector == "" {
		if orig.EndpointKind != "" || orig.EndpointGeneration != "" {
			return CallRecord{}, fmt.Errorf("call %d has inconsistent root endpoint identity", id)
		}
	} else {
		if orig.EndpointGeneration == "" {
			return CallRecord{}, fmt.Errorf("call %d has no endpoint generation and cannot be replayed safely", id)
		}
		switch orig.EndpointKind {
		case endpointKindConnector:
			connectors, supported := g.connectorStore()
			if !supported {
				return CallRecord{}, fmt.Errorf("connector store unavailable for replay")
			}
			connector, exists := connectors.VirtualConnector(ctx, orig.Connector)
			if !exists || connector.Epoch != orig.EndpointGeneration {
				return CallRecord{}, fmt.Errorf(
					"connector %q was deleted or replaced since call %d",
					orig.Connector,
					id,
				)
			}
			if !toSet(connector.Tools[orig.Account])[orig.Tool] {
				return CallRecord{}, fmt.Errorf(
					"connector %q no longer exposes %s/%s",
					orig.Connector,
					orig.Account,
					orig.Tool,
				)
			}
			guards := compileGuards(connector)
			replayGuards = &guards
		case endpointKindNamespace:
			namespaces, supported := g.namespaceStore()
			if !supported {
				return CallRecord{}, fmt.Errorf("namespace store unavailable for replay")
			}
			namespace, exists := namespaces.Namespace(ctx, orig.Connector)
			if !exists || namespace.Epoch != orig.EndpointGeneration {
				return CallRecord{}, fmt.Errorf(
					"namespace %q was deleted or replaced since call %d",
					orig.Connector,
					id,
				)
			}
			if !toSet(namespace.Accounts)[orig.Account] {
				return CallRecord{}, fmt.Errorf(
					"namespace %q no longer includes account %q",
					orig.Connector,
					orig.Account,
				)
			}
		default:
			return CallRecord{}, fmt.Errorf("call %d has unknown endpoint kind %q", id, orig.EndpointKind)
		}
	}

	// The tool must still be live: the CURRENT cached definition supplies the
	// annotations for the read-only check, and its absence means the account
	// was removed or the tool no longer exists / was curated off.
	g.mu.Lock()
	var tool mcp.Tool
	found := false
	for _, ct := range g.cached[orig.Account] {
		if ct.sourceName == orig.Tool {
			tool, found = ct.tool, true
			break
		}
	}
	g.mu.Unlock()
	if !found {
		return CallRecord{}, fmt.Errorf("account %q has no live tool %q (account removed or tool gone)", orig.Account, orig.Tool)
	}
	if !readOnlyTool(tool, orig.Tool) && !force {
		return CallRecord{}, ErrReplayForceRequired
	}

	var args map[string]any
	if err := json.Unmarshal([]byte(orig.Args), &args); err != nil {
		return CallRecord{}, fmt.Errorf("recorded args are not valid JSON (truncated by the size cap?): %v", err)
	}
	a, ok := g.store.Account(orig.Account)
	if !ok {
		return CallRecord{}, fmt.Errorf("account %q not found", orig.Account)
	}

	start := time.Now()
	execution := g.executeUpstream(
		ctx,
		UsageCallMeta{
			Account: orig.Account, Tool: orig.Tool, Connector: orig.Connector, Replay: true,
		},
		args,
		func(callCtx context.Context) (*mcp.CallToolResult, error) {
			return g.upstreamFor(a).CallTool(callCtx, orig.Tool, args)
		},
	)
	if execution.usageErr != nil {
		return CallRecord{}, execution.usageErr
	}
	res, callErr := execution.result, execution.callErr
	// A connector-attributed replay re-applies that exact incarnation's current
	// response guards. Identity was validated against durable store state above
	// before any upstream dispatch.
	var guard string
	if replayGuards != nil && callErr == nil && res != nil {
		res, guard = applyGuards(res, *replayGuards)
	}
	rec := CallRecord{
		Account: orig.Account, Tool: orig.Tool, OK: callErr == nil,
		Ms:                 time.Since(start).Milliseconds(),
		Connector:          orig.Connector, // attribute replay to the validated endpoint
		EndpointKind:       orig.EndpointKind,
		EndpointGeneration: orig.EndpointGeneration,
		Decision:           "replay",
		Args:               clampPayload(orig.Args, maxPayloadBytes),
		Guard:              guard,
	}
	if res != nil {
		rec.Result = marshalPayload(res)
	}
	if callErr != nil {
		rec.Error = callErr.Error()
	}
	g.audit.LogCall(rec)
	return rec, nil
}

package engine

import (
	"net/http"
	"time"
)

// Evidence is deliberately a bounded view of retained audit records, not a
// claim about every historical call or whether a model followed context.
type controlConnectionEvidence struct {
	CheckedAt         time.Time  `json:"checked_at"`
	ToolCallAt        *time.Time `json:"tool_call_at,omitempty"`
	SkillsRetrievedAt *time.Time `json:"skills_retrieved_at,omitempty"`
	MemoryRecalledAt  *time.Time `json:"memory_recalled_at,omitempty"`
}

func (c *ConsoleAPI) handleControlMCPClientConnectionEvidence(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		controlWire.writeMethodNotAllowed(w, http.MethodGet)
		return
	}
	store, actor, failure := c.mcpClientManagement(r)
	if failure != nil {
		controlWire.writeFailure(w, failure)
		return
	}
	client, failure := c.managedMCPClient(r, store, actor)
	if failure != nil {
		controlWire.writeFailure(w, failure)
		return
	}
	audit, ok := c.store.(AuditSink)
	if !ok {
		writeControlProblem(w, http.StatusNotImplemented, controlCodeCapabilityUnavailable, "connection evidence is unavailable")
		return
	}
	calls, err := audit.RecentCalls(r.Context(), 500)
	if err != nil {
		writeControlProblem(w, http.StatusBadGateway, controlCodeEngineUnavailable, "connection evidence is unavailable")
		return
	}
	result := controlConnectionEvidence{CheckedAt: time.Now().UTC()}
	for _, call := range calls {
		if !call.OK || call.Connector != client.Slug || call.EndpointKind != endpointKindClient || call.EndpointGeneration != client.Epoch {
			continue
		}
		update := func(target **time.Time) {
			if *target == nil || call.TS.After(**target) {
				at := call.TS.UTC()
				*target = &at
			}
		}
		update(&result.ToolCallAt)
		if call.Tool == "library_skill_activation" {
			update(&result.SkillsRetrievedAt)
		}
		if call.Tool == "library_memory_recall" || call.Tool == "library_memory_read" {
			update(&result.MemoryRecalledAt)
		}
	}
	writeJSON(w, http.StatusOK, result)
}

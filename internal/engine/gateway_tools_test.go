package engine

import (
	"context"
	"encoding/json"
	"testing"
)

// TestListAccountToolsSizeBytes covers SOUR-10 (docs/design-upgrades/README.md
// §7 item 1): the tool catalog needs a real per-tool definition byte size
// instead of the hardcoded "Unknown" the frontend previously had no data for.
func TestListAccountToolsSizeBytes(t *testing.T) {
	g := newConnectorTestGateway(t, map[string][]string{
		"acct": {"search", "create_page"},
	})
	tools, err := g.ListAccountTools(context.Background(), "acct")
	if err != nil {
		t.Fatalf("ListAccountTools: %v", err)
	}
	if len(tools) != 2 {
		t.Fatalf("want 2 tools, got %d", len(tools))
	}
	for _, tool := range tools {
		if tool.SizeBytes <= 0 {
			t.Errorf("tool %q: want positive SizeBytes, got %d", tool.Name, tool.SizeBytes)
		}
		// Sanity bound: a two-word test tool's wire definition should be a
		// small fixed-overhead JSON object, not something wildly larger (a
		// regression that accidentally serialized, say, the whole Account
		// would blow well past this).
		if tool.SizeBytes > 500 {
			t.Errorf("tool %q: SizeBytes %d looks too large for a minimal test tool", tool.Name, tool.SizeBytes)
		}
	}
	// The field must actually reach the wire — writeJSON serializes ToolInfo
	// directly with no intermediate DTO, so a plain marshal round-trip is
	// sufficient to catch a future accidental omitempty/rename.
	encoded, err := json.Marshal(tools[0])
	if err != nil {
		t.Fatalf("marshal ToolInfo: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := decoded["sizeBytes"]; !ok {
		t.Errorf("encoded ToolInfo missing sizeBytes field: %s", encoded)
	}
}

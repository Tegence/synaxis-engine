package engine

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestHostedActivationSnapshotIsServiceOnlyAndAggregateOnly(t *testing.T) {
	mux, _, _, key, now, _, _ := hostedNamespaceConsole(t)

	owner := hostedNamespaceRequest(
		t,
		mux,
		key,
		now,
		"usr_owner",
		"owner",
		http.MethodGet,
		"/api/activation",
		"",
	)
	if owner.Code != http.StatusForbidden {
		t.Fatalf("owner activation status=%d body=%s; want 403", owner.Code, owner.Body)
	}

	service := hostedNamespaceRequest(
		t,
		mux,
		key,
		now,
		platformServiceActorID,
		"service",
		http.MethodGet,
		"/api/activation",
		"",
	)
	if service.Code != http.StatusOK {
		t.Fatalf("service activation status=%d body=%s", service.Code, service.Body)
	}
	var snapshot activationSnapshotDTO
	if err := json.Unmarshal(service.Body.Bytes(), &snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot.ConnectionCount != 2 {
		t.Fatalf("connection count=%d, want 2", snapshot.ConnectionCount)
	}
	var raw map[string]any
	if err := json.Unmarshal(service.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	if len(raw) != 1 {
		t.Fatalf("activation snapshot leaked connection metadata: %s", service.Body)
	}
}

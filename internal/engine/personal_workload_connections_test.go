package engine

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
)

func TestPersonalWorkloadServiceBoundaryAndSnapshot(t *testing.T) {
	h := newWorkloadConsole(t)
	ctx := context.Background()
	body := `{"name":"Personal helper","slug":"personal-helper","subject":"agt_personal","kind":"workload"}`
	client := decodeControlClient(t, h.control(platformServiceActorID, "service", http.MethodPost, "/control/v1/workload-clients", body), http.StatusCreated)
	if r := h.control(platformServiceActorID, "service", http.MethodPost, "/control/v1/workload-clients", `{"name":"Interactive backdoor","kind":"interactive"}`); r.Code != http.StatusForbidden {
		t.Fatalf("interactive service create=%d %s", r.Code, r.Body)
	}
	if r := h.control("usr_operator", "operator", http.MethodPost, "/control/v1/workload-clients", body); r.Code != http.StatusForbidden {
		t.Fatalf("operator service create=%d", r.Code)
	}
	folder, err := h.store.CreateConnectionNamespace(ctx, ConnectionNamespace{Label: "Personal", OwnerSubject: "usr_owner", CreatedBy: "usr_owner"})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.store.Create(ctx, Account{Name: "own_source", URL: "https://personal.example/mcp", ConnectionScope: ConnectionScopePersonal, OwnerSubject: "usr_owner", ConnectionNamespaceID: folder.ID}); err != nil {
		t.Fatal(err)
	}
	account, _ := h.store.Account("own_source")
	h.gateway.mu.Lock()
	h.gateway.cached[account.Name] = []cachedTool{{tool: mcp.NewTool(account.Name + "__get_item"), sourceName: "get_item", accountIncarnationID: account.IncarnationID, accountRevision: account.Revision, accountURL: account.URL}}
	h.gateway.mu.Unlock()
	path := "/control/v1/mcp-clients/" + client.ID + "/personal-connections"
	makeBody := func(owner string, ns []string, revision int64) string {
		raw, _ := json.Marshal(map[string]any{"ownerSubject": owner, "namespaceIds": ns, "scopeRevision": revision})
		return string(raw)
	}
	if r := h.control("usr_owner", "owner", http.MethodPut, path, makeBody("usr_owner", []string{folder.ID}, 1)); r.Code != http.StatusForbidden {
		t.Fatalf("human service impersonation=%d", r.Code)
	}
	if r := h.control(platformServiceActorID, "service", http.MethodPut, path, makeBody("usr_other", []string{folder.ID}, 1)); r.Code != http.StatusForbidden {
		t.Fatalf("foreign folder=%d %s", r.Code, r.Body)
	}
	if r := h.control(platformServiceActorID, "service", http.MethodPut, path, makeBody("usr_owner", []string{folder.ID}, 1)); r.Code != http.StatusOK {
		t.Fatalf("personal snapshot=%d %s", r.Code, r.Body)
	}
	grants, _ := h.store.ConnectionGrants(ctx)
	if len(grants) != 1 || !strings.HasPrefix(grants[0].ID, "cgr_self_") || !grants[0].RequireWriteApproval || grants[0].RecipientRef != client.Subject || len(grants[0].Tools) != 1 {
		t.Fatalf("snapshot=%+v", grants)
	}
	if !grants[0].PersonalWorkload || !grants[0].ExpiresAt.IsZero() || !connectionGrantAllows(grants[0], account, client.Subject, "get_item", time.Now().Add(2*365*24*time.Hour)) {
		t.Fatal("no-expiry personal agent gained a hidden annual source expiry")
	}
	expires := time.Now().UTC().Add(400 * 24 * time.Hour).Truncate(time.Second)
	renewed, _ := json.Marshal(map[string]any{"ownerSubject": "usr_owner", "namespaceIds": []string{folder.ID}, "scopeRevision": 2, "expiresAt": expires})
	if r := h.control(platformServiceActorID, "service", http.MethodPut, path, string(renewed)); r.Code != http.StatusOK {
		t.Fatalf("explicit personal expiry=%d %s", r.Code, r.Body)
	}
	grants, _ = h.store.ConnectionGrants(ctx)
	if len(grants) != 2 || grants[0].RevokedAt == nil || !grants[1].ExpiresAt.Equal(expires) || connectionGrantAllows(grants[1], account, client.Subject, "get_item", expires) {
		t.Fatalf("personal expiry did not replace old authority: %+v", grants)
	}
	if err := h.store.Create(ctx, Account{Name: "later_source", URL: "https://later.example/mcp", ConnectionScope: ConnectionScopePersonal, OwnerSubject: "usr_owner", ConnectionNamespaceID: folder.ID}); err != nil {
		t.Fatal(err)
	}
	if grants, _ := h.store.ConnectionGrants(ctx); len(grants) != 2 {
		t.Fatal("folder auto expanded")
	}
	if r := h.control(platformServiceActorID, "service", http.MethodPut, path, makeBody("usr_owner", nil, 2)); r.Code != http.StatusOK {
		t.Fatalf("remove=%d %s", r.Code, r.Body)
	}
	grants, _ = h.store.ConnectionGrants(ctx)
	if grants[0].RevokedAt == nil || grants[1].RevokedAt == nil {
		t.Fatal("removed selection retained capability")
	}
	if r := h.control(platformServiceActorID, "service", http.MethodPut, "/control/v1/subjects/usr_owner/access", `{"allowed":false}`); r.Code != http.StatusOK {
		t.Fatalf("deny=%d %s", r.Code, r.Body)
	}
	if r := h.control(platformServiceActorID, "service", http.MethodPut, path, makeBody("usr_owner", []string{folder.ID}, 3)); r.Code != http.StatusForbidden {
		t.Fatalf("denied owner=%d", r.Code)
	}
	if r := h.control(platformServiceActorID, "service", http.MethodGet, "/control/v1/connection-grants", ""); r.Code != http.StatusOK {
		t.Fatalf("service list=%d", r.Code)
	}
}

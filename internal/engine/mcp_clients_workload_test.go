package engine

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"narthex/backend/internal/oauthas"
)

func TestFileStoreMCPClientKindRoundTripsAndDefaultsToInteractive(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "accounts.json")
	store, err := LoadFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	interactive, err := store.CreateMCPClient(ctx, MCPClient{Name: "Codex", Subject: "usr_owner"})
	if err != nil {
		t.Fatal(err)
	}
	workload, err := store.CreateMCPClient(ctx, MCPClient{Name: "Cloud agent", Subject: "agt_1", Kind: MCPClientKindWorkload})
	if err != nil {
		t.Fatal(err)
	}
	if interactive.Kind != MCPClientKindInteractive || workload.Kind != MCPClientKindWorkload || workload.OAuthClientID != "" {
		t.Fatalf("created kinds interactive=%q workload=%q binding=%q", interactive.Kind, workload.Kind, workload.OAuthClientID)
	}
	for _, kind := range []MCPClientKind{"robot", "Workload", " workload"} {
		if _, err := store.CreateMCPClient(ctx, MCPClient{Name: "Bad " + string(kind), Subject: "agt_2", Kind: kind}); !errors.Is(err, ErrInvalidMCPClient) {
			t.Fatalf("create with kind %q err=%v; want ErrInvalidMCPClient", kind, err)
		}
	}

	reloaded, err := LoadFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []MCPClient{interactive, workload} {
		got, ok := reloaded.MCPClient(ctx, want.ID)
		if !ok || got.Kind != want.Kind {
			t.Fatalf("reloaded %s kind=%q ok=%v; want %q", want.ID, got.Kind, ok, want.Kind)
		}
	}

	// A record written before kinds existed loads as interactive, and the
	// normalized value is persisted on that first load.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	for _, entry := range document["mcp_clients"].([]any) {
		record := entry.(map[string]any)
		if record["id"] == interactive.ID {
			delete(record, "kind")
		}
	}
	legacy, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, legacy, 0o600); err != nil {
		t.Fatal(err)
	}
	migrated, err := LoadFileStore(path)
	if err != nil {
		t.Fatalf("load legacy record: %v", err)
	}
	if got, _ := migrated.MCPClient(ctx, interactive.ID); got.Kind != MCPClientKindInteractive {
		t.Fatalf("legacy record kind=%q; want interactive", got.Kind)
	}
	persisted, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var onDisk struct {
		MCPClients []struct {
			ID   string `json:"id"`
			Kind string `json:"kind"`
		} `json:"mcp_clients"`
	}
	if err := json.Unmarshal(persisted, &onDisk); err != nil {
		t.Fatal(err)
	}
	kinds := map[string]string{}
	for _, record := range onDisk.MCPClients {
		kinds[record.ID] = record.Kind
	}
	if len(kinds) != 2 || kinds[interactive.ID] != "interactive" || kinds[workload.ID] != "workload" {
		t.Fatalf("kinds on disk after the legacy load=%v; want both persisted", kinds)
	}

	// An unknown stored kind fails closed instead of being guessed.
	corrupt := strings.Replace(string(legacy), `"kind":"workload"`, `"kind":"robot"`, 1)
	if !strings.Contains(corrupt, `"kind":"robot"`) {
		t.Fatal("fixture did not contain the workload record")
	}
	if err := os.WriteFile(path, []byte(corrupt), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFileStore(path); !errors.Is(err, ErrInvalidMCPClient) {
		t.Fatalf("load with unknown kind err=%v; want ErrInvalidMCPClient", err)
	}
}

func TestFileStoreWorkloadIdentityBindingIsReservedIdempotentAndKeepsEpoch(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "accounts.json")
	store, err := LoadFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	bound := exerciseMCPClientWorkloadIdentity(t, ctx, store, "file")

	// The binding written above survives a restart unchanged.
	reloaded, err := LoadFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	current, ok := reloaded.MCPClient(ctx, bound.ID)
	if !ok || current.Kind != MCPClientKindWorkload || current.OAuthClientID != workloadOAuthClientID(bound.ID) ||
		current.Epoch != bound.Epoch || current.Revision != bound.Revision {
		t.Fatalf("reloaded=%+v ok=%v; want %+v", current, ok, bound)
	}
}

// exerciseMCPClientWorkloadIdentity is the store-parity contract for kinds
// and the reserved workload binding, shared by FileStore and PgStore tests.
// Every record it creates has a subject ending in suffix (agt_, usr_, and
// agt_retired_ prefixes) so a Postgres caller can remove exactly those rows.
// It leaves one active, bound workload client behind and returns it.
func exerciseMCPClientWorkloadIdentity(t *testing.T, ctx context.Context, store MCPClientStore, suffix string) MCPClient {
	t.Helper()
	workload, err := store.CreateMCPClient(ctx, MCPClient{Name: "Cloud agent " + suffix, Subject: "agt_" + suffix, Kind: MCPClientKindWorkload})
	if err != nil {
		t.Fatalf("create workload client: %v", err)
	}
	interactive, err := store.CreateMCPClient(ctx, MCPClient{Name: "Codex " + suffix, Subject: "usr_" + suffix})
	if err != nil {
		t.Fatalf("create interactive client: %v", err)
	}
	if workload.Kind != MCPClientKindWorkload || interactive.Kind != MCPClientKindInteractive {
		t.Fatalf("kinds workload=%q interactive=%q", workload.Kind, interactive.Kind)
	}

	if _, err := store.BindMCPClientWorkloadIdentity(ctx, interactive.ID); !errors.Is(err, ErrMCPClientKind) {
		t.Fatalf("workload bind of an interactive client err=%v; want ErrMCPClientKind", err)
	}
	if _, err := store.BindMCPClientWorkloadIdentity(ctx, "mcpcli_missing_"+suffix); !errors.Is(err, ErrMCPClientNotFound) {
		t.Fatalf("workload bind of an unknown client err=%v; want ErrMCPClientNotFound", err)
	}
	bound, err := store.BindMCPClientWorkloadIdentity(ctx, workload.ID)
	if err != nil {
		t.Fatalf("workload bind: %v", err)
	}
	// Revision records the durable change; the epoch deliberately does not
	// move because no token could exist while the client was unbound.
	if bound.OAuthClientID != workloadOAuthClientID(workload.ID) || bound.Revision != workload.Revision+1 || bound.Epoch != workload.Epoch {
		t.Fatalf("bound=%+v; before=%+v", bound, workload)
	}
	again, err := store.BindMCPClientWorkloadIdentity(ctx, workload.ID)
	if err != nil || again.Revision != bound.Revision || again.Epoch != bound.Epoch || again.OAuthClientID != bound.OAuthClientID {
		t.Fatalf("repeated bind=%+v err=%v; want the unchanged record %+v", again, err, bound)
	}
	if byOAuth, ok := store.ActiveMCPClientByOAuthClientID(ctx, workloadOAuthClientID(workload.ID)); !ok || byOAuth.ID != workload.ID {
		t.Fatalf("lookup by workload identity=%+v ok=%v", byOAuth, ok)
	}

	// The consent path can neither bind a workload client nor hand the
	// reserved namespace to an interactive one, whoever the actor is.
	owner := PlatformActor{UserID: workload.Subject, Role: "owner"}
	if MCPClientAllowsActor(bound, owner) {
		t.Fatal("a human actor was admitted to a workload client")
	}
	if _, err := store.BindMCPClientOAuthClient(ctx, workload.ID, "mcp_v1.dcr."+suffix, MCPClientPrecondition{ID: workload.ID, Revision: bound.Revision}, owner); !errors.Is(err, ErrInvalidMCPClient) {
		t.Fatalf("DCR bind of a workload client err=%v; want ErrInvalidMCPClient", err)
	}
	if _, err := store.BindMCPClientOAuthClient(ctx, interactive.ID, workloadOAuthClientID(interactive.ID), MCPClientPrecondition{ID: interactive.ID, Revision: interactive.Revision}, PlatformActor{UserID: interactive.Subject, Role: "operator"}); !errors.Is(err, ErrInvalidMCPClient) {
		t.Fatalf("reserved identity on an interactive client err=%v; want ErrInvalidMCPClient", err)
	}

	// Kind is immutable; echoing the current kind is an ordinary update.
	if _, err := store.UpdateMCPClient(ctx, MCPClient{ID: workload.ID, Name: bound.Name, Kind: MCPClientKindInteractive}, MCPClientPrecondition{ID: workload.ID, Revision: bound.Revision}); !errors.Is(err, ErrInvalidMCPClient) {
		t.Fatalf("kind change err=%v; want ErrInvalidMCPClient", err)
	}
	renamed, err := store.UpdateMCPClient(ctx, MCPClient{ID: workload.ID, Name: "Renamed agent " + suffix, Kind: MCPClientKindWorkload}, MCPClientPrecondition{ID: workload.ID, Revision: bound.Revision})
	if err != nil || renamed.Kind != MCPClientKindWorkload || renamed.OAuthClientID != bound.OAuthClientID {
		t.Fatalf("rename=%+v err=%v", renamed, err)
	}

	// A reset clears the reserved identity and rotates the epoch like any
	// other reset; the next workload bind restores it without rotating.
	reset, err := store.ResetMCPClientOAuthClient(ctx, workload.ID, MCPClientPrecondition{ID: workload.ID, Revision: renamed.Revision})
	if err != nil || reset.OAuthClientID != "" || reset.Epoch == renamed.Epoch {
		t.Fatalf("reset=%+v err=%v", reset, err)
	}
	rebound, err := store.BindMCPClientWorkloadIdentity(ctx, workload.ID)
	if err != nil || rebound.OAuthClientID != workloadOAuthClientID(workload.ID) || rebound.Epoch != reset.Epoch || rebound.Revision != reset.Revision+1 {
		t.Fatalf("rebind after reset=%+v err=%v; reset=%+v", rebound, err, reset)
	}

	// Kind is checked before status, so a revoked interactive record still
	// reads as a kind refusal, while a revoked workload client is terminal.
	revokedInteractive, err := store.RevokeMCPClient(ctx, interactive.ID, "usr_owner", MCPClientPrecondition{ID: interactive.ID, Revision: interactive.Revision})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.BindMCPClientWorkloadIdentity(ctx, revokedInteractive.ID); !errors.Is(err, ErrMCPClientKind) {
		t.Fatalf("workload bind of a revoked interactive client err=%v; want ErrMCPClientKind", err)
	}
	second, err := store.CreateMCPClient(ctx, MCPClient{Name: "Retired agent " + suffix, Subject: "agt_retired_" + suffix, Kind: MCPClientKindWorkload})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.RevokeMCPClient(ctx, second.ID, "usr_owner", MCPClientPrecondition{ID: second.ID, Revision: second.Revision}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.BindMCPClientWorkloadIdentity(ctx, second.ID); !errors.Is(err, ErrMCPClientRevoked) {
		t.Fatalf("workload bind of a revoked workload client err=%v; want ErrMCPClientRevoked", err)
	}
	return rebound
}

// TestWorkloadClientsRefuseInteractiveConsent proves the browser consent
// path can never bind a workload client, including when the consenting
// actor's user ID equals the workload subject (the self-hosted local admin),
// and that the refusal is indistinguishable from a subject mismatch.
func TestWorkloadClientsRefuseInteractiveConsent(t *testing.T) {
	ctx := context.Background()
	store, gateway := newMCPClientGateway(t)
	hostedWorkload, err := store.CreateMCPClient(ctx, MCPClient{Name: "Owner agent", Subject: "usr_owner", Kind: MCPClientKindWorkload})
	if err != nil {
		t.Fatal(err)
	}
	localWorkload, err := store.CreateMCPClient(ctx, MCPClient{Name: "Local agent", Subject: "local-admin", Kind: MCPClientKindWorkload})
	if err != nil {
		t.Fatal(err)
	}
	localInteractive, err := store.CreateMCPClient(ctx, MCPClient{Name: "Local Codex", Subject: "local-admin", CreatedBy: "local-admin"})
	if err != nil {
		t.Fatal(err)
	}
	if err := gateway.RefreshMCPClients(ctx); err != nil {
		t.Fatal(err)
	}

	// Hosted consent calls AuthorizeMCPConsent with the signed subject/role.
	workloadErr := gateway.AuthorizeMCPConsent(ctx, "usr_owner", "owner", "mcp_v1.dcr-owner", "/mcp/clients/"+hostedWorkload.Slug)
	mismatchErr := gateway.AuthorizeMCPConsent(ctx, "usr_other", "owner", "mcp_v1.dcr-other", "/mcp/clients/"+localInteractive.Slug)
	if workloadErr == nil || !errors.Is(workloadErr, errMCPClientConsentRefused) || mismatchErr == nil || workloadErr.Error() != mismatchErr.Error() {
		t.Fatalf("workload consent err=%v, subject mismatch err=%v; want the same refusal", workloadErr, mismatchErr)
	}
	if current, _ := store.MCPClient(ctx, hostedWorkload.ID); current.OAuthClientID != "" || current.Revision != hostedWorkload.Revision {
		t.Fatalf("refused consent changed the workload client: %+v", current)
	}

	// Self-hosted password consent: the local admin may bind its interactive
	// client but is refused for a workload client with the very same subject.
	const issuer = "https://engine.example"
	authorization := oauthas.New(issuer, "pw", "consent-test-secret")
	if err := authorization.ConfigureTokenGeneration(ctx, store); err != nil {
		t.Fatal(err)
	}
	authorization.SetEpochLookup(func(path string) (string, bool) {
		slug, ok := mcpClientSlugFromResource(path)
		if !ok {
			return "", false
		}
		return gateway.MCPClientEpoch(slug)
	})
	authorization.SetClientResourceAuthorizer(gateway.MCPClientAllowsOAuthClient)
	authorization.SetLocalConsentAuthorizer(gateway.AuthorizeMCPConsent)
	mux := http.NewServeMux()
	authorization.Routes(mux)
	registration := httptest.NewRecorder()
	mux.ServeHTTP(registration, httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(`{"client_name":"consent test","redirect_uris":["https://client.example/callback"]}`)))
	var registered struct {
		ClientID string `json:"client_id"`
	}
	if registration.Code != http.StatusCreated || json.Unmarshal(registration.Body.Bytes(), &registered) != nil || registered.ClientID == "" {
		t.Fatalf("register=%d body=%s", registration.Code, registration.Body)
	}
	consent := func(slug string) *url.URL {
		t.Helper()
		sum := sha256.Sum256([]byte(strings.Repeat("v", 64)))
		form := url.Values{
			"client_id":             {registered.ClientID},
			"redirect_uri":          {"https://client.example/callback"},
			"response_type":         {"code"},
			"code_challenge_method": {"S256"},
			"code_challenge":        {base64.RawURLEncoding.EncodeToString(sum[:])},
			"resource":              {issuer + "/mcp/clients/" + slug},
			"password":              {"pw"},
		}
		request := httptest.NewRequest(http.MethodPost, "/authorize", strings.NewReader(form.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		if response.Code != http.StatusFound {
			t.Fatalf("authorize %s=%d body=%s", slug, response.Code, response.Body)
		}
		location, err := url.Parse(response.Header().Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		return location
	}
	refused := consent(localWorkload.Slug)
	if refused.Query().Get("error") != "access_denied" || refused.Query().Get("code") != "" {
		t.Fatalf("workload consent redirect=%s; want access_denied without a code", refused)
	}
	if current, _ := store.MCPClient(ctx, localWorkload.ID); current.OAuthClientID != "" {
		t.Fatalf("password consent bound a workload client: %+v", current)
	}
	allowed := consent(localInteractive.Slug)
	if allowed.Query().Get("code") == "" || allowed.Query().Get("error") != "" {
		t.Fatalf("interactive consent redirect=%s; want a code", allowed)
	}
	if current, _ := store.MCPClient(ctx, localInteractive.ID); current.OAuthClientID != registered.ClientID {
		t.Fatalf("interactive consent binding=%q; want %q", current.OAuthClientID, registered.ClientID)
	}
}

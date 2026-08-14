package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"narthex/backend/internal/engine"
)

func TestNewEngineHTTPServerPreservesStreamingResponses(t *testing.T) {
	server := newEngineHTTPServer("8080", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	if server.ReadHeaderTimeout != 10*time.Second {
		t.Fatalf("ReadHeaderTimeout = %s, want 10s", server.ReadHeaderTimeout)
	}
	if server.WriteTimeout != 0 {
		t.Fatalf("WriteTimeout = %s, want unset for streamable MCP", server.WriteTimeout)
	}
}

func TestServeEngineHTTPDrainsActiveRequestsOnContextCancellation(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	started := make(chan struct{})
	release := make(chan struct{})
	var startOnce sync.Once
	var releaseOnce sync.Once
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		startOnce.Do(func() { close(started) })
		<-release
		w.WriteHeader(http.StatusOK)
	})}
	serveErr := make(chan error, 1)
	go func() { serveErr <- serveEngineHTTP(ctx, server, listener) }()

	clientErr := make(chan error, 1)
	go func() {
		client := &http.Client{Transport: &http.Transport{Proxy: nil}}
		response, err := client.Get("http://" + listener.Addr().String())
		if err == nil {
			response.Body.Close()
		}
		clientErr <- err
	}()

	select {
	case <-started:
	case <-time.After(time.Second):
		releaseOnce.Do(func() { close(release) })
		t.Fatal("active request never reached the server")
	}
	cancel()
	// Shutdown must wait for this live request rather than dropping its stream
	// or returning before the handler is allowed to finish.
	select {
	case err := <-serveErr:
		releaseOnce.Do(func() { close(release) })
		t.Fatalf("server returned before active request drained: %v", err)
	case <-time.After(75 * time.Millisecond):
	}
	releaseOnce.Do(func() { close(release) })

	select {
	case err := <-clientErr:
		if err != nil {
			t.Fatalf("active request did not drain successfully: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("active request did not finish")
	}
	select {
	case err := <-serveErr:
		if err != nil {
			t.Fatalf("serveEngineHTTP shutdown: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not stop after active request drained")
	}
}

type testShutdownDependency struct {
	calls int
	err   error
}

func (d *testShutdownDependency) Shutdown(context.Context) error {
	d.calls++
	return d.err
}

type testCloseDependency struct{ calls int }

func (d *testCloseDependency) Close() { d.calls++ }

func TestShutdownEngineDependenciesUsesGracefulHookBeforeCloseFallback(t *testing.T) {
	wantErr := errors.New("flush audit")
	shutdowner := &testShutdownDependency{err: wantErr}
	closer := &testCloseDependency{}
	if err := shutdownEngineDependencies(context.Background(), shutdowner, closer); !errors.Is(err, wantErr) {
		t.Fatalf("shutdownEngineDependencies error = %v, want %v", err, wantErr)
	}
	if shutdowner.calls != 1 {
		t.Fatalf("Shutdown calls = %d, want 1", shutdowner.calls)
	}
	if closer.calls != 1 {
		t.Fatalf("Close calls = %d, want 1", closer.calls)
	}
}

func TestAdminTokenFromEnv(t *testing.T) {
	t.Run("Synaxis name has precedence", func(t *testing.T) {
		t.Setenv("SYNAXIS_ADMIN_TOKEN", "synaxis-token")
		t.Setenv("ENGINE_ADMIN_TOKEN", "legacy-token")
		if got := adminTokenFromEnv(); got != "synaxis-token" {
			t.Fatalf("adminTokenFromEnv() = %q, want Synaxis token", got)
		}
	})

	t.Run("legacy engine alias remains supported", func(t *testing.T) {
		t.Setenv("SYNAXIS_ADMIN_TOKEN", "")
		t.Setenv("ENGINE_ADMIN_TOKEN", "legacy-token")
		if got := adminTokenFromEnv(); got != "legacy-token" {
			t.Fatalf("adminTokenFromEnv() = %q, want legacy token", got)
		}
	})

	t.Run("unset leaves machine authentication disabled", func(t *testing.T) {
		t.Setenv("SYNAXIS_ADMIN_TOKEN", "")
		t.Setenv("ENGINE_ADMIN_TOKEN", "")
		if got := adminTokenFromEnv(); got != "" {
			t.Fatalf("adminTokenFromEnv() = %q, want empty", got)
		}
	})
}

func TestLegacyAdminEnabledFromEnv(t *testing.T) {
	t.Run("default is disabled", func(t *testing.T) {
		t.Setenv("SYNAXIS_ENABLE_LEGACY_ADMIN", "")
		t.Setenv("ENGINE_ENABLE_LEGACY_ADMIN", "")
		if legacyAdminEnabledFromEnv() {
			t.Fatal("legacy admin must be disabled unless explicitly enabled")
		}
	})

	t.Run("Synaxis setting has precedence", func(t *testing.T) {
		t.Setenv("SYNAXIS_ENABLE_LEGACY_ADMIN", "true")
		t.Setenv("ENGINE_ENABLE_LEGACY_ADMIN", "false")
		if !legacyAdminEnabledFromEnv() {
			t.Fatal("Synaxis setting should enable legacy admin")
		}
	})

	t.Run("legacy alias remains supported", func(t *testing.T) {
		t.Setenv("SYNAXIS_ENABLE_LEGACY_ADMIN", "")
		t.Setenv("ENGINE_ENABLE_LEGACY_ADMIN", "true")
		if !legacyAdminEnabledFromEnv() {
			t.Fatal("legacy setting should enable legacy admin")
		}
	})

	t.Run("invalid values fail closed", func(t *testing.T) {
		t.Setenv("SYNAXIS_ENABLE_LEGACY_ADMIN", "sometimes")
		if legacyAdminEnabledFromEnv() {
			t.Fatal("invalid legacy admin setting must fail closed")
		}
	})
}

func TestLocalAdminAuthEnabledFromEnv(t *testing.T) {
	t.Run("standard self-hosted default is disabled", func(t *testing.T) {
		t.Setenv("ENGINE_LOCAL_ADMIN_AUTH_ENABLED", "")
		if localAdminAuthEnabledFromEnv() {
			t.Fatal("local admin auth must be disabled unless explicitly enabled")
		}
	})
	t.Run("explicit enable opens local login", func(t *testing.T) {
		t.Setenv("ENGINE_LOCAL_ADMIN_AUTH_ENABLED", "true")
		if !localAdminAuthEnabledFromEnv() {
			t.Fatal("explicit local admin auth enable was ignored")
		}
	})
	t.Run("invalid values fail closed", func(t *testing.T) {
		t.Setenv("ENGINE_LOCAL_ADMIN_AUTH_ENABLED", "sometimes")
		if localAdminAuthEnabledFromEnv() {
			t.Fatal("invalid local admin auth setting must fail closed")
		}
	})
}

func clearStartupSecurityEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		"ENGINE_PASSWORD",
		"ENGINE_SECRET",
		"ENGINE_DEVELOPMENT_MODE",
		"ENGINE_LOCAL_ADMIN_AUTH_ENABLED",
		"SYNAXIS_ENABLE_LEGACY_ADMIN",
		"ENGINE_ENABLE_LEGACY_ADMIN",
		"SYNAXIS_WORKSPACE_ID",
		"ENGINE_ENCRYPTION_KEY",
	} {
		t.Setenv(key, "")
	}
}

func TestStartupSecurityConfigFailsClosedByDefault(t *testing.T) {
	t.Run("missing credentials stop startup", func(t *testing.T) {
		clearStartupSecurityEnv(t)
		if _, err := startupSecurityConfigFromEnv(); err == nil {
			t.Fatal("unattended self-hosted Engine accepted missing password and secret")
		}
	})

	t.Run("configured self-hosted Engine keeps password routes disabled", func(t *testing.T) {
		clearStartupSecurityEnv(t)
		t.Setenv("ENGINE_PASSWORD", "unique-self-hosted-password")
		t.Setenv("ENGINE_SECRET", "unique-self-hosted-secret")
		config, err := startupSecurityConfigFromEnv()
		if err != nil {
			t.Fatalf("startupSecurityConfigFromEnv(): %v", err)
		}
		if config.localAdminAuth || config.legacyAdmin {
			t.Fatalf("default self-hosted password routes local=%v legacy=%v, want both disabled", config.localAdminAuth, config.legacyAdmin)
		}
		if config.generatedPassword || config.generatedSecret {
			t.Fatal("configured self-hosted Engine unexpectedly generated credentials")
		}
	})

	t.Run("invalid development flag cannot unlock convenience mode", func(t *testing.T) {
		clearStartupSecurityEnv(t)
		t.Setenv("ENGINE_DEVELOPMENT_MODE", "sometimes")
		if _, err := startupSecurityConfigFromEnv(); err == nil {
			t.Fatal("invalid development flag was accepted")
		}
	})
}

func TestStartupSecurityConfigDevelopmentAndLegacyOptIns(t *testing.T) {
	clearStartupSecurityEnv(t)
	t.Setenv("ENGINE_DEVELOPMENT_MODE", "true")
	config, err := startupSecurityConfigFromEnv()
	if err != nil {
		t.Fatalf("development config: %v", err)
	}
	if !config.development || !config.generatedPassword || !config.generatedSecret {
		t.Fatalf("development credentials were not generated: %+v", config)
	}
	if config.password == "" || config.secret == "" {
		t.Fatal("development config generated an empty credential")
	}
	if !config.localAdminAuth {
		t.Fatal("explicit development mode should enable the local console")
	}
	if config.legacyAdmin {
		t.Fatal("development mode must not implicitly re-enable legacy administration")
	}

	t.Setenv("SYNAXIS_ENABLE_LEGACY_ADMIN", "true")
	config, err = startupSecurityConfigFromEnv()
	if err != nil {
		t.Fatalf("explicit legacy development config: %v", err)
	}
	if !config.legacyAdmin {
		t.Fatal("explicit legacy opt-in was ignored")
	}
}

func TestStartupSecurityConfigHostedModeRemainsMachineOnly(t *testing.T) {
	clearStartupSecurityEnv(t)
	t.Setenv("SYNAXIS_WORKSPACE_ID", "workspace-one")
	t.Setenv("ENGINE_PASSWORD", "hosted-engine-password")
	t.Setenv("ENGINE_SECRET", "hosted-engine-secret")
	// Hosted deployments must remain protected even if an inherited environment
	// attempts to re-enable self-hosted password routes.
	t.Setenv("ENGINE_LOCAL_ADMIN_AUTH_ENABLED", "true")
	t.Setenv("SYNAXIS_ENABLE_LEGACY_ADMIN", "true")
	config, err := startupSecurityConfigFromEnv()
	if err != nil {
		t.Fatalf("hosted config: %v", err)
	}
	if !config.hosted || config.localAdminAuth || config.legacyAdmin {
		t.Fatalf("hosted password routes local=%v legacy=%v, want both disabled", config.localAdminAuth, config.legacyAdmin)
	}
}

func TestEncryptionKeyFromEnvRequiresHostedKey(t *testing.T) {
	t.Run("self-hosted may omit encryption for local development", func(t *testing.T) {
		t.Setenv("ENGINE_ENCRYPTION_KEY", "")
		key, err := encryptionKeyFromEnv(false)
		if err != nil || key != "" {
			t.Fatalf("encryptionKeyFromEnv(false) = %q, %v", key, err)
		}
	})
	t.Run("hosted workspace rejects a missing or whitespace key", func(t *testing.T) {
		for _, value := range []string{"", "  \t"} {
			t.Setenv("ENGINE_ENCRYPTION_KEY", value)
			if _, err := encryptionKeyFromEnv(true); err == nil {
				t.Fatalf("hosted workspace accepted encryption key %q", value)
			}
		}
	})
	t.Run("hosted workspace retains a configured key for validation", func(t *testing.T) {
		key := base64.StdEncoding.EncodeToString(make([]byte, 32))
		t.Setenv("ENGINE_ENCRYPTION_KEY", key)
		got, err := encryptionKeyFromEnv(true)
		if err != nil || got != key {
			t.Fatalf("encryptionKeyFromEnv(true) = %q, %v", got, err)
		}
	})
}

type fakeEncryptionStore struct {
	cipher       *engine.Cipher
	migrationErr error
}

func (s *fakeEncryptionStore) SetCipher(cipher *engine.Cipher) { s.cipher = cipher }
func (s *fakeEncryptionStore) EncryptExisting(context.Context) error {
	return s.migrationErr
}

func TestConfigureStoreEncryptionFailsClosedOnMigrationFailure(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	t.Run("no key keeps explicitly local storage plaintext", func(t *testing.T) {
		enabled, err := configureStoreEncryption(context.Background(), nil, "")
		if err != nil || enabled {
			t.Fatalf("configure empty key = enabled=%v err=%v", enabled, err)
		}
	})
	t.Run("invalid key is rejected before a store is mutated", func(t *testing.T) {
		store := &fakeEncryptionStore{}
		if _, err := configureStoreEncryption(context.Background(), store, "not-a-key"); err == nil {
			t.Fatal("invalid encryption key was accepted")
		}
		if store.cipher != nil {
			t.Fatal("invalid key configured a cipher on the store")
		}
	})
	t.Run("migration failure is returned to the startup caller", func(t *testing.T) {
		migrationErr := errors.New("corrupt encrypted row")
		store := &fakeEncryptionStore{migrationErr: migrationErr}
		enabled, err := configureStoreEncryption(context.Background(), store, key)
		if enabled || !errors.Is(err, migrationErr) {
			t.Fatalf("configure migration error = enabled=%v err=%v", enabled, err)
		}
		if store.cipher == nil {
			t.Fatal("configured encryption key was not installed before migration")
		}
	})
	t.Run("successful migration enables encryption", func(t *testing.T) {
		store := &fakeEncryptionStore{}
		enabled, err := configureStoreEncryption(context.Background(), store, key)
		if err != nil || !enabled || store.cipher == nil {
			t.Fatalf("configure success = enabled=%v cipher=%v err=%v", enabled, store.cipher, err)
		}
	})
}

func TestPasswordAdminRoutesAreAbsentWithoutExplicitOptIn(t *testing.T) {
	clearStartupSecurityEnv(t)
	t.Setenv("ENGINE_PASSWORD", "unique-self-hosted-password")
	t.Setenv("ENGINE_SECRET", "unique-self-hosted-secret")
	config, err := startupSecurityConfigFromEnv()
	if err != nil {
		t.Fatalf("startup security config: %v", err)
	}

	mux := http.NewServeMux()
	console := engine.NewConsoleAPI(
		nil, nil, nil,
		config.password, config.secret,
		"https://engine.example", "http://localhost:3000", "",
		engine.WithLocalAdminAuth(config.localAdminAuth),
	)
	console.Routes(mux)
	registerLegacyAdminRoutes(mux, config.legacyAdmin, config.password, "https://engine.example", nil, nil, nil)

	for _, path := range []string{"/api/login", "/admin/token"} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("default %s = %d, want 404", path, rec.Code)
		}
	}
}

func TestExplicitLegacyAdminOptInRegistersCompatibilityForm(t *testing.T) {
	clearStartupSecurityEnv(t)
	t.Setenv("ENGINE_DEVELOPMENT_MODE", "true")
	t.Setenv("SYNAXIS_ENABLE_LEGACY_ADMIN", "true")
	config, err := startupSecurityConfigFromEnv()
	if err != nil {
		t.Fatalf("development legacy config: %v", err)
	}
	mux := http.NewServeMux()
	registerLegacyAdminRoutes(mux, config.legacyAdmin, config.password, "https://engine.example", nil, nil, nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin/token", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("explicit legacy /admin/token = %d, want 200", rec.Code)
	}
}

func TestHostedConsentConfigFromEnv(t *testing.T) {
	publicKey := make([]byte, ed25519.PublicKeySize)
	for i := range publicKey {
		publicKey[i] = byte(i)
	}
	encoded := base64.StdEncoding.EncodeToString(publicKey)

	t.Run("unset leaves password consent configured", func(t *testing.T) {
		t.Setenv("ENGINE_CONSENT_URL", "")
		t.Setenv("ENGINE_CONSENT_PUBLIC_KEY", "")
		url, key, err := hostedConsentConfigFromEnv()
		if err != nil || url != "" || key != nil {
			t.Fatalf("hostedConsentConfigFromEnv() = %q, %v, %v", url, key, err)
		}
	})
	t.Run("both values configure delegation", func(t *testing.T) {
		t.Setenv("ENGINE_CONSENT_URL", "https://app.example/oauth/consent")
		t.Setenv("ENGINE_CONSENT_PUBLIC_KEY", encoded)
		url, key, err := hostedConsentConfigFromEnv()
		if err != nil {
			t.Fatalf("hostedConsentConfigFromEnv(): %v", err)
		}
		if url != "https://app.example/oauth/consent" || string(key) != string(publicKey) {
			t.Fatalf("unexpected hosted config URL=%q key=%x", url, key)
		}
	})
	t.Run("partial configuration fails", func(t *testing.T) {
		t.Setenv("ENGINE_CONSENT_URL", "https://app.example/oauth/consent")
		t.Setenv("ENGINE_CONSENT_PUBLIC_KEY", "")
		if _, _, err := hostedConsentConfigFromEnv(); err == nil {
			t.Fatal("partial hosted consent configuration must fail")
		}
	})
	t.Run("wrong key size fails", func(t *testing.T) {
		t.Setenv("ENGINE_CONSENT_URL", "https://app.example/oauth/consent")
		t.Setenv("ENGINE_CONSENT_PUBLIC_KEY", base64.StdEncoding.EncodeToString([]byte("short")))
		if _, _, err := hostedConsentConfigFromEnv(); err == nil {
			t.Fatal("invalid hosted consent key must fail")
		}
	})
}

func TestHostedActorVerifierFromEnvFailsClosedOutsideSelfHosting(t *testing.T) {
	publicKey := make(ed25519.PublicKey, ed25519.PublicKeySize)
	t.Run("self-hosted has no verifier", func(t *testing.T) {
		t.Setenv("SYNAXIS_WORKSPACE_ID", "")
		verifier, err := hostedActorVerifierFromEnv(publicKey, "https://engine.example")
		if err != nil || verifier != nil {
			t.Fatalf("self-hosted actor verifier=%v err=%v", verifier, err)
		}
	})
	t.Run("hosted workspace requires public key", func(t *testing.T) {
		t.Setenv("SYNAXIS_WORKSPACE_ID", "wsp_actor")
		if _, err := hostedActorVerifierFromEnv(nil, "https://engine.example"); err == nil {
			t.Fatal("hosted workspace without an actor public key was accepted")
		}
	})
	t.Run("hosted workspace pins issuer audience", func(t *testing.T) {
		t.Setenv("SYNAXIS_WORKSPACE_ID", "wsp_actor")
		verifier, err := hostedActorVerifierFromEnv(publicKey, "https://engine.example")
		if err != nil || verifier == nil {
			t.Fatalf("hosted actor verifier=%v err=%v", verifier, err)
		}
		if _, err := hostedActorVerifierFromEnv(publicKey, "not-an-origin"); err == nil {
			t.Fatal("invalid Engine issuer audience was accepted")
		}
	})
}

func TestHostedUsageGateFromEnvIsOptionalAndFailClosed(t *testing.T) {
	publicKey := make(ed25519.PublicKey, ed25519.PublicKeySize)
	t.Run("self-hosted default is unlimited", func(t *testing.T) {
		t.Setenv("SYNAXIS_WORKSPACE_ID", "")
		gate, err := hostedUsageGateFromEnv(context.Background(), nil, nil)
		if err != nil || gate != nil {
			t.Fatalf("self-hosted usage gate = %v, %v", gate, err)
		}
	})
	t.Run("workspace requires public key", func(t *testing.T) {
		t.Setenv("SYNAXIS_WORKSPACE_ID", "workspace-one")
		t.Setenv("SYNAXIS_PROVISION_GENERATION", "7")
		if _, err := hostedUsageGateFromEnv(context.Background(), nil, nil); err == nil {
			t.Fatal("hosted workspace without signing key was accepted")
		}
	})
	t.Run("generation is canonical and positive", func(t *testing.T) {
		for _, generation := range []string{"", "0", "-1", "07", "not-a-number"} {
			t.Run(generation, func(t *testing.T) {
				t.Setenv("SYNAXIS_WORKSPACE_ID", "workspace-one")
				t.Setenv("SYNAXIS_PROVISION_GENERATION", generation)
				if _, err := hostedUsageGateFromEnv(context.Background(), nil, publicKey); err == nil {
					t.Fatalf("generation %q was accepted", generation)
				}
			})
		}
	})
	t.Run("hosted mode requires durable store", func(t *testing.T) {
		t.Setenv("SYNAXIS_WORKSPACE_ID", "workspace-one")
		t.Setenv("SYNAXIS_PROVISION_GENERATION", "7")
		if _, err := hostedUsageGateFromEnv(context.Background(), nil, publicKey); err == nil {
			t.Fatal("hosted mode accepted a store without durable usage support")
		}
	})
}

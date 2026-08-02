package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"narthex/backend/internal/engine"
)

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

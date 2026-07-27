package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"
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
	t.Run("self-hosted default remains enabled", func(t *testing.T) {
		t.Setenv("SYNAXIS_ENABLE_LEGACY_ADMIN", "")
		t.Setenv("ENGINE_ENABLE_LEGACY_ADMIN", "")
		if !legacyAdminEnabledFromEnv() {
			t.Fatal("legacy admin should remain enabled by default for self-hosting")
		}
	})

	t.Run("Synaxis setting has precedence", func(t *testing.T) {
		t.Setenv("SYNAXIS_ENABLE_LEGACY_ADMIN", "false")
		t.Setenv("ENGINE_ENABLE_LEGACY_ADMIN", "true")
		if legacyAdminEnabledFromEnv() {
			t.Fatal("Synaxis setting should disable legacy admin")
		}
	})

	t.Run("legacy alias remains supported", func(t *testing.T) {
		t.Setenv("SYNAXIS_ENABLE_LEGACY_ADMIN", "")
		t.Setenv("ENGINE_ENABLE_LEGACY_ADMIN", "false")
		if legacyAdminEnabledFromEnv() {
			t.Fatal("legacy setting should disable legacy admin")
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
	t.Run("self-hosted default remains enabled", func(t *testing.T) {
		t.Setenv("ENGINE_LOCAL_ADMIN_AUTH_ENABLED", "")
		if !localAdminAuthEnabledFromEnv() {
			t.Fatal("local admin auth should remain enabled by default")
		}
	})
	t.Run("hosted deployment can disable it", func(t *testing.T) {
		t.Setenv("ENGINE_LOCAL_ADMIN_AUTH_ENABLED", "false")
		if localAdminAuthEnabledFromEnv() {
			t.Fatal("local admin auth should be disabled")
		}
	})
	t.Run("invalid values fail closed", func(t *testing.T) {
		t.Setenv("ENGINE_LOCAL_ADMIN_AUTH_ENABLED", "sometimes")
		if localAdminAuthEnabledFromEnv() {
			t.Fatal("invalid local admin auth setting must fail closed")
		}
	})
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

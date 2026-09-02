package oauthas

import (
	"context"
	"testing"
	"time"
)

// currentReadCount is a small helper so the cache tests read
// memoryTokenGenerationStore.currentReads under its own lock, matching the
// pattern already used throughout revocation_test.go.
func currentReadCount(store *memoryTokenGenerationStore) int {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.currentReads
}

// TestSyncTokenGenerationCachesWithinTTLThenExpires proves the Step 2 cache:
// a cold instance always reads through on its first sync (never skips the
// one read that could catch an externally advanced generation — see
// TestLocallyAuthenticAccessTokenReadsDurableGenerationAndDiesImmediatelyAfterRemoteRevoke
// in revocation_test.go for why that matters), a second sync within
// tokenGenerationCacheTTL is a cache hit (no durable read), and a sync after
// the TTL elapses reads through again.
func TestSyncTokenGenerationCachesWithinTTLThenExpires(t *testing.T) {
	store := &memoryTokenGenerationStore{}
	now := time.Now()
	server := New("https://engine.example", "pw", "shared-signing-secret")
	server.SetEpochLookup(rootEpoch)
	server.now = func() time.Time { return now }
	configureGeneration(t, server, store)

	if err := server.syncTokenGeneration(context.Background()); err != nil {
		t.Fatalf("cold sync: %v", err)
	}
	if got := currentReadCount(store); got != 1 {
		t.Fatalf("cold sync performed %d durable reads, want 1", got)
	}

	// Still within the TTL: a cache hit must not read the store again.
	now = now.Add(tokenGenerationCacheTTL - time.Millisecond)
	if err := server.syncTokenGeneration(context.Background()); err != nil {
		t.Fatalf("cached sync: %v", err)
	}
	if got := currentReadCount(store); got != 1 {
		t.Fatalf("cached sync performed %d durable reads, want still 1 (cache hit)", got)
	}

	// Past the TTL: the cache must expire and read through again.
	now = now.Add(2 * time.Millisecond)
	if err := server.syncTokenGeneration(context.Background()); err != nil {
		t.Fatalf("post-TTL sync: %v", err)
	}
	if got := currentReadCount(store); got != 2 {
		t.Fatalf("post-TTL sync performed %d durable reads, want 2 (cache expired)", got)
	}
}

// TestRevokeAllInvalidatesTheGenerationCache proves the "explicit
// invalidation wherever the generation is mutated" half of Step 2: a local
// RevokeAll must force the very next syncTokenGeneration call to read
// through, even though it lands well inside what would otherwise still be a
// warm cache window.
func TestRevokeAllInvalidatesTheGenerationCache(t *testing.T) {
	store := &memoryTokenGenerationStore{}
	now := time.Now()
	server := New("https://engine.example", "pw", "shared-signing-secret")
	server.SetEpochLookup(rootEpoch)
	server.now = func() time.Time { return now }
	configureGeneration(t, server, store)

	if err := server.syncTokenGeneration(context.Background()); err != nil {
		t.Fatalf("initial sync: %v", err)
	}
	if got := currentReadCount(store); got != 1 {
		t.Fatalf("initial sync performed %d durable reads, want 1", got)
	}

	// Well within the TTL window established by the sync above.
	now = now.Add(time.Millisecond)
	if err := server.RevokeAll(context.Background()); err != nil {
		t.Fatalf("RevokeAll: %v", err)
	}

	if err := server.syncTokenGeneration(context.Background()); err != nil {
		t.Fatalf("sync immediately after RevokeAll: %v", err)
	}
	if got := currentReadCount(store); got != 2 {
		t.Fatalf("sync after RevokeAll performed %d durable reads, want 2 (mutation must invalidate the cache)", got)
	}
}

// TestConfigureTokenGenerationInvalidatesTheGenerationCache proves the other
// explicit-invalidation site: a (re-)configuration never inherits a cache
// window, so the very next sync always confirms against the newly wired
// store instead of trusting stale timing state.
func TestConfigureTokenGenerationInvalidatesTheGenerationCache(t *testing.T) {
	firstStore := &memoryTokenGenerationStore{}
	now := time.Now()
	server := New("https://engine.example", "pw", "shared-signing-secret")
	server.SetEpochLookup(rootEpoch)
	server.now = func() time.Time { return now }
	configureGeneration(t, server, firstStore)

	if err := server.syncTokenGeneration(context.Background()); err != nil {
		t.Fatalf("sync against first store: %v", err)
	}
	if got := currentReadCount(firstStore); got != 1 {
		t.Fatalf("sync against first store performed %d durable reads, want 1", got)
	}

	secondStore := &memoryTokenGenerationStore{}
	// Re-configuring immediately afterward (still within what would be a warm
	// window) must not let the next sync skip confirming the new store.
	configureGeneration(t, server, secondStore)
	if err := server.syncTokenGeneration(context.Background()); err != nil {
		t.Fatalf("sync against second store: %v", err)
	}
	if got := currentReadCount(secondStore); got != 1 {
		t.Fatalf("sync against second store performed %d durable reads, want 1 (ConfigureTokenGeneration must invalidate the cache)", got)
	}
}

package engine

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// exerciseControlIdempotencyStore asserts the store-level invariants shared by
// FileStore and PgStore: identity is (key, resource path); only well-formed
// completed results are stored; the first record wins; lookups honor the
// expiry instant exactly; and expired identities are pruned and reusable.
// Every key carries prefix so a shared database can be cleaned by prefix.
func exerciseControlIdempotencyStore(t *testing.T, ctx context.Context, store ControlIdempotencyStore, prefix string) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	key := prefix + "-create"
	path := "/control/v1/mcp-clients"
	record := ControlIdempotencyRecord{
		Key: key, ResourcePath: path, ActorRef: "wsp_a|usr_a|owner", BodyDigest: libraryDigest("body A"),
		Status: http.StatusCreated, Body: []byte("{\"id\":\"mcpcli_1\",\"raw\":\"\x00\xff\"}"),
		CreatedAt: now, ExpiresAt: now.Add(controlIdempotencyHorizon),
	}

	if _, found, err := store.ControlIdempotencyRecord(ctx, key, path, now); err != nil || found {
		t.Fatalf("absent lookup found=%t err=%v", found, err)
	}
	for name, mutate := range map[string]func(*ControlIdempotencyRecord){
		"non-v1 path":   func(r *ControlIdempotencyRecord) { r.ResourcePath = "/api/mcp-clients" },
		"empty path":    func(r *ControlIdempotencyRecord) { r.ResourcePath = "" },
		"digest":        func(r *ControlIdempotencyRecord) { r.BodyDigest = "nope" },
		"failed status": func(r *ControlIdempotencyRecord) { r.Status = http.StatusConflict },
		"expiry":        func(r *ControlIdempotencyRecord) { r.ExpiresAt = r.CreatedAt },
		"zero created":  func(r *ControlIdempotencyRecord) { r.CreatedAt = time.Time{} },
		"key space":     func(r *ControlIdempotencyRecord) { r.Key = prefix + " spaced" },
		"empty key":     func(r *ControlIdempotencyRecord) { r.Key = "" },
	} {
		invalid := record
		mutate(&invalid)
		if _, stored, err := store.StoreControlIdempotencyRecord(ctx, invalid); !errors.Is(err, ErrInvalidControlIdempotencyRecord) || stored {
			t.Fatalf("%s stored=%t err=%v; want invalid record", name, stored, err)
		}
	}
	if _, found, err := store.ControlIdempotencyRecord(ctx, key, path, now); err != nil || found {
		t.Fatalf("rejected records were stored: found=%t err=%v", found, err)
	}

	winner, stored, err := store.StoreControlIdempotencyRecord(ctx, record)
	if err != nil || !stored || winner.Key != key || winner.ResourcePath != path || winner.ActorRef != record.ActorRef ||
		winner.BodyDigest != record.BodyDigest || winner.Status != record.Status || !bytes.Equal(winner.Body, record.Body) ||
		!winner.CreatedAt.Equal(record.CreatedAt) || !winner.ExpiresAt.Equal(record.ExpiresAt) {
		t.Fatalf("store=%+v stored=%t err=%v", winner, stored, err)
	}
	got, found, err := store.ControlIdempotencyRecord(ctx, key, path, now.Add(controlIdempotencyHorizon-time.Second))
	if err != nil || !found || got.ActorRef != record.ActorRef || got.BodyDigest != record.BodyDigest || got.Status != record.Status || !bytes.Equal(got.Body, record.Body) {
		t.Fatalf("lookup=%+v found=%t err=%v", got, found, err)
	}
	if _, found, err := store.ControlIdempotencyRecord(ctx, key, path, record.ExpiresAt); err != nil || found {
		t.Fatalf("lookup at expiry found=%t err=%v; want expired", found, err)
	}
	if _, found, err := store.ControlIdempotencyRecord(ctx, key, path+"/mcpcli_1", now); err != nil || found {
		t.Fatalf("lookup on another path found=%t err=%v", found, err)
	}
	if _, found, err := store.ControlIdempotencyRecord(ctx, prefix+"-other", path, now); err != nil || found {
		t.Fatalf("lookup with another key found=%t err=%v", found, err)
	}

	// The first record wins under the same identity, whatever the later
	// caller sends, so a conflicting retry is detected from the stored values.
	duplicate := record
	duplicate.ActorRef, duplicate.BodyDigest, duplicate.Status, duplicate.Body = "wsp_a|usr_b|admin", libraryDigest("body B"), http.StatusOK, []byte("{}")
	duplicate.CreatedAt, duplicate.ExpiresAt = now.Add(time.Minute), now.Add(time.Minute+controlIdempotencyHorizon)
	winner, stored, err = store.StoreControlIdempotencyRecord(ctx, duplicate)
	if err != nil || stored || winner.ActorRef != record.ActorRef || winner.BodyDigest != record.BodyDigest || winner.Status != record.Status || !bytes.Equal(winner.Body, record.Body) {
		t.Fatalf("duplicate store winner=%+v stored=%t err=%v; want first record", winner, stored, err)
	}
	// The same key on another resource path is a distinct identity.
	other := record
	other.ResourcePath = path + "/mcpcli_1"
	if _, stored, err := store.StoreControlIdempotencyRecord(ctx, other); err != nil || !stored {
		t.Fatalf("same key other path stored=%t err=%v", stored, err)
	}

	// An expired identity is invisible to lookups, pruned by the next store,
	// and reusable by a fresh record.
	stale := ControlIdempotencyRecord{
		Key: prefix + "-expired", ResourcePath: path, ActorRef: "wsp_a|usr_a|owner", BodyDigest: libraryDigest("stale"),
		Status: http.StatusOK, Body: []byte("{}"), CreatedAt: now.Add(-2 * controlIdempotencyHorizon), ExpiresAt: now.Add(-controlIdempotencyHorizon),
	}
	if _, stored, err := store.StoreControlIdempotencyRecord(ctx, stale); err != nil || !stored {
		t.Fatalf("store stale fixture stored=%t err=%v", stored, err)
	}
	if got, found, err := store.ControlIdempotencyRecord(ctx, stale.Key, path, stale.ExpiresAt.Add(-time.Second)); err != nil || !found || got.BodyDigest != stale.BodyDigest {
		t.Fatalf("stale fixture before its expiry=%+v found=%t err=%v", got, found, err)
	}
	if _, found, err := store.ControlIdempotencyRecord(ctx, stale.Key, path, now); err != nil || found {
		t.Fatalf("expired record served: found=%t err=%v", found, err)
	}
	fresh := stale
	fresh.ActorRef, fresh.BodyDigest, fresh.CreatedAt, fresh.ExpiresAt = "wsp_a|usr_c|owner", libraryDigest("fresh"), now, now.Add(time.Hour)
	winner, stored, err = store.StoreControlIdempotencyRecord(ctx, fresh)
	if err != nil || !stored || winner.ActorRef != fresh.ActorRef || winner.BodyDigest != fresh.BodyDigest {
		t.Fatalf("expired identity reuse winner=%+v stored=%t err=%v", winner, stored, err)
	}
	if got, found, err := store.ControlIdempotencyRecord(ctx, stale.Key, path, stale.ExpiresAt.Add(-time.Second)); err != nil || !found || got.BodyDigest != fresh.BodyDigest {
		t.Fatalf("stale record survived pruning: %+v found=%t err=%v", got, found, err)
	}

	// The actor reference the control wrapper derives from a verified
	// assertion is storable as-is on both backends.
	request := httptest.NewRequest(http.MethodPost, path, nil)
	request = request.WithContext(withPlatformActor(request.Context(), PlatformActor{WorkspaceID: "wsp_123", UserID: "usr_456", Role: "owner"}))
	actorScoped := record
	actorScoped.Key, actorScoped.ActorRef = prefix+"-actor", controlActorRef(request)
	if actorScoped.ActorRef != "wsp_123|usr_456|owner" {
		t.Fatalf("actor ref=%q", actorScoped.ActorRef)
	}
	if winner, stored, err := store.StoreControlIdempotencyRecord(ctx, actorScoped); err != nil || !stored || winner.ActorRef != actorScoped.ActorRef {
		t.Fatalf("actor-scoped store winner=%+v stored=%t err=%v", winner, stored, err)
	}
}

func TestFileStoreControlIdempotencyRecordsPersistAndExpire(t *testing.T) {
	ctx := context.Background()
	store := newLibraryFileStore(t)
	exerciseControlIdempotencyStore(t, ctx, store, "file")

	reloaded, err := LoadFileStore(store.path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for name, key := range map[string]string{"create": "file-create", "expired identity reuse": "file-expired", "actor": "file-actor"} {
		if _, found, err := reloaded.ControlIdempotencyRecord(ctx, key, "/control/v1/mcp-clients", now); err != nil || !found {
			t.Fatalf("%s record did not survive reload: found=%t err=%v", name, found, err)
		}
	}
	if _, found, err := reloaded.ControlIdempotencyRecord(ctx, "file-create", "/control/v1/mcp-clients", now.Add(2*controlIdempotencyHorizon)); err != nil || found {
		t.Fatalf("reloaded record ignored expiry: found=%t err=%v", found, err)
	}
}

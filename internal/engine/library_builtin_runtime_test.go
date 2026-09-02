package engine

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strconv"
	"testing"
	"time"
)

func newBuiltInRuntimeFileFixture(t *testing.T) (*FileStore, MCPClient) {
	t.Helper()
	store := newLibraryFileStore(t)
	client, err := store.CreateMCPClient(context.Background(), MCPClient{
		Name: "Managed runtime agent", Subject: "usr_managed_runtime", CreatedBy: "usr_managed_runtime",
	})
	if err != nil {
		t.Fatalf("CreateMCPClient: %v", err)
	}
	if err := store.ReconcileBuiltInLibrary(context.Background()); err != nil {
		t.Fatalf("ReconcileBuiltInLibrary: %v", err)
	}
	return store, client
}

func requireManagedActivationIntegrityFailure(t *testing.T, store *FileStore, clientID string) {
	t.Helper()
	bundle, err := BuildLibrarySkillActivationBundleForAgentSurface(context.Background(), store, clientID)
	if !errors.Is(err, ErrLibrarySkillActivationIntegrity) {
		t.Fatalf("activation error=%v, want %v", err, ErrLibrarySkillActivationIntegrity)
	}
	if len(bundle.Skills) != 0 || bundle.BundleDigest != "" {
		t.Fatalf("integrity failure returned a partial managed activation: %+v", bundle)
	}
}

func TestUsingSynaxisActivationFailsClosedOnPostStartupFileTampering(t *testing.T) {
	tests := []struct {
		name   string
		tamper func(*FileStore, string)
	}{
		{
			name: "tracked appended version",
			tamper: func(store *FileStore, clientID string) {
				content := "# Runtime replacement\nThis did not come from the running binary."
				store.librarySkillVersions = append(store.librarySkillVersions, &LibrarySkillVersion{
					ID: usingSynaxisSkillVersionIDPrefix + "2", SkillID: usingSynaxisSkillID, Version: 2,
					Content: content, Digest: libraryDigest(content), RequestedCapabilities: []string{},
					CreatedBy: "usr_legacy_writer", CreatedAt: time.Now().UTC(),
				})
				for _, binding := range store.librarySkillBindings {
					if binding != nil && binding.ID == usingSynaxisBindingID(clientID) {
						binding.Mode = LibraryBindingModeTrack
						binding.PinnedVersionID = ""
					}
				}
			},
		},
		{
			name: "self-consistent current-version replacement",
			tamper: func(store *FileStore, _ string) {
				for _, version := range store.librarySkillVersions {
					if version != nil && version.ID == usingSynaxisSkillVersionID {
						version.Content = "# Replaced managed instructions"
						version.Digest = libraryDigest(version.Content)
					}
				}
			},
		},
		{
			name: "missing managed binding",
			tamper: func(store *FileStore, clientID string) {
				kept := store.librarySkillBindings[:0]
				for _, binding := range store.librarySkillBindings {
					if binding == nil || binding.ID != usingSynaxisBindingID(clientID) {
						kept = append(kept, binding)
					}
				}
				store.librarySkillBindings = kept
			},
		},
		{
			name: "selection without authoritative marker",
			tamper: func(store *FileStore, _ string) {
				delete(store.libraryBuiltInCurrentVersions, usingSynaxisSkillID)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store, client := newBuiltInRuntimeFileFixture(t)
			store.mu.Lock()
			test.tamper(store, client.ID)
			store.mu.Unlock()
			requireManagedActivationIntegrityFailure(t, store, client.ID)
		})
	}
}

func TestUsingSynaxisActivationFailsClosedOnLegacyPriorityTiesAndOverflow(t *testing.T) {
	store, client := newBuiltInRuntimeFileFixture(t)
	ctx := context.Background()
	priorities := []int{usingSynaxisBindingPriority}
	if strconv.IntSize > 32 {
		priorities = append(priorities, int(int64(usingSynaxisBindingPriority)+1))
	}
	for index, legacyPriority := range priorities {
		skill, version, err := store.CreateLibrarySkillWithInitialVersion(ctx, LibrarySkill{
			Slug: "legacy-priority-" + strconv.Itoa(index), Name: "Legacy priority", CreatedBy: "usr_legacy",
		}, LibrarySkillVersion{Content: "# Legacy priority", CreatedBy: "usr_legacy"})
		if err != nil {
			t.Fatalf("create legacy-priority skill: %v", err)
		}
		binding, err := store.UpsertLibrarySkillBinding(ctx, LibrarySkillBinding{
			SkillID: skill.ID, ScopeKind: LibraryScopeAgentSurface, ScopeID: client.ID,
			Mode: LibraryBindingModePin, PinnedVersionID: version.ID, Priority: 0, CreatedBy: "usr_legacy",
		})
		if err != nil {
			t.Fatalf("create legacy-priority binding: %v", err)
		}
		store.mu.Lock()
		for _, persisted := range store.librarySkillBindings {
			if persisted != nil && persisted.ID == binding.ID {
				persisted.Priority = legacyPriority
			}
		}
		store.mu.Unlock()
	}

	resolution, err := ResolveLibrarySkillsForAgentSurface(ctx, store, client.ID)
	if !errors.Is(err, errLibraryBuiltInRuntimeIntegrity) || len(resolution.Skills) != 0 {
		t.Fatalf("legacy out-of-range resolution=(%+v,%v), want integrity failure without partial skills", resolution, err)
	}
	requireManagedActivationIntegrityFailure(t, store, client.ID)
}

func TestUsingSynaxisRuntimeAttestationFailsClosedOnPostStartupFileTampering(t *testing.T) {
	for _, test := range []struct {
		name   string
		tamper func(*FileStore, string)
	}{
		{
			name: "tracked appended version",
			tamper: func(store *FileStore, clientID string) {
				content := "# Runtime attestation replacement"
				store.librarySkillVersions = append(store.librarySkillVersions, &LibrarySkillVersion{
					ID: usingSynaxisSkillVersionIDPrefix + "2", SkillID: usingSynaxisSkillID, Version: 2,
					Content: content, Digest: libraryDigest(content), RequestedCapabilities: []string{},
					CreatedBy: "usr_legacy_writer", CreatedAt: time.Now().UTC(),
				})
				for _, binding := range store.librarySkillBindings {
					if binding != nil && binding.ID == usingSynaxisBindingID(clientID) {
						binding.Mode = LibraryBindingModeTrack
						binding.PinnedVersionID = ""
					}
				}
			},
		},
		{
			name: "missing managed binding",
			tamper: func(store *FileStore, clientID string) {
				kept := store.librarySkillBindings[:0]
				for _, binding := range store.librarySkillBindings {
					if binding == nil || binding.ID != usingSynaxisBindingID(clientID) {
						kept = append(kept, binding)
					}
				}
				store.librarySkillBindings = kept
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := newLibraryFileStore(t)
			if err := store.ReconcileBuiltInLibrary(context.Background()); err != nil {
				t.Fatalf("ReconcileBuiltInLibrary: %v", err)
			}
			fixture := newRuntimeAttestationFixture(t, store)
			raw := runtimeAttestationBody(
				t, fixture, "managed-runtime-tamper", base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{31}, 32)),
				time.Now().UTC().Add(5*time.Minute).Format(time.RFC3339Nano), "# Host output",
			)
			path := libraryRuntimeAttestationPath(fixture.client.Slug)
			signature := ed25519.Sign(fixture.private, libraryRuntimeAttestationSigningMessage(path, raw))
			store.mu.Lock()
			test.tamper(store, fixture.client.ID)
			store.mu.Unlock()
			if _, _, _, _, err := store.IngestLibraryRuntimeAttestation(context.Background(), LibraryRuntimeAttestation{
				ClientID: fixture.client.ID, Path: path, RawBody: raw, Signature: signature,
			}); !errors.Is(err, ErrLibraryRuntimeAttestationInvalid) {
				t.Fatalf("tampered managed selection attestation error=%v, want %v", err, ErrLibraryRuntimeAttestationInvalid)
			}
			if runs, err := store.LibraryRuns(context.Background()); err != nil || len(runs) != 0 {
				t.Fatalf("tampered managed selection created runtime output: runs=%+v err=%v", runs, err)
			}
		})
	}
}

func TestBuiltInRuntimeValidationUsesKnownAuthoritativeVersionInsteadOfCompiledHead(t *testing.T) {
	definition := usingSynaxisDefinition()
	v1 := definition.Versions[0]
	v2Content := usingSynaxisSkillContent + "\n## Future compiled revision\n"
	v2 := builtInLibrarySkillVersionDefinition{
		Revision: 2, VersionID: usingSynaxisSkillVersionIDPrefix + "2",
		Content: v2Content, ContentDigest: libraryDigest(v2Content),
	}
	definition.Versions = append(definition.Versions, v2)
	definition.CurrentVersionID = v2.VersionID
	now := time.Now().UTC()
	clientID := "mcpcli_authoritative_rollback"
	binding := definition.binding(clientID, now)
	binding.PinnedVersionID = v1.VersionID
	selection := LibraryAgentSurfaceSkillSelection{
		Skill: definition.skill(now), Binding: binding, Version: definition.version(v1, now),
	}
	if err := validateBuiltInLibraryAgentSurfaceSelections(definition, clientID, []LibraryAgentSurfaceSkillSelection{selection}, v1.VersionID, true); err != nil {
		t.Fatalf("newer compiled manifest rejected authoritative known rollback pin: %v", err)
	}
	if err := validateBuiltInLibraryAgentSurfaceSelections(usingSynaxisDefinition(), clientID, []LibraryAgentSurfaceSkillSelection{selection}, v2.VersionID, true); !errors.Is(err, errLibraryBuiltInRuntimeIntegrity) {
		t.Fatalf("older binary accepted unknown authoritative version: %v", err)
	}
}

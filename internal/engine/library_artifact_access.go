package engine

import "context"

// libraryArtifactAccess is the artifact/version selected by a live,
// subject-bound MCP surface. A grant always selects one exact immutable
// version; direct ownership may select the caller's current private head.
// Access is deliberately evaluated at every tool call, rather than cached in
// a projected MCP server, so grant revocation takes effect without an endpoint
// rebuild.
type libraryArtifactAccess struct {
	Artifact LibraryArtifact
	Version  LibraryArtifactVersion
	Mode     string // "owned" or "granted"
}

func libraryArtifactDirectlyOwnedBySurface(ctx context.Context, store LibraryStore, artifact LibraryArtifact, actorRef, surfaceRef string) bool {
	if artifact.CreatedBy != actorRef || artifact.RunID == "" {
		return false
	}
	// New records carry a queryable surface projection. Legacy records may be
	// backfilled lazily by their store, so retain the run provenance check as
	// the authorization fence in either case.
	if artifact.AgentSurfaceID != "" && artifact.AgentSurfaceID != surfaceRef {
		return false
	}
	run, found := store.LibraryRun(ctx, artifact.RunID)
	if !found || run.ActorRef != actorRef || run.SurfaceRef != surfaceRef {
		return false
	}
	switch artifact.Origin {
	case LibraryArtifactOriginAgentDirect:
		return run.Origin == LibraryRunOriginAgentDirect
	case LibraryArtifactOriginSkillRun:
		// Only the separate signed host-attestation ingress can create this
		// combination. A generic skill_run record remains visible to owners
		// through management APIs but is never promoted into a client-owned
		// artifact projection merely because it names a surface.
		return run.Origin == LibraryRunOriginSkillRun && run.Attestation == LibraryRunAttestationHost
	default:
		return false
	}
}

func latestLibraryArtifactVersion(ctx context.Context, store LibraryStore, artifactID string) (LibraryArtifactVersion, bool) {
	versions, err := store.LibraryArtifactVersions(ctx, artifactID)
	if err != nil || len(versions) == 0 {
		return LibraryArtifactVersion{}, false
	}
	return versions[len(versions)-1], true
}

// libraryMCPClientArtifactAccess resolves read/list access for one client.
// It must not silently advance a granted artifact to its latest version: only
// direct ownership has an implicit private-head read; grants always resolve
// the version and digest stored at grant creation.
func libraryMCPClientArtifactAccess(ctx context.Context, store LibraryStore, artifact LibraryArtifact, client MCPClient) (libraryArtifactAccess, bool) {
	if libraryArtifactDirectlyOwnedBySurface(ctx, store, artifact, client.Subject, client.ID) {
		version, found := latestLibraryArtifactVersion(ctx, store, artifact.ID)
		if !found {
			return libraryArtifactAccess{}, false
		}
		return libraryArtifactAccess{Artifact: artifact, Version: version, Mode: "owned"}, true
	}
	grant, found := store.ActiveLibraryArtifactGrant(ctx, artifact.ID, client.ID)
	if !found {
		return libraryArtifactAccess{}, false
	}
	version, found := store.LibraryArtifactVersion(ctx, artifact.ID, grant.ArtifactVersionID)
	if !found || version.Digest != grant.ArtifactVersionDigest {
		return libraryArtifactAccess{}, false
	}
	return libraryArtifactAccess{Artifact: artifact, Version: version, Mode: "granted"}, true
}

// librarySurfaceMayUseArtifactVersion is used only when a direct agent writes
// source provenance. Unlike a normal direct read, direct ownership can cite
// any one of its own immutable versions because the caller supplied an exact
// version+digest. A shared surface must match its sole live grant exactly.
func librarySurfaceMayUseArtifactVersion(ctx context.Context, store LibraryStore, artifactID, versionID, digest, actorRef, surfaceRef, grantSurfaceID string) bool {
	artifact, found := store.LibraryArtifact(ctx, artifactID)
	if !found {
		return false
	}
	version, found := store.LibraryArtifactVersion(ctx, artifactID, versionID)
	if !found || version.Digest != digest {
		return false
	}
	// A host-attested result is list/read-owned by its exact surface, but it is
	// not automatically a trusted *input* to a new direct-agent provenance
	// claim. Keep the pre-existing direct-output citation rule narrow; an owner
	// can still deliberately delegate an exact host-output version by grant.
	if artifact.Origin == LibraryArtifactOriginAgentDirect && libraryArtifactDirectlyOwnedBySurface(ctx, store, artifact, actorRef, surfaceRef) {
		return true
	}
	if grantSurfaceID == "" {
		return false
	}
	grant, found := store.ActiveLibraryArtifactGrant(ctx, artifactID, grantSurfaceID)
	return found && grant.ArtifactVersionID == versionID && grant.ArtifactVersionDigest == digest
}

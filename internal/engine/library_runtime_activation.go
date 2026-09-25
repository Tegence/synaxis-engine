package engine

import (
	"crypto/ed25519"
	"net/http"
	"time"
)

const (
	libraryRuntimeTimestampHeader   = "X-Synaxis-Runtime-Timestamp"
	libraryRuntimeActivationMaxSkew = 2 * time.Minute
	// libraryRuntimeClientEpochHeader tells the signed host which client
	// epoch its later run correlation must name. The epoch is an
	// authorization fact, not a secret, and the caller has already proven
	// possession of the client's attestor key.
	libraryRuntimeClientEpochHeader = "X-Synaxis-Client-Epoch"
)

func libraryRuntimeActivationPath(slug string) string {
	return "/runtime/clients/" + slug + "/activation"
}

// libraryRuntimeActivationSigningMessage is the GET form of the shared host
// signing scheme: the timestamp stands in for a request body so a captured
// signature is only replayable inside the skew window and only for this path.
func libraryRuntimeActivationSigningMessage(path, timestamp string) []byte {
	return libraryRuntimeSigningMessage(http.MethodGet, path, []byte(timestamp))
}

func validLibraryRuntimeTimestamp(raw string, now time.Time) bool {
	parsed, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil || raw != parsed.UTC().Format(time.RFC3339Nano) {
		return false
	}
	skew := now.UTC().Sub(parsed)
	if skew < 0 {
		skew = -skew
	}
	return skew <= libraryRuntimeActivationMaxSkew
}

// NewLibraryRuntimeActivationHandler serves the signed, non-browser fetch of a
// client's full activation bundle. It has the same posture as the skill-run
// attestation ingress: no CORS, never mounted under /api or /mcp, slug-only
// client lookup, and a 404 for browser-shaped requests or clients without a
// configured attestor key. The bundle it returns is the same context-only
// handoff the MCP activation tool produces; it grants nothing.
func NewLibraryRuntimeActivationHandler(store LibraryRuntimeAttestationStore) http.Handler {
	mcpStore, ok := store.(MCPClientStore)
	libraryStore, libraryOK := store.(LibraryStore)
	if !ok || !libraryOK {
		return http.NotFoundHandler()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if r.URL.RawQuery != "" || r.Header.Get("Origin") != "" || r.Header.Get("Sec-Fetch-Mode") != "" {
			http.NotFound(w, r)
			return
		}
		client, key, found := libraryRuntimeClientForSlug(r, mcpStore)
		if !found {
			http.NotFound(w, r)
			return
		}
		now := time.Now().UTC()
		timestamp := r.Header.Get(libraryRuntimeTimestampHeader)
		if len(r.Header.Values(libraryRuntimeTimestampHeader)) != 1 || !validLibraryRuntimeTimestamp(timestamp, now) {
			http.Error(w, "invalid runtime signature", http.StatusUnauthorized)
			return
		}
		signature, err := decodeLibraryRuntimeSignature(r.Header.Get(libraryRuntimeAttestationSignatureHeader))
		if err != nil || !ed25519.Verify(key, libraryRuntimeActivationSigningMessage(r.URL.Path, timestamp), signature) {
			http.Error(w, "invalid runtime signature", http.StatusUnauthorized)
			return
		}
		bundle, err := BuildLibrarySkillActivationBundleForAgentSurface(r.Context(), libraryStore, client.ID)
		if err != nil {
			http.Error(w, "activation bundle unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set(libraryRuntimeClientEpochHeader, client.Epoch)
		writeJSON(w, http.StatusOK, bundle)
	})
}

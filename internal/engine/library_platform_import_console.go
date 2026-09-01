package engine

import (
	"encoding/json"
	"io"
	"net/http"
)

// handleLibraryPlatformSkillDraftImport is intentionally narrower than the
// ordinary self-hosted generator endpoint. A hosted Platform broker has
// already performed the provider call and now gives the Engine only a typed,
// editable candidate. The normal ConsoleAPI security wrapper has already
// required both the Engine machine credential and a request-bound actor
// assertion before this handler runs.
func (c *ConsoleAPI) handleLibraryPlatformSkillDraftImport(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	// This is a hosted boundary, not a second self-hosted draft API. In hosted
	// mode the actor verifier is the proof that the request came through the
	// Platform control plane rather than a browser session or copied local
	// token.
	if c.actorVerifier == nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "platform draft import is unavailable"})
		return
	}
	actor, ok := PlatformActorFromContext(r.Context())
	if !ok || (actor.Role != "owner" && actor.Role != "admin") || actor.UserID == platformServiceActorID {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "workspace administration is required"})
		return
	}
	if !c.librarySupported(w) {
		return
	}
	var request LibraryPlatformSkillDraftImport
	if !decodeStrictLibraryPlatformDraftImportBody(w, r, &request) {
		return
	}
	draft, replayed, err := c.libraryStore.ImportPlatformLibrarySkillDraft(r.Context(), request, actor.UserID)
	if err != nil {
		writeLibraryError(w, err)
		return
	}
	status := http.StatusCreated
	if replayed {
		status = http.StatusOK
	}
	writeJSON(w, status, struct {
		Draft    LibrarySkillDraft `json:"draft"`
		Replayed bool              `json:"replayed"`
	}{Draft: draft, Replayed: replayed})
}

func decodeStrictLibraryPlatformDraftImportBody(w http.ResponseWriter, r *http.Request, destination *LibraryPlatformSkillDraftImport) bool {
	if r.Body == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "JSON body is required"})
		return false
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, libraryConsoleBodyLimit))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid platform draft import"})
		return false
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid platform draft import"})
		return false
	}
	return true
}

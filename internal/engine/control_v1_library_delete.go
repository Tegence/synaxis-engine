package engine

import (
	"net/http"
	"strings"
)

// handleControlLibraryArtifactDelete serves
// DELETE /control/v1/library/artifacts/{id} (docs/CONTROL_V1.md, "Library
// artifact erasure"). Only the hosting control plane's service actor may
// erase an artifact: it is how outputs of runs that must not outlive their
// retention are removed. The answer is 204 whether the artifact was erased
// now or earlier; 404 means the Engine never knew the ID.
func (c *ConsoleAPI) handleControlLibraryArtifactDelete(w http.ResponseWriter, r *http.Request) {
	_, _, actor, failure := c.controlLibraryAdministration(r)
	if failure != nil {
		controlWire.writeFailure(w, failure)
		return
	}
	if actor.Role != "service" || actor.UserID != platformServiceActorID {
		controlWire.writeFailure(w, newConsoleFailure(http.StatusForbidden, controlCodeForbidden, "artifact erasure requires the Platform service"))
		return
	}
	eraser, ok := c.libraryStore.(LibraryArtifactEraser)
	if !ok {
		controlWire.writeFailure(w, newConsoleFailure(http.StatusNotImplemented, controlCodeCapabilityUnavailable, "artifact erasure is not supported by this store"))
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if validateLibraryOpaqueRef("artifact", id, false) != nil {
		controlWire.writeFailure(w, newConsoleFailure(http.StatusNotFound, controlCodeNotFound, controlLibraryNotFoundTitle))
		return
	}
	found, err := eraser.DeleteLibraryArtifact(r.Context(), id)
	if err != nil {
		controlWire.writeFailure(w, newConsoleFailure(http.StatusBadGateway, controlCodeEngineUnavailable, "artifact erasure is unavailable"))
		return
	}
	if !found {
		controlWire.writeFailure(w, newConsoleFailure(http.StatusNotFound, controlCodeNotFound, controlLibraryNotFoundTitle))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

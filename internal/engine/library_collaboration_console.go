package engine

import (
	"encoding/json"
	"errors"
	"net/http"
)

type collaborationEnvelope struct {
	LibraryCollaborationRequest
	Token string `json:"token,omitempty"`
}

func collaborationHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
}

func writeCollaborationError(w http.ResponseWriter, err error) {
	status, code, message := http.StatusInternalServerError, "collaboration_unavailable", "Collaboration is unavailable"
	switch {
	case errors.Is(err, ErrCollaborationUnavailable):
		status, code, message = 404, "not_found", "Collaboration access is unavailable"
	case errors.Is(err, ErrCollaborationForbidden):
		status, code, message = 403, "forbidden", err.Error()
	case errors.Is(err, ErrCollaborationConflict):
		status, code, message = 409, "version_conflict", err.Error()
	case errors.Is(err, ErrCollaborationInvalid), errors.Is(err, ErrLibraryArtifactFormatMismatch):
		status, code, message = 400, "validation_failed", "Invalid request; collaboration supports text and Markdown outputs"
	case errors.Is(err, ErrCollaborationCapacity):
		status, code, message = 409, "capacity", err.Error()
	}
	writeControlProblem(w, status, code, message)
}

func (c *ConsoleAPI) serveCollaboration(w http.ResponseWriter, r *http.Request, actor LibraryCollaborationActor) {
	collaborationHeaders(w)
	store, ok := c.libraryStore.(LibraryCollaborationStore)
	if !ok {
		writeCollaborationError(w, ErrCollaborationUnavailable)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var envelope collaborationEnvelope
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2<<20))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&envelope) != nil {
		writeCollaborationError(w, ErrCollaborationInvalid)
		return
	}
	if envelope.Token != "" {
		actor = LibraryCollaborationActor{Kind: "capability"}
	}
	if actor.Kind == "capability" {
		actor.Ref = envelope.GrantID
		actor.Token = envelope.Token
	}
	if id := r.PathValue("id"); id != "" {
		envelope.ArtifactID = id
	}
	if envelope.Operation == "list" {
		result, err := store.CollaborationArtifacts(r.Context(), actor)
		if err != nil {
			writeCollaborationError(w, err)
			return
		}
		writeJSON(w, 200, result)
		return
	}
	result, err := store.Collaborate(r.Context(), actor, envelope.LibraryCollaborationRequest)
	if err != nil {
		writeCollaborationError(w, err)
		return
	}
	writeJSON(w, 200, result)
}

func (c *ConsoleAPI) handleLibraryCollaboration(w http.ResponseWriter, r *http.Request) {
	actor, ok := c.requireLibraryAdministrator(w, r)
	if !ok {
		return
	}
	c.serveCollaboration(w, r, LibraryCollaborationActor{Kind: "admin", Ref: libraryActorRef(actor)})
}

func (c *ConsoleAPI) handlePublicLibraryCollaboration(w http.ResponseWriter, r *http.Request) {
	c.serveCollaboration(w, r, LibraryCollaborationActor{Kind: "capability"})
}

func (c *ConsoleAPI) handleControlLibraryCollaboration(w http.ResponseWriter, r *http.Request) {
	_, _, actor, failure := c.controlLibraryAdministration(r)
	if failure != nil {
		controlWire.writeFailure(w, failure)
		return
	}
	subject, scoped, failure := controlSubject(r)
	if failure != nil {
		controlWire.writeFailure(w, failure)
		return
	}
	if scoped {
		c.serveCollaboration(w, r, LibraryCollaborationActor{Kind: "subject", Ref: subject})
		return
	}
	if actor.Role == "service" {
		c.serveCollaboration(w, r, LibraryCollaborationActor{Kind: "capability"})
		return
	}

	c.serveCollaboration(w, r, LibraryCollaborationActor{Kind: "admin", Ref: actor.UserID})
}

package engine

import (
	"errors"
	"net/http"
)

func (c *ConsoleAPI) handleControlMemberSkills(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeControlProblem(w, http.StatusMethodNotAllowed, controlCodeValidationFailed, "POST is required")
		return
	}
	store, ok := c.libraryStore.(LibraryMemberSkillStore)
	if !ok {
		writeControlProblem(w, http.StatusNotImplemented, controlCodeCapabilityUnavailable, "member skills are unavailable")
		return
	}
	actor, ok := c.connectionNamespaceActor(r)
	if !ok || actor.UserID != platformServiceActorID || actor.Role != "service" {
		writeControlProblem(w, http.StatusForbidden, controlCodeForbidden, "member skills require the Platform service")
		return
	}
	subject, scoped, failure := controlSubject(r)
	if failure != nil {
		controlWire.writeFailure(w, failure)
		return
	}
	if !scoped || len(r.Header.Values(controlSubjectsHeader)) != 0 {
		writeControlProblem(w, http.StatusBadRequest, controlCodeValidationFailed, "one member subject is required")
		return
	}
	var request LibraryMemberSkillRequest
	if failure := controlWire.decodeJSON(w, r, &request); failure != nil {
		controlWire.writeFailure(w, failure)
		return
	}
	request.Subject = subject
	result, err := store.MemberLibrarySkills(r.Context(), request)
	if err != nil {
		code, status := controlCodeValidationFailed, http.StatusBadRequest
		switch {
		case errors.Is(err, ErrLibrarySkillGrantNotFound), errors.Is(err, ErrLibrarySkillNotFound), errors.Is(err, ErrLibrarySkillVersionNotFound), errors.Is(err, ErrLibraryBindingNotFound), errors.Is(err, ErrMCPClientNotFound):
			code, status = controlCodeNotFound, http.StatusNotFound
		case errors.Is(err, ErrLibraryMemberSkillAccess):
			code, status = controlCodeForbidden, http.StatusForbidden
		case errors.Is(err, ErrLibraryMemberSkillConflict):
			code, status = controlCodeRevisionMismatch, http.StatusConflict
		}
		writeControlProblem(w, status, code, "skill operation could not be completed")
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (c *ConsoleAPI) handleControlSkillGrants(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeControlProblem(w, http.StatusMethodNotAllowed, controlCodeValidationFailed, "POST is required")
		return
	}
	actor, ok := c.connectionNamespaceActor(r)
	if !ok || actor.UserID != platformServiceActorID || actor.Role != "service" {
		writeControlProblem(w, http.StatusForbidden, controlCodeForbidden, "skill sharing requires the Platform service")
		return
	}
	store, ok := c.libraryStore.(LibrarySkillGrantStore)
	if !ok {
		writeControlProblem(w, http.StatusNotImplemented, controlCodeCapabilityUnavailable, "skill sharing is unavailable")
		return
	}
	if len(r.Header.Values(controlSubjectsHeader)) != 0 || r.Header.Get(controlSubjectHeader) != "" {
		writeControlProblem(w, http.StatusBadRequest, controlCodeValidationFailed, "service scope is required")
		return
	}
	var req LibrarySkillGrantRequest
	if failure := controlWire.decodeJSON(w, r, &req); failure != nil {
		controlWire.writeFailure(w, failure)
		return
	}
	out, err := store.LibrarySkillGrants(r.Context(), req)
	if err != nil {
		status, code := http.StatusBadRequest, controlCodeValidationFailed
		if errors.Is(err, ErrLibrarySkillGrantNotFound) {
			status, code = http.StatusNotFound, controlCodeNotFound
		}
		if errors.Is(err, ErrLibraryMemberSkillConflict) {
			status, code = http.StatusConflict, controlCodeRevisionMismatch
		}
		writeControlProblem(w, status, code, "skill sharing could not be updated")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

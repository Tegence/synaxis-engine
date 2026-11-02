package engine

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
)

func (c *ConsoleAPI) controlLibraryChatService(w http.ResponseWriter, r *http.Request) (LibraryChatArtifactStore, bool) {
	_, _, actor, failure := c.controlLibraryAdministration(r)
	if failure != nil {
		controlWire.writeFailure(w, failure)
		return nil, false
	}
	if actor.Role != "service" || actor.UserID != platformServiceActorID {
		controlWire.writeFailure(w, newConsoleFailure(http.StatusForbidden, controlCodeForbidden, "chat artifact operations require the Platform service"))
		return nil, false
	}
	if r.Method != http.MethodPost {
		controlWire.writeMethodNotAllowed(w, http.MethodPost)
		return nil, false
	}
	chats, ok := c.libraryStore.(LibraryChatArtifactStore)
	if !ok {
		controlWire.writeFailure(w, newConsoleFailure(http.StatusNotImplemented, controlCodeCapabilityUnavailable, "chat artifacts are unavailable"))
		return nil, false
	}
	return chats, true
}
func writeControlLibraryChatError(w http.ResponseWriter, err error) {
	if errors.Is(err, ErrLibraryArtifactNotFound) || errors.Is(err, ErrLibraryArtifactVersionNotFound) || errors.Is(err, ErrMCPClientNotFound) || errors.Is(err, ErrMCPClientRevoked) {
		controlWire.writeFailure(w, newConsoleFailure(http.StatusNotFound, controlCodeNotFound, controlLibraryNotFoundTitle))
		return
	}
	controlWire.writeFailure(w, newConsoleFailure(http.StatusBadGateway, controlCodeEngineUnavailable, "chat artifacts are unavailable"))
}
func (c *ConsoleAPI) handleControlLibraryChatClassify(w http.ResponseWriter, r *http.Request) {
	chats, ok := c.controlLibraryChatService(w, r)
	if !ok {
		return
	}
	var request struct {
		Replies []LibraryChatReplyReference `json:"replies"`
	}
	if failure := decodeControlLibraryChatJSON(w, r, &request); failure != nil {
		controlWire.writeFailure(w, failure)
		return
	}
	if err := validateLibraryChatClassification(request.Replies); err != nil {
		controlWire.writeFailure(w, newConsoleFailure(http.StatusBadRequest, controlCodeValidationFailed, err.Error()))
		return
	}
	classified, err := chats.ClassifyLibraryChatReplies(r.Context(), request.Replies)
	if err != nil {
		writeControlLibraryChatError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, struct {
		Classified int `json:"classified"`
	}{classified})
}
func (c *ConsoleAPI) handleControlLibraryChatSave(w http.ResponseWriter, r *http.Request) {
	chats, ok := c.controlLibraryChatService(w, r)
	if !ok {
		return
	}
	// The artifact identity is path-bound. The body cannot nominate source text.
	var request struct {
		ArtifactVersionID string `json:"artifactVersionId"`
		AgentSurfaceID    string `json:"agentSurfaceId"`
		Subject           string `json:"subject"`
		Title             string `json:"title"`
	}
	if failure := decodeControlLibraryChatJSON(w, r, &request); failure != nil {
		controlWire.writeFailure(w, failure)
		return
	}
	input := LibraryChatSaveRequest{LibraryChatReplyReference: LibraryChatReplyReference{ArtifactID: r.PathValue("id"), ArtifactVersionID: request.ArtifactVersionID, AgentSurfaceID: request.AgentSurfaceID, Subject: request.Subject}, Title: request.Title}
	if err := validateLibraryChatSave(input); err != nil {
		controlWire.writeFailure(w, newConsoleFailure(http.StatusBadRequest, controlCodeValidationFailed, err.Error()))
		return
	}
	result, err := chats.SaveLibraryChatReply(r.Context(), input)
	if err != nil {
		writeControlLibraryChatError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// Mutations accept only the declared source references and title; authored body
// content is always read server-side from the immutable reply.
func decodeControlLibraryChatJSON(w http.ResponseWriter, r *http.Request, destination any) *consoleFailure {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return newConsoleFailure(http.StatusBadRequest, controlCodeValidationFailed, "invalid chat artifact request")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return newConsoleFailure(http.StatusBadRequest, controlCodeValidationFailed, "invalid chat artifact request")
	}
	return nil
}

// Exact parent-version authorization was checked by the common control reader.
// SVG remains download-only, under the existing no-script media policy.
func (c *ConsoleAPI) writeControlLibraryArtifactMedia(w http.ResponseWriter, r *http.Request, artifact LibraryArtifact, version LibraryArtifactVersion) {
	mediaStore, ok := c.libraryStore.(LibraryArtifactMediaStore)
	if !ok {
		controlWire.writeFailure(w, newConsoleFailure(http.StatusNotImplemented, controlCodeCapabilityUnavailable, "artifact media is unavailable"))
		return
	}
	if version.Format != LibraryArtifactFormatImage {
		controlWire.writeFailure(w, newConsoleFailure(http.StatusNotFound, controlCodeNotFound, controlLibraryNotFoundTitle))
		return
	}
	media, found, err := mediaStore.LibraryArtifactMedia(r.Context(), artifact.ID, version.ID)
	if err != nil || !found || validateLibraryArtifactMediaForVersion(version, media) != nil {
		controlWire.writeFailure(w, newConsoleFailure(http.StatusNotFound, controlCodeNotFound, controlLibraryNotFoundTitle))
		return
	}
	data, found, err := mediaStore.LibraryArtifactImageBytes(r.Context(), artifact.ID, version.ID)
	if err != nil || !found || validateLibraryArtifactMediaBytes(media, data) != nil {
		controlWire.writeFailure(w, newConsoleFailure(http.StatusNotFound, controlCodeNotFound, controlLibraryNotFoundTitle))
		return
	}
	disposition := "inline"
	if media.DeliveryMode == libraryArtifactImageDeliveryDownloadOnly {
		disposition = "attachment"
	}
	w.Header().Set("Content-Type", media.MIMEType)
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.Header().Set("Content-Disposition", disposition+`; filename="`+version.ID+libraryArtifactMediaExtension(media.MIMEType)+`"`)
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; sandbox")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

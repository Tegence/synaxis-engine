package engine

import "net/http"

// activationSnapshotDTO contains only an aggregate count. It is intentionally
// separate from /api/servers so the hosted Platform can measure activation
// without receiving account names, provider URLs, credential state, or
// namespace membership.
type activationSnapshotDTO struct {
	ConnectionCount int `json:"connectionCount"`
}

func (c *ConsoleAPI) handleActivation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	// A hosted Engine has no local-admin fallback. Only the Platform service
	// actor may request this aggregate, which keeps a browser management
	// request from becoming a cross-namespace analytics channel.
	if c.actorVerifier != nil {
		actor, ok := PlatformActorFromContext(r.Context())
		if !ok || actor.Role != "service" || actor.UserID != platformServiceActorID {
			writeJSON(w, http.StatusForbidden, map[string]string{
				"error": "activation metrics require the Platform service",
			})
			return
		}
	}
	count := 0
	if c.store != nil {
		count = len(c.store.Accounts())
	}
	writeJSON(w, http.StatusOK, activationSnapshotDTO{ConnectionCount: count})
}

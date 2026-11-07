package engine

import (
	"context"
	"io"
	"net/http"
	"time"
)

const (
	managedBrowserReconcilePath       = "/control/v1/managed-browser/reconcile"
	managedBrowserReconcileCapability = "managed-kernel-browser-reconcile-v1"
	managedBrowserReconcileTimeout    = 25 * time.Second
)

func (c *ConsoleAPI) handleManagedBrowserReconcile(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		controlWire.writeMethodNotAllowed(w, http.MethodPost)
		return
	}
	actor, ok := PlatformActorFromContext(r.Context())
	if !ok || actor.UserID != platformServiceActorID || actor.Role != "service" {
		controlWire.writeFailure(w, newConsoleFailure(http.StatusForbidden, controlCodeForbidden, "browser cleanup requires Platform authority"))
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1))
	if err != nil || len(body) != 0 || r.URL.RawQuery != "" || r.URL.ForceQuery {
		controlWire.writeFailure(w, newConsoleFailure(http.StatusBadRequest, controlCodeValidationFailed, "browser cleanup accepts no input"))
		return
	}
	service := c.browserSignIn
	if service == nil || service.hostedProvider == nil {
		controlWire.writeFailure(w, newConsoleFailure(http.StatusNotImplemented, controlCodeCapabilityUnavailable, "hosted browser cleanup is unavailable"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), managedBrowserReconcileTimeout)
	defer cancel()
	pending, err := service.reconcileHostedBrowser(ctx)
	if ctx.Err() != nil {
		pending = true
	} else if err != nil {
		controlWire.writeFailure(w, newConsoleFailure(http.StatusBadGateway, controlCodeEngineUnavailable, "could not check hosted browser cleanup"))
		return
	}
	writeJSON(w, http.StatusOK, struct {
		Pending bool `json:"pending"`
	}{Pending: pending})
}

// Reuse the Engine's cleanup ledgers and provider fences. A retained saved
// profile needs no active work. An unavailable provider or a failed compare
// and swap keeps the workspace eligible for another scheduled pass.
func (s *BrowserSignInService) reconcileHostedBrowser(ctx context.Context) (bool, error) {
	pending, err := s.reconcileBrowserRuns(ctx, true)
	if err != nil {
		return true, err
	}
	flows, err := s.flows.BrowserSignIns(ctx)
	if err != nil {
		return true, err
	}
	for _, flow := range flows {
		if err := ctx.Err(); err != nil {
			return true, err
		}
		if flow.State == "closed" || !s.isHostedBrowser(s.providerFor(flow.Provider, flow.ConfigurationID)) {
			continue
		}
		updated, err := s.advance(ctx, flow)
		if err != nil || (updated.State != "saved" && updated.State != "closed") {
			pending = true
		}
	}
	return pending, nil
}

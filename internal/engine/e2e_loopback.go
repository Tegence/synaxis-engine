//go:build engine_e2e_loopback

package engine

import (
	"context"
	"net"
	"net/http"
	"time"

	"narthex/backend/internal/upstreamoauth"
)

// This file is compiled only into an Engine built with
//
//	go build -tags engine_e2e_loopback ./cmd/engine
//
// which a local end-to-end stack uses when an upstream listens on plain HTTP
// on this machine (a caller-delegated connection whose URL, token endpoint
// and resource are http://localhost).
// Release images never pass the tag, so no environment variable or request
// can turn this on in a deployed Engine.
//
// It opens exactly two package seams: a caller-delegated connection may name
// http on a loopback host (callerDelegatedAllowLoopbackHTTP), and upstream
// dials, including the caller-grant exchange, may reach a loopback host.
// Every other destination still goes through the hardened dialer, so private
// and link-local addresses stay refused.
func init() {
	callerDelegatedAllowLoopbackHTTP = true
	newUpstreamTransport = loopbackUpstreamTransport
}

func loopbackUpstreamTransport() http.RoundTripper {
	transport := upstreamoauth.NewHardenedTransport()
	hardened := transport.DialContext
	direct := &net.Dialer{Timeout: 10 * time.Second}
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if host, _, err := net.SplitHostPort(addr); err == nil && loopbackHost(host) {
			return direct.DialContext(ctx, network, addr)
		}
		return hardened(ctx, network, addr)
	}
	return transport
}

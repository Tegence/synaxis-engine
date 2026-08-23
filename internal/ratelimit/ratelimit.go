// Package ratelimit provides a small process-local sliding-window limiter for
// the engine's password-gated surfaces (console login, OAuth consent). The
// engine is documented as single-replica, so a process-local limiter is
// sufficient; if multi-replica engines ever ship, this must be revisited.
//
// Denial is backoff-by-429 only, never a hard lockout: the engine is
// single-user by design (one shared password) and the legitimate administrator
// must never be permanently locked out.
package ratelimit

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Limiter allows a fixed number of attempts per key per sliding window.
// Entries are swept lazily on each check, which bounds the map to keys seen
// within the current window. It is safe for concurrent use.
type Limiter struct {
	mu       sync.Mutex
	limit    int
	window   time.Duration
	attempts map[string][]time.Time
	// now is a test seam; production limiters use time.Now.
	now func() time.Time
}

func New(limit int, window time.Duration) *Limiter {
	return &Limiter{
		limit:    limit,
		window:   window,
		attempts: make(map[string][]time.Time),
		now:      time.Now,
	}
}

// Allow records one attempt for key and reports whether it is within the
// limit. Attempts older than the window are swept before counting.
func (l *Limiter) Allow(key string) bool {
	now := l.now()
	cutoff := now.Add(-l.window)

	l.mu.Lock()
	defer l.mu.Unlock()

	kept := l.attempts[key][:0]
	for _, at := range l.attempts[key] {
		if at.After(cutoff) {
			kept = append(kept, at)
		}
	}
	if len(kept) == 0 {
		delete(l.attempts, key)
	} else {
		l.attempts[key] = kept
	}
	if len(kept) >= l.limit {
		return false
	}
	l.attempts[key] = append(l.attempts[key], now)
	return true
}

// RemoteIP keys a limiter by the host part of an http.Request's RemoteAddr —
// Go's raw TCP peer address. There is deliberately no trusted-proxy/
// X-Forwarded-For parsing here: RemoteAddr is always the socket peer, so it
// cannot be spoofed by request content. Callers that need to key on the
// original client through a reverse proxy should use ClientIP instead, which
// keeps this same safe default unless the caller explicitly opts in.
func RemoteIP(remoteAddr string) string {
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return host
	}
	return remoteAddr
}

// ClientIP resolves the rate-limit key for r.
//
// By default (trustProxyHeaders is false) this is exactly RemoteIP(r.RemoteAddr):
// the socket peer address, which cannot be spoofed. Self-hosted Engines are
// commonly run behind a TLS-terminating reverse proxy (nginx, Caddy, Traefik,
// Cloudflare Tunnel, ...), in which case RemoteAddr is the proxy's own fixed
// address for every request — collapsing every real client onto one shared
// bucket and letting a single attacker exhaust it for everyone, including the
// administrator.
//
// When trustProxyHeaders is true, the LAST entry of a present X-Forwarded-For
// header is used instead (falling back to RemoteAddr if the header is absent,
// empty, or its last entry does not parse as an IP address). The last entry
// is the one a directly-adjacent reverse proxy appends itself; nginx, Caddy,
// Traefik, and Cloudflare Tunnel all do this by default without extra
// configuration. Every earlier entry may have been set by the client itself
// and must not be trusted.
//
// trustProxyHeaders MUST be enabled ONLY when the engine sits directly behind
// exactly one reverse-proxy hop that the operator controls end-to-end. If any
// untrusted network path can reach the engine directly (bypassing that proxy)
// or inject its own X-Forwarded-For, an attacker can spoof this header to
// pick an arbitrary rate-limit key — trivially defeating the limiter.
func ClientIP(r *http.Request, trustProxyHeaders bool) string {
	if trustProxyHeaders {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			candidate := strings.TrimSpace(parts[len(parts)-1])
			candidate = strings.Trim(candidate, "[]")
			if ip := net.ParseIP(candidate); ip != nil {
				return ip.String()
			}
		}
	}
	return RemoteIP(r.RemoteAddr)
}

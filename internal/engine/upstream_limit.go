package engine

import (
	"errors"
	"io"
	"net/http"
	"sync/atomic"
)

const (
	// The public cap applies to the decoded CallToolResult. Allow a modest
	// amount for the JSON-RPC envelope and SSE framing, while bounding bytes
	// before mcp-go's JSON/SSE decoders can allocate from an upstream body.
	upstreamMCPResponseFramingAllowance int64 = 64 << 10
	maxUpstreamMCPResponseBytes               = int64(MaxMCPResultBytes) +
		upstreamMCPResponseFramingAllowance
)

// ErrUpstreamResponseTooLarge survives mcp-go's transport wrappers and is
// converted at the gateway boundary into the existing structured
// result_too_large tool result.
var ErrUpstreamResponseTooLarge = errors.New("upstream MCP response exceeded the Engine safety limit")

// upstreamResponseLimiter is installed as the HTTP client's RoundTripper.
// Streamable HTTP uses this client for both application/json responses and
// per-request text/event-stream responses, so both are bounded before decode.
type upstreamResponseLimiter struct {
	base     http.RoundTripper
	exceeded atomic.Bool
}

func newUpstreamResponseLimiter(base http.RoundTripper) *upstreamResponseLimiter {
	if base == nil {
		base = http.DefaultTransport
	}
	return &upstreamResponseLimiter{base: base}
}

func (l *upstreamResponseLimiter) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := l.base.RoundTrip(request)
	if err != nil || response == nil || response.Body == nil {
		return response, err
	}
	if response.ContentLength > maxUpstreamMCPResponseBytes {
		l.exceeded.Store(true)
		response.Body = &upstreamRejectedBody{source: response.Body}
		return response, nil
	}
	response.Body = &upstreamBoundedBody{
		source:    response.Body,
		remaining: maxUpstreamMCPResponseBytes,
		onExceeded: func() {
			l.exceeded.Store(true)
		},
	}
	return response, nil
}

func (l *upstreamResponseLimiter) reset() {
	l.exceeded.Store(false)
}

func (l *upstreamResponseLimiter) classify(err error) error {
	if l.exceeded.Load() {
		return ErrUpstreamResponseTooLarge
	}
	return err
}

type upstreamRejectedBody struct {
	source io.ReadCloser
}

func (b *upstreamRejectedBody) Read([]byte) (int, error) {
	return 0, ErrUpstreamResponseTooLarge
}

func (b *upstreamRejectedBody) Close() error {
	return b.source.Close()
}

type upstreamBoundedBody struct {
	source     io.ReadCloser
	remaining  int64
	onExceeded func()
}

func (b *upstreamBoundedBody) Read(destination []byte) (int, error) {
	if len(destination) == 0 {
		return 0, nil
	}
	if b.remaining <= 0 {
		var probe [1]byte
		n, err := b.source.Read(probe[:])
		if n > 0 {
			b.onExceeded()
			return 0, ErrUpstreamResponseTooLarge
		}
		return 0, err
	}

	readLimit := int64(len(destination))
	if readLimit > b.remaining+1 {
		readLimit = b.remaining + 1
	}
	n, err := b.source.Read(destination[:int(readLimit)])
	if int64(n) > b.remaining {
		allowed := int(b.remaining)
		b.remaining = 0
		b.onExceeded()
		return allowed, ErrUpstreamResponseTooLarge
	}
	b.remaining -= int64(n)
	return n, err
}

func (b *upstreamBoundedBody) Close() error {
	return b.source.Close()
}

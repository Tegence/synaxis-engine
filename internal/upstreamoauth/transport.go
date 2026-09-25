package upstreamoauth

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"
)

// ErrUnsafeOutboundAddress is returned before an upstream connection is made
// when DNS resolves a host to an address that is not safe to reach from the
// Engine. Keeping this sentinel lets callers and tests distinguish a refused
// network destination from an ordinary provider outage.
var ErrUnsafeOutboundAddress = errors.New("refusing to connect to a non-public address")

// NewHardenedTransport returns the direct-only transport used for every
// Engine-initiated request to an upstream MCP or OAuth server. It resolves the
// destination at dial time, validates every returned address, then dials the
// validated IP rather than the original hostname. The latter is important: a
// second resolver lookup performed by a normal hostname dial could otherwise
// turn a safe DNS answer into a DNS-rebinding request to an internal address.
//
// Environment proxies are deliberately disabled. A CONNECT proxy would make
// the transport validate only the proxy address while the proxy itself could
// reach a private upstream destination.
func NewHardenedTransport() *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = safeDialer()
	// A cloned default transport leaves DialTLSContext nil. Set it explicitly
	// so all TLS connections continue through the validating DialContext.
	transport.DialTLSContext = nil
	return transport
}

// NewHardenedHTTPClient constructs an upstream-only HTTP client.
func NewHardenedHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:       timeout,
		Transport:     NewHardenedTransport(),
		CheckRedirect: CheckUpstreamRedirect,
	}
}

// safeDialer resolves an upstream hostname and rejects unsafe results before
// opening a socket. It intentionally connects to the resolved IP, never the
// original hostname, so resolution and connection cannot be split by a DNS
// rebinding response.
func safeDialer() func(ctx context.Context, network, addr string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	return newSafeDialer(net.DefaultResolver.LookupIPAddr, dialer.DialContext)
}

type lookupIPAddrFunc func(context.Context, string) ([]net.IPAddr, error)
type dialContextFunc func(context.Context, string, string) (net.Conn, error)

// newSafeDialer exposes the resolution and connection boundary to focused
// tests. Production callers always use safeDialer above.
func newSafeDialer(lookup lookupIPAddrFunc, dial dialContextFunc) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("split upstream address: %w", err)
		}
		ips, err := lookup(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("resolve upstream host %q: %w", host, err)
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("resolve upstream host %q: no addresses", host)
		}
		for _, resolved := range ips {
			if isUnsafeOutboundIP(resolved.IP) {
				return nil, fmt.Errorf("%w: %s", ErrUnsafeOutboundAddress, resolved.IP)
			}
		}

		// Dial the pinned answer instead of host:port. This avoids a second DNS
		// lookup in net.Dialer, which is the window DNS rebinding attacks need.
		return dial(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
	}
}

func isUnsafeOutboundIP(ip net.IP) bool {
	if ip == nil {
		return true
	}

	// Unwrap IPv6 transition mechanisms that embed an IPv4 address before the
	// standard checks: net.IP.IsPrivate and friends do not decode them, so on
	// a DNS64/NAT64 network a synthesized answer could smuggle a private IPv4
	// past the guard. The embedded address is re-checked recursively, which
	// also covers loopback/link-local embeddings, not just RFC 1918.
	if v6 := ip.To16(); v6 != nil && ip.To4() == nil {
		switch {
		case v6[0] == 0x00 && v6[1] == 0x64 && v6[2] == 0xff && v6[3] == 0x9b &&
			// NAT64 (RFC 6052): 64:ff9b::/96, IPv4 in the last 4 bytes.
			v6[4] == 0 && v6[5] == 0 && v6[6] == 0 && v6[7] == 0 &&
			v6[8] == 0 && v6[9] == 0 && v6[10] == 0 && v6[11] == 0:
			return isUnsafeOutboundIP(net.IPv4(v6[12], v6[13], v6[14], v6[15]))
		case v6[0] == 0x20 && v6[1] == 0x02:
			// 6to4 (RFC 3056): 2002::/16, IPv4 in bytes 2-5.
			return isUnsafeOutboundIP(net.IPv4(v6[2], v6[3], v6[4], v6[5]))
		case v6[0] == 0x20 && v6[1] == 0x01 && v6[2] == 0 && v6[3] == 0:
			// Teredo (RFC 4380): 2001::/32, server IPv4 in bytes 4-7.
			return isUnsafeOutboundIP(net.IPv4(v6[4], v6[5], v6[6], v6[7]))
		}
	}

	if ip.IsUnspecified() || ip.IsLoopback() || ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() {
		return true
	}

	// RFC 6598 shared address space is not public Internet address space, but
	// net.IP.IsPrivate intentionally excludes it. Blocking it also covers a
	// commonly used cloud-internal metadata range (100.100.100.200).
	if v4 := ip.To4(); v4 != nil && v4[0] == 100 && v4[1]&0xc0 == 0x40 {
		return true
	}
	return false
}

// CheckUpstreamRedirect stops HTTPS downgrade and malformed redirects before
// a new request is issued. It is exported so callers that safely decorate
// NewHardenedTransport (such as Engine's response limiter) retain the same
// redirect policy. The hardened transport performs the authoritative DNS/IP
// check again when the redirect target is dialed.
func CheckUpstreamRedirect(request *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return errors.New("upstream redirect limit exceeded")
	}
	if err := validateHTTPSURL(request.URL); err != nil {
		return fmt.Errorf("upstream redirect rejected: %w", err)
	}
	return nil
}

func validateHTTPSURL(u *url.URL) error {
	if u == nil {
		return errors.New("url is required")
	}
	if u.Scheme != "https" {
		return errors.New("url must use https")
	}
	if u.Hostname() == "" {
		return errors.New("url must have a host")
	}
	if u.User != nil {
		return errors.New("url must not contain user credentials")
	}
	if ip := net.ParseIP(u.Hostname()); ip != nil && isUnsafeOutboundIP(ip) {
		return fmt.Errorf("%w: %s", ErrUnsafeOutboundAddress, ip)
	}
	return nil
}

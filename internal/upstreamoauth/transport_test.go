package upstreamoauth

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestSafeDialerPinsTheValidatedDNSAnswer(t *testing.T) {
	const resolvedIP = "8.8.8.8"
	stop := errors.New("stop after observing the dial target")
	var gotAddress string

	dial := newSafeDialer(
		func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP(resolvedIP)}}, nil
		},
		func(_ context.Context, _, address string) (net.Conn, error) {
			gotAddress = address
			return nil, stop
		},
	)

	_, err := dial(context.Background(), "tcp", "rebindable.example:443")
	if !errors.Is(err, stop) {
		t.Fatalf("dial error = %v, want the test dialer error", err)
	}
	if gotAddress != resolvedIP+":443" {
		t.Fatalf("dialed %q, want resolved IP %q rather than the hostname", gotAddress, resolvedIP+":443")
	}
}

func TestSafeDialerFailsClosedWhenDNSAlsoReturnsAnUnsafeAddress(t *testing.T) {
	dialed := false
	dial := newSafeDialer(
		func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{
				{IP: net.ParseIP("8.8.8.8")},
				{IP: net.ParseIP("127.0.0.1")},
			}, nil
		},
		func(context.Context, string, string) (net.Conn, error) {
			dialed = true
			return nil, nil
		},
	)

	_, err := dial(context.Background(), "tcp", "mixed.example:443")
	if !errors.Is(err, ErrUnsafeOutboundAddress) {
		t.Fatalf("dial error = %v, want ErrUnsafeOutboundAddress", err)
	}
	if dialed {
		t.Fatal("dialer was called after an unsafe DNS answer")
	}
}

func TestHardenedHTTPClientBlocksUnsafeInitialDestination(t *testing.T) {
	client := NewHardenedHTTPClient(time.Second)
	_, err := client.Get("https://127.0.0.1:443/mcp")
	if !errors.Is(err, ErrUnsafeOutboundAddress) {
		t.Fatalf("GET loopback error = %v, want ErrUnsafeOutboundAddress", err)
	}
}

func TestHardenedHTTPClientRejectsUnsafeAndDowngradeRedirects(t *testing.T) {
	for _, target := range []string{
		"https://127.0.0.1:443/internal",
		"http://public.example/downgrade",
	} {
		t.Run(target, func(t *testing.T) {
			var calls atomic.Int32
			client := &http.Client{
				Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
					calls.Add(1)
					return &http.Response{
						StatusCode: http.StatusFound,
						Header:     http.Header{"Location": []string{target}},
						Body:       io.NopCloser(&emptyReader{}),
						Request:    request,
					}, nil
				}),
				CheckRedirect: CheckUpstreamRedirect,
			}

			_, err := client.Get("https://mcp.example/start")
			if err == nil {
				t.Fatal("redirect to an unsafe target unexpectedly succeeded")
			}
			if calls.Load() != 1 {
				t.Fatalf("redirect made %d round trips, want only the initial request", calls.Load())
			}
			if target[:5] == "https" && !errors.Is(err, ErrUnsafeOutboundAddress) {
				t.Fatalf("private redirect error = %v, want ErrUnsafeOutboundAddress", err)
			}
		})
	}
}

func TestNewHardenedTransportDisablesProxyAndKeepsDialValidation(t *testing.T) {
	transport := NewHardenedTransport()
	if transport.Proxy != nil {
		t.Fatal("hardened transport must not use environment proxies")
	}
	if transport.DialContext == nil {
		t.Fatal("hardened transport must install a validating DialContext")
	}
	if transport.DialTLSContext != nil {
		t.Fatal("hardened transport must route TLS dials through DialContext")
	}
}

type emptyReader struct{}

func (*emptyReader) Read([]byte) (int, error) { return 0, io.EOF }

func TestIsUnsafeOutboundIPUnwrapsTransitionAddresses(t *testing.T) {
	tests := []struct {
		name   string
		raw    string
		unsafe bool
	}{
		{"NAT64 embeds private 10.x", "64:ff9b::a00:1", true},
		{"NAT64 embeds link-local metadata", "64:ff9b::a9fe:a9fe", true},
		{"NAT64 embeds loopback", "64:ff9b::7f00:1", true},
		{"NAT64 embeds RFC 6598", "64:ff9b::6440:1", true},
		{"NAT64 embeds public IP", "64:ff9b::808:808", false}, // 8.8.8.8
		{"6to4 embeds link-local metadata", "2002:a9fe:a9fe::", true},
		{"6to4 embeds private 192.168", "2002:c0a8:101::", true},
		{"6to4 embeds public IP", "2002:808:808::", false}, // 8.8.8.8
		{"Teredo server private 10.x", "2001::a00:1:0:0:0:0", true},
		{"Teredo server link-local metadata", "2001::a9fe:a9fe:0:0:0:0", true},
		{"Teredo server public IP", "2001::808:808:0:0:0:0", false}, // 8.8.8.8
		{"ordinary public IPv6 untouched", "2001:4860:4860::8888", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ip := net.ParseIP(tc.raw)
			if ip == nil {
				t.Fatalf("ParseIP(%q) = nil", tc.raw)
			}
			if got := isUnsafeOutboundIP(ip); got != tc.unsafe {
				t.Fatalf("isUnsafeOutboundIP(%s) = %v, want %v", tc.raw, got, tc.unsafe)
			}
		})
	}
}

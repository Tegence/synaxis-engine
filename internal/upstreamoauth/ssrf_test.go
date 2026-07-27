package upstreamoauth

import (
	"context"
	"strings"
	"testing"
)

func TestValidateUpstreamURL(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "http rejected",
			raw:     "http://x",
			wantErr: true,
			errMsg:  "must be https",
		},
		{
			name:    "empty rejected",
			raw:     "",
			wantErr: true,
			errMsg:  "must be https",
		},
		{
			name:    "https with valid host accepted",
			raw:     "https://mcp.notion.com/mcp",
			wantErr: false,
		},
		{
			name:    "https with public IP accepted at URL level",
			raw:     "https://1.2.3.4",
			wantErr: false,
		},
		{
			name:    "ftp rejected",
			raw:     "ftp://example.com",
			wantErr: true,
			errMsg:  "must be https",
		},
		{
			name:    "https no host rejected",
			raw:     "https://",
			wantErr: true,
			errMsg:  "must have a host",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateUpstreamURL(tc.raw)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q, got nil", tc.raw)
				}
				if tc.errMsg != "" && !strings.Contains(err.Error(), tc.errMsg) {
					t.Fatalf("expected error containing %q, got: %v", tc.errMsg, err)
				}
			} else {
				if err != nil {
					t.Fatalf("expected no error for %q, got: %v", tc.raw, err)
				}
			}
		})
	}
}

func TestValidateUpstreamURL_Export(t *testing.T) {
	// Confirm the exported thin wrapper delegates correctly.
	if err := ValidateUpstreamURL("https://mcp.notion.com/mcp"); err != nil {
		t.Fatalf("expected no error for mcp.notion.com, got: %v", err)
	}
	if err := ValidateUpstreamURL("http://mcp.notion.com/mcp"); err == nil {
		t.Fatal("expected error for http scheme, got nil")
	}
}

func TestSafeDialer_BlocksPrivateAddresses(t *testing.T) {
	dial := safeDialer()
	ctx := context.Background()

	blockedAddrs := []struct {
		name string
		addr string
	}{
		{"loopback IPv4", "127.0.0.1:443"},
		{"link-local GCP metadata", "169.254.169.254:443"},
		{"RFC-1918 10.x", "10.0.0.1:443"},
		{"RFC-1918 192.168.x", "192.168.1.1:443"},
		{"RFC-1918 172.16.x", "172.16.0.1:443"},
	}

	for _, tc := range blockedAddrs {
		t.Run(tc.name, func(t *testing.T) {
			conn, err := dial(ctx, "tcp", tc.addr)
			if err == nil {
				conn.Close()
				t.Fatalf("expected dial to %s to be refused, but it succeeded", tc.addr)
			}
			if !strings.Contains(err.Error(), "non-public") {
				t.Fatalf("expected error mentioning 'non-public', got: %v", err)
			}
		})
	}
}

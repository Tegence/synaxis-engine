package engine

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// canonicalAccountURL returns a comparison-only representation of an upstream
// MCP URL. It deliberately normalizes only URL components whose equivalence is
// unambiguous for an HTTPS request (scheme/host case, the default port, and an
// empty root path). Paths and queries otherwise remain byte-for-byte distinct:
// treating two differently encoded paths or reordered query strings as equal
// could move a stored credential to a different upstream resource.
func canonicalAccountURL(raw string) (string, error) {
	u, err := url.ParseRequestURI(strings.TrimSpace(raw))
	if err != nil || !u.IsAbs() || u.Opaque != "" || u.Host == "" {
		return "", fmt.Errorf("invalid account URL")
	}
	if !strings.EqualFold(u.Scheme, "https") || u.User != nil || u.Fragment != "" {
		return "", fmt.Errorf("invalid account URL")
	}

	hostname := strings.ToLower(u.Hostname())
	if hostname == "" {
		return "", fmt.Errorf("invalid account URL")
	}
	port := u.Port()
	if port == "443" {
		port = ""
	}
	host := hostname
	if strings.Contains(hostname, ":") || port != "" {
		host = net.JoinHostPort(hostname, port)
		if port == "" {
			host = "[" + hostname + "]"
		}
	}

	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	canonical := "https://" + host + path
	if u.ForceQuery || u.RawQuery != "" {
		canonical += "?" + u.RawQuery
	}
	return canonical, nil
}

func equalAccountURL(left, right string) bool {
	canonicalLeft, err := canonicalAccountURL(left)
	if err != nil {
		return false
	}
	canonicalRight, err := canonicalAccountURL(right)
	return err == nil && canonicalLeft == canonicalRight
}

// equalAccountSnapshotURL is used only to bind an already-loaded live handler
// to its stored destination. Exact equality is sufficient for legacy/local
// HTTP test endpoints; otherwise use the stricter HTTPS canonical comparison.
func equalAccountSnapshotURL(left, right string) bool {
	if strings.TrimSpace(left) == strings.TrimSpace(right) {
		return true
	}
	return equalAccountURL(left, right)
}

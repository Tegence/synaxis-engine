// Package engine is the internal MCP gateway (the MetaMCP replacement spike).
//
// upstream.go is the differentiator: an MCP *client* to an upstream server with
// REFRESH-AND-REDIAL on 401. MetaMCP refreshes the stored token on a 401 but
// keeps serving from a dead pooled connection, so providers with short-lived
// rotating tokens (Notion) drop ~hourly. Here, a 401 refreshes the token AND
// re-dials a fresh connection that picks the new token up. ~20 lines, owned.
package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/client/transport"
	"github.com/mark3labs/mcp-go/mcp"
)

// Upstream is one connected backend account (e.g. "tegence_notion").
type Upstream struct {
	Name string // the tool prefix Claude sees: <Name>__<tool>
	URL  string // the upstream MCP Streamable HTTP endpoint
	// Available verifies that this client snapshot still belongs to the live
	// durable account incarnation. Gateway-provided upstreams always set it;
	// standalone/bootstrap callers may omit it.
	Available func() bool
	// Credential atomically resolves the credential for this exact client
	// snapshot. Gateway uses it to avoid a check/read gap where a deleted name
	// could be recreated between Available and Token. Standalone callers may
	// omit it and retain the legacy Available + Token path.
	Credential func() (string, error)
	// Token returns the current upstream access token.
	Token func() string
	// Refresh obtains a fresh access token (and persists it). Called on a 401;
	// nil means token-auth with no refresh (e.g. a static PAT).
	Refresh func(ctx context.Context) error
}

type upstreamConnection struct {
	client    *client.Client
	responses *upstreamResponseLimiter
}

func isUnauthorized(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "401") ||
		strings.Contains(s, "unauthorized") ||
		strings.Contains(s, "authorization required") || // mcp-go's phrasing for a 401
		strings.Contains(s, "invalid_token") ||
		strings.Contains(s, "invalid access token")
}

// dial opens a fresh MCP client to the upstream using the CURRENT token, and
// completes the handshake. A new client per dial is what lets a refreshed token
// take effect — the core of refresh-and-redial.
func (u *Upstream) dial(ctx context.Context) (*upstreamConnection, error) {
	headers := map[string]string{}
	if u.Credential != nil {
		token, err := u.Credential()
		if err != nil {
			return nil, err
		}
		if token != "" {
			headers["Authorization"] = "Bearer " + token
		}
	} else {
		if u.Available != nil && !u.Available() {
			return nil, ErrAccountIncarnation
		}
		if u.Token != nil {
			if token := u.Token(); token != "" {
				headers["Authorization"] = "Bearer " + token
			}
		}
	}
	responseLimiter := newUpstreamResponseLimiter(http.DefaultTransport)
	httpClient := &http.Client{Transport: responseLimiter}
	c, err := client.NewStreamableHttpClient(
		u.URL,
		transport.WithHTTPHeaders(headers),
		transport.WithHTTPBasicClient(httpClient),
	)
	if err != nil {
		return nil, err
	}
	if err := c.Start(ctx); err != nil {
		c.Close()
		return nil, responseLimiter.classify(err)
	}
	init := mcp.InitializeRequest{}
	init.Params.ProtocolVersion = mcp.LATEST_PROTOCOL_VERSION
	init.Params.ClientInfo = mcp.Implementation{Name: "synaxis-engine", Version: "0.0"}
	if _, err := c.Initialize(ctx, init); err != nil {
		err = responseLimiter.classify(err)
		c.Close()
		return nil, err
	}
	return &upstreamConnection{client: c, responses: responseLimiter}, nil
}

// withConn runs fn against a live upstream connection. On a 401 it refreshes the
// token and RE-DIALS once before giving up — the behaviour MetaMCP lacks.
func (u *Upstream) withConn(ctx context.Context, fn func(*client.Client) error) error {
	connection, err := u.dial(ctx)
	if err == nil {
		defer connection.client.Close()
		connection.responses.reset()
		err = connection.responses.classify(fn(connection.client))
		if err == nil {
			return nil
		}
	}
	if isUnauthorized(err) && u.Refresh != nil {
		if rerr := u.Refresh(ctx); rerr != nil {
			return fmt.Errorf("%s: refresh failed: %w", u.Name, rerr)
		}
		connection2, derr := u.dial(ctx) // re-dial with the freshly-refreshed token
		if derr != nil {
			return fmt.Errorf("%s: re-dial after refresh failed: %w", u.Name, derr)
		}
		defer connection2.client.Close()
		connection2.responses.reset()
		return connection2.responses.classify(fn(connection2.client))
	}
	return err
}

// ListTools returns the upstream's tools, prefixed with "<Name>__".
func (u *Upstream) ListTools(ctx context.Context) ([]mcp.Tool, error) {
	var tools []mcp.Tool
	err := u.withConn(ctx, func(c *client.Client) error {
		request := mcp.ListToolsRequest{}
		var encodedBytes int64
		const maxPages = 100
		for page := 0; page < maxPages; page++ {
			res, err := c.ListToolsByPage(ctx, request)
			if err != nil {
				return err
			}
			raw, err := json.Marshal(res.Tools)
			if err != nil {
				return fmt.Errorf("measure upstream tools page: %w", err)
			}
			encodedBytes += int64(len(raw))
			if encodedBytes > maxUpstreamMCPResponseBytes {
				return ErrUpstreamResponseTooLarge
			}
			for _, tool := range res.Tools {
				encodedBytes += int64(len(u.Name) + 2)
				if encodedBytes > maxUpstreamMCPResponseBytes {
					return ErrUpstreamResponseTooLarge
				}
				tool.Name = u.Name + "__" + tool.Name
				tools = append(tools, tool)
			}
			if res.NextCursor == "" {
				return nil
			}
			request.Params.Cursor = res.NextCursor
		}
		return errors.New("upstream tool pagination exceeded 100 pages")
	})
	return tools, err
}

// CallTool routes a prefixed tool call to this upstream (prefix already stripped
// by the caller). Same refresh-and-redial guarantee.
func (u *Upstream) CallTool(ctx context.Context, bareName string, args map[string]any) (*mcp.CallToolResult, error) {
	var out *mcp.CallToolResult
	err := u.withConn(ctx, func(c *client.Client) error {
		req := mcp.CallToolRequest{}
		req.Params.Name = bareName
		req.Params.Arguments = args
		res, err := c.CallTool(ctx, req)
		if err != nil {
			return err
		}
		out = res
		return nil
	})
	return out, err
}

// dialTimeout is the per-attempt ceiling (kept here so tests can reason about it).
const dialTimeout = 20 * time.Second

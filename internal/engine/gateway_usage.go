package engine

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
)

const usageSettlementTimeout = 5 * time.Second

type upstreamExecution struct {
	result   *mcp.CallToolResult
	callErr  error
	usageErr error
}

// SetUsageGate enables hosted metering. A nil gate is the self-hosted default:
// calls remain quota-unlimited, while the universal deadline and payload caps
// still protect the Engine process.
func (g *Gateway) SetUsageGate(gate *UsageGate) { g.usage = gate }

// executeUpstream is the single dispatch boundary for normal MCP calls and
// operator-requested replays. Admission commits before the network call;
// settlement completes synchronously afterward and is independent of the
// best-effort audit sink.
func (g *Gateway) executeUpstream(
	ctx context.Context,
	meta UsageCallMeta,
	args map[string]any,
	call func(context.Context) (*mcp.CallToolResult, error),
) upstreamExecution {
	maxCallSeconds := StarterMaxCallSeconds
	var reservation UsageReservation
	if g.usage != nil {
		var err error
		reservation, err = g.usage.Admit(ctx, meta)
		if err != nil {
			return upstreamExecution{usageErr: err}
		}
		maxCallSeconds = reservation.MaxCallSeconds
	}

	callCtx, cancel := context.WithTimeout(ctx, time.Duration(maxCallSeconds)*time.Second)
	started := time.Now()
	result, callErr := call(callCtx)
	runtime := time.Since(started)
	cancel()

	requestBytes := jsonSize(args)
	resultBytes := jsonSize(result)
	preDecodeTooLarge := errors.Is(callErr, ErrUpstreamResponseTooLarge)
	if preDecodeTooLarge {
		// The transport stopped reading before decode. Charge a bounded
		// over-limit result rather than zero bytes, then preserve the same
		// structured result_too_large behavior as the post-decode check.
		resultBytes = MaxMCPResultBytes + 1
	}
	execution := upstreamExecution{
		result: result, callErr: callErr,
	}

	if g.usage != nil {
		settleCtx, settleCancel := context.WithTimeout(context.Background(), usageSettlementTimeout)
		err := g.usage.Settle(settleCtx, reservation, runtime, requestBytes+resultBytes)
		settleCancel()
		if err != nil {
			// The durable reservation remains open and will be recovered. Do
			// not return the upstream result: retrying a mutating call would be
			// dangerous, so the structured error explicitly says not to.
			execution.result = nil
			execution.callErr = nil
			execution.usageErr = err
			return execution
		}
	}

	if preDecodeTooLarge || resultBytes > MaxMCPResultBytes {
		execution.result = resultLimitToolResult()
		execution.callErr = nil
	}
	return execution
}

func jsonSize(value any) int64 {
	if value == nil {
		return 0
	}
	raw, err := json.Marshal(value)
	if err != nil {
		// mcp-go will be unable to encode the same value. Charging zero here is
		// preferable to inventing bytes; the caller still receives a protocol
		// serialization failure and the call/runtime have already been counted.
		log.Printf("engine: measure MCP payload: %v", err)
		return 0
	}
	return int64(len(raw))
}

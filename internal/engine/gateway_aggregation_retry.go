package engine

import (
	"context"
	"log"
	"time"
)

// aggregationRetryDelays are the waits before each extra listing of an
// account whose re-aggregation failed right after a connection write (about
// a minute in all). An authorization server may accept a new listing
// credential only once the control plane's write has returned (it records
// the credential after the control plane answers), so the write's own
// listing can be refused for a moment. Without these retries the account
// would stay without tools until the next health sweep (StartWatch). A
// variable so tests can shorten it.
var aggregationRetryDelays = []time.Duration{2 * time.Second, 5 * time.Second, 15 * time.Second, 40 * time.Second}

// replaceAccountListingSoon re-aggregates the account after a committed
// connection write, as ReplaceAccount does, and when that listing fails it
// lists the same account incarnation again after each aggregationRetryDelays
// wait, in the background, until it is projected. One retry loop runs per
// account name at a time. The write's answer never waits for it.
func (g *Gateway) replaceAccountListingSoon(ctx context.Context, name string) {
	if _, err := g.ReplaceAccount(ctx, name); err == nil {
		return
	}
	account, found := g.store.Account(name)
	if !found || account.IncarnationID == "" {
		return
	}
	if _, running := g.aggregationRetries.LoadOrStore(name, struct{}{}); running {
		return
	}
	incarnation := account.IncarnationID
	delays := append([]time.Duration(nil), aggregationRetryDelays...)
	log.Printf("engine: account %q could not be listed after a connection write; listing it again shortly", name)
	go func() {
		defer g.aggregationRetries.Delete(name)
		for _, delay := range delays {
			time.Sleep(delay)
			current, found := g.store.Account(name)
			if !found || current.IncarnationID != incarnation {
				return
			}
			if g.accountProjected(current) {
				// The start-up reconcile or the health sweep listed it first.
				log.Printf("engine: account %q was listed by another pass after a connection write", name)
				return
			}
			actx, cancel := context.WithTimeout(context.Background(), aggregateAccountTimeout)
			_, err := g.addAccountSnapshot(actx, current)
			cancel()
			if err == nil {
				log.Printf("engine: account %q listed on retry after a connection write", name)
				return
			}
		}
		log.Printf("engine: account %q still could not be listed after a connection write; the health sweep retries it", name)
	}()
}

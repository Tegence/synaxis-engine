package engine

import (
	"log"
	"net/http"
	"sync"
	"sync/atomic"
)

// NoteDeprecated records one use of a compatibility surface that is scheduled
// for removal. The first use per process is logged, so production logs answer
// "does anything still depend on this?" before the removal date in
// DEPRECATIONS.md arrives; later uses are counted and otherwise silent. Every
// name passed here must have a row in that ledger
// (TestDeprecatedSurfacesAreInTheLedger pins it).
func NoteDeprecated(name string) {
	hits, _ := deprecatedHits.LoadOrStore(name, new(atomic.Int64))
	if hits.(*atomic.Int64).Add(1) == 1 {
		log.Printf("deprecated: %s was used; DEPRECATIONS.md names the replacement and the earliest removal date", name)
	}
}

// deprecatedHandler serves a compatibility route and records each use.
func deprecatedHandler(name string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		NoteDeprecated(name)
		next(w, r)
	}
}

var deprecatedHits sync.Map

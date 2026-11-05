package engine

// The knowledge index is a derived, tenant-blind projection. It never grants
// access to source records. Only trusted source services can search it; they
// must reauthorize and hydrate every reference against their source of truth.
import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

const knowledgeMaxDocuments = 10000

var knowledgeSourceID = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,199}$`)
var knowledgeID = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_./:-]{0,199}$`)
var ErrKnowledgeConflict = errors.New("knowledge version conflict")
var ErrKnowledgeCapacity = errors.New("knowledge index capacity reached")

type KnowledgeDocument struct {
	Source  string `json:"source"`
	ID      string `json:"id"`
	Version int64  `json:"version"`
	Title   string `json:"title,omitempty"`
	Text    string `json:"text,omitempty"`
	Deleted bool   `json:"deleted,omitempty"`
}
type KnowledgeReference struct {
	ID      string `json:"id"`
	Version int64  `json:"version"`
	Score   int    `json:"score"`
}
type KnowledgePage struct {
	Items []KnowledgeReference `json:"items"`
	Next  int                  `json:"next,omitempty"`
	Mode  string               `json:"mode"`
}
type KnowledgeStore interface {
	PutKnowledge(context.Context, KnowledgeDocument) error
	VisitKnowledge(context.Context, string, func(KnowledgeDocument) error) error
}

func (d KnowledgeDocument) valid() bool {
	return knowledgeSourceID.MatchString(d.Source) && knowledgeID.MatchString(d.ID) && d.Version > 0 && len(d.Title) <= 2000 && len(d.Text) <= 65536 && (!d.Deleted || d.Title == "" && d.Text == "")
}
func knowledgeDigest(d KnowledgeDocument) string {
	b, _ := json.Marshal(d)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func knowledgeSigningKey(token string) []byte {
	if token == "" {
		return nil
	}
	h := hmac.New(sha256.New, []byte(token))
	h.Write([]byte("synaxis/knowledge/v1"))
	return h.Sum(nil)
}
func knowledgeToken(key []byte, source string) string {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(source))
	return hex.EncodeToString(h.Sum(nil))
}

func (c *ConsoleAPI) knowledgeRoutes(mux *http.ServeMux) {
	// Credential issuance uses the control boundary and bypasses response replay
	// persistence. Rotating the engine admin secret revokes all source tokens.
	mux.HandleFunc("POST /control/v1/knowledge/sources/{source}/credential", c.controlV1Credential(func(w http.ResponseWriter, r *http.Request) {
		source := r.PathValue("source")
		if c.actorVerifier != nil {
			actor, ok := c.connectionNamespaceActor(r)
			if !ok || actor.Role != "service" || actor.UserID != platformServiceActorID {
				writeControlProblem(w, http.StatusForbidden, controlCodeForbidden, "source credentials require the Platform service")
				return
			}
		}
		if !knowledgeSourceID.MatchString(source) || len(c.knowledgeKey) == 0 {
			http.Error(w, "invalid source", 400)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"source": source, "token": knowledgeToken(c.knowledgeKey, source)})
	}))
	mux.HandleFunc("PUT /knowledge/v1/sources/{source}/documents", c.knowledgeHandler(false))
	mux.HandleFunc("POST /knowledge/v1/sources/{source}/search", c.knowledgeHandler(true))
}
func (c *ConsoleAPI) knowledgeHandler(search bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		source := r.PathValue("source")
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") || !knowledgeSourceID.MatchString(source) || len(c.knowledgeKey) == 0 || subtle.ConstantTimeCompare([]byte(token), []byte(knowledgeToken(c.knowledgeKey, source))) != 1 {
			http.Error(w, "unauthorized", 401)
			return
		}
		data, ok := c.store.(KnowledgeStore)
		if !ok {
			http.Error(w, "index unavailable", 503)
			return
		}
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 512<<10))
		decoder.DisallowUnknownFields()
		if search {
			var input struct {
				Query  string `json:"query"`
				Offset int    `json:"offset"`
			}
			if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF || len(strings.TrimSpace(input.Query)) < 2 || len(input.Query) > 100 || input.Offset < 0 || input.Offset > knowledgeMaxDocuments {
				http.Error(w, "invalid query", 400)
				return
			}
			page, err := searchKnowledge(r.Context(), data, source, input.Query, input.Offset)
			if err != nil {
				http.Error(w, "index unavailable", 503)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(page)
			return
		}
		var document KnowledgeDocument
		if decoder.Decode(&document) != nil || decoder.Decode(new(any)) != io.EOF || document.Source != source || !document.valid() {
			http.Error(w, "invalid document", 400)
			return
		}
		err := data.PutKnowledge(r.Context(), document)
		if errors.Is(err, ErrKnowledgeConflict) {
			http.Error(w, "version conflict", 409)
			return
		}
		if errors.Is(err, ErrKnowledgeCapacity) {
			http.Error(w, "index capacity reached", 507)
			return
		}
		if err != nil {
			http.Error(w, "index unavailable", 503)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}
func searchKnowledge(ctx context.Context, store KnowledgeStore, source, query string, offset int) (KnowledgePage, error) {
	terms := strings.FieldsFunc(strings.ToLower(query), func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsNumber(r) })
	page := KnowledgePage{Items: []KnowledgeReference{}, Mode: "keyword"}
	if len(terms) == 0 {
		return page, nil
	}
	hits := []KnowledgeReference{}
	err := store.VisitKnowledge(ctx, source, func(d KnowledgeDocument) error {
		if d.Deleted {
			return nil
		}
		title, body := strings.ToLower(d.Title), strings.ToLower(d.Text)
		score := 0
		for _, term := range terms {
			if strings.Contains(title, term) {
				score += 4
			} else if strings.Contains(body, term) {
				score++
			} else {
				return nil
			}
		}
		hits = append(hits, KnowledgeReference{d.ID, d.Version, score})
		return nil
	})
	if err != nil {
		return page, err
	}
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].Score == hits[j].Score {
			return hits[i].ID < hits[j].ID
		}
		return hits[i].Score > hits[j].Score
	})
	if offset >= len(hits) {
		return page, nil
	}
	end := min(offset+100, len(hits))
	page.Items = hits[offset:end]
	if end < len(hits) {
		page.Next = end
	}
	return page, nil
}

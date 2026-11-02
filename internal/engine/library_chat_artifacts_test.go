package engine

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
)

func exerciseLibraryChatArtifacts(t *testing.T, store LibraryStore, chats LibraryChatArtifactStore, owner, other MCPClient, legacy func(string), revoke func()) LibraryChatSaveResult {
	t.Helper()
	ctx := context.Background()
	create := func(title, kind string, refs []LibraryChatArtifactRef) (LibraryArtifact, LibraryArtifactVersion) {
		t.Helper()
		if kind == "" {
			kind = LibraryContentArtifact
		}
		_, a, v, err := store.CreateLibraryMCPClientArtifactWithInitialVersion(ctx, owner, LibraryArtifact{Title: title, Origin: LibraryArtifactOriginAgentDirect, ContentKind: kind, LinkedArtifacts: refs}, LibraryArtifactVersion{Format: LibraryArtifactFormatMarkdown, Body: "# private body " + title})
		if err != nil {
			t.Fatal(err)
		}
		return a, v
	}
	artifact, artifactV := create("Deliverable", "", nil)
	if artifact.ContentKind != LibraryContentArtifact {
		t.Fatalf("new write was not explicitly classified: %+v", artifact)
	}
	link := LibraryChatArtifactRef{ArtifactID: artifact.ID, ArtifactVersionID: artifactV.ID, Digest: artifactV.Digest}
	reply, replyV := create("Ordinary answer", LibraryContentChatReply, []LibraryChatArtifactRef{link})
	create("Later answer", LibraryContentChatReply, nil)
	bad := link
	bad.Digest = strings.Repeat("0", 64)
	if _, _, _, err := store.CreateLibraryMCPClientArtifactWithInitialVersion(ctx, owner, LibraryArtifact{Title: "Bad link", Origin: LibraryArtifactOriginAgentDirect, ContentKind: LibraryContentChatReply, LinkedArtifacts: []LibraryChatArtifactRef{bad}}, LibraryArtifactVersion{Format: "markdown", Body: "x"}); !errors.Is(err, ErrLibraryArtifactNotFound) {
		t.Fatalf("unverified link accepted: %v", err)
	}
	for _, kind := range []string{LibraryContentArtifact, "invalid"} {
		if _, _, _, err := store.CreateLibraryMCPClientArtifactWithInitialVersion(ctx, owner, LibraryArtifact{Title: "Bad kind", Origin: LibraryArtifactOriginAgentDirect, ContentKind: kind, LinkedArtifacts: []LibraryChatArtifactRef{link}}, LibraryArtifactVersion{Format: "markdown", Body: "x"}); err == nil {
			t.Fatalf("kind %s accepted linked refs", kind)
		}
	}
	// Filtering happens before page limits: the two newer replies never consume
	// either visible page or its cursor.
	console, err := store.LibraryConsoleArtifactPage(ctx, LibraryConsolePageCursor{}, 1)
	if err != nil || len(console.Artifacts) != 1 || console.Artifacts[0].Artifact.ID != artifact.ID {
		t.Fatalf("console page=%+v err=%v", console, err)
	}
	root, err := store.LibraryMCPRootArtifactPage(ctx, LibraryMCPRootPageCursor{}, 1)
	if err != nil || len(root.Artifacts) != 1 || root.Artifacts[0].ID != artifact.ID {
		t.Fatalf("root page=%+v err=%v", root, err)
	}
	clientPage, err := store.LibraryMCPClientArtifactPage(ctx, owner, LibraryMCPClientArtifactCursor{}, 1)
	if err != nil || len(clientPage.Artifacts) != 1 || clientPage.Artifacts[0].Artifact.ID != artifact.ID {
		t.Fatalf("client page=%+v err=%v", clientPage, err)
	}
	control, err := store.(LibraryControlArtifactStore).LibraryControlArtifactPage(ctx, LibraryControlArtifactScope{AgentSurfaceIDs: []string{owner.ID}}, LibraryControlArtifactCursor{}, 1)
	if err != nil || len(control.Artifacts) != 1 || control.Artifacts[0].Artifact.ID != artifact.ID {
		t.Fatalf("control page=%+v err=%v", control, err)
	}
	runPage, err := store.LibraryConsoleRunPage(ctx, LibraryConsolePageCursor{}, 1)
	if err != nil || len(runPage.Runs) != 1 || runPage.Runs[0].ID != artifact.RunID {
		t.Fatalf("chat provenance leaked into Library runs: %+v %v", runPage, err)
	}
	if _, err := store.CreateLibraryArtifactGrant(ctx, LibraryArtifactGrant{ArtifactID: reply.ID, ArtifactVersionID: replyV.ID, ArtifactVersionDigest: replyV.Digest, AgentSurfaceID: other.ID, CreatedBy: owner.Subject}); err != nil {
		t.Fatal(err)
	}
	granted, err := store.LibraryMCPClientArtifactPage(ctx, other, LibraryMCPClientArtifactCursor{}, 10)
	if err != nil || len(granted.Artifacts) != 0 {
		t.Fatalf("granted reply leaked: %+v %v", granted, err)
	}
	cards, saved, err := chats.LibraryChatArtifactCards(ctx, reply.ID, replyV.ID, []string{owner.ID})
	if err != nil || len(cards) != 1 || cards[0].ArtifactVersionID != artifactV.ID || saved != nil {
		t.Fatalf("cards=%+v saved=%+v err=%v", cards, saved, err)
	}
	cards, saved, err = chats.LibraryChatArtifactCards(ctx, reply.ID, replyV.ID, []string{other.ID})
	if err != nil || len(cards) != 0 || saved != nil {
		t.Fatal("card access crossed a surface")
	}
	request := LibraryChatSaveRequest{LibraryChatReplyReference: LibraryChatReplyReference{ArtifactID: reply.ID, ArtifactVersionID: replyV.ID, AgentSurfaceID: owner.ID, Subject: owner.Subject}, Title: "Saved deliverable"}
	wrong := request
	wrong.AgentSurfaceID = other.ID
	wrong.Subject = other.Subject
	if _, err := chats.SaveLibraryChatReply(ctx, wrong); !errors.Is(err, ErrLibraryArtifactNotFound) {
		t.Fatalf("wrong owner saved reply: %v", err)
	}
	// A response-lost retry or two tabs clicking Save can create only one copy.
	var wg sync.WaitGroup
	results := make(chan LibraryChatSaveResult, 8)
	failures := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := chats.SaveLibraryChatReply(ctx, request)
			if err != nil {
				failures <- err
			} else {
				results <- result
			}
		}()
	}
	wg.Wait()
	close(results)
	close(failures)
	for err := range failures {
		t.Fatal(err)
	}
	var first LibraryChatSaveResult
	created := 0
	for result := range results {
		if first.Artifact.ArtifactID == "" {
			first = result
		}
		if first.Artifact.ArtifactID != result.Artifact.ArtifactID {
			t.Fatal("duplicate saved copies")
		}
		if !result.Replayed {
			created++
		}
	}
	if created != 1 || first.Artifact.ArtifactID == reply.ID {
		t.Fatalf("created=%d copy=%+v", created, first)
	}
	copy, found := store.LibraryArtifact(ctx, first.Artifact.ArtifactID)
	if !found || copy.ContentKind != LibraryContentArtifact || copy.SourceArtifactID != reply.ID || copy.SourceArtifactVersionID != replyV.ID || copy.SourceArtifactDigest != replyV.Digest {
		t.Fatalf("copy provenance=%+v", copy)
	}
	copied, found := store.LibraryArtifactVersion(ctx, copy.ID, first.Artifact.ArtifactVersionID)
	if !found || copied.Body != replyV.Body || copied.Digest != replyV.Digest {
		t.Fatal("save changed reply bytes")
	}
	if _, err := store.CreateLibraryArtifactVersion(ctx, LibraryArtifactVersion{ArtifactID: reply.ID, Format: "markdown", Body: "mutated"}); !errors.Is(err, ErrLibraryArtifactNotFound) {
		t.Fatalf("reply was mutable: %v", err)
	}
	if _, err := store.CreateLibraryArtifactVersion(ctx, LibraryArtifactVersion{ArtifactID: copy.ID, Format: "markdown", Body: "Edited deliverable"}); err != nil {
		t.Fatal(err)
	}
	cards, saved, err = chats.LibraryChatArtifactCards(ctx, reply.ID, replyV.ID, []string{owner.ID})
	if err != nil || len(cards) != 1 || saved == nil || saved.ArtifactVersionID != copied.ID {
		t.Fatalf("saved card did not stay pinned: %+v %v", saved, err)
	}
	original, _ := store.LibraryArtifactVersion(ctx, reply.ID, replyV.ID)
	if original.Body != replyV.Body {
		t.Fatal("original conversation changed")
	}
	// Classify only old records whose persisted kind was absent. Exact new
	// artifacts never become hidden even if an obsolete runner references them.
	old, oldV := create("Legacy answer", "", nil)
	legacy(old.ID)
	refs := []LibraryChatReplyReference{{ArtifactID: old.ID, ArtifactVersionID: oldV.ID, AgentSurfaceID: owner.ID, Subject: owner.Subject}, {ArtifactID: artifact.ID, ArtifactVersionID: artifactV.ID, AgentSurfaceID: owner.ID, Subject: owner.Subject}, {ArtifactID: "libart_missing", ArtifactVersionID: "libav_missing", AgentSurfaceID: owner.ID, Subject: owner.Subject}}
	badRefs := append([]LibraryChatReplyReference(nil), refs...)
	badRefs[0].Subject = other.Subject
	if _, err := chats.ClassifyLibraryChatReplies(ctx, badRefs); !errors.Is(err, ErrLibraryArtifactNotFound) {
		t.Fatalf("classified wrong owner: %v", err)
	}
	if count, err := chats.ClassifyLibraryChatReplies(ctx, refs); err != nil || count != 1 {
		t.Fatalf("classification count=%d err=%v", count, err)
	}
	if count, err := chats.ClassifyLibraryChatReplies(ctx, refs); err != nil || count != 0 {
		t.Fatalf("classification replay count=%d err=%v", count, err)
	}
	current, _ := store.LibraryArtifact(ctx, artifact.ID)
	if current.ContentKind != LibraryContentArtifact {
		t.Fatal("explicit artifact reclassified")
	}
	revoke()
	if _, err := chats.SaveLibraryChatReply(ctx, request); !errors.Is(err, ErrLibraryArtifactNotFound) {
		t.Fatalf("revoked surface replayed save: %v", err)
	}
	cards, saved, err = chats.LibraryChatArtifactCards(ctx, reply.ID, replyV.ID, []string{owner.ID})
	if len(cards) != 0 || saved != nil {
		t.Fatalf("revoked surface leaked cards: %+v %+v %v", cards, saved, err)
	}
	if count, err := chats.ClassifyLibraryChatReplies(ctx, refs); err != nil || count != 0 {
		t.Fatalf("revoked history classification count=%d err=%v", count, err)
	}
	return first
}
func TestLibraryChatArtifactsFileParity(t *testing.T) {
	ctx := context.Background()
	store := newLibraryFileStore(t)
	owner := newAuthoringLeaseMCPClient(t, store, "usr_chat_owner")
	other := newAuthoringLeaseMCPClient(t, store, "usr_chat_other")
	saved := exerciseLibraryChatArtifacts(t, store, store, owner, other, func(id string) {
		store.mu.Lock()
		defer store.mu.Unlock()
		store.libraryArtifactLocked(id).ContentKind = ""
		if err := store.saveLocked(); err != nil {
			t.Fatal(err)
		}
	}, func() {
		if _, err := store.RevokeMCPClient(ctx, owner.ID, "usr_owner", MCPClientPrecondition{ID: owner.ID, Revision: owner.Revision}); err != nil {
			t.Fatal(err)
		}
	})
	reopened, err := LoadFileStore(store.path)
	if err != nil {
		t.Fatal(err)
	}
	artifact, found := reopened.LibraryArtifact(ctx, saved.Artifact.ArtifactID)
	if !found || artifact.ContentKind != LibraryContentArtifact || len(reopened.libraryChatSaves) != 1 {
		t.Fatal("copy/classification receipts did not survive restart")
	}
}
func TestPgLibraryChatArtifactsParity(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL for PostgreSQL chat artifact contracts")
	}
	ctx := context.Background()
	store, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	cipher, err := NewCipher(base64.RawStdEncoding.EncodeToString(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	store.SetCipher(cipher)
	suffix := newPgFixtureSuffix()
	createClient := func(subject string) MCPClient {
		client, err := store.CreateMCPClient(ctx, MCPClient{Name: "Chat " + subject + suffix, Subject: subject + suffix, CreatedBy: "usr_owner"})
		if err != nil {
			t.Fatal(err)
		}
		return client
	}
	owner := createClient("usr_chat_owner_")
	other := createClient("usr_chat_other_")
	defer func() {
		ids := []string{owner.ID, other.ID}
		_, _ = store.pool.Exec(ctx, `DELETE FROM narthex_library_chat_saves WHERE source_artifact_id IN (SELECT id FROM narthex_library_artifacts WHERE agent_surface_id=ANY($1::text[]))`, ids)
		_, _ = store.pool.Exec(ctx, `DELETE FROM narthex_library_artifact_grants WHERE agent_surface_id=ANY($1::text[])`, ids)
		_, _ = store.pool.Exec(ctx, `DELETE FROM narthex_library_artifact_versions WHERE artifact_id IN (SELECT id FROM narthex_library_artifacts WHERE agent_surface_id=ANY($1::text[]))`, ids)
		_, _ = store.pool.Exec(ctx, `DELETE FROM narthex_library_artifacts WHERE agent_surface_id=ANY($1::text[])`, ids)
		// Run provenance is encrypted, so select the fixture runs by decrypted actor.
		runs, _ := store.LibraryRuns(ctx)
		for _, run := range runs {
			if run.ActorRef == owner.Subject || run.ActorRef == other.Subject {
				_, _ = store.pool.Exec(ctx, `DELETE FROM narthex_library_runs WHERE id=$1`, run.ID)
			}
		}
		_, _ = store.pool.Exec(ctx, `DELETE FROM narthex_mcp_clients WHERE id=ANY($1::text[])`, ids)
	}()
	saved := exerciseLibraryChatArtifacts(t, store, store, owner, other, func(id string) {
		if _, err := store.pool.Exec(ctx, `UPDATE narthex_library_artifacts SET content_kind='' WHERE id=$1`, id); err != nil {
			t.Fatal(err)
		}
	}, func() {
		if _, err := store.RevokeMCPClient(ctx, owner.ID, "usr_owner", MCPClientPrecondition{ID: owner.ID, Revision: owner.Revision}); err != nil {
			t.Fatal(err)
		}
	})
	var title, body string
	if err := store.pool.QueryRow(ctx, `SELECT a.title,v.body FROM narthex_library_artifacts a JOIN narthex_library_artifact_versions v ON v.artifact_id=a.id WHERE a.id=$1 AND v.id=$2`, saved.Artifact.ArtifactID, saved.Artifact.ArtifactVersionID).Scan(&title, &body); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(title, encPrefix) || !strings.HasPrefix(body, encPrefix) {
		t.Fatal("saved content was not encrypted")
	}
	reopened, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	reopened.Close()
}

func TestControlLibraryChatArtifactsServiceOnlyAndExactRead(t *testing.T) {
	mux, store, key, now, _ := newHostedControlConsole(t)
	ctx := context.Background()
	client := newAuthoringLeaseMCPClient(t, store, "agt_chat")
	_, reply, version, err := store.CreateLibraryMCPClientArtifactWithInitialVersion(ctx, client, LibraryArtifact{Title: "Reply", Origin: LibraryArtifactOriginAgentDirect, ContentKind: LibraryContentChatReply}, LibraryArtifactVersion{Format: "markdown", Body: "Keep me in chat"})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]string{"artifactVersionId": version.ID, "agentSurfaceId": client.ID, "subject": client.Subject, "title": "Saved answer"})
	path := "/control/v1/library/artifacts/" + reply.ID + "/save"
	for _, actor := range []struct{ id, role string }{{"usr_owner", "owner"}, {"usr_admin", "admin"}, {"usr_operator", "operator"}} {
		response := controlLibraryRequest(t, mux, key, now, actor.id, actor.role, http.MethodPost, path, string(body), "")
		if response.Code != http.StatusForbidden {
			t.Fatalf("nonservice write status=%d body=%s", response.Code, response.Body)
		}
	}
	response := controlLibraryRequest(t, mux, key, now, platformServiceActorID, "service", http.MethodPost, path, string(body), "")
	if response.Code != http.StatusOK {
		t.Fatalf("save status=%d body=%s", response.Code, response.Body)
	}
	response = controlLibraryRequest(t, mux, key, now, platformServiceActorID, "service", http.MethodGet, "/control/v1/library/artifacts/"+reply.ID+"/versions/"+version.ID, "", client.Subject)
	var result controlLibraryVersionBodyDTO
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusOK || result.ContentKind != LibraryContentChatReply || result.Body != version.Body || result.SavedArtifact == nil || result.SavedArtifact.ArtifactID == reply.ID {
		t.Fatalf("read response=%s", response.Body)
	}
	// A missing linked deliverable never erases the original answer.
	store.mu.Lock()
	store.libraryArtifactLocked(reply.ID).LinkedArtifacts = []LibraryChatArtifactRef{{ArtifactID: "libart_missing", ArtifactVersionID: "libav_missing", Digest: strings.Repeat("0", 64)}}
	store.mu.Unlock()
	response = controlLibraryRequest(t, mux, key, now, platformServiceActorID, "service", http.MethodGet, "/control/v1/library/artifacts/"+reply.ID+"/versions/"+version.ID, "", client.Subject)
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusOK || result.Body != version.Body || len(result.Artifacts) != 0 {
		t.Fatalf("missing card lost answer: %s", response.Body)
	}
	// Unknown JSON fields (including browser-supplied body) cannot become content.
	response = controlLibraryRequest(t, mux, key, now, platformServiceActorID, "service", http.MethodPost, path, strings.TrimSuffix(string(body), "}")+`,"body":"forged"}`, "")
	if response.Code != http.StatusBadRequest {
		t.Fatalf("accepted source text status=%d", response.Code)
	}
}

func TestMCPChatReplyExactVersionRead(t *testing.T) {
	ctx := context.Background()
	store, gateway := newMCPClientGateway(t)
	owner := newAuthoringLeaseMCPClient(t, store, "usr_chat_exact")
	artifact, first := createDirectArtifactForClientVersionTest(t, store, owner)
	_, err := store.CreateLibraryArtifactVersion(ctx, LibraryArtifactVersion{ArtifactID: artifact.ID, Format: "markdown", Body: "Later editable artifact"})
	if err != nil {
		t.Fatal(err)
	}
	if err := gateway.RefreshMCPClients(ctx); err != nil {
		t.Fatal(err)
	}
	server := clientLibraryServer(t, gateway, owner.Slug)
	exact := callLibraryTool(t, server, "library_artifact_read", map[string]any{"artifactId": artifact.ID, "artifactVersionId": first.ID})
	if strings.Contains(exact, `"isError":true`) || !strings.Contains(libraryToolJSONText(t, exact), first.Body) || strings.Contains(exact, "Later editable artifact") {
		t.Fatalf("exact read=%s", exact)
	}
	latest := callLibraryTool(t, server, "library_artifact_read", map[string]any{"artifactId": artifact.ID})
	if strings.Contains(latest, `"isError":true`) || !strings.Contains(latest, "Later editable artifact") {
		t.Fatalf("latest read=%s", latest)
	}
	missing := callLibraryTool(t, server, "library_artifact_read", map[string]any{"artifactId": artifact.ID, "artifactVersionId": "libav_missing"})
	if !strings.Contains(missing, `"isError":true`) {
		t.Fatal("missing exact version fell back to head")
	}
	_, reply, replyV, err := store.CreateLibraryMCPClientArtifactWithInitialVersion(ctx, owner, LibraryArtifact{Title: "Reply", Origin: LibraryArtifactOriginAgentDirect, ContentKind: LibraryContentChatReply}, LibraryArtifactVersion{Format: "markdown", Body: "Immutable reply"})
	if err != nil {
		t.Fatal(err)
	}
	denied := callLibraryTool(t, server, "library_artifact_version_create", map[string]any{"requestId": "change-reply", "artifactId": reply.ID, "expectedArtifactVersionId": replyV.ID, "expectedDigest": replyV.Digest, "body": "changed"})
	if !strings.Contains(denied, `"isError":true`) {
		t.Fatal("MCP appended reply")
	}
}

func TestControlLibraryChatArtifactMediaHonorsExactGrantAndRevocation(t *testing.T) {
	mux, store, key, now, _ := newHostedControlConsole(t)
	ctx := context.Background()
	owner := newAuthoringLeaseMCPClient(t, store, "agt_image_owner")
	reader := newAuthoringLeaseMCPClient(t, store, "agt_image_reader")
	canonical, _ := libraryArtifactTestPNG(t)
	_, artifact, first, err := store.CreateLibraryMCPClientImageArtifactWithInitialVersion(ctx, owner, LibraryArtifact{Title: "Chart", Origin: LibraryArtifactOriginAgentDirect}, canonical, "Chart")
	if err != nil {
		t.Fatal(err)
	}
	_, reply, replyVersion, err := store.CreateLibraryMCPClientArtifactWithInitialVersion(ctx, owner, LibraryArtifact{Title: "Here is your chart", Origin: LibraryArtifactOriginAgentDirect, ContentKind: LibraryContentChatReply, LinkedArtifacts: []LibraryChatArtifactRef{{ArtifactID: artifact.ID, ArtifactVersionID: first.ID, Digest: first.Digest}}}, LibraryArtifactVersion{Format: "markdown", Body: "Your chart is ready."})
	if err != nil {
		t.Fatal(err)
	}
	cards, _, err := store.LibraryChatArtifactCards(ctx, reply.ID, replyVersion.ID, []string{owner.ID})
	if err != nil || len(cards) != 1 || cards[0].Format != LibraryArtifactFormatImage || cards[0].ArtifactVersionID != first.ID {
		t.Fatalf("image card=%+v err=%v", cards, err)
	}
	second, err := store.CreateLibraryMCPClientImageArtifactVersion(ctx, owner, LibraryMCPClientImageArtifactVersionCreateRequest{RequestID: "second-chart", ArtifactID: artifact.ID, ExpectedArtifactVersionID: first.ID, ExpectedDigest: first.Digest, Image: canonical, AltText: "Second chart"})
	if err != nil {
		t.Fatal(err)
	}
	read := func(subject, version string) *http.Response {
		t.Helper()
		response := controlLibraryRequest(t, mux, key, now, platformServiceActorID, "service", http.MethodGet, "/control/v1/library/artifacts/"+artifact.ID+"/versions/"+version+"/media", "", subject)
		return response.Result()
	}
	response := read(owner.Subject, first.ID)
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "image/png" || !strings.HasPrefix(response.Header.Get("Content-Disposition"), "inline;") {
		t.Fatalf("owner media=%+v", response)
	}
	response.Body.Close()
	response = read(reader.Subject, first.ID)
	if response.StatusCode != http.StatusNotFound {
		t.Fatal("reader received ungranted image")
	}
	response.Body.Close()
	grant, err := store.CreateLibraryArtifactGrant(ctx, LibraryArtifactGrant{ArtifactID: artifact.ID, ArtifactVersionID: first.ID, ArtifactVersionDigest: first.Digest, AgentSurfaceID: reader.ID, CreatedBy: "usr_owner"})
	if err != nil {
		t.Fatal(err)
	}
	response = read(reader.Subject, first.ID)
	if response.StatusCode != http.StatusOK {
		t.Fatal("exact image grant did not read")
	}
	response.Body.Close()
	response = read(reader.Subject, second.Version.ID)
	if response.StatusCode != http.StatusNotFound {
		t.Fatal("image grant advanced to a later version")
	}
	response.Body.Close()
	if _, err := store.RevokeLibraryArtifactGrant(ctx, artifact.ID, grant.ID, "usr_owner", now); err != nil {
		t.Fatal(err)
	}
	response = read(reader.Subject, first.ID)
	if response.StatusCode != http.StatusNotFound {
		t.Fatal("revoked grant still reads image")
	}
	response.Body.Close()
	if _, err := store.RevokeMCPClient(ctx, owner.ID, "usr_owner", MCPClientPrecondition{ID: owner.ID, Revision: owner.Revision}); err != nil {
		t.Fatal(err)
	}
	response = read(owner.Subject, first.ID)
	if response.StatusCode != http.StatusNotFound {
		t.Fatal("revoked owner still reads image")
	}
	response.Body.Close()
}

func TestMCPChatReplyFromOlderRunnerCanBeClassifiedAfterUpgrade(t *testing.T) {
	ctx := context.Background()
	store, gateway := newMCPClientGateway(t)
	client := newAuthoringLeaseMCPClient(t, store, "agt_rolling_runner")
	if err := gateway.RefreshMCPClients(ctx); err != nil {
		t.Fatal(err)
	}
	result := callLibraryTool(t, clientLibraryServer(t, gateway, client.Slug), "library_artifact_create", map[string]any{"title": "Old runner final answer", "format": "markdown", "body": "Historical reply"})
	var ref LibraryChatArtifactRef
	if err := json.Unmarshal([]byte(libraryToolJSONText(t, result)), &ref); err != nil {
		t.Fatal(err)
	}
	artifact, found := store.LibraryArtifact(ctx, ref.ArtifactID)
	if !found || artifact.ContentKind != "" {
		t.Fatalf("omitted content kind lost its compatibility classification: %+v", artifact)
	}
	count, err := store.ClassifyLibraryChatReplies(ctx, []LibraryChatReplyReference{{ArtifactID: ref.ArtifactID, ArtifactVersionID: ref.ArtifactVersionID, AgentSurfaceID: client.ID, Subject: client.Subject}})
	if err != nil || count != 1 {
		t.Fatalf("old-runner classification=%d %v", count, err)
	}
	version, found := store.LibraryArtifactVersion(ctx, ref.ArtifactID, ref.ArtifactVersionID)
	if !found || version.Body != "Historical reply" {
		t.Fatal("old conversation changed")
	}
}

func TestControlLibraryCombinedSubjectsCannotReadChatReplies(t *testing.T) {
	mux, store, key, now, _ := newHostedControlConsole(t)
	ctx := context.Background()
	member := newAuthoringLeaseMCPClient(t, store, "usr_combined")
	agent := newAuthoringLeaseMCPClient(t, store, "agt_combined")
	other := newAuthoringLeaseMCPClient(t, store, "agt_unrelated")
	create := func(client MCPClient, kind, title string) (LibraryArtifact, LibraryArtifactVersion) {
		t.Helper()
		_, artifact, version, err := store.CreateLibraryMCPClientArtifactWithInitialVersion(ctx, client, LibraryArtifact{Title: title, Origin: LibraryArtifactOriginAgentDirect, ContentKind: kind}, LibraryArtifactVersion{Format: "markdown", Body: title})
		if err != nil {
			t.Fatal(err)
		}
		return artifact, version
	}
	visible, version := create(agent, LibraryContentArtifact, "Agent deliverable")
	create(member, LibraryContentArtifact, "Personal deliverable")
	private, privateVersion := create(agent, LibraryContentChatReply, "Private conversation")
	unrelated, unrelatedVersion := create(other, LibraryContentArtifact, "Unrelated deliverable")
	union := member.Subject + "," + agent.Subject
	request := func(actor, role, path, subjects string) *httptest.ResponseRecorder {
		t.Helper()
		return hostedNamespaceRequestWithHeaders(t, mux, key, now, actor, role, http.MethodGet, path, "", map[string]string{controlSubjectsHeader: subjects})
	}
	base := "/control/v1/library/artifacts"
	page := decodeControlLibraryPage(t, request(platformServiceActorID, "service", base, union))
	if len(page.Artifacts) != 2 {
		t.Fatalf("combined page=%+v", page)
	}
	for _, route := range []string{base + "/" + visible.ID, base + "/" + visible.ID + "/versions/" + version.ID} {
		if response := request(platformServiceActorID, "service", route, union); response.Code != http.StatusOK {
			t.Fatalf("combined artifact read=%d %s", response.Code, response.Body)
		}
	}
	for _, route := range []string{base + "/" + private.ID, base + "/" + private.ID + "/versions/" + privateVersion.ID, base + "/" + private.ID + "/versions/" + privateVersion.ID + "/media", base + "/" + unrelated.ID, base + "/" + unrelated.ID + "/versions/" + unrelatedVersion.ID} {
		if response := request(platformServiceActorID, "service", route, union); response.Code != http.StatusNotFound {
			t.Fatalf("private content leaked via %s: %d %s", route, response.Code, response.Body)
		}
	}
	for _, role := range []string{"owner", "admin", "operator"} {
		if response := request("usr_"+role, role, base, union); response.Code != http.StatusForbidden {
			t.Fatalf("%s supplied union: %d", role, response.Code)
		}
	}
	for _, subjects := range []string{"", member.Subject + "," + member.Subject, member.Subject + ",", member.Subject + ",bad subject", platformServiceActorID} {
		if response := request(platformServiceActorID, "service", base, subjects); response.Code != http.StatusBadRequest {
			t.Fatalf("accepted invalid union %q: %d", subjects, response.Code)
		}
	}
	response := hostedNamespaceRequestWithHeaders(t, mux, key, now, platformServiceActorID, "service", http.MethodGet, base, "", map[string]string{controlSubjectsHeader: union, controlSubjectHeader: member.Subject})
	if response.Code != http.StatusBadRequest {
		t.Fatal("accepted ambiguous subjects")
	}
	if _, err := store.RevokeMCPClient(ctx, agent.ID, "usr_owner", MCPClientPrecondition{ID: agent.ID, Revision: agent.Revision}); err != nil {
		t.Fatal(err)
	}
	page = decodeControlLibraryPage(t, request(platformServiceActorID, "service", base, union))
	if len(page.Artifacts) != 1 {
		t.Fatal("revoked agent contributes union scope")
	}
	if response := request(platformServiceActorID, "service", base+"/"+visible.ID+"/versions/"+version.ID, union); response.Code != http.StatusNotFound {
		t.Fatal("revoked agent artifact still readable")
	}
}

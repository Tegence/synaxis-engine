package engine

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestPgLibraryMCPClientArtifactVersionIsAtomicIdempotentAndEncrypted(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to run the Postgres MCP client artifact-version integration test")
	}
	ctx := context.Background()
	store, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatalf("NewPgStore: %v", err)
	}
	t.Cleanup(store.Close)
	cipher, err := NewCipher(base64.RawStdEncoding.EncodeToString(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	store.SetCipher(cipher)

	suffix := newPgFixtureSuffix()
	client, err := store.CreateMCPClient(ctx, MCPClient{
		Name: "PG artifact revision " + suffix, Subject: "usr_pg_artifact_" + suffix, CreatedBy: "usr_pg_owner",
	})
	if err != nil {
		t.Fatalf("CreateMCPClient: %v", err)
	}
	client, err = store.BindMCPClientOAuthClient(ctx, client.ID, "oauth-pg-artifact-"+suffix, MCPClientPrecondition{ID: client.ID, Revision: client.Revision}, PlatformActor{UserID: client.Subject, Role: "operator"})
	if err != nil {
		t.Fatalf("BindMCPClientOAuthClient: %v", err)
	}
	var artifact LibraryArtifact
	var first LibraryArtifactVersion
	var run LibraryRun
	t.Cleanup(func() {
		_, _ = store.pool.Exec(context.Background(), `DELETE FROM narthex_library_mcp_client_artifact_version_requests WHERE client_id=$1`, client.ID)
		if artifact.ID != "" {
			_, _ = store.pool.Exec(context.Background(), `DELETE FROM narthex_library_artifact_versions WHERE artifact_id=$1`, artifact.ID)
			_, _ = store.pool.Exec(context.Background(), `DELETE FROM narthex_library_artifacts WHERE id=$1`, artifact.ID)
		}
		if run.ID != "" {
			_, _ = store.pool.Exec(context.Background(), `DELETE FROM narthex_library_runs WHERE id=$1`, run.ID)
		}
		_, _ = store.pool.Exec(context.Background(), `DELETE FROM narthex_mcp_clients WHERE id=$1`, client.ID)
	})

	run, artifact, first, err = store.CreateLibraryMCPClientArtifactWithInitialVersion(ctx, client, LibraryArtifact{
		Title: "PG client artifact", Origin: LibraryArtifactOriginAgentDirect,
	}, LibraryArtifactVersion{Format: LibraryArtifactFormatMarkdown, Body: "# PG version one"})
	if err != nil {
		t.Fatalf("CreateLibraryMCPClientArtifactWithInitialVersion: %v", err)
	}
	request := LibraryMCPClientArtifactVersionCreateRequest{
		RequestID: "pg-artifact-v2", ArtifactID: artifact.ID,
		ExpectedArtifactVersionID: first.ID, ExpectedDigest: first.Digest, Body: "# PG version two",
	}
	updated, err := store.CreateLibraryMCPClientArtifactVersion(ctx, client, request)
	if err != nil {
		t.Fatalf("CreateLibraryMCPClientArtifactVersion: %v", err)
	}
	if updated.Replayed || updated.Version.Version != 2 || updated.Version.CreatedBy != client.Subject || updated.Version.RedactionStatus != LibraryRedactionPending {
		t.Fatalf("updated PG version=%+v", updated)
	}
	if replay, err := store.CreateLibraryMCPClientArtifactVersion(ctx, client, request); err != nil || !replay.Replayed || replay.Version.ID != updated.Version.ID {
		t.Fatalf("PG replay=%+v err=%v", replay, err)
	}
	changed := request
	changed.Body = "# changed replay"
	if _, err := store.CreateLibraryMCPClientArtifactVersion(ctx, client, changed); !errors.Is(err, ErrLibraryMCPClientArtifactVersionRequestConflict) {
		t.Fatalf("changed PG replay error=%v, want %v", err, ErrLibraryMCPClientArtifactVersionRequestConflict)
	}

	var rawBody, rawCreatedBy string
	if err := store.pool.QueryRow(ctx, `SELECT body,created_by FROM narthex_library_artifact_versions WHERE id=$1`, updated.Version.ID).Scan(&rawBody, &rawCreatedBy); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(rawBody, encPrefix) || !strings.HasPrefix(rawCreatedBy, encPrefix) || rawBody == updated.Version.Body || rawCreatedBy == updated.Version.CreatedBy {
		t.Fatalf("PG artifact revision private fields were not encrypted: body=%q creator=%q", rawBody, rawCreatedBy)
	}
	var receiptVersionID string
	if err := store.pool.QueryRow(ctx, `SELECT artifact_version_id FROM narthex_library_mcp_client_artifact_version_requests WHERE client_id=$1 AND client_epoch=$2 AND artifact_id=$3 AND operation=$4`, client.ID, client.Epoch, artifact.ID, libraryMCPClientArtifactVersionOperationTextCreate).Scan(&receiptVersionID); err != nil || receiptVersionID != updated.Version.ID {
		t.Fatalf("PG artifact revision receipt=%q err=%v updated=%q", receiptVersionID, err, updated.Version.ID)
	}
}

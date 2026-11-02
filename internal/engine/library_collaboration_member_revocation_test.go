package engine

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

// A named workspace member uses the same live grant across requests. Revoking
// it must fence saved IDs and successful mutation retries, not only the list.
func exerciseMemberCollaborationRevocation(t *testing.T, library LibraryStore, collaboration LibraryCollaborationStore) {
	t.Helper()
	ctx := context.Background()
	admin := LibraryCollaborationActor{Kind: "admin", Ref: "usr_owner"}
	for _, role := range []string{"view", "comment", "edit"} {
		t.Run(role, func(t *testing.T) {
			artifact, initial := collaborationFixture(t, library)
			other, _ := collaborationFixture(t, library)
			if pg, ok := library.(*PgStore); ok {
				t.Cleanup(func() {
					for _, id := range []string{artifact.ID, other.ID} {
						for _, query := range []string{
							`DELETE FROM narthex_library_collaborations WHERE artifact_id=$1`,
							`DELETE FROM narthex_library_artifact_versions WHERE artifact_id=$1`,
							`DELETE FROM narthex_library_artifacts WHERE id=$1`,
						} {
							if _, err := pg.pool.Exec(ctx, query, id); err != nil {
								t.Errorf("clean up member collaboration fixture: %v", err)
							}
						}
					}
				})
			}
			member := LibraryCollaborationActor{Kind: "subject", Ref: "usr_operator_" + artifact.ID}
			call := func(actor LibraryCollaborationActor, req LibraryCollaborationRequest) (LibraryCollaborationResult, error) {
				req.ArtifactID = artifact.ID
				return collaboration.Collaborate(ctx, actor, req)
			}
			readRequest := LibraryCollaborationRequest{Operation: "read"}
			if _, err := call(member, readRequest); !errors.Is(err, ErrCollaborationUnavailable) {
				t.Fatalf("unshared artifact read: %v", err)
			}
			grant, err := call(admin, LibraryCollaborationRequest{Operation: "grant", Kind: "subject", Recipient: member.Ref, Label: "Operator", Role: role})
			if err != nil || grant.Grant == nil || grant.Token != "" {
				t.Fatalf("named-member grant=%+v err=%v", grant, err)
			}
			read, err := call(member, readRequest)
			if err != nil || read.Role != role || read.Version == nil || read.Version.ID != initial.ID || read.Version.Body != initial.Body {
				t.Fatalf("shared read=%+v err=%v", read, err)
			}
			listed, err := collaboration.CollaborationArtifacts(ctx, member)
			if err != nil || len(listed) != 1 || listed[0].ArtifactID != artifact.ID || listed[0].Role != role {
				t.Fatalf("shared list=%+v err=%v", listed, err)
			}
			if _, err := collaboration.Collaborate(ctx, member, LibraryCollaborationRequest{Operation: "read", ArtifactID: other.ID}); !errors.Is(err, ErrCollaborationUnavailable) {
				t.Fatalf("grant escaped to unrelated artifact: %v", err)
			}
			if _, err := call(LibraryCollaborationActor{Kind: "subject", Ref: member.Ref + "_coworker"}, readRequest); !errors.Is(err, ErrCollaborationUnavailable) {
				t.Fatalf("grant escaped to unrelated member: %v", err)
			}
			for _, operation := range []string{"grant", "grants", "revoke"} {
				if _, err := call(member, LibraryCollaborationRequest{Operation: operation, GrantID: grant.Grant.ID}); !errors.Is(err, ErrCollaborationForbidden) {
					t.Fatalf("member managed %s: %v", operation, err)
				}
			}

			commentRequest := LibraryCollaborationRequest{Operation: "comment", RequestID: "member-comment", VersionID: initial.ID, Body: "Shared review comment"}
			_, commentErr := call(member, commentRequest)
			if role == "view" {
				if !errors.Is(commentErr, ErrCollaborationForbidden) {
					t.Fatalf("view grant allowed comment: %v", commentErr)
				}
			} else if commentErr != nil {
				t.Fatalf("%s grant could not comment: %v", role, commentErr)
			}
			editRequest := LibraryCollaborationRequest{Operation: "edit", RequestID: "member-edit", VersionID: initial.ID, ExpectedDigest: initial.Digest, Body: "# Operator revision"}
			edited, editErr := call(member, editRequest)
			if role != "edit" {
				if !errors.Is(editErr, ErrCollaborationForbidden) {
					t.Fatalf("%s grant allowed edit: %v", role, editErr)
				}
			} else {
				if editErr != nil || edited.Version == nil || edited.Version.Body != editRequest.Body || edited.Version.Version != 2 {
					t.Fatalf("shared edit=%+v err=%v", edited, editErr)
				}
				replayed, err := call(member, editRequest)
				if err != nil || !replayed.Replayed || replayed.Version == nil || replayed.Version.ID != edited.Version.ID {
					t.Fatalf("live edit retry=%+v err=%v", replayed, err)
				}
			}

			// Live collaboration intentionally follows future revisions of this
			// artifact. Pinned handoffs have a separate exact-version contract.
			latest, err := library.CreateLibraryArtifactVersion(ctx, LibraryArtifactVersion{ArtifactID: artifact.ID, Format: LibraryArtifactFormatMarkdown, Body: "# Owner follow-up", CreatedBy: "usr_owner"})
			if err != nil {
				t.Fatal(err)
			}
			read, err = call(member, readRequest)
			if err != nil || read.Version == nil || read.Version.ID != latest.ID || read.Version.Body != latest.Body {
				t.Fatalf("live future revision=%+v err=%v", read, err)
			}
			if _, err := call(admin, LibraryCollaborationRequest{Operation: "revoke", GrantID: grant.Grant.ID}); err != nil {
				t.Fatal(err)
			}
			for _, request := range []LibraryCollaborationRequest{readRequest, commentRequest, editRequest, {Operation: "edit", RequestID: "new-after-revoke", VersionID: latest.ID, ExpectedDigest: latest.Digest, Body: "Denied edit"}} {
				if _, err := call(member, request); !errors.Is(err, ErrCollaborationUnavailable) {
					t.Fatalf("revoked %s request %q accepted: %v", request.Operation, request.RequestID, err)
				}
			}
			listed, err = collaboration.CollaborationArtifacts(ctx, member)
			if err != nil || len(listed) != 0 {
				t.Fatalf("revoked grant remained listed=%+v err=%v", listed, err)
			}
			retained, err := call(admin, readRequest)
			if err != nil || retained.Version == nil || retained.Version.ID != latest.ID || retained.Version.Body != latest.Body {
				t.Fatalf("revocation altered owner work=%+v err=%v", retained, err)
			}
			versions, err := library.LibraryArtifactVersions(ctx, artifact.ID)
			if err != nil || len(versions) == 0 || versions[0].ID != initial.ID || versions[0].Body != initial.Body {
				t.Fatalf("source revision was overwritten: %+v err=%v", versions, err)
			}
		})
	}
}

func TestLibraryMemberCollaborationRolesAndRevocation(t *testing.T) {
	store := newLibraryFileStore(t)
	exerciseMemberCollaborationRevocation(t, store, store)
}

func TestPgLibraryMemberCollaborationRolesAndRevocation(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL")
	}
	store, err := NewPgStore(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	cipher, err := NewCipher(base64.RawStdEncoding.EncodeToString(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	store.SetCipher(cipher)
	exerciseMemberCollaborationRevocation(t, store, store)
}

func TestControlLibraryMemberCollaborationRevocation(t *testing.T) {
	mux, store, key, now, _ := newHostedControlConsole(t)
	artifact, initial := collaborationFixture(t, store)
	invoke := func(subject string, request LibraryCollaborationRequest) *httptest.ResponseRecorder {
		t.Helper()
		request.ArtifactID = artifact.ID
		body, err := json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		actor, role := platformServiceActorID, "service"
		if subject == "" {
			actor, role = "usr_owner", "owner"
		}
		return controlLibraryRequest(t, mux, key, now, actor, role, http.MethodPost, "/control/v1/library/collaboration", string(body), subject)
	}
	read := LibraryCollaborationRequest{Operation: "read"}
	if response := invoke("usr_operator", read); response.Code != http.StatusNotFound {
		t.Fatalf("pre-grant read=%d %s", response.Code, response.Body)
	}
	response := invoke("", LibraryCollaborationRequest{Operation: "grant", Kind: "subject", Recipient: "usr_operator", Label: "Operator", Role: "edit"})
	var grant LibraryCollaborationResult
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &grant) != nil || grant.Grant == nil {
		t.Fatalf("grant=%d %s", response.Code, response.Body)
	}
	edit := LibraryCollaborationRequest{Operation: "edit", RequestID: "signed-member-edit", VersionID: initial.ID, ExpectedDigest: initial.Digest, Body: "# Signed member revision"}
	for _, request := range []LibraryCollaborationRequest{read, edit, edit} {
		response := invoke("usr_operator", request)
		if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("live %s=%d %s", request.Operation, response.Code, response.Body)
		}
	}
	response = invoke("", LibraryCollaborationRequest{Operation: "revoke", GrantID: grant.Grant.ID})
	if response.Code != http.StatusOK {
		t.Fatalf("revoke=%d %s", response.Code, response.Body)
	}
	// The previously successful request must be authorized again before its
	// result can be replayed. Keeping the tab/session open grants no exception.
	for _, request := range []LibraryCollaborationRequest{read, edit} {
		response := invoke("usr_operator", request)
		if response.Code != http.StatusNotFound || response.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("revoked %s=%d %s", request.Operation, response.Code, response.Body)
		}
	}
	response = invoke("usr_operator", LibraryCollaborationRequest{Operation: "list"})
	var listed []LibraryCollaborationSummary
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &listed) != nil || len(listed) != 0 {
		t.Fatalf("revoked listing=%d %s", response.Code, response.Body)
	}
}

package firehose

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/open-runtimes/types-for-go/v4/openruntimes"

	"github.com/ModdingFriendly/appwrite-library/appwrite"
)

const committedRowJSON = `{"$id":"row-1","$sequence":7,"$tableId":"shifts","$databaseId":"database-test","$createdAt":"2026-11-18T00:00:00.000+00:00","$updatedAt":"2026-11-18T00:10:00.000+00:00","$permissions":["read(\"team:org1/admin\")"],"status":"closed"}`

// TestCreateReturnsTheCommittedRow is the regression test for rows written
// inside the audit transaction. Appwrite returns $sequence, $createdAt and
// $updatedAt empty for a staged row, so the gateway must read the committed row
// back before handing it to a client that validates a complete row.
func TestCreateReturnsTheCommittedRow(t *testing.T) {
	var reads int32
	srv := newTransactionServer(t,
		`{"$id":"row-1","$sequence":0,"$tableId":"shifts","$databaseId":"database-test","$createdAt":"","$updatedAt":"","$permissions":["read(\"team:org1/admin\")"],"status":"open"}`,
		func(w http.ResponseWriter, _ *http.Request) {
			atomic.AddInt32(&reads, 1)
			writeJSON(w, http.StatusOK, committedRowJSON)
		})
	defer srv.Close()
	setEnv(t, srv.URL)

	created, err := Create(testContext(), "shifts", map[string]any{"status": "open"}, []string{`read("team:org1/admin")`}, func(created map[string]any) Event {
		return gatewayEvent("row-1", created)
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if got := atomic.LoadInt32(&reads); got != 1 {
		t.Fatalf("re-read calls = %d, want 1", got)
	}
	if created["$createdAt"] == "" || created["$updatedAt"] == "" || created["$sequence"] == nil {
		t.Fatalf("returned an incomplete staged row: %#v", created)
	}
}

// TestUpdateReturnsTheCommittedRow proves the same contract for updates, whose
// staged row carries an empty $updatedAt.
func TestUpdateReturnsTheCommittedRow(t *testing.T) {
	var reads int32
	srv := newTransactionServer(t,
		`{"$id":"row-1","$sequence":0,"$createdAt":"","$updatedAt":"","status":"closed"}`,
		func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Query().Get("transactionId") != "" {
				writeJSON(w, http.StatusOK, `{"$id":"row-1","$sequence":7,"$createdAt":"2026-11-18T00:00:00.000+00:00","$updatedAt":"2026-11-18T00:00:00.000+00:00","status":"open"}`)
				return
			}
			atomic.AddInt32(&reads, 1)
			writeJSON(w, http.StatusOK, committedRowJSON)
		})
	defer srv.Close()
	setEnv(t, srv.URL)

	updated, err := Update(testContext(), "shifts", "row-1", map[string]any{"status": "closed"}, func(before, after map[string]any) Event {
		return gatewayEvent("row-1", after)
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if got := atomic.LoadInt32(&reads); got != 1 {
		t.Fatalf("re-read calls = %d, want 1", got)
	}
	if updated["$updatedAt"] != "2026-11-18T00:10:00.000+00:00" {
		t.Fatalf("update returned the staged row: %#v", updated)
	}
}

// TestCreateKeepsTheStagedRowWhenTheReadBackFails proves the write still reports
// success: the transaction committed, so a failed re-read must not fail the
// mutation.
func TestCreateKeepsTheStagedRowWhenTheReadBackFails(t *testing.T) {
	srv := newTransactionServer(t, `{"$id":"row-1","status":"open"}`, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusInternalServerError, `{"message":"boom","code":500,"type":"general_unknown"}`)
	})
	defer srv.Close()
	setEnv(t, srv.URL)

	created, err := Create(testContext(), "shifts", map[string]any{"status": "open"}, nil, func(created map[string]any) Event {
		return gatewayEvent("row-1", created)
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created["$id"] != "row-1" {
		t.Fatalf("expected the staged row fallback, got %#v", created)
	}
}

// newTransactionServer mocks the transaction, row write, audit append and commit
// endpoints. getRow answers the post-commit re-read (and the in-transaction read
// an update performs first).
func newTransactionServer(t *testing.T, rowBody string, getRow http.HandlerFunc) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/rows/row-1"):
			getRow(w, r)
		case r.Method == http.MethodPost && r.URL.Path == "/tablesdb/transactions":
			writeJSON(w, http.StatusCreated, `{"$id":"tx-1","status":"pending"}`)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/tables/"+Table+"/rows"):
			writeJSON(w, http.StatusCreated, `{"$id":"event-1"}`)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/rows"):
			writeJSON(w, http.StatusCreated, rowBody)
		case r.Method == http.MethodPatch && strings.HasSuffix(r.URL.Path, "/rows/row-1"):
			writeJSON(w, http.StatusOK, `{"$id":"row-1","status":"closed"}`)
		case r.Method == http.MethodPatch && r.URL.Path == "/tablesdb/transactions/tx-1":
			writeJSON(w, http.StatusOK, `{"$id":"tx-1","status":"committed"}`)
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			writeJSON(w, http.StatusNotFound, `{}`)
		}
	}))
}

func gatewayEvent(rowID string, row map[string]any) Event {
	return BuildGatewayEvent(Spec{
		Caller:  Caller{TeamID: "org1", UserID: "user1", Role: "admin"},
		Op:      OpCreate,
		Table:   "shifts",
		Entity:  "shift",
		Naming:  DefaultNaming("shift"),
		Version: 1,
		RowID:   rowID,
		Data:    map[string]any{"status": "open"},
		After:   row,
		Now:     time.Now(),
	})
}

func testContext() openruntimes.Context {
	return openruntimes.NewContext(openruntimes.Logger{})
}

func setEnv(t *testing.T, endpoint string) {
	t.Helper()
	t.Setenv(appwrite.EnvEndpoint, endpoint)
	t.Setenv(appwrite.EnvProjectID, "project-test")
	t.Setenv(appwrite.EnvDatabaseID, "database-test")
}

func writeJSON(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(json.RawMessage(body))
}

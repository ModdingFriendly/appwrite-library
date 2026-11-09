package appwrite_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/appwrite/sdk-for-go/tablesdb"
	"github.com/open-runtimes/types-for-go/v4/openruntimes"

	"github.com/ModdingFriendly/appwrite-library/appwrite"
	"github.com/ModdingFriendly/appwrite-library/httpx"
)

func transactionError(t *testing.T, err error) *httpx.Error {
	t.Helper()
	var domain *httpx.Error
	if !errors.As(err, &domain) {
		t.Fatalf("error = %T %v, want *httpx.Error", err, err)
	}
	return domain
}

func TestInTransactionCommitsAfterExactAcknowledgement(t *testing.T) {
	t.Setenv(appwrite.EnvEndpoint, "")
	t.Setenv(appwrite.EnvProjectID, "")
	t.Setenv(appwrite.EnvDatabaseID, "")

	var created, staged, committed, rolledBack bool

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/tablesdb/transactions":
			created = true
			var body struct {
				TTL int `json:"ttl"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode create transaction: %v", err)
			}
			if body.TTL != appwrite.DefaultTransactionTTL {
				t.Fatalf("ttl = %d, want %d", body.TTL, appwrite.DefaultTransactionTTL)
			}
			writeJSON(w, http.StatusCreated, `{"$id":"tx-1","status":"pending"}`)
		case r.Method == http.MethodPost && r.URL.Path == "/tablesdb/database-test/tables/tickets/rows":
			staged = true
			var body struct {
				Data          map[string]any `json:"data"`
				TransactionID string         `json:"transactionId"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode row: %v", err)
			}
			if body.TransactionID != "tx-1" {
				t.Fatalf("transactionId = %q", body.TransactionID)
			}
			writeJSON(w, http.StatusCreated, `{"$id":"row-1"}`)
		case r.Method == http.MethodPatch && r.URL.Path == "/tablesdb/transactions/tx-1":
			var body struct {
				Commit   bool `json:"commit"`
				Rollback bool `json:"rollback"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode transaction update: %v", err)
			}
			switch {
			case body.Commit:
				committed = true
				writeJSON(w, http.StatusOK, `{"$id":"tx-1","status":"committed"}`)
			case body.Rollback:
				rolledBack = true
				writeJSON(w, http.StatusOK, `{"$id":"tx-1","status":"rolled_back"}`)
			default:
				t.Fatalf("transaction update had neither commit nor rollback")
			}
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	t.Setenv(appwrite.EnvEndpoint, srv.URL)
	t.Setenv(appwrite.EnvProjectID, "project-test")
	t.Setenv(appwrite.EnvDatabaseID, "database-test")

	err := appwrite.InTransaction(testContext(), func(t *tablesdb.TablesDB, txID string) error {
		_, err := t.CreateRow("database-test", "tickets", "row-1",
			map[string]any{"device": "Phone"},
			t.WithCreateRowTransactionId(txID),
		)
		return err
	})
	if err != nil {
		t.Fatalf("InTransaction: %v", err)
	}
	if !created || !staged || !committed {
		t.Fatalf("created=%v staged=%v committed=%v", created, staged, committed)
	}
	if rolledBack {
		t.Fatal("committed transaction was rolled back")
	}
}

func TestInTransactionCallbackErrorRollsBack(t *testing.T) {
	sentinel := errors.New("callback failed")
	var staged, committed, rolledBack bool

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/tablesdb/transactions":
			writeJSON(w, http.StatusCreated, `{"$id":"tx-1","status":"pending"}`)
		case r.Method == http.MethodPost && r.URL.Path == "/tablesdb/database-test/tables/tickets/rows":
			staged = true
			var body struct {
				TransactionID string `json:"transactionId"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode row: %v", err)
			}
			if body.TransactionID != "tx-1" {
				t.Fatalf("transactionId = %q", body.TransactionID)
			}
			writeJSON(w, http.StatusCreated, `{"$id":"row-1"}`)
		case r.Method == http.MethodPatch && r.URL.Path == "/tablesdb/transactions/tx-1":
			var body struct {
				Commit   bool `json:"commit"`
				Rollback bool `json:"rollback"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode transaction update: %v", err)
			}
			if body.Commit {
				committed = true
			}
			if body.Rollback {
				rolledBack = true
			}
			writeJSON(w, http.StatusOK, `{"$id":"tx-1","status":"rolled_back"}`)
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	err := appwrite.InTransactionWith(testContext(), config(srv.URL), func(t *tablesdb.TablesDB, txID string) error {
		if _, err := t.CreateRow("database-test", "tickets", "row-1",
			map[string]any{"device": "Phone"},
			t.WithCreateRowTransactionId(txID),
		); err != nil {
			return err
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("error = %v, want callback error", err)
	}
	if !staged || !rolledBack || committed {
		t.Fatalf("staged=%v rolledBack=%v committed=%v", staged, rolledBack, committed)
	}
}

func TestInTransactionCommitHTTPErrorRollsBack(t *testing.T) {
	var rolledBack bool

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/tablesdb/transactions":
			writeJSON(w, http.StatusCreated, `{"$id":"tx-1","status":"pending"}`)
		case r.Method == http.MethodPatch && r.URL.Path == "/tablesdb/transactions/tx-1":
			var body struct {
				Commit   bool `json:"commit"`
				Rollback bool `json:"rollback"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode transaction update: %v", err)
			}
			if body.Commit {
				writeJSON(w, http.StatusInternalServerError, `{"message":"commit failed internally"}`)
				return
			}
			if body.Rollback {
				rolledBack = true
				writeJSON(w, http.StatusOK, `{"$id":"tx-1","status":"rolled_back"}`)
				return
			}
			t.Fatalf("transaction update had neither commit nor rollback")
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	err := appwrite.InTransactionWith(testContext(), config(srv.URL), func(t *tablesdb.TablesDB, txID string) error {
		return nil
	})
	domain := transactionError(t, err)
	if domain.Status != http.StatusBadGateway || domain.Code != "upstream_error" {
		t.Fatalf("error = %#v", domain)
	}
	if strings.Contains(domain.Message, "commit failed internally") {
		t.Fatalf("provider detail leaked: %q", domain.Message)
	}
	if !rolledBack {
		t.Fatal("commit failure did not attempt rollback")
	}
}

func TestInTransactionFailsClosedOnAmbiguousCommitStatus(t *testing.T) {
	tests := []struct {
		name       string
		response   string
		wantStatus string
	}{
		{"empty status", `{"$id":"tx-1","status":""}`, "empty"},
		{"missing status", `{"$id":"tx-1"}`, "empty"},
		{"committing status", `{"$id":"tx-1","status":"committing"}`, "committing"},
		{"failed status", `{"$id":"tx-1","status":"failed"}`, "failed"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var commitSeen, rollbackSeen bool

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.Method == http.MethodPost && r.URL.Path == "/tablesdb/transactions":
					writeJSON(w, http.StatusCreated, `{"$id":"tx-1","status":"pending"}`)
				case r.Method == http.MethodPatch && r.URL.Path == "/tablesdb/transactions/tx-1":
					var body struct {
						Commit   bool `json:"commit"`
						Rollback bool `json:"rollback"`
					}
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
						t.Fatalf("decode transaction update: %v", err)
					}
					if body.Commit {
						commitSeen = true
						writeJSON(w, http.StatusOK, tc.response)
						return
					}
					if body.Rollback {
						rollbackSeen = true
						writeJSON(w, http.StatusOK, `{"$id":"tx-1","status":"rolled_back"}`)
						return
					}
					t.Fatalf("transaction update had neither commit nor rollback")
				default:
					t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
				}
			}))
			defer srv.Close()

			err := appwrite.InTransactionWith(testContext(), config(srv.URL), func(t *tablesdb.TablesDB, txID string) error {
				return nil
			})
			domain := transactionError(t, err)
			if domain.Status != http.StatusBadGateway || domain.Message != "database transaction did not commit" {
				t.Fatalf("error = %#v", domain)
			}
			if domain.Params["status"] != tc.wantStatus {
				t.Fatalf("status param = %#v, want %q", domain.Params["status"], tc.wantStatus)
			}
			if !commitSeen || !rollbackSeen {
				t.Fatalf("commitSeen=%v rollbackSeen=%v", commitSeen, rollbackSeen)
			}
		})
	}
}

func TestInTransactionRollbackErrorIsLoggedPrivately(t *testing.T) {
	logFile, err := os.CreateTemp(t.TempDir(), "transaction-errors-*.log")
	if err != nil {
		t.Fatalf("create log file: %v", err)
	}
	ctx := openruntimes.NewContext(openruntimes.Logger{Enabled: true, StreamErrors: logFile})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/tablesdb/transactions":
			writeJSON(w, http.StatusCreated, `{"$id":"tx-1","status":"pending"}`)
		case r.Method == http.MethodPatch && r.URL.Path == "/tablesdb/transactions/tx-1":
			var body struct {
				Commit   bool `json:"commit"`
				Rollback bool `json:"rollback"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode transaction update: %v", err)
			}
			if body.Commit {
				writeJSON(w, http.StatusInternalServerError, `{"message":"commit failed"}`)
				return
			}
			if body.Rollback {
				writeJSON(w, http.StatusInternalServerError, `{"message":"rollback failed: backend detail"}`)
				return
			}
			t.Fatalf("transaction update had neither commit nor rollback")
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	err = appwrite.InTransactionWith(ctx, config(srv.URL), func(t *tablesdb.TablesDB, txID string) error {
		return nil
	})
	domain := transactionError(t, err)
	if strings.Contains(domain.Message, "rollback failed: backend detail") {
		t.Fatalf("rollback detail leaked: %q", domain.Message)
	}

	if err := logFile.Close(); err != nil {
		t.Fatalf("close log file: %v", err)
	}
	logged, err := os.ReadFile(logFile.Name())
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}
	if !strings.Contains(string(logged), "rollback transaction tx-1") ||
		!strings.Contains(string(logged), "rollback failed: backend detail") {
		t.Fatalf("private log = %q", string(logged))
	}
}

func TestInTransactionAmbiguousRollbackAckIsLogged(t *testing.T) {
	logFile, err := os.CreateTemp(t.TempDir(), "transaction-rollback-*.log")
	if err != nil {
		t.Fatalf("create log file: %v", err)
	}
	ctx := openruntimes.NewContext(openruntimes.Logger{Enabled: true, StreamErrors: logFile})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/tablesdb/transactions":
			writeJSON(w, http.StatusCreated, `{"$id":"tx-1","status":"pending"}`)
		case r.Method == http.MethodPatch && r.URL.Path == "/tablesdb/transactions/tx-1":
			var body struct {
				Commit   bool `json:"commit"`
				Rollback bool `json:"rollback"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode transaction update: %v", err)
			}
			if body.Commit {
				writeJSON(w, http.StatusInternalServerError, `{"message":"commit failed"}`)
				return
			}
			if body.Rollback {
				writeJSON(w, http.StatusOK, `{"$id":"tx-1","status":"failed"}`)
				return
			}
			t.Fatalf("transaction update had neither commit nor rollback")
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	err = appwrite.InTransactionWith(ctx, config(srv.URL), func(t *tablesdb.TablesDB, txID string) error {
		return nil
	})
	transactionError(t, err)

	if err := logFile.Close(); err != nil {
		t.Fatalf("close log file: %v", err)
	}
	logged, err := os.ReadFile(logFile.Name())
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}
	if !strings.Contains(string(logged), "rollback status failed") {
		t.Fatalf("private log = %q", string(logged))
	}
}

func TestInTransactionCreateFailureDoesNotRunCallback(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/tablesdb/transactions" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		writeJSON(w, http.StatusInternalServerError, `{"message":"transactions unavailable"}`)
	}))
	defer srv.Close()

	err := appwrite.InTransactionWith(testContext(), config(srv.URL), func(t *tablesdb.TablesDB, txID string) error {
		called = true
		return nil
	})
	domain := transactionError(t, err)
	if domain.Status != http.StatusBadGateway {
		t.Fatalf("error = %#v", domain)
	}
	if called {
		t.Fatal("callback ran without a transaction")
	}
}

func TestInTransactionRequiresCallback(t *testing.T) {
	err := appwrite.InTransactionWith(testContext(), appwrite.Config{}, nil)
	domain := transactionError(t, err)
	if domain.Status != http.StatusBadRequest || domain.Code != "bad_request" {
		t.Fatalf("error = %#v", domain)
	}
}

func TestInTransactionRequiresExplicitConfiguration(t *testing.T) {
	called := false
	err := appwrite.InTransactionWith(testContext(), appwrite.Config{}, func(t *tablesdb.TablesDB, txID string) error {
		called = true
		return nil
	})
	if !errors.Is(err, appwrite.ErrMissingEndpoint) {
		t.Fatalf("error = %v, want ErrMissingEndpoint", err)
	}
	if called {
		t.Fatal("callback ran without configuration")
	}
}

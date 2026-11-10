package appwrite_test

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/open-runtimes/types-for-go/v4/openruntimes"

	"github.com/ModdingFriendly/appwrite-library/appwrite"
	"github.com/ModdingFriendly/appwrite-library/httpx"
)

type ticket struct {
	ID     string `json:"$id"`
	Device string `json:"device"`
	Status string `json:"status"`
}

func testContext() openruntimes.Context {
	return openruntimes.NewContext(openruntimes.Logger{})
}

func config(serverURL string) appwrite.Config {
	return appwrite.Config{
		Endpoint:   serverURL,
		ProjectID:  "project-test",
		DatabaseID: "database-test",
		APIKey:     "execution-key-test",
	}
}

func writeJSON(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}

func assertHeader(t *testing.T, r *http.Request, name, want string) {
	t.Helper()
	if got := r.Header.Get(name); got != want {
		t.Fatalf("%s = %q, want %q", name, got, want)
	}
}

func TestListWithDecodesRowsAndSendsQueries(t *testing.T) {
	var gotPath, gotMethod string
	var gotQueries []string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod = r.URL.Path, r.Method
		gotQueries = r.URL.Query()["queries[]"]
		assertHeader(t, r, "X-Appwrite-Project", "project-test")
		assertHeader(t, r, "X-Appwrite-Key", "execution-key-test")
		assertHeader(t, r, "X-Appwrite-Response-Format", appwrite.DefaultResponseFormat)
		writeJSON(w, http.StatusOK, `{"total":2,"rows":[`+
			`{"$id":"a","device":"iPhone","status":"open"},`+
			`{"$id":"b","device":"Pixel","status":"closed"}]}`)
	}))
	defer srv.Close()

	page, err := appwrite.ListWith[ticket](testContext(), config(srv.URL), "tickets",
		appwrite.Equal("organization_id", "team-1"),
		appwrite.Limit(10),
	)
	if err != nil {
		t.Fatalf("ListWith: %v", err)
	}
	if gotMethod != http.MethodGet || gotPath != "/tablesdb/database-test/tables/tickets/rows" {
		t.Fatalf("request = %s %s", gotMethod, gotPath)
	}
	if len(gotQueries) != 2 || !strings.Contains(gotQueries[0], "organization_id") {
		t.Fatalf("queries = %#v", gotQueries)
	}
	if page.Total != 2 || len(page.Rows) != 2 {
		t.Fatalf("page = %#v", page)
	}
	if page.Rows[0].ID != "a" || page.Rows[0].Device != "iPhone" || page.Rows[1].Status != "closed" {
		t.Fatalf("rows = %#v", page.Rows)
	}
}

func TestLegacyListUsesExplicitEnvironment(t *testing.T) {
	t.Setenv(appwrite.EnvEndpoint, "")
	t.Setenv(appwrite.EnvFunctionEndpoint, "")
	t.Setenv(appwrite.EnvProjectID, "")
	t.Setenv(appwrite.EnvFunctionProjectID, "")
	t.Setenv(appwrite.EnvDatabaseID, "")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, `{"total":1,"rows":[{"$id":"x","device":"Laptop","status":"open"}]}`)
	}))
	defer srv.Close()

	t.Setenv(appwrite.EnvEndpoint, srv.URL)
	t.Setenv(appwrite.EnvProjectID, "project-env")
	t.Setenv(appwrite.EnvDatabaseID, "database-env")

	ctx := testContext()
	ctx.Req.Headers = map[string]string{"x-appwrite-key": "key-env"}

	page, err := appwrite.List[ticket](ctx, "tickets")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if page.Total != 1 || len(page.Rows) != 1 || page.Rows[0].Device != "Laptop" {
		t.Fatalf("page = %#v", page)
	}
}

func TestGetWithDecodesRow(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/tablesdb/database-test/tables/tickets/rows/row-1" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		writeJSON(w, http.StatusOK, `{"$id":"row-1","device":"Tablet","status":"open"}`)
	}))
	defer srv.Close()

	row, err := appwrite.GetWith[ticket](testContext(), config(srv.URL), "tickets", "row-1")
	if err != nil {
		t.Fatalf("GetWith: %v", err)
	}
	if row.ID != "row-1" || row.Device != "Tablet" {
		t.Fatalf("row = %#v", row)
	}
}

func TestCreateWithSendsPermissionsAndDecodes(t *testing.T) {
	var body struct {
		RowID       string         `json:"rowId"`
		Data        map[string]any `json:"data"`
		Permissions []string       `json:"permissions"`
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/tablesdb/database-test/tables/tickets/rows" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		writeJSON(w, http.StatusCreated, `{"$id":"created-1","device":"Camera","status":"open"}`)
	}))
	defer srv.Close()

	created, err := appwrite.CreateWith[ticket](testContext(), config(srv.URL), "tickets",
		map[string]any{"device": "Camera", "status": "open"},
		[]string{`read("team:team-1/admin")`},
	)
	if err != nil {
		t.Fatalf("CreateWith: %v", err)
	}
	if body.RowID == "" {
		t.Fatal("rowId was not sent")
	}
	if body.Data["device"] != "Camera" {
		t.Fatalf("data = %#v", body.Data)
	}
	if len(body.Permissions) != 1 || body.Permissions[0] != `read("team:team-1/admin")` {
		t.Fatalf("permissions = %#v", body.Permissions)
	}
	if created.ID != "created-1" || created.Device != "Camera" {
		t.Fatalf("created = %#v", created)
	}
}

func TestUpdateWithPatchesRow(t *testing.T) {
	var body struct {
		Data map[string]any `json:"data"`
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch || r.URL.Path != "/tablesdb/database-test/tables/tickets/rows/row-1" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		writeJSON(w, http.StatusOK, `{"$id":"row-1","device":"Tablet","status":"closed"}`)
	}))
	defer srv.Close()

	updated, err := appwrite.UpdateWith[ticket](testContext(), config(srv.URL), "tickets", "row-1",
		map[string]any{"status": "closed"})
	if err != nil {
		t.Fatalf("UpdateWith: %v", err)
	}
	if body.Data["status"] != "closed" {
		t.Fatalf("data = %#v", body.Data)
	}
	if updated.Status != "closed" {
		t.Fatalf("updated = %#v", updated)
	}
}

func TestDeleteWithRemovesRow(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete || r.URL.Path != "/tablesdb/database-test/tables/tickets/rows/row-1" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		writeJSON(w, http.StatusOK, `{}`)
	}))
	defer srv.Close()

	if err := appwrite.DeleteWith(testContext(), config(srv.URL), "tickets", "row-1"); err != nil {
		t.Fatalf("DeleteWith: %v", err)
	}
}

func TestMapErrorFromRealSDKResponses(t *testing.T) {
	tests := []struct {
		status     int
		wantStatus int
		code       string
		message    string
		secret     string
	}{
		{http.StatusBadRequest, http.StatusBadRequest, "bad_request", appwrite.MessageBadRequest, "invalid document structure: total"},
		{http.StatusUnauthorized, http.StatusUnauthorized, "unauthorized", appwrite.MessageUnauthorized, "user unauthorized"},
		{http.StatusForbidden, http.StatusForbidden, "forbidden", appwrite.MessageForbidden, "missing scope rows.read"},
		{http.StatusNotFound, http.StatusNotFound, "not_found", appwrite.MessageNotFound, "row not found"},
		{http.StatusConflict, http.StatusConflict, "conflict", appwrite.MessageConflict, "row already exists"},
		{http.StatusPreconditionFailed, http.StatusPreconditionFailed, "precondition_failed", appwrite.MessageStale, "stale version"},
		{http.StatusInternalServerError, http.StatusBadGateway, "upstream_error", appwrite.MessageUpstream, "internal database secret"},
	}

	for _, tc := range tests {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				writeJSON(w, tc.status, `{"message":"`+tc.secret+`","type":"server_error","code":`+
					strconv.Itoa(tc.status)+`}`)
			}))
			defer srv.Close()

			_, err := appwrite.GetWith[ticket](testContext(), config(srv.URL), "tickets", "row-1")
			if err == nil {
				t.Fatal("expected error")
			}
			var domain *httpx.Error
			if !errors.As(err, &domain) {
				t.Fatalf("error = %T %v, want *httpx.Error", err, err)
			}
			if domain.Status != tc.wantStatus {
				t.Fatalf("status = %d, want %d", domain.Status, tc.wantStatus)
			}
			if domain.Code != tc.code {
				t.Fatalf("code = %q, want %q", domain.Code, tc.code)
			}
			// The public message is stable and never the upstream message, even
			// for 4xx: Appwrite echoes row content back in its own messages.
			if domain.Message != tc.message {
				t.Fatalf("message = %q, want %q", domain.Message, tc.message)
			}
			if strings.Contains(domain.Message, tc.secret) {
				t.Fatalf("upstream message leaked into the public message: %q", domain.Message)
			}
			// The raw detail must survive privately for the log line.
			if !strings.Contains(domain.Detail, tc.secret) {
				t.Fatalf("private detail %q lost the upstream message %q", domain.Detail, tc.secret)
			}
			if got := domain.Params["status"]; got != tc.status {
				t.Fatalf("params status = %#v, want %d", got, tc.status)
			}
			if got := domain.Params["table"]; got != "tickets" {
				t.Fatalf("params table = %#v", got)
			}
			if got := domain.Params["reason"]; got != "server_error" {
				t.Fatalf("params reason = %#v, want the sanitised Appwrite type", got)
			}
		})
	}
}

// TestMapErrorDropsUnsafeReason proves the machine-readable reason only passes
// through when it is a bounded identifier.
func TestMapErrorDropsUnsafeReason(t *testing.T) {
	for _, raw := range []string{
		`{"message":"x","type":"<script>alert(1)</script>"}`,
		`{"message":"x","type":"UPPER CASE"}`,
		`{"message":"x"}`,
		`not json`,
		`{"message":"x","type":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`,
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusBadRequest, raw)
		}))
		_, err := appwrite.GetWith[ticket](testContext(), config(srv.URL), "tickets", "row-1")
		srv.Close()

		var domain *httpx.Error
		if !errors.As(err, &domain) {
			t.Fatalf("error = %T %v", err, err)
		}
		if _, present := domain.Params["reason"]; present {
			t.Fatalf("unsafe reason %q was exposed: %#v", raw, domain.Params)
		}
	}
}

func TestMapErrorHidesNonSDKDetail(t *testing.T) {
	cause := errors.New("dial tcp 10.0.0.1: secret token")
	err := appwrite.MapError(cause, "tickets")
	var domain *httpx.Error
	if !errors.As(err, &domain) {
		t.Fatalf("error = %T", err)
	}
	if domain.Status != http.StatusBadGateway || domain.Code != "upstream_error" {
		t.Fatalf("error = %#v", domain)
	}
	if domain.Message != appwrite.MessageUpstream {
		t.Fatalf("message = %q, want the stable upstream message", domain.Message)
	}
	if strings.Contains(domain.Message, "secret token") {
		t.Fatalf("message leaked raw error: %q", domain.Message)
	}
	if !errors.Is(err, cause) {
		t.Fatal("MapError dropped the cause, so callers cannot detect transport conditions")
	}
	if appwrite.MapError(nil, "tickets") != nil {
		t.Fatal("MapError(nil) should be nil")
	}
}

func TestDecodeFailureIsSafe(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, `{"total":1,"rows":[{"$id":"row-1","device":42}]}`)
	}))
	defer srv.Close()

	_, err := appwrite.ListWith[ticket](testContext(), config(srv.URL), "tickets")
	var domain *httpx.Error
	if !errors.As(err, &domain) {
		t.Fatalf("error = %T %v", err, err)
	}
	if domain.Status != http.StatusBadGateway || domain.Message != "could not decode appwrite response" {
		t.Fatalf("error = %#v", domain)
	}
	if len(domain.Params) != 1 || domain.Params["table"] != "tickets" {
		t.Fatalf("params = %#v", domain.Params)
	}
}

func TestConfigValidationHasNoDefaults(t *testing.T) {
	if _, err := appwrite.NewClient(appwrite.Config{}); !errors.Is(err, appwrite.ErrMissingEndpoint) {
		t.Fatalf("NewClient(empty) error = %v", err)
	}
	if _, err := appwrite.NewClient(appwrite.Config{Endpoint: "https://example.test/v1"}); !errors.Is(err, appwrite.ErrMissingProjectID) {
		t.Fatalf("NewClient(missing project) error = %v", err)
	}
	if _, err := appwrite.NewTables(appwrite.Config{Endpoint: "https://example.test/v1", ProjectID: "p"}); !errors.Is(err, appwrite.ErrMissingDatabaseID) {
		t.Fatalf("NewTables(missing database) error = %v", err)
	}
}

func TestConfigFromEnvReadsExplicitValues(t *testing.T) {
	t.Setenv(appwrite.EnvEndpoint, "")
	t.Setenv(appwrite.EnvFunctionEndpoint, "https://runtime.example/v1")
	t.Setenv(appwrite.EnvProjectID, "")
	t.Setenv(appwrite.EnvFunctionProjectID, "runtime-project")
	t.Setenv(appwrite.EnvDatabaseID, "runtime-database")
	t.Setenv(appwrite.EnvResponseFormat, "")

	ctx := testContext()
	ctx.Req.Headers = map[string]string{"X-Appwrite-Key": "runtime-key"}

	cfg := appwrite.ConfigFromEnv(ctx)
	if cfg.Endpoint != "https://runtime.example/v1" {
		t.Fatalf("endpoint = %q", cfg.Endpoint)
	}
	if cfg.ProjectID != "runtime-project" {
		t.Fatalf("project = %q", cfg.ProjectID)
	}
	if cfg.DatabaseID != "runtime-database" {
		t.Fatalf("database = %q", cfg.DatabaseID)
	}
	if cfg.APIKey != "runtime-key" {
		t.Fatalf("api key = %q", cfg.APIKey)
	}
}

// TestResponseFormatStaysDecodable pins the format the SDK models were
// generated for. Appwrite 2.6.1 serialises `$sequence` as a JSON string while
// sdk-for-go v1.0.0 decodes it as int, which breaks every row read.
func TestResponseFormatStaysDecodable(t *testing.T) {
	if appwrite.DefaultResponseFormat != "1.8.0" {
		t.Fatalf("DefaultResponseFormat = %q, want 1.8.0 (SDK-compatible)", appwrite.DefaultResponseFormat)
	}
	var seen string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("X-Appwrite-Response-Format")
		assertHeader(t, r, "X-Appwrite-Response-Format", appwrite.DefaultResponseFormat)
		writeJSON(w, http.StatusOK, `{"total":1,"rows":[{"$id":"row1","$sequence":1,"device":"iPhone","status":"New"}]}`)
	}))
	defer server.Close()

	// Rows carry numeric $sequence at the pinned format; decoding must succeed.
	page, err := appwrite.ListWith[ticket](testContext(), config(server.URL), "tickets")
	if err != nil {
		t.Fatalf("ListWith: %v", err)
	}
	if len(page.Rows) != 1 || page.Rows[0].Device != "iPhone" {
		t.Fatalf("page = %#v", page)
	}
	if seen != appwrite.DefaultResponseFormat {
		t.Fatalf("header = %q, want %q", seen, appwrite.DefaultResponseFormat)
	}
}

// TestSDKTransactionSupport proves the pinned Appwrite SDK (v1.0.0) already
// supports TablesDB transactions, so billing/quote work does not need an SDK
// upgrade. It exercises create transaction -> row write in transaction ->
// commit through the real SDK client.
func TestSDKTransactionSupport(t *testing.T) {
	var sawTransactionID, sawCommit bool

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/tablesdb/transactions":
			writeJSON(w, http.StatusCreated, `{"$id":"tx-1","$createdAt":"2026-01-01T00:00:00.000Z",`+
				`"$updatedAt":"2026-01-01T00:00:00.000Z","status":"pending","operations":0,`+
				`"expiresAt":"2026-01-01T00:05:00.000Z"}`)
		case r.Method == http.MethodPost && r.URL.Path == "/tablesdb/database-test/tables/tickets/rows":
			var body struct {
				TransactionID string `json:"transactionId"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode row body: %v", err)
			}
			sawTransactionID = body.TransactionID == "tx-1"
			writeJSON(w, http.StatusCreated, `{"$id":"row-tx","device":"Phone","status":"open"}`)
		case r.Method == http.MethodPatch && r.URL.Path == "/tablesdb/transactions/tx-1":
			var body struct {
				Commit bool `json:"commit"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode commit body: %v", err)
			}
			sawCommit = body.Commit
			writeJSON(w, http.StatusOK, `{"$id":"tx-1","$createdAt":"2026-01-01T00:00:00.000Z",`+
				`"$updatedAt":"2026-01-01T00:00:01.000Z","status":"committed","operations":1,`+
				`"expiresAt":"2026-01-01T00:05:00.000Z"}`)
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	tables, err := appwrite.NewTables(config(srv.URL))
	if err != nil {
		t.Fatalf("NewTables: %v", err)
	}

	tx, err := tables.CreateTransaction()
	if err != nil {
		t.Fatalf("CreateTransaction: %v", err)
	}
	if tx.Id != "tx-1" || tx.Status != "pending" {
		t.Fatalf("transaction = %#v", tx)
	}

	row, err := tables.CreateRow("database-test", "tickets", "row-tx",
		map[string]any{"device": "Phone"},
		tables.WithCreateRowTransactionId(tx.Id),
	)
	if err != nil {
		t.Fatalf("CreateRow in transaction: %v", err)
	}
	if row.Id != "row-tx" {
		t.Fatalf("row = %#v", row)
	}

	committed, err := tables.UpdateTransaction(tx.Id, tables.WithUpdateTransactionCommit(true))
	if err != nil {
		t.Fatalf("UpdateTransaction commit: %v", err)
	}
	if committed.Status != "committed" {
		t.Fatalf("committed = %#v", committed)
	}
	if !sawTransactionID || !sawCommit {
		t.Fatalf("transactionId sent = %v, commit sent = %v", sawTransactionID, sawCommit)
	}
}

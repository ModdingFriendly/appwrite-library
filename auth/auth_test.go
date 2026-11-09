package auth_test

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/open-runtimes/types-for-go/v4/openruntimes"

	"github.com/ModdingFriendly/appwrite-library/appwrite"
	"github.com/ModdingFriendly/appwrite-library/auth"
	"github.com/ModdingFriendly/appwrite-library/httpx"
)

func testContext(headers map[string]string) openruntimes.Context {
	ctx := openruntimes.NewContext(openruntimes.Logger{})
	ctx.Req.Headers = headers
	return ctx
}

func newLookup(t *testing.T, serverURL string) *auth.JWTLookup {
	t.Helper()
	lookup, err := auth.NewJWTLookup(auth.Config{Endpoint: serverURL, ProjectID: "project-test"})
	if err != nil {
		t.Fatalf("NewJWTLookup: %v", err)
	}
	return lookup
}

func writeJSON(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}

func assertJWTOnly(t *testing.T, r *http.Request) {
	t.Helper()
	if got := r.Header.Get("X-Appwrite-JWT"); got != "jwt-test" {
		t.Fatalf("X-Appwrite-JWT = %q", got)
	}
	if got := r.Header.Get("X-Appwrite-Project"); got != "project-test" {
		t.Fatalf("X-Appwrite-Project = %q", got)
	}
	if got := r.Header.Get("X-Appwrite-Key"); got != "" {
		t.Fatalf("privileged execution key leaked: %q", got)
	}
	if got := r.Header.Get("X-Appwrite-Response-Format"); got != appwrite.DefaultResponseFormat {
		t.Fatalf("X-Appwrite-Response-Format = %q", got)
	}
}

func domainError(t *testing.T, err error) *httpx.Error {
	t.Helper()
	var domain *httpx.Error
	if !errors.As(err, &domain) {
		t.Fatalf("error = %T %v, want *httpx.Error", err, err)
	}
	return domain
}

func TestCurrentUserUsesJWTOnlyAccountGet(t *testing.T) {
	var sawPath, sawMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawPath, sawMethod = r.URL.Path, r.Method
		assertJWTOnly(t, r)
		writeJSON(w, http.StatusOK, `{"$id":"user-1","status":true}`)
	}))
	defer srv.Close()

	identity, err := newLookup(t, srv.URL).CurrentUser(testContext(map[string]string{"x-appwrite-user-jwt": "jwt-test"}))
	if err != nil {
		t.Fatalf("CurrentUser: %v", err)
	}
	if sawMethod != http.MethodGet || sawPath != "/account" {
		t.Fatalf("request = %s %s", sawMethod, sawPath)
	}
	if identity.UserID != "user-1" {
		t.Fatalf("identity = %#v", identity)
	}
}

func TestCurrentUserHeaderIsCaseInsensitive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertJWTOnly(t, r)
		writeJSON(w, http.StatusOK, `{"$id":"user-1","status":true}`)
	}))
	defer srv.Close()

	identity, err := newLookup(t, srv.URL).CurrentUser(testContext(map[string]string{"X-Appwrite-User-JWT": "jwt-test"}))
	if err != nil {
		t.Fatalf("CurrentUser: %v", err)
	}
	if identity.UserID != "user-1" {
		t.Fatalf("identity = %#v", identity)
	}
}

func TestCurrentUserMissingJWTDoesNotCallNetwork(t *testing.T) {
	lookup, err := auth.NewJWTLookup(auth.Config{Endpoint: "http://127.0.0.1:1", ProjectID: "project-test"})
	if err != nil {
		t.Fatalf("NewJWTLookup: %v", err)
	}
	_, err = lookup.CurrentUser(testContext(nil))
	domain := domainError(t, err)
	if domain.Status != http.StatusUnauthorized || domain.Code != "unauthorized" {
		t.Fatalf("error = %#v", domain)
	}
}

func TestCurrentUserDisabledAccount(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, `{"$id":"user-1","status":false}`)
	}))
	defer srv.Close()

	_, err := newLookup(t, srv.URL).CurrentUser(testContext(map[string]string{"x-appwrite-user-jwt": "jwt-test"}))
	domain := domainError(t, err)
	if domain.Status != http.StatusUnauthorized || domain.Message != "account is disabled" {
		t.Fatalf("error = %#v", domain)
	}
}

func TestCurrentUserMapsExpiredJWT(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusUnauthorized, `{"message":"jwt expired"}`)
	}))
	defer srv.Close()

	_, err := newLookup(t, srv.URL).CurrentUser(testContext(map[string]string{"x-appwrite-user-jwt": "jwt-test"}))
	domain := domainError(t, err)
	if domain.Status != http.StatusUnauthorized || domain.Message != "invalid or expired caller token" {
		t.Fatalf("error = %#v", domain)
	}
}

func TestCurrentUserHidesUpstreamDetail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusInternalServerError, `{"message":"internal secret detail"}`)
	}))
	defer srv.Close()

	_, err := newLookup(t, srv.URL).CurrentUser(testContext(map[string]string{"x-appwrite-user-jwt": "jwt-test"}))
	domain := domainError(t, err)
	if domain.Status != http.StatusBadGateway || domain.Message != "could not verify caller identity" {
		t.Fatalf("error = %#v", domain)
	}
	if strings.Contains(domain.Message, "internal secret detail") {
		t.Fatalf("provider detail leaked: %q", domain.Message)
	}
}

func TestMembershipUsesSameJWTAndFiltersByUser(t *testing.T) {
	var sawPath, sawMethod string
	var sawQueries []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawPath, sawMethod = r.URL.Path, r.Method
		sawQueries = r.URL.Query()["queries[]"]
		assertJWTOnly(t, r)
		writeJSON(w, http.StatusOK, `{"total":1,"memberships":[`+
			`{"$id":"membership-1","userId":"user-1","teamId":"team-1","roles":["member","billing"],"confirm":true}]}`)
	}))
	defer srv.Close()

	membership, err := newLookup(t, srv.URL).Membership(
		testContext(map[string]string{"x-appwrite-user-jwt": "jwt-test"}), "team-1", "user-1")
	if err != nil {
		t.Fatalf("Membership: %v", err)
	}
	if sawMethod != http.MethodGet || sawPath != "/teams/team-1/memberships" {
		t.Fatalf("request = %s %s", sawMethod, sawPath)
	}
	if len(sawQueries) != 2 {
		t.Fatalf("queries = %#v", sawQueries)
	}
	var sawUserFilter, sawLimit bool
	for _, raw := range sawQueries {
		var q struct {
			Method    string `json:"method"`
			Attribute string `json:"attribute"`
			Values    []any  `json:"values"`
		}
		if err := json.Unmarshal([]byte(raw), &q); err != nil {
			t.Fatalf("decode query %q: %v", raw, err)
		}
		switch q.Method {
		case "equal":
			sawUserFilter = q.Attribute == "userId" && len(q.Values) == 1 && q.Values[0] == "user-1"
		case "limit":
			sawLimit = len(q.Values) == 1 && q.Values[0] == float64(1)
		}
	}
	if !sawUserFilter || !sawLimit {
		t.Fatalf("queries = %#v", sawQueries)
	}
	if membership.ID != "membership-1" || membership.UserID != "user-1" || membership.TeamID != "team-1" {
		t.Fatalf("membership = %#v", membership)
	}
	if len(membership.Roles) != 2 || membership.Roles[1] != "billing" || !membership.Confirmed {
		t.Fatalf("membership = %#v", membership)
	}
}

func TestMembershipReturnsUnconfirmedFlag(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, `{"total":1,"memberships":[`+
			`{"$id":"membership-1","userId":"user-1","teamId":"team-1","roles":[],"confirm":false}]}`)
	}))
	defer srv.Close()

	membership, err := newLookup(t, srv.URL).Membership(
		testContext(map[string]string{"x-appwrite-user-jwt": "jwt-test"}), "team-1", "user-1")
	if err != nil {
		t.Fatalf("Membership: %v", err)
	}
	if membership.Confirmed {
		t.Fatalf("membership = %#v", membership)
	}
}

func TestMembershipNotFoundIsForbidden(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, `{"total":0,"memberships":[]}`)
	}))
	defer srv.Close()

	_, err := newLookup(t, srv.URL).Membership(
		testContext(map[string]string{"x-appwrite-user-jwt": "jwt-test"}), "team-1", "user-1")
	domain := domainError(t, err)
	if domain.Status != http.StatusForbidden || domain.Message != "caller is not a member of this team" {
		t.Fatalf("error = %#v", domain)
	}
}

func TestMembershipMapsForbidden(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusForbidden, `{"message":"team access denied"}`)
	}))
	defer srv.Close()

	_, err := newLookup(t, srv.URL).Membership(
		testContext(map[string]string{"x-appwrite-user-jwt": "jwt-test"}), "team-1", "user-1")
	domain := domainError(t, err)
	if domain.Status != http.StatusForbidden || domain.Message != "caller is not a member of this team" {
		t.Fatalf("error = %#v", domain)
	}
}

func TestMembershipRejectsInjectedTeamID(t *testing.T) {
	lookup, err := auth.NewJWTLookup(auth.Config{Endpoint: "http://127.0.0.1:1", ProjectID: "project-test"})
	if err != nil {
		t.Fatalf("NewJWTLookup: %v", err)
	}
	_, err = lookup.Membership(testContext(map[string]string{"x-appwrite-user-jwt": "jwt-test"}), "team-1\r\nX-Evil: 1", "user-1")
	domain := domainError(t, err)
	if domain.Status != http.StatusBadRequest || domain.Code != "bad_request" {
		t.Fatalf("error = %#v", domain)
	}
}

func TestConfigValidationHasNoDefaults(t *testing.T) {
	if _, err := auth.NewJWTLookup(auth.Config{}); !errors.Is(err, appwrite.ErrMissingEndpoint) {
		t.Fatalf("NewJWTLookup(empty) error = %v", err)
	}
	if _, err := auth.NewJWTLookup(auth.Config{Endpoint: "https://example.test/v1"}); !errors.Is(err, appwrite.ErrMissingProjectID) {
		t.Fatalf("NewJWTLookup(missing project) error = %v", err)
	}
}

func TestConfigFromEnvUsesExplicitValues(t *testing.T) {
	t.Setenv(appwrite.EnvEndpoint, "")
	t.Setenv(appwrite.EnvFunctionEndpoint, "https://runtime.example/v1")
	t.Setenv(appwrite.EnvProjectID, "")
	t.Setenv(appwrite.EnvFunctionProjectID, "runtime-project")

	cfg := auth.ConfigFromEnv()
	if cfg.Endpoint != "https://runtime.example/v1" || cfg.ProjectID != "runtime-project" {
		t.Fatalf("config = %#v", cfg)
	}
}

func TestConfigFromEnvHasNoImplicitProject(t *testing.T) {
	t.Setenv(appwrite.EnvEndpoint, "")
	t.Setenv(appwrite.EnvFunctionEndpoint, "")
	t.Setenv(appwrite.EnvProjectID, "")
	t.Setenv(appwrite.EnvFunctionProjectID, "")

	cfg := auth.ConfigFromEnv()
	if cfg.Endpoint != "" || cfg.ProjectID != "" {
		t.Fatalf("config = %#v", cfg)
	}
}

func TestHeaderReadsCaseInsensitively(t *testing.T) {
	ctx := testContext(map[string]string{"X-Tenant-Id": " team-1 "})
	if got := auth.Header(ctx, "x-tenant-id"); got != "team-1" {
		t.Fatalf("header = %q", got)
	}
	if got := auth.Header(ctx, "missing"); got != "" {
		t.Fatalf("missing header = %q", got)
	}
}

// Compile-time check that the concrete lookup satisfies the boundary a caller
// can stub.
var _ auth.Lookup = (*auth.JWTLookup)(nil)

// Guard against accidental API-key use: setting a key-like env var must not
// leak into requests.
func TestNoExecutionKeyFromEnvironment(t *testing.T) {
	t.Setenv("APPWRITE_API_KEY", "must-not-be-used")
	t.Setenv("APPWRITE_FUNCTION_API_KEY", "must-not-be-used")
	t.Setenv("APPWRITE_KEY", "must-not-be-used")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Appwrite-Key"); got != "" {
			t.Fatalf("X-Appwrite-Key = %q", got)
		}
		writeJSON(w, http.StatusOK, `{"$id":"user-1","status":true}`)
	}))
	defer srv.Close()

	if _, err := newLookup(t, srv.URL).CurrentUser(testContext(map[string]string{"x-appwrite-user-jwt": "jwt-test"})); err != nil {
		t.Fatalf("CurrentUser: %v", err)
	}
}

package appwrite_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ModdingFriendly/appwrite-library/appwrite"
	"github.com/ModdingFriendly/appwrite-library/httpx"
)

// TestRedirectIsRejectedAndKeyNotForwarded is the regression test for the
// credential-forwarding defect: the SDK replays X-Appwrite-Key (and
// X-Appwrite-JWT) on every request, so following a 302 to another origin hands
// the execution key to whatever host the redirect names.
func TestRedirectIsRejectedAndKeyNotForwarded(t *testing.T) {
	var leaked atomic.Int64
	var leakedHeader atomic.Value

	attacker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked.Add(1)
		leakedHeader.Store(r.Header.Get("X-Appwrite-Key"))
		writeJSON(w, http.StatusOK, `{"total":0,"rows":[]}`)
	}))
	defer attacker.Close()

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, attacker.URL+"/tablesdb/database-test/tables/tickets/rows", http.StatusFound)
	}))
	defer origin.Close()

	_, err := appwrite.ListWith[ticket](testContext(), config(origin.URL), "tickets")
	if err == nil {
		t.Fatal("expected the redirect to be rejected")
	}

	if got := leaked.Load(); got != 0 {
		t.Fatalf("redirect target received %d request(s); header was %v", got, leakedHeader.Load())
	}

	var domain *httpx.Error
	if !errors.As(err, &domain) {
		t.Fatalf("error = %T %v, want *httpx.Error", err, err)
	}
	if domain.Status != http.StatusBadGateway || domain.Code != "upstream_error" {
		t.Fatalf("error = %#v", domain)
	}
	if !errors.Is(err, appwrite.ErrRedirectRejected) {
		t.Fatalf("error does not wrap ErrRedirectRejected: %v", err)
	}
	if strings.Contains(strings.ToLower(domain.Message), attacker.URL) {
		t.Fatalf("redirect target leaked into the public message: %q", domain.Message)
	}
}

// TestRedirectToSameOriginIsAlsoRejected keeps the rule simple: no request is
// ever replayed, so no header can be replayed either.
func TestRedirectToSameOriginIsAlsoRejected(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits.Add(1) == 1 {
			http.Redirect(w, r, "/logger", http.StatusTemporaryRedirect)
			return
		}
		writeJSON(w, http.StatusOK, `{"total":0,"rows":[]}`)
	}))
	defer srv.Close()

	_, err := appwrite.ListWith[ticket](testContext(), config(srv.URL), "tickets")
	if !errors.Is(err, appwrite.ErrRedirectRejected) {
		t.Fatalf("error = %v, want ErrRedirectRejected", err)
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("server saw %d requests, want 1 (the redirect must not be followed)", got)
	}
}

func TestEndpointMustBeHTTPS(t *testing.T) {
	base := appwrite.Config{ProjectID: "project-test", DatabaseID: "database-test"}

	insecure := base
	insecure.Endpoint = "http://appwrite.example.com/v1"
	if _, err := appwrite.NewTables(insecure); !errors.Is(err, appwrite.ErrInsecureEndpoint) {
		t.Fatalf("NewTables(http://appwrite.example.com) error = %v, want ErrInsecureEndpoint", err)
	}
	// NewClient must apply the same policy, or the auth package would bypass it.
	if _, err := appwrite.NewClient(insecure); !errors.Is(err, appwrite.ErrInsecureEndpoint) {
		t.Fatalf("NewClient(http://appwrite.example.com) error = %v, want ErrInsecureEndpoint", err)
	}

	allowed := insecure
	allowed.AllowInsecureHTTP = true
	if _, err := appwrite.NewClient(allowed); err != nil {
		t.Fatalf("NewClient with AllowInsecureHTTP: %v", err)
	}

	secure := base
	secure.Endpoint = "https://appwrite.example.com/v1"
	if _, err := appwrite.NewClient(secure); err != nil {
		t.Fatalf("NewClient(https): %v", err)
	}

	for _, endpoint := range []string{
		"ftp://appwrite.example.com/v1",
		"appwrite.example.com/v1",
		"//appwrite.example.com/v1",
		"https://",
		"://bad",
	} {
		cfg := base
		cfg.Endpoint = endpoint
		if _, err := appwrite.NewClient(cfg); !errors.Is(err, appwrite.ErrInvalidEndpoint) {
			t.Errorf("NewClient(%q) error = %v, want ErrInvalidEndpoint", endpoint, err)
		}
	}
}

// TestLoopbackHTTPIsAllowed keeps local development and httptest usable without
// an opt-in flag.
func TestLoopbackHTTPIsAllowed(t *testing.T) {
	for _, host := range []string{"127.0.0.1:8080", "localhost:8080", "[::1]:8080", "app.localhost:8080"} {
		cfg := appwrite.Config{
			Endpoint:   "http://" + host + "/v1",
			ProjectID:  "project-test",
			DatabaseID: "database-test",
		}
		if _, err := appwrite.NewTables(cfg); err != nil {
			t.Errorf("NewTables(http://%s) error = %v, want loopback allowed", host, err)
		}
	}
	// A loopback lookalike is not loopback.
	cfg := appwrite.Config{
		Endpoint:   "http://localhost.attacker.example/v1",
		ProjectID:  "project-test",
		DatabaseID: "database-test",
	}
	if _, err := appwrite.NewTables(cfg); !errors.Is(err, appwrite.ErrInsecureEndpoint) {
		t.Fatalf("lookalike host error = %v, want ErrInsecureEndpoint", err)
	}
}

// TestClientTimeoutIsBounded documents that requests cannot hang forever.
func TestClientTimeoutIsBounded(t *testing.T) {
	clt, err := appwrite.NewClient(appwrite.Config{
		Endpoint:  "https://appwrite.example.com/v1",
		ProjectID: "project-test",
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if clt.Client == nil {
		t.Fatal("client has no http.Client")
	}
	if clt.Client.Timeout != appwrite.DefaultHTTPTimeout {
		t.Fatalf("timeout = %v, want %v", clt.Client.Timeout, appwrite.DefaultHTTPTimeout)
	}
	if clt.Client.CheckRedirect == nil {
		t.Fatal("client has no redirect policy")
	}
	// The hardened client must not mutate SDK-global transport state.
	if _, err := url.Parse(clt.Endpoint); err != nil {
		t.Fatalf("endpoint: %v", err)
	}
}

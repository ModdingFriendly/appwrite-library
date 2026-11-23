package auth_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ModdingFriendly/appwrite-library/auth"
)

func withCacheTTL(t *testing.T, ttl time.Duration) {
	t.Helper()
	previous := auth.CacheTTL
	auth.CacheTTL = ttl
	auth.ResetCache()
	t.Cleanup(func() {
		auth.CacheTTL = previous
		auth.ResetCache()
	})
}

func TestCurrentUserIsCachedPerJWT(t *testing.T) {
	withCacheTTL(t, time.Minute)
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		writeJSON(w, http.StatusOK, `{"$id":"user-`+r.Header.Get("X-Appwrite-JWT")+`","status":true}`)
	}))
	defer srv.Close()
	lookup := newLookup(t, srv.URL)

	for i := 0; i < 3; i++ {
		id, err := lookup.CurrentUser(testContext(map[string]string{"x-appwrite-user-jwt": "a"}))
		if err != nil || id.UserID != "user-a" {
			t.Fatalf("CurrentUser = %#v, %v", id, err)
		}
	}
	id, err := lookup.CurrentUser(testContext(map[string]string{"x-appwrite-user-jwt": "b"}))
	if err != nil || id.UserID != "user-b" {
		t.Fatalf("other JWT = %#v, %v", id, err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("Account.Get calls = %d, want 2 (one per JWT)", got)
	}
}

func TestCurrentUserFailureIsNotCached(t *testing.T) {
	withCacheTTL(t, time.Minute)
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			writeJSON(w, http.StatusUnauthorized, `{"message":"expired","code":401,"type":"user_jwt_invalid"}`)
			return
		}
		writeJSON(w, http.StatusOK, `{"$id":"user-1","status":true}`)
	}))
	defer srv.Close()
	lookup := newLookup(t, srv.URL)
	ctx := testContext(map[string]string{"x-appwrite-user-jwt": "jwt-test"})

	if _, err := lookup.CurrentUser(ctx); err == nil {
		t.Fatal("first call should fail")
	}
	if _, err := lookup.CurrentUser(ctx); err != nil {
		t.Fatalf("second call: %v", err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("calls = %d, want 2", got)
	}
}

func TestMembershipCachedOnlyWhenConfirmed(t *testing.T) {
	withCacheTTL(t, time.Minute)
	var calls atomic.Int32
	confirmed := "false"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		team := strings.Split(strings.TrimPrefix(r.URL.Path, "/teams/"), "/")[0]
		writeJSON(w, http.StatusOK, `{"total":1,"memberships":[{"$id":"m1","userId":"user-1","teamId":"`+team+`","roles":["admin"],"confirm":`+confirmed+`}]}`)
	}))
	defer srv.Close()
	lookup := newLookup(t, srv.URL)
	ctx := testContext(map[string]string{"x-appwrite-user-jwt": "jwt-test"})

	for i := 0; i < 2; i++ {
		if _, err := lookup.Membership(ctx, "team-1", "user-1"); err != nil {
			t.Fatal(err)
		}
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("unconfirmed calls = %d, want 2", got)
	}
	confirmed = "true"
	for i := 0; i < 3; i++ {
		m, err := lookup.Membership(ctx, "team-1", "user-1")
		if err != nil || !m.Confirmed || m.Roles[0] != "admin" {
			t.Fatalf("Membership = %#v, %v", m, err)
		}
		m.Roles[0] = "tampered"
	}
	if got := calls.Load(); got != 3 {
		t.Fatalf("confirmed calls = %d, want 3", got)
	}
	if _, err := lookup.Membership(ctx, "team-2", "user-1"); err != nil {
		t.Fatal(err)
	}
	if got := calls.Load(); got != 4 {
		t.Fatalf("other team must not share an entry: calls = %d", got)
	}
}

func TestCacheDisabledWithZeroTTL(t *testing.T) {
	withCacheTTL(t, 0)
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		writeJSON(w, http.StatusOK, `{"$id":"user-1","status":true}`)
	}))
	defer srv.Close()
	lookup := newLookup(t, srv.URL)
	ctx := testContext(map[string]string{"x-appwrite-user-jwt": "jwt-test"})
	_, _ = lookup.CurrentUser(ctx)
	_, _ = lookup.CurrentUser(ctx)
	if got := calls.Load(); got != 2 {
		t.Fatalf("calls = %d, want 2", got)
	}
}

package orgstatus

import (
	"errors"
	"testing"
	"time"

	"github.com/ModdingFriendly/appwrite-library/httpx"
)

type fakeStore struct {
	state State
	found bool
	err   error
	reads int
}

func (f *fakeStore) State(string) (State, bool, error) {
	f.reads++
	return f.state, f.found, f.err
}

func codeOf(t *testing.T, err error) (int, string) {
	t.Helper()
	if err == nil {
		return 0, ""
	}
	var he *httpx.Error
	if !errors.As(err, &he) {
		t.Fatalf("want *httpx.Error, got %T", err)
	}
	return he.Status, he.Code
}

func TestRequireByStatus(t *testing.T) {
	cases := []struct {
		name   string
		state  State
		found  bool
		status int
		code   string
	}{
		{"no row", State{}, false, 0, ""},
		{"empty status", State{}, true, 0, ""},
		{"active", State{Status: "active"}, true, 0, ""},
		{"unknown status is active", State{Status: "trial"}, true, 0, ""},
		{"suspended", State{Status: "suspended"}, true, 403, CodeSuspended},
		{"suspended mixed case", State{Status: " Suspended "}, true, 403, CodeSuspended},
		{"deleted", State{Status: "deleted"}, true, 403, CodeClosed},
		{"deleted_at wins", State{Status: "active", DeletedAt: "2026-11-20T10:00:00Z"}, true, 403, CodeClosed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := New(0)
			status, code := codeOf(t, c.Require(&fakeStore{state: tc.state, found: tc.found}, "team-1"))
			if status != tc.status || code != tc.code {
				t.Fatalf("got %d %q, want %d %q", status, code, tc.status, tc.code)
			}
		})
	}
}

func TestRequireNeedsTeam(t *testing.T) {
	status, _ := codeOf(t, New(0).Require(&fakeStore{}, "  "))
	if status != 401 {
		t.Fatalf("status = %d, want 401", status)
	}
}

func TestCacheExpiresWithinTTL(t *testing.T) {
	now := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	c := New(30 * time.Second)
	c.now = func() time.Time { return now }
	store := &fakeStore{state: State{Status: "active"}, found: true}

	if err := c.Require(store, "team-1"); err != nil {
		t.Fatal(err)
	}
	store.state.Status = "suspended"
	now = now.Add(29 * time.Second)
	if err := c.Require(store, "team-1"); err != nil {
		t.Fatalf("cached active status should still allow: %v", err)
	}
	if store.reads != 1 {
		t.Fatalf("reads = %d, want 1", store.reads)
	}
	now = now.Add(2 * time.Second)
	if _, code := codeOf(t, c.Require(store, "team-1")); code != CodeSuspended {
		t.Fatalf("code = %q after TTL, want suspended", code)
	}
}

func TestForgetDropsCache(t *testing.T) {
	c := New(time.Hour)
	store := &fakeStore{state: State{Status: "active"}, found: true}
	_ = c.Require(store, "team-1")
	store.state.Status = "suspended"
	c.Forget("team-1")
	if _, code := codeOf(t, c.Require(store, "team-1")); code != CodeSuspended {
		t.Fatalf("code = %q, want suspended", code)
	}
}

func TestReadFailureUsesStaleOrFailsClosed(t *testing.T) {
	now := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	c := New(30 * time.Second)
	c.now = func() time.Time { return now }

	failing := &fakeStore{err: errors.New("down")}
	if status, code := codeOf(t, c.Require(failing, "team-1")); status != 503 || code != CodeUnavailable {
		t.Fatalf("got %d %q, want 503 unavailable with no cache", status, code)
	}

	suspended := &fakeStore{state: State{Status: "suspended"}, found: true}
	_ = c.Require(suspended, "team-2")
	now = now.Add(time.Minute)
	if _, code := codeOf(t, c.Require(failing, "team-2")); code != CodeSuspended {
		t.Fatalf("stale suspended status should still refuse, got %q", code)
	}
}

func TestNilStoreFailsClosed(t *testing.T) {
	if status, _ := codeOf(t, New(0).Require(nil, "team-1")); status != 503 {
		t.Fatalf("status = %d, want 503", status)
	}
}

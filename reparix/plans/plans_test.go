package plans

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/open-runtimes/types-for-go/v4/openruntimes"

	"github.com/ModdingFriendly/appwrite-library/appwrite"
	"github.com/ModdingFriendly/appwrite-library/httpx"
)

type fakeStore struct {
	limits Limits
	found  bool
	err    error
}

func (f fakeStore) Limits(string) (Limits, bool, error) { return f.limits, f.found, f.err }

func counter(n float64, err error, calls *int) Counter {
	return func() (float64, error) {
		*calls++
		return n, err
	}
}

func TestCheckRefusesOnlyPastTheLimit(t *testing.T) {
	limits := Limits{Plan: "starter", MaxTicketsPerMonth: 100}
	if err := Check(limits, TicketsPerMonth, 99, 1); err != nil {
		t.Fatalf("the 100th ticket was refused: %v", err)
	}
	err := Check(limits, TicketsPerMonth, 100, 1)
	var he *httpx.Error
	if !errors.As(err, &he) || he.Status != 402 || he.Code != Code {
		t.Fatalf("the 101st ticket: %v", err)
	}
	if he.Params["metric"] != "tickets_per_month" || he.Params["limit"] != 100 || he.Params["used"] != 100.0 || he.Params["plan"] != "starter" {
		t.Fatalf("params %v", he.Params)
	}
	if !strings.Contains(he.Message, "100 repairs a month") {
		t.Fatalf("message %q", he.Message)
	}
}

func TestCheckTreatsZeroAndNegativeAsUnlimited(t *testing.T) {
	for _, limit := range []int{0, -1} {
		if err := Check(Limits{MaxUsers: limit}, Users, 1e6, 1); err != nil {
			t.Fatalf("limit %d refused: %v", limit, err)
		}
	}
}

func TestCheckStorageCountsTheUpload(t *testing.T) {
	limits := Limits{MaxStorageMB: 100}
	if err := Check(limits, StorageMB, 99, 0.5); err != nil {
		t.Fatal(err)
	}
	if err := Check(limits, StorageMB, 99, 2); err == nil {
		t.Fatal("an upload past the storage limit was allowed")
	}
}

func TestEnforce(t *testing.T) {
	limited := fakeStore{limits: Limits{MaxSMSPerMonth: 10}, found: true}
	cases := []struct {
		name      string
		store     fakeStore
		used      float64
		countErr  error
		refused   bool
		wantCount int
	}{
		{"under the limit", limited, 9, nil, false, 1},
		{"at the limit", limited, 10, nil, true, 1},
		{"no billing account", fakeStore{}, 1e6, nil, false, 0},
		{"unlimited metric", fakeStore{limits: Limits{MaxUsers: 3}, found: true}, 1e6, nil, false, 0},
		{"plan unreadable", fakeStore{err: errors.New("down")}, 1e6, nil, false, 0},
		{"usage unreadable", limited, 0, errors.New("down"), false, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			var logged []string
			err := Enforce(tc.store, "org", SMSPerMonth, 1, counter(tc.used, tc.countErr, &calls), func(s string) { logged = append(logged, s) })
			if (err != nil) != tc.refused || calls != tc.wantCount {
				t.Fatalf("err %v calls %d", err, calls)
			}
			if (tc.store.err != nil || tc.countErr != nil) && len(logged) != 1 {
				t.Fatalf("logged %v", logged)
			}
		})
	}
}

func TestMonthStart(t *testing.T) {
	at := time.Date(2026, 11, 18, 23, 30, 0, 0, time.FixedZone("x", -5*3600))
	if got := MonthStart(at); !got.Equal(time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("month start %v", got)
	}
}

func storeContext(t *testing.T, url string) openruntimes.Context {
	t.Helper()
	t.Setenv(appwrite.EnvEndpoint, url)
	t.Setenv(appwrite.EnvProjectID, "project-test")
	t.Setenv(appwrite.EnvDatabaseID, "database-test")
	ctx := openruntimes.NewContext(openruntimes.Logger{})
	ctx.Req.Headers = map[string]string{"x-appwrite-key": "execution-key-test"}
	return ctx
}

func reply(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, body)
}

func TestAppwriteStoreFallsBackToTheStripePrice(t *testing.T) {
	var planQueries [][]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queries := r.URL.Query()["queries[]"]
		switch {
		case strings.HasSuffix(r.URL.Path, "/tables/billing_accounts/rows"):
			if !strings.Contains(strings.Join(queries, " "), `"org-1"`) {
				t.Errorf("account queries %v", queries)
			}
			reply(w, `{"total":1,"rows":[{"plan":"retired","stripe_price_id":"price_1"}]}`)
		case strings.HasSuffix(r.URL.Path, "/tables/plans/rows"):
			planQueries = append(planQueries, queries)
			if strings.Contains(strings.Join(queries, " "), "price_1") {
				reply(w, `{"total":1,"rows":[{"$id":"pro","max_users":5,"max_tickets_per_month":200,"max_sms_per_month":50,"max_storage_mb":1024}]}`)
				return
			}
			reply(w, `{"total":0,"rows":[]}`)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(500)
		}
	}))
	defer srv.Close()

	limits, found, err := AppwriteStore{Ctx: storeContext(t, srv.URL)}.Limits("org-1")
	if err != nil || !found {
		t.Fatalf("found %v err %v", found, err)
	}
	if limits != (Limits{Plan: "pro", MaxUsers: 5, MaxTicketsPerMonth: 200, MaxSMSPerMonth: 50, MaxStorageMB: 1024}) {
		t.Fatalf("limits %+v", limits)
	}
	if len(planQueries) != 2 || !strings.Contains(strings.Join(planQueries[0], " "), "retired") {
		t.Fatalf("plan lookups %v", planQueries)
	}
}

func TestAppwriteStoreWithoutAnAccount(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reply(w, `{"total":0,"rows":[]}`)
	}))
	defer srv.Close()
	if _, found, err := (AppwriteStore{Ctx: storeContext(t, srv.URL)}).Limits("org-1"); found || err != nil {
		t.Fatalf("found %v err %v", found, err)
	}
}

func TestCountersUseTheTotalAndTheMonth(t *testing.T) {
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.URL.Path+" "+strings.Join(r.URL.Query()["queries[]"], " "))
		if strings.HasSuffix(r.URL.Path, "/tables/usage/rows") {
			reply(w, `{"total":3,"rows":[{"quantity":412.5}]}`)
			return
		}
		reply(w, `{"total":37,"rows":[{"$id":"x"}]}`)
	}))
	defer srv.Close()
	ctx := storeContext(t, srv.URL)
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)

	if n, err := TicketsThisMonth(ctx, "org-1", now)(); n != 37 || err != nil {
		t.Fatalf("tickets %v %v", n, err)
	}
	if n, err := SMSThisMonth(ctx, "org-1", now)(); n != 37 || err != nil {
		t.Fatalf("sms %v %v", n, err)
	}
	if n, err := StoredMB(ctx, "org-1")(); n != 412.5 || err != nil {
		t.Fatalf("storage %v %v", n, err)
	}
	if !strings.Contains(got[0], "/tables/tickets/rows") || !strings.Contains(got[0], "2026-11-01T00:00:00Z") || !strings.Contains(got[0], "greaterThanEqual") {
		t.Fatalf("tickets query %s", got[0])
	}
	if !strings.Contains(got[1], "/tables/messages/rows") || !strings.Contains(got[1], `"sms"`) || !strings.Contains(got[1], `"outbound"`) {
		t.Fatalf("sms query %s", got[1])
	}
}

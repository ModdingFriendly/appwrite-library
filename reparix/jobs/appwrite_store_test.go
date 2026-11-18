package jobs

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/open-runtimes/types-for-go/v4/openruntimes"

	"github.com/ModdingFriendly/appwrite-library/appwrite"
)

func storeContext(t *testing.T, url string) openruntimes.Context {
	t.Helper()
	t.Setenv(appwrite.EnvEndpoint, url)
	t.Setenv(appwrite.EnvProjectID, "project-test")
	t.Setenv(appwrite.EnvDatabaseID, "database-test")
	ctx := openruntimes.NewContext(openruntimes.Logger{})
	ctx.Req.Headers = map[string]string{"x-appwrite-key": "execution-key-test"}
	return ctx
}

func reply(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}

func TestPurgeDeletesOldRowsAndIgnoresGoneOnes(t *testing.T) {
	var mu sync.Mutex
	lists := 0
	var queries []string
	deleted := []string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/tables/api_logs/rows"):
			lists++
			queries = r.URL.Query()["queries[]"]
			if lists == 1 {
				reply(w, 200, `{"total":2,"rows":[{"$id":"r1"},{"$id":"r2"}]}`)
				return
			}
			reply(w, 200, `{"total":0,"rows":[]}`)
		case r.Method == http.MethodDelete && strings.HasSuffix(r.URL.Path, "/rows/r1"):
			deleted = append(deleted, "r1")
			w.WriteHeader(204)
		case r.Method == http.MethodDelete && strings.HasSuffix(r.URL.Path, "/rows/r2"):
			reply(w, 404, `{"message":"Row not found","code":404,"type":"row_not_found"}`)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(500)
		}
	}))
	defer srv.Close()

	cutoff := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)
	tally, err := Purge(storeContext(t, srv.URL), "api_logs", "team1", "$createdAt", cutoff, 10)
	if err != nil {
		t.Fatal(err)
	}
	if tally.Changed != 1 || tally.Skipped != 1 || tally.More {
		t.Fatalf("tally %+v", tally)
	}
	joined := strings.Join(queries, " ")
	if !strings.Contains(joined, `"organization_id"`) || !strings.Contains(joined, "team1") || !strings.Contains(joined, "2026-08-20T00:00:00Z") || !strings.Contains(joined, "lessThan") {
		t.Fatalf("queries %v", queries)
	}
	if len(deleted) != 1 {
		t.Fatalf("deleted %v", deleted)
	}
}

func TestPurgeStopsAtTheLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			reply(w, 200, `{"total":5,"rows":[{"$id":"a"},{"$id":"b"}]}`)
			return
		}
		w.WriteHeader(204)
	}))
	defer srv.Close()
	tally, err := Purge(storeContext(t, srv.URL), "api_logs", "team1", "$createdAt", time.Now(), 2)
	if err != nil {
		t.Fatal(err)
	}
	if tally.Changed != 2 || !tally.More {
		t.Fatalf("tally %+v", tally)
	}
}

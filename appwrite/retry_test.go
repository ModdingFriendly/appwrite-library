package appwrite_test

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/ModdingFriendly/appwrite-library/appwrite"
)

// TestReadRetriesTransientTransportFailure covers the failure mode that broke
// clock-in: a connection to the API died mid-request and the SDK surfaced a
// generic upstream error. A GET has no side effects, so it is replayed.
func TestReadRetriesTransientTransportFailure(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) == 1 {
			hijacker, ok := w.(http.Hijacker)
			if !ok {
				t.Fatal("test server does not support hijacking")
			}
			conn, _, err := hijacker.Hijack()
			if err != nil {
				t.Fatalf("hijack: %v", err)
			}
			_ = conn.Close()
			return
		}
		writeJSON(w, http.StatusOK, `{"total":0,"rows":[]}`)
	}))
	defer srv.Close()

	page, err := appwrite.ListWith[map[string]any](testContext(), config(srv.URL), "tickets")
	if err != nil {
		t.Fatalf("ListWith: %v", err)
	}
	if page == nil || page.Total != 0 {
		t.Fatalf("page = %+v", page)
	}
	if got := atomic.LoadInt32(&calls); got < 2 {
		t.Fatalf("requests = %d, want a retry", got)
	}
}

// TestReadRetriesTransientStatus retries the statuses Appwrite returns while it
// is briefly unavailable.
func TestReadRetriesTransientStatus(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) == 1 {
			writeJSON(w, http.StatusServiceUnavailable, `{"message":"maintenance","code":503,"type":"general_service_unavailable"}`)
			return
		}
		writeJSON(w, http.StatusOK, `{"total":1,"rows":[{"$id":"row-1"}]}`)
	}))
	defer srv.Close()

	page, err := appwrite.ListWith[map[string]any](testContext(), config(srv.URL), "tickets")
	if err != nil {
		t.Fatalf("ListWith: %v", err)
	}
	if page.Total != 1 {
		t.Fatalf("total = %d", page.Total)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("requests = %d, want 2", got)
	}
}

// TestWriteIsNotRetried proves a POST is never replayed: Appwrite cannot tell a
// retried create from a second one, so a transient failure surfaces instead of
// risking a duplicate row.
func TestWriteIsNotRetried(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		writeJSON(w, http.StatusServiceUnavailable, `{"message":"maintenance","code":503,"type":"general_service_unavailable"}`)
	}))
	defer srv.Close()

	if _, err := appwrite.CreateWith[map[string]any](testContext(), config(srv.URL), "tickets", map[string]any{"title": "x"}, nil); err == nil {
		t.Fatal("expected an error")
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("requests = %d, want 1 (POST must not be retried)", got)
	}
}

// TestReadStopsAfterRetryBudget bounds the retries so a dead endpoint cannot
// stall a function past its execution budget.
func TestReadStopsAfterRetryBudget(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		writeJSON(w, http.StatusBadGateway, `{"message":"bad gateway","code":502,"type":"general_unknown"}`)
	}))
	defer srv.Close()

	if _, err := appwrite.ListWith[map[string]any](testContext(), config(srv.URL), "tickets"); err == nil {
		t.Fatal("expected an error")
	}
	if got := atomic.LoadInt32(&calls); got != appwrite.DefaultRetryAttempts {
		t.Fatalf("requests = %d, want %d", got, appwrite.DefaultRetryAttempts)
	}
}

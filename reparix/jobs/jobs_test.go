package jobs

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ModdingFriendly/appwrite-library/httpx"
)

type memStore struct {
	orgs    []string
	orgErr  error
	lastErr error
	runs    []Run
}

func (m *memStore) Organisations() ([]string, error) { return m.orgs, m.orgErr }

func (m *memStore) LastRun(service, job string) (Run, bool, error) {
	if m.lastErr != nil {
		return Run{}, false, m.lastErr
	}
	for i := len(m.runs) - 1; i >= 0; i-- {
		if m.runs[i].Service == service && m.runs[i].Job == job {
			return m.runs[i], true, nil
		}
	}
	return Run{}, false, nil
}

func (m *memStore) Record(run Run) error {
	m.runs = append(m.runs, run)
	return nil
}

var t0 = time.Date(2026, 11, 18, 3, 0, 0, 0, time.UTC)

func fixedClock(at *time.Time) func() time.Time { return func() time.Time { return *at } }

func TestRunVisitsEveryOrganisationAndRecords(t *testing.T) {
	store := &memStore{orgs: []string{"b", "a", "c", "a", ""}}
	now := t0
	var visited []string
	job := Job{Name: "cleanup", Org: func(org string, at time.Time, limit int) (Tally, error) {
		visited = append(visited, org)
		if limit != DefaultLimit || !at.Equal(t0) {
			t.Fatalf("limit %d at %v", limit, at)
		}
		return Tally{Changed: 2, Skipped: 1}, nil
	}}
	summary := Runner{Service: "svc", Store: store, Now: fixedClock(&now)}.Run(job)

	if !reflect.DeepEqual(visited, []string{"a", "b", "c"}) {
		t.Fatalf("visited %v", visited)
	}
	if len(summary.Runs) != 1 || len(store.runs) != 1 {
		t.Fatalf("runs %+v", summary)
	}
	run := store.runs[0]
	if run.Status != StatusOK || run.Organisations != 3 || run.Changed != 6 || run.Skipped != 3 || run.Service != "svc" || run.Job != "cleanup" {
		t.Fatalf("run %+v", run)
	}
}

func TestRunSkipsJobsThatAreNotDue(t *testing.T) {
	store := &memStore{orgs: []string{"a"}}
	now := t0
	calls := 0
	job := Job{Name: "daily", Every: 24 * time.Hour, Org: func(string, time.Time, int) (Tally, error) {
		calls++
		return Tally{}, nil
	}}
	runner := Runner{Service: "svc", Store: store, Now: fixedClock(&now)}

	runner.Run(job)
	now = t0.Add(time.Hour)
	summary := runner.Run(job)
	if calls != 1 || len(summary.NotDue) != 1 || summary.NotDue[0] != "daily" {
		t.Fatalf("calls %d summary %+v", calls, summary)
	}
	// A daily cron that fires a little early is still due.
	now = t0.Add(24*time.Hour - 30*time.Second)
	runner.Run(job)
	if calls != 2 {
		t.Fatalf("calls %d", calls)
	}
}

func TestRunWhenTheLastRunCannotBeRead(t *testing.T) {
	store := &memStore{orgs: []string{"a"}, lastErr: errors.New("down")}
	now := t0
	calls := 0
	Runner{Service: "svc", Store: store, Now: fixedClock(&now)}.Run(Job{Name: "j", Every: time.Hour, Org: func(string, time.Time, int) (Tally, error) {
		calls++
		return Tally{}, nil
	}})
	if calls != 1 {
		t.Fatalf("calls %d", calls)
	}
}

func TestOrganisationFailureDoesNotStopTheOthers(t *testing.T) {
	store := &memStore{orgs: []string{"a", "b", "c"}}
	now := t0
	job := Job{Name: "j", Org: func(org string, _ time.Time, _ int) (Tally, error) {
		if org == "b" {
			return Tally{Changed: 1}, &httpx.Error{Status: 502, Code: "upstream_error", Message: "appwrite request failed", Detail: "secret detail"}
		}
		return Tally{Changed: 1}, nil
	}}
	Runner{Service: "svc", Store: store, Now: fixedClock(&now)}.Run(job)
	run := store.runs[0]
	if run.Status != StatusPartial || run.FailedOrgs != 1 || run.Organisations != 3 || run.Changed != 3 {
		t.Fatalf("run %+v", run)
	}
	if run.Error != "upstream_error: appwrite request failed" {
		t.Fatalf("error %q", run.Error)
	}
}

func TestEveryOrganisationFailingIsFailed(t *testing.T) {
	store := &memStore{orgs: []string{"a", "b"}}
	now := t0
	Runner{Service: "svc", Store: store, Now: fixedClock(&now)}.Run(Job{Name: "j", Org: func(string, time.Time, int) (Tally, error) {
		return Tally{}, errors.New("boom")
	}})
	if store.runs[0].Status != StatusFailed || store.runs[0].Error != "boom" {
		t.Fatalf("run %+v", store.runs[0])
	}
}

func TestListingFailureIsRecorded(t *testing.T) {
	store := &memStore{orgErr: errors.New("cannot list")}
	now := t0
	Runner{Service: "svc", Store: store, Now: fixedClock(&now)}.Run(Job{Name: "j", Org: func(string, time.Time, int) (Tally, error) {
		t.Fatal("must not run")
		return Tally{}, nil
	}})
	if store.runs[0].Status != StatusFailed || store.runs[0].Error != "cannot list" {
		t.Fatalf("run %+v", store.runs[0])
	}
}

func TestBacklogIsPartial(t *testing.T) {
	store := &memStore{orgs: []string{"a"}}
	now := t0
	Runner{Service: "svc", Store: store, Now: fixedClock(&now)}.Run(Job{Name: "j", Limit: 5, Org: func(_ string, _ time.Time, limit int) (Tally, error) {
		return Tally{Changed: limit, More: true}, nil
	}})
	run := store.runs[0]
	if run.Status != StatusPartial || run.Backlog != 1 || run.Changed != 5 {
		t.Fatalf("run %+v", run)
	}
}

func TestBudgetStopsAndTheNextRunResumes(t *testing.T) {
	store := &memStore{orgs: []string{"a", "b", "c", "d"}}
	now := t0
	var visited []string
	job := Job{Name: "j", Org: func(org string, _ time.Time, _ int) (Tally, error) {
		visited = append(visited, org)
		now = now.Add(4 * time.Second)
		return Tally{}, nil
	}}
	runner := Runner{Service: "svc", Store: store, Now: fixedClock(&now), Budget: 7 * time.Second}

	runner.Run(job)
	if !reflect.DeepEqual(visited, []string{"a", "b"}) || store.runs[0].ResumeAfter != "b" || store.runs[0].Status != StatusPartial {
		t.Fatalf("visited %v run %+v", visited, store.runs[0])
	}
	visited = nil
	runner.Run(job)
	if !reflect.DeepEqual(visited, []string{"c", "d"}) || store.runs[1].ResumeAfter != "d" {
		t.Fatalf("visited %v run %+v", visited, store.runs[1])
	}
	visited = nil
	runner.Budget = time.Minute
	runner.Run(job)
	if !reflect.DeepEqual(visited, []string{"a", "b", "c", "d"}) || store.runs[2].ResumeAfter != "" || store.runs[2].Status != StatusOK {
		t.Fatalf("visited %v run %+v", visited, store.runs[2])
	}
}

func TestBudgetAlwaysVisitsOneOrganisation(t *testing.T) {
	store := &memStore{orgs: []string{"a", "b"}}
	now := t0
	calls := 0
	Runner{Service: "svc", Store: store, Now: fixedClock(&now), Budget: time.Nanosecond}.Run(Job{Name: "j", Org: func(string, time.Time, int) (Tally, error) {
		calls++
		now = now.Add(time.Second)
		return Tally{}, nil
	}})
	if calls != 1 || store.runs[0].ResumeAfter != "a" {
		t.Fatalf("calls %d run %+v", calls, store.runs[0])
	}
}

func TestOrderResumesAfterAMissingOrganisation(t *testing.T) {
	got := Order([]string{"d", "a", "c"}, "b")
	if !reflect.DeepEqual(got, []string{"c", "d", "a"}) {
		t.Fatalf("order %v", got)
	}
}

func TestDescribeBoundsText(t *testing.T) {
	long := strings.Repeat("é", 400) + "\nsecond line"
	got := Describe(errors.New(long))
	if len(got) > maxError || strings.Contains(got, "second") {
		t.Fatalf("describe %d %q", len(got), got[:20])
	}
}

func TestRunData(t *testing.T) {
	data := RunData(Run{Service: "s", Job: "j", StartedAt: t0, FinishedAt: t0.Add(time.Second), Status: StatusOK, Changed: 2})
	if data["started_at"] != "2026-11-18T03:00:00Z" || data["finished_at"] != "2026-11-18T03:00:01Z" || data["changed"] != 2 {
		t.Fatalf("data %v", data)
	}
}

// Package jobs runs Reparix scheduled jobs: Appwrite scheduled executions
// (header x-appwrite-trigger: schedule) that do housekeeping for every
// organisation.
//
// Each Function has one cron schedule, so a service lists all its jobs and the
// Runner decides which are due from the shared run log (the job_runs table):
// a job with Every set runs only when its last recorded run started at least
// that long ago. A job with Every zero runs on every execution.
//
// A job is written per organisation. The Runner gives each organisation a
// bounded amount of work (Job.Limit) so one busy organisation cannot use the
// whole execution, and it stops starting new organisations once the run's time
// Budget is spent. It records where it stopped, and the next run of that job
// starts with the next organisation. An organisation whose work fails is
// recorded and skipped; the others still run.
//
// Jobs must be idempotent: a run can be cut short, repeated or overlap with
// another, and running a job twice must not send or create anything twice.
//
// The run log never holds request data. A failure is recorded as an error code
// (for an httpx.Error) or a short message the job itself wrote.
package jobs

import (
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/ModdingFriendly/appwrite-library/httpx"
)

// Status of a recorded run.
const (
	// StatusOK means every organisation was visited and none failed or was left
	// with more work.
	StatusOK = "ok"
	// StatusPartial means the run did useful work but some organisations failed,
	// hit their limit, or were not reached before the budget ran out.
	StatusPartial = "partial"
	// StatusFailed means nothing could be done: the organisations could not be
	// listed, or every organisation failed.
	StatusFailed = "failed"
)

const (
	// DefaultLimit is the work bound per organisation when Job.Limit is zero.
	DefaultLimit = 500
	// DefaultBudget is the run's time budget when Runner.Budget is zero.
	DefaultBudget = 20 * time.Second
	// maxError bounds the error text kept in the run log.
	maxError = 300
)

// Tally is what a job did for one organisation.
type Tally struct {
	// Changed counts rows created, updated or deleted and messages sent.
	Changed int
	// Skipped counts work found already done, such as a row that exists.
	Skipped int
	// More is true when the organisation still has work after Limit items; the
	// next run continues it.
	More bool
}

// Job is one scheduled job.
type Job struct {
	// Name is the stable id recorded in the run log, such as "api_log_retention".
	Name string
	// Every is the least time between two runs. Zero runs on every execution.
	Every time.Duration
	// Limit bounds the work per organisation per run. Zero means DefaultLimit.
	Limit int
	// Org does the job for one organisation, at most limit items.
	Org func(orgID string, now time.Time, limit int) (Tally, error)
}

// Run is one recorded run of a job: a row of the job_runs table.
type Run struct {
	Service       string    `json:"service"`
	Job           string    `json:"job"`
	StartedAt     time.Time `json:"started_at"`
	FinishedAt    time.Time `json:"finished_at"`
	Status        string    `json:"status"`
	Organisations int       `json:"organisations"`
	FailedOrgs    int       `json:"failed_orgs"`
	Backlog       int       `json:"backlog"`
	Changed       int       `json:"changed"`
	Skipped       int       `json:"skipped"`
	// ResumeAfter is the last organisation visited when the budget ran out; the
	// next run starts after it. Empty when the run reached every organisation.
	ResumeAfter string `json:"resume_after,omitempty"`
	Error       string `json:"error,omitempty"`
}

// Store lists organisations and reads and writes the run log.
type Store interface {
	// Organisations returns the team id of every organisation.
	Organisations() ([]string, error)
	// LastRun returns the most recent recorded run of a job, and false when
	// there is none.
	LastRun(service, job string) (Run, bool, error)
	// Record appends a run to the log.
	Record(run Run) error
}

// Runner runs a service's jobs.
type Runner struct {
	// Service is the Function that owns the jobs, such as "service-admin".
	Service string
	Store   Store
	// Now returns the current time. Nil means time.Now in UTC.
	Now func() time.Time
	// Budget bounds one job's run time. Zero means DefaultBudget.
	Budget time.Duration
	// Log receives one line per job. Nil discards it.
	Log func(string)
}

// Summary is what one execution did, returned as the execution's response.
type Summary struct {
	Runs   []Run    `json:"runs"`
	NotDue []string `json:"not_due"`
}

// Run runs each job that is due, in order, and records each run.
func (r Runner) Run(jobs ...Job) Summary {
	summary := Summary{Runs: []Run{}, NotDue: []string{}}
	for _, job := range jobs {
		last, found, err := r.Store.LastRun(r.Service, job.Name)
		if err != nil {
			// The jobs are idempotent, so running when unsure is the safe side.
			r.log(job.Name + ": could not read the last run; running anyway")
			found = false
		}
		if found && !Due(job.Every, last.StartedAt, r.now()) {
			summary.NotDue = append(summary.NotDue, job.Name)
			continue
		}
		resume := ""
		if found {
			resume = last.ResumeAfter
		}
		run := r.runJob(job, resume)
		if err := r.Store.Record(run); err != nil {
			r.log(job.Name + ": could not record the run")
		}
		r.log(job.Name + ": " + run.Status)
		summary.Runs = append(summary.Runs, run)
	}
	return summary
}

// Due reports whether a job last started at last is due again at now. A run up
// to a tenth of the interval early still counts, so a daily cron that fires a
// few seconds earlier than yesterday is not skipped for a day.
func Due(every time.Duration, last, now time.Time) bool {
	if every <= 0 || last.IsZero() {
		return true
	}
	return now.Sub(last) >= every-every/10
}

// Order returns the organisations sorted, starting with the first one after
// resumeAfter, so a run cut short continues where the last one stopped.
func Order(orgs []string, resumeAfter string) []string {
	sorted := append([]string(nil), orgs...)
	sort.Strings(sorted)
	if resumeAfter == "" {
		return sorted
	}
	start := sort.SearchStrings(sorted, resumeAfter)
	if start < len(sorted) && sorted[start] == resumeAfter {
		start++
	}
	return append(sorted[start:], sorted[:start]...)
}

func (r Runner) runJob(job Job, resumeAfter string) Run {
	started := r.now()
	run := Run{Service: r.Service, Job: job.Name, StartedAt: started}
	limit := job.Limit
	if limit <= 0 {
		limit = DefaultLimit
	}
	budget := r.Budget
	if budget <= 0 {
		budget = DefaultBudget
	}

	orgs, err := r.Store.Organisations()
	if err != nil {
		run.Status = StatusFailed
		run.Error = Describe(err)
		run.FinishedAt = r.now()
		return run
	}
	ordered := Order(dedupe(orgs), resumeAfter)
	for i, orgID := range ordered {
		if i > 0 && r.now().Sub(started) >= budget {
			run.ResumeAfter = ordered[i-1]
			break
		}
		run.Organisations++
		tally, err := job.Org(orgID, started, limit)
		run.Changed += tally.Changed
		run.Skipped += tally.Skipped
		if tally.More {
			run.Backlog++
		}
		if err != nil {
			run.FailedOrgs++
			if run.Error == "" {
				run.Error = Describe(err)
			}
		}
	}

	switch {
	case run.Organisations > 0 && run.FailedOrgs == run.Organisations:
		run.Status = StatusFailed
	case run.FailedOrgs > 0 || run.Backlog > 0 || run.ResumeAfter != "":
		run.Status = StatusPartial
	default:
		run.Status = StatusOK
	}
	run.FinishedAt = r.now()
	return run
}

// Describe turns an error into text that is safe for the run log: the code of
// an httpx.Error, or the first line of any other error, cut to a bounded length.
func Describe(err error) string {
	if err == nil {
		return ""
	}
	var he *httpx.Error
	if errors.As(err, &he) && he != nil {
		if he.Code != "" {
			return he.Code + ": " + he.Message
		}
		return he.Message
	}
	text := err.Error()
	if i := strings.IndexByte(text, '\n'); i >= 0 {
		text = text[:i]
	}
	if len(text) > maxError {
		text = strings.ToValidUTF8(text[:maxError], "")
	}
	return text
}

func dedupe(orgs []string) []string {
	seen := make(map[string]bool, len(orgs))
	out := make([]string, 0, len(orgs))
	for _, id := range orgs {
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out
}

func (r Runner) now() time.Time {
	if r.Now != nil {
		return r.Now().UTC()
	}
	return time.Now().UTC()
}

func (r Runner) log(line string) {
	if r.Log != nil {
		r.Log("jobs " + r.Service + " " + line)
	}
}

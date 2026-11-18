package jobs

import (
	"errors"
	"time"

	"github.com/open-runtimes/types-for-go/v4/openruntimes"

	"github.com/ModdingFriendly/appwrite-library/appwrite"
	"github.com/ModdingFriendly/appwrite-library/httpx"
)

// RunsTable is the run log table. It is platform-level: one row per job run,
// readable only with the server key.
const RunsTable = "job_runs"

const (
	orgPage = 100
	// maxOrganisations bounds the organisation listing.
	maxOrganisations = 10_000
	purgePage        = 100
)

// AppwriteStore is the Store for a Function execution, using the execution's
// server key from the environment.
type AppwriteStore struct {
	Ctx openruntimes.Context
}

// Organisations returns the team id of every row of the organizations table.
func (s AppwriteStore) Organisations() ([]string, error) {
	ids := []string{}
	for offset := 0; offset < maxOrganisations; offset += orgPage {
		page, err := appwrite.List[struct {
			TeamID string `json:"team_id"`
		}](s.Ctx, "organizations", appwrite.Limit(orgPage), appwrite.Offset(offset))
		if err != nil {
			return nil, err
		}
		for _, row := range page.Rows {
			if row.TeamID != "" {
				ids = append(ids, row.TeamID)
			}
		}
		if len(page.Rows) < orgPage {
			break
		}
	}
	return ids, nil
}

// LastRun returns the latest job_runs row for a service's job.
func (s AppwriteStore) LastRun(service, job string) (Run, bool, error) {
	page, err := appwrite.List[Run](s.Ctx, RunsTable,
		appwrite.Equal("service", service),
		appwrite.Equal("job", job),
		appwrite.OrderDesc("started_at"),
		appwrite.Limit(1))
	if err != nil {
		return Run{}, false, err
	}
	if len(page.Rows) == 0 {
		return Run{}, false, nil
	}
	return page.Rows[0], true, nil
}

// Record appends a job_runs row with no row permissions, so only the server
// key can read it.
func (s AppwriteStore) Record(run Run) error {
	_, err := appwrite.Create[map[string]any](s.Ctx, RunsTable, RunData(run), []string{})
	return err
}

// RunData is the job_runs row for a run.
func RunData(run Run) map[string]any {
	return map[string]any{
		"service":       run.Service,
		"job":           run.Job,
		"started_at":    run.StartedAt.UTC().Format(time.RFC3339),
		"finished_at":   run.FinishedAt.UTC().Format(time.RFC3339),
		"status":        run.Status,
		"organisations": run.Organisations,
		"failed_orgs":   run.FailedOrgs,
		"backlog":       run.Backlog,
		"changed":       run.Changed,
		"skipped":       run.Skipped,
		"resume_after":  run.ResumeAfter,
		"error":         run.Error,
	}
}

// Purge deletes up to limit rows of a tenant table for one organisation whose
// column holds a time before cutoff, narrowed by any extra queries. A row that
// is already gone is not an error, so overlapping runs are harmless. The table
// must have an organization_id column.
func Purge(ctx openruntimes.Context, table, orgID, column string, cutoff time.Time, limit int, extra ...string) (Tally, error) {
	var tally Tally
	queries := append([]string{
		appwrite.Equal("organization_id", orgID),
		appwrite.LessThan(column, cutoff.UTC().Format(time.RFC3339)),
	}, extra...)
	for tally.Changed+tally.Skipped < limit {
		size := min(purgePage, limit-tally.Changed-tally.Skipped)
		page, err := appwrite.List[struct {
			ID string `json:"$id"`
		}](ctx, table, append(queries, appwrite.Limit(size))...)
		if err != nil {
			return tally, err
		}
		for _, row := range page.Rows {
			if err := appwrite.Delete(ctx, table, row.ID); err != nil {
				var he *httpx.Error
				if errors.As(err, &he) && he.Status == 404 {
					tally.Skipped++
					continue
				}
				return tally, err
			}
			tally.Changed++
		}
		if len(page.Rows) < size {
			return tally, nil
		}
	}
	tally.More = true
	return tally, nil
}

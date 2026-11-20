package orgstatus

import (
	"github.com/open-runtimes/types-for-go/v4/openruntimes"

	"github.com/ModdingFriendly/appwrite-library/appwrite"
)

const organizationsTable = "organizations"

// AppwriteStore reads the organisation row with the execution's server key.
type AppwriteStore struct {
	Ctx openruntimes.Context
}

// State reads status and deleted_at from the organisation's row.
func (s AppwriteStore) State(teamID string) (State, bool, error) {
	page, err := appwrite.List[struct {
		Status    string `json:"status"`
		DeletedAt string `json:"deleted_at"`
	}](s.Ctx, organizationsTable,
		appwrite.Equal("team_id", teamID),
		appwrite.Limit(1))
	if err != nil {
		return State{}, false, err
	}
	if len(page.Rows) == 0 {
		return State{}, false, nil
	}
	row := page.Rows[0]
	return State{Status: row.Status, DeletedAt: row.DeletedAt}, true, nil
}

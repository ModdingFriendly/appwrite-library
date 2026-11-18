package plans

import (
	"time"

	"github.com/open-runtimes/types-for-go/v4/openruntimes"

	"github.com/ModdingFriendly/appwrite-library/appwrite"
)

const (
	accountsTable = "billing_accounts"
	plansTable    = "plans"
	ticketsTable  = "tickets"
	messagesTable = "messages"
	usageTable    = "usage"
)

// AppwriteStore reads plans with the execution's server key.
type AppwriteStore struct {
	Ctx openruntimes.Context
}

type planRow struct {
	ID                 string `json:"$id"`
	MaxUsers           int    `json:"max_users"`
	MaxTicketsPerMonth int    `json:"max_tickets_per_month"`
	MaxSMSPerMonth     int    `json:"max_sms_per_month"`
	MaxStorageMB       int    `json:"max_storage_mb"`
}

// Limits reads the organisation's billing_accounts row and the plans row it
// names, by id first and then by Stripe price.
func (s AppwriteStore) Limits(orgID string) (Limits, bool, error) {
	accounts, err := appwrite.List[struct {
		Plan          string `json:"plan"`
		StripePriceID string `json:"stripe_price_id"`
	}](s.Ctx, accountsTable, appwrite.Equal("organization_id", orgID), appwrite.Limit(1))
	if err != nil {
		return Limits{}, false, err
	}
	if len(accounts.Rows) == 0 {
		return Limits{}, false, nil
	}
	account := accounts.Rows[0]
	lookups := [][]string{}
	if account.Plan != "" {
		lookups = append(lookups, []string{appwrite.Equal("$id", account.Plan)})
	}
	if account.StripePriceID != "" {
		lookups = append(lookups, []string{appwrite.Equal("stripe_price_id", account.StripePriceID)})
	}
	for _, queries := range lookups {
		page, err := appwrite.List[planRow](s.Ctx, plansTable, append(queries, appwrite.Limit(1))...)
		if err != nil {
			return Limits{}, false, err
		}
		if len(page.Rows) > 0 {
			row := page.Rows[0]
			return Limits{
				Plan:               row.ID,
				MaxUsers:           row.MaxUsers,
				MaxTicketsPerMonth: row.MaxTicketsPerMonth,
				MaxSMSPerMonth:     row.MaxSMSPerMonth,
				MaxStorageMB:       row.MaxStorageMB,
			}, true, nil
		}
	}
	return Limits{}, false, nil
}

// TicketsThisMonth counts the organisation's tickets created since the start
// of now's month.
func TicketsThisMonth(ctx openruntimes.Context, orgID string, now time.Time) Counter {
	return countRows(ctx, ticketsTable,
		appwrite.Equal("organization_id", orgID),
		appwrite.GreaterThanEqual("$createdAt", MonthStart(now).Format(time.RFC3339)))
}

// SMSThisMonth counts the organisation's outbound SMS messages since the start
// of now's month.
func SMSThisMonth(ctx openruntimes.Context, orgID string, now time.Time) Counter {
	return countRows(ctx, messagesTable,
		appwrite.Equal("organization_id", orgID),
		appwrite.Equal("channel", "sms"),
		appwrite.Equal("direction", "outbound"),
		appwrite.GreaterThanEqual("$createdAt", MonthStart(now).Format(time.RFC3339)))
}

// StoredMB is the organisation's latest storage_mb usage snapshot.
func StoredMB(ctx openruntimes.Context, orgID string) Counter {
	return func() (float64, error) {
		page, err := appwrite.List[struct {
			Quantity float64 `json:"quantity"`
		}](ctx, usageTable,
			appwrite.Equal("organization_id", orgID),
			appwrite.Equal("metric", "storage_mb"),
			appwrite.OrderDesc("period_start"),
			appwrite.Limit(1))
		if err != nil {
			return 0, err
		}
		if len(page.Rows) == 0 {
			return 0, nil
		}
		return page.Rows[0].Quantity, nil
	}
}

func countRows(ctx openruntimes.Context, table string, queries ...string) Counter {
	return func() (float64, error) {
		page, err := appwrite.List[struct {
			ID string `json:"$id"`
		}](ctx, table, append(queries, appwrite.Limit(1))...)
		if err != nil {
			return 0, err
		}
		return float64(page.Total), nil
	}
}

// Package plans enforces Reparix plan limits on the server (PAR-1304).
//
// An organisation's plan comes from its billing_accounts row: the row's plan
// names a plans row by id, or, failing that, by its Stripe price. The plan sets
// four limits, where zero or less means unlimited:
//
//   - max_users: staff seats, counted as team memberships including pending
//     invitations;
//   - max_tickets_per_month: tickets created since the start of the calendar
//     month (UTC);
//   - max_sms_per_month: outbound SMS messages since the start of the month;
//   - max_storage_mb: stored files, in MB.
//
// Grace: a limit only refuses a create that would take the organisation past
// it. An organisation already over a limit, for example after a downgrade, keeps
// reading and editing what it has; only new rows of that kind are refused.
// An organisation with no billing account or no matching plan is not limited,
// and a failure to read the plan or the usage lets the create through and logs
// it, so a billing outage never stops a shop from booking in a repair.
//
// A refusal is an *httpx.Error with status 402 and code "plan_limit_reached",
// whose Params name the metric, the usage, the limit and the plan.
package plans

import (
	"fmt"
	"time"

	"github.com/ModdingFriendly/appwrite-library/httpx"
)

// Code is the error code of a refused create.
const Code = "plan_limit_reached"

// Metric is a limited resource.
type Metric string

const (
	Users           Metric = "users"
	TicketsPerMonth Metric = "tickets_per_month"
	SMSPerMonth     Metric = "sms_per_month"
	StorageMB       Metric = "storage_mb"
)

// Limits are the limits of an organisation's plan. Zero or less is unlimited.
type Limits struct {
	Plan               string `json:"plan"`
	MaxUsers           int    `json:"max_users"`
	MaxTicketsPerMonth int    `json:"max_tickets_per_month"`
	MaxSMSPerMonth     int    `json:"max_sms_per_month"`
	MaxStorageMB       int    `json:"max_storage_mb"`
}

// For returns the limit of a metric, zero when it is unlimited or unknown.
func (l Limits) For(metric Metric) int {
	var limit int
	switch metric {
	case Users:
		limit = l.MaxUsers
	case TicketsPerMonth:
		limit = l.MaxTicketsPerMonth
	case SMSPerMonth:
		limit = l.MaxSMSPerMonth
	case StorageMB:
		limit = l.MaxStorageMB
	}
	if limit < 0 {
		return 0
	}
	return limit
}

// Store reads an organisation's plan.
type Store interface {
	// Limits returns the limits of the organisation's plan, and false when it
	// has no billing account or the account names no known plan.
	Limits(orgID string) (Limits, bool, error)
}

// Counter returns how much of a metric the organisation uses now.
type Counter func() (float64, error)

// Check refuses adding more of a metric when used plus adding would exceed the
// limit. A limit of zero never refuses.
func Check(limits Limits, metric Metric, used, adding float64) error {
	limit := limits.For(metric)
	if limit <= 0 || used+adding <= float64(limit) {
		return nil
	}
	return &httpx.Error{
		Status:  402,
		Code:    Code,
		Message: message(metric, limit),
		Params: map[string]any{
			"metric": string(metric),
			"used":   used,
			"limit":  limit,
			"plan":   limits.Plan,
		},
	}
}

// Enforce checks one create for an organisation: it reads the plan, and only
// when the metric is limited counts the usage. adding is how much the create
// adds (1 for a row, the file size in MB for an upload). It returns the refusal
// or nil; a failure to read the plan or the usage is logged and allowed.
func Enforce(store Store, orgID string, metric Metric, adding float64, count Counter, log func(string)) error {
	limits, found, err := store.Limits(orgID)
	if err != nil {
		logf(log, "plans: could not read the plan of %s; allowing %s", orgID, metric)
		return nil
	}
	if !found || limits.For(metric) <= 0 {
		return nil
	}
	used, err := count()
	if err != nil {
		logf(log, "plans: could not count %s for %s; allowing", metric, orgID)
		return nil
	}
	return Check(limits, metric, used, adding)
}

// MonthStart is the start of now's calendar month in UTC, the window of the
// monthly limits.
func MonthStart(now time.Time) time.Time {
	now = now.UTC()
	return time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
}

func message(metric Metric, limit int) string {
	switch metric {
	case Users:
		return fmt.Sprintf("Your plan allows %d team members. Upgrade your plan to add more.", limit)
	case TicketsPerMonth:
		return fmt.Sprintf("Your plan allows %d repairs a month. Upgrade your plan to book in more this month.", limit)
	case SMSPerMonth:
		return fmt.Sprintf("Your plan allows %d text messages a month. Upgrade your plan to send more this month.", limit)
	case StorageMB:
		return fmt.Sprintf("Your plan allows %d MB of file storage. Upgrade your plan or delete files to upload more.", limit)
	}
	return "Your plan limit has been reached. Upgrade your plan to continue."
}

func logf(log func(string), format string, args ...any) {
	if log != nil {
		log(fmt.Sprintf(format, args...))
	}
}

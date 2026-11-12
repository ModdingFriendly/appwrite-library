package activity

import (
	"context"
	"errors"
	"strings"
)

// ErrNotWritable reports an event that must not be stored: it has no verified
// organisation, no usable event name, or a source outside the shared set.
var ErrNotWritable = errors.New("activity event is not writable")

// Writer appends one activity row to the ledger.
//
// It receives the sanitised column map and the read-only staff ACL for the
// event's organisation, so the consumer owns only the transport. A writer must
// not retry, and must return an error instead of panicking.
type Writer func(ctx context.Context, data map[string]any, permissions []string) error

// Record appends one event to the ledger on a best-effort basis.
//
// The returned error is noise for the caller's private log: an activity write
// must never fail, retry or roll back the business mutation it describes.
// Callers log the error and carry on, exactly like the handler that produced
// the event. A nil writer means "not configured" and is a no-op, never an
// implicit live call.
func Record(ctx context.Context, writer Writer, event Event) error {
	if writer == nil {
		return nil
	}
	data, ok := event.Payload()
	if !ok {
		return ErrNotWritable
	}
	return writer(ctx, data, RowPermissions(event.OrganizationID))
}

// RowPermissions is the read-only staff ACL for one activity row.
//
// There is no update, delete or write grant, and no customer, guest, `users`
// or `any` grant: the feed is staff-only and a client can never edit the
// ledger. An invalid organisation yields no grant at all.
func RowPermissions(teamID string) []string {
	team := strings.TrimSpace(teamID)
	if !organizationIDPattern.MatchString(team) {
		return []string{}
	}
	return []string{
		`read("team:` + team + `/admin")`,
		`read("team:` + team + `/technician")`,
	}
}

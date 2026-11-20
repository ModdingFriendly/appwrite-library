// Package orgstatus refuses requests for organisations a platform operator has
// suspended or deleted (PAR-1301).
//
// Every Reparix service calls Require from its auth boundary, after the
// caller's membership is verified and before any tenant work, so a suspended
// organisation is refused by the server and not only hidden in the UI. The
// status lives on the organisation's `organizations` row (keyed by team_id):
//
//   - "active", empty or missing: allowed;
//   - "suspended": 403 organization_suspended;
//   - "deleted", or any row with deleted_at set: 403 organization_closed.
//
// An organisation with no row is allowed here; whether an unprovisioned team
// may write tenant data is the tenant package's rule, not this one.
//
// Lookups are cached per team for TTL (30 seconds by default) in the warm
// runtime, so a suspension takes effect within a minute without adding a
// database read to every request. When a read fails, the last known status is
// used if there is one; otherwise the request fails with 503 rather than
// silently skipping the check.
package orgstatus

import (
	"strings"
	"sync"
	"time"

	"github.com/ModdingFriendly/appwrite-library/httpx"
)

const (
	// CodeSuspended is the error code for a suspended organisation.
	CodeSuspended = "organization_suspended"
	// CodeClosed is the error code for a deleted organisation.
	CodeClosed = "organization_closed"
	// CodeUnavailable is the error code when the status cannot be read.
	CodeUnavailable = "organization_status_unavailable"

	StatusActive    = "active"
	StatusSuspended = "suspended"
	StatusDeleted   = "deleted"

	// DefaultTTL keeps a suspension effective within the one-minute target.
	DefaultTTL = 30 * time.Second
)

// State is an organisation's stored status.
type State struct {
	Status    string
	DeletedAt string
}

// Effective returns the status the check enforces: deleted when deleted_at is
// set, otherwise the stored status, with empty meaning active.
func (s State) Effective() string {
	if strings.TrimSpace(s.DeletedAt) != "" {
		return StatusDeleted
	}
	switch strings.ToLower(strings.TrimSpace(s.Status)) {
	case StatusSuspended:
		return StatusSuspended
	case StatusDeleted:
		return StatusDeleted
	default:
		return StatusActive
	}
}

// Store reads an organisation's status by team id.
type Store interface {
	// State returns the organisation's status, and false when it has no row.
	State(teamID string) (State, bool, error)
}

// Checker enforces organisation status with a short per-team cache. The zero
// value is not usable; build one with New. A Checker is safe for concurrent use.
type Checker struct {
	ttl   time.Duration
	now   func() time.Time
	mu    sync.Mutex
	cache map[string]entry
}

type entry struct {
	status string
	at     time.Time
}

// New returns a Checker that caches each team's status for ttl. A ttl of zero
// or less disables caching.
func New(ttl time.Duration) *Checker {
	return &Checker{ttl: ttl, now: time.Now, cache: map[string]entry{}}
}

// Default is the process-wide checker services use, so the cache survives
// between executions on a warm runtime.
var Default = New(DefaultTTL)

// Require returns nil when the organisation may be used, or the refusal.
func Require(store Store, teamID string) error {
	return Default.Require(store, teamID)
}

// Require returns nil when the organisation may be used, or the refusal.
func (c *Checker) Require(store Store, teamID string) error {
	teamID = strings.TrimSpace(teamID)
	if teamID == "" {
		return httpx.Unauthorized("organization header required", nil)
	}
	status, err := c.status(store, teamID)
	if err != nil {
		return err
	}
	return Refusal(status)
}

// Refusal maps an effective status to the error a service returns.
func Refusal(status string) error {
	switch status {
	case StatusSuspended:
		return &httpx.Error{
			Status:  403,
			Code:    CodeSuspended,
			Message: "This account is suspended. Contact Reparix support to restore access.",
		}
	case StatusDeleted:
		return &httpx.Error{
			Status:  403,
			Code:    CodeClosed,
			Message: "This account has been closed.",
		}
	}
	return nil
}

// Forget drops a team's cached status, for the service that just changed it.
func (c *Checker) Forget(teamID string) {
	c.mu.Lock()
	delete(c.cache, strings.TrimSpace(teamID))
	c.mu.Unlock()
}

func (c *Checker) status(store Store, teamID string) (string, error) {
	now := c.now()
	c.mu.Lock()
	cached, ok := c.cache[teamID]
	c.mu.Unlock()
	if ok && c.ttl > 0 && now.Sub(cached.at) < c.ttl {
		return cached.status, nil
	}
	if store == nil {
		return "", unavailable()
	}
	state, found, err := store.State(teamID)
	if err != nil {
		if ok {
			// A stale answer beats refusing every request during a blip.
			return cached.status, nil
		}
		return "", unavailable()
	}
	status := StatusActive
	if found {
		status = state.Effective()
	}
	if c.ttl > 0 {
		c.mu.Lock()
		c.cache[teamID] = entry{status: status, at: now}
		c.mu.Unlock()
	}
	return status, nil
}

func unavailable() error {
	return &httpx.Error{
		Status:  503,
		Code:    CodeUnavailable,
		Message: "We could not confirm this account's status. Try again in a moment.",
	}
}

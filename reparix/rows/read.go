package rows

import (
	"strings"

	"github.com/ModdingFriendly/appwrite-library/appwrite"
	"github.com/ModdingFriendly/appwrite-library/httpx"
	"github.com/ModdingFriendly/appwrite-library/reparix/tenant"
)

// ReadPolicy is the consumer-supplied policy for one readable table.
//
// The consumer owns the table list and the role check; the engine owns the
// tenant filter, the query/window/projection bounds and the response recheck.
type ReadPolicy struct {
	// Table is the Appwrite table id. ReadPolicySet.Admit fills it from the map
	// key when empty.
	Table string
	// Global marks a table without an organization_id column. It is the only
	// case where no tenant filter is injected and no row recheck is applied.
	Global bool
	// Allow is an explicit metadata projection. A non-nil slice makes every
	// column not named here unreadable (including on a client select); nil
	// leaves the table's business columns readable, subject to Deny and the
	// global credential deny list.
	Allow []string
	// Deny names columns that must never leave the server for this table, even
	// when a widened query returns them.
	Deny []string
}

// ReadPolicySet is the subset of tables one consumer exposes. Unknown tables
// fail closed. Denied names an explicit refusal reason for tables that exist
// but must never be read through the gateway.
type ReadPolicySet struct {
	Tables map[string]ReadPolicy
	Denied map[string]string
}

// Admit resolves table against the supplied policy set. It is fail closed: an
// empty table is 400, a denied table is 403 with the consumer's reason, and an
// absent table is 403.
func (set ReadPolicySet) Admit(table string) (ReadPolicy, error) {
	table = strings.TrimSpace(table)
	if table == "" {
		return ReadPolicy{}, httpx.BadRequest("table_id is required", map[string]any{"field": "table_id"})
	}
	if reason, denied := set.Denied[table]; denied {
		return ReadPolicy{}, httpx.Forbidden("table is not readable through the read gateway", map[string]any{
			"table":  table,
			"reason": reason,
		})
	}
	policy, ok := set.Tables[table]
	if !ok {
		return ReadPolicy{}, httpx.Forbidden("table is not readable through the read gateway", map[string]any{
			"table": table,
		})
	}
	if policy.Table == "" {
		policy.Table = table
	}
	return policy, nil
}

// ReadPlan is the validated, authoritative read produced by ReadEngine.Prepare.
// Queries already contains the tenant filter, the caller's safe queries, the
// projection and the bounded window, in that order. The consumer executes it
// and then passes the returned rows to Apply.
type ReadPlan struct {
	Table  string
	TeamID string
	Policy ReadPolicy
	// Queries is the server-owned query list. Never append client input after
	// Prepare; the tenant filter must stay first.
	Queries []string
	Limit   int
	Offset  int
	// Select is the validated client projection, before organization_id is
	// added to the Appwrite select query.
	Select []string
}

// ReadEngine applies consumer-supplied read policies to a request.
type ReadEngine struct {
	Policies ReadPolicySet
}

// Prepare validates the request and builds the authoritative read plan: table
// admission, tenant identity, client queries, one bounded window, the
// projection and the tenant filter. It performs no I/O.
func (e ReadEngine) Prepare(teamID string, req *ReadRequest) (*ReadPlan, error) {
	if req == nil {
		return nil, httpx.BadRequest("request body is required", nil)
	}
	if !tenant.ValidID(teamID) {
		return nil, httpx.Forbidden("verified caller identity is invalid", nil)
	}
	policy, err := e.Policies.Admit(req.TableID)
	if err != nil {
		return nil, err
	}

	clientQueries, queryLimit, queryOffset, err := ValidateReadQueries(req.Queries)
	if err != nil {
		return nil, err
	}
	limit, offset, err := ResolveReadWindow(req.Limit, req.Offset, queryLimit, queryOffset)
	if err != nil {
		return nil, err
	}
	selectFields, err := NormalizeReadSelect(req.Select)
	if err != nil {
		return nil, err
	}
	if err := ValidateSelect(selectFields, policy.Allow, policy.Deny); err != nil {
		return nil, err
	}

	queries := make([]string, 0, len(clientQueries)+4)
	if !policy.Global {
		// The authoritative tenant filter. Never derived from the request.
		queries = append(queries, TenantFilter(teamID))
	}
	queries = append(queries, clientQueries...)
	if len(selectFields) > 0 {
		queries = append(queries, SelectQuery(selectFields, !policy.Global))
	}
	queries = append(queries, appwrite.Limit(limit), appwrite.Offset(offset))

	return &ReadPlan{
		Table:   policy.Table,
		TeamID:  teamID,
		Policy:  policy,
		Queries: queries,
		Limit:   limit,
		Offset:  offset,
		Select:  selectFields,
	}, nil
}

// PrepareRead is the package-level form of ReadEngine.Prepare.
func PrepareRead(set ReadPolicySet, teamID string, req *ReadRequest) (*ReadPlan, error) {
	return ReadEngine{Policies: set}.Prepare(teamID, req)
}

// Apply rechecks and sanitises the rows returned by Appwrite. Rows outside the
// verified tenant are dropped and counted; they must never be returned. System
// ACL/sequence fields and non-readable columns are removed in place. The
// returned slice is always non-nil so a page marshals as [] rather than null.
func (p *ReadPlan) Apply(rows []map[string]any) (kept []map[string]any, dropped int) {
	if p == nil {
		return []map[string]any{}, 0
	}
	if !p.Policy.Global {
		rows, dropped = FilterTenantRows(rows, p.TeamID)
	} else if rows == nil {
		rows = []map[string]any{}
	}
	for _, row := range rows {
		StripSystemFields(row)
		ProjectRow(row, p.Policy.Allow, p.Policy.Deny)
	}
	return rows, dropped
}

// RequireRowTenant is the defence-in-depth recheck before an update or delete.
// A missing row, an empty tenant and a cross-tenant row all return the same
// 404, so the check cannot be used as a cross-tenant existence oracle.
func RequireRowTenant(table string, row map[string]any, teamID string) error {
	if row == nil || !tenant.CheckRowTenant(row, teamID) {
		return httpx.NotFound("row not found", map[string]any{"table": table})
	}
	return nil
}

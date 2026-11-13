package rows

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"

	"github.com/appwrite/sdk-for-go/query"

	"github.com/ModdingFriendly/appwrite-library/appwrite"
	"github.com/ModdingFriendly/appwrite-library/httpx"
	"github.com/ModdingFriendly/appwrite-library/reparix/tenant"
)

// neverReadable is credential material no read may return, regardless of
// table. Per-table projections are the primary control; this deny list is the
// defence-in-depth net for a new column, a widened query or a table added
// without a projection.
var neverReadable = []string{
	"api_key", "secret", "secret_hash", "token", "token_hash",
	"password_hash", "password_fingerprint", "private_key",
	"webhook_secret", "signing_secret",
}

// NeverReadableFields returns a copy of the global credential deny list.
func NeverReadableFields() []string { return append([]string(nil), neverReadable...) }

func fieldSet(names ...string) map[string]struct{} {
	set := make(map[string]struct{}, len(names))
	for _, n := range names {
		set[n] = struct{}{}
	}
	return set
}

var neverReadableSet = fieldSet(neverReadable...)

// MetadataFields is the common projection prefix for sensitive tables: system
// metadata plus the tenant column the response recheck needs.
func MetadataFields(extra ...string) []string {
	return append([]string{"$id", "$createdAt", "$updatedAt", "$tableId", "$databaseId", tenant.OrganizationField}, extra...)
}

// ReadRequest is the strict body of a row-list read. Limit and Offset are
// pointers so "absent" differs from an explicit 0 and a value supplied twice
// (body plus query) can be rejected.
type ReadRequest struct {
	TableID string   `json:"table_id"`
	Queries []string `json:"queries,omitempty"`
	Select  []string `json:"select,omitempty"`
	Limit   *int     `json:"limit,omitempty"`
	Offset  *int     `json:"offset,omitempty"`
}

// ParseReadRequest strictly decodes a request body: non-empty, at most
// MaxReadBodyBytes, no unknown fields, exactly one JSON object.
func ParseReadRequest(body []byte) (*ReadRequest, error) {
	if len(bytes.TrimSpace(body)) == 0 {
		return nil, httpx.BadRequest("request body is required", nil)
	}
	if len(body) > MaxReadBodyBytes {
		return nil, httpx.BadRequest("request body is too large", map[string]any{"max_bytes": MaxReadBodyBytes})
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	var req ReadRequest
	if err := dec.Decode(&req); err != nil {
		return nil, httpx.BadRequest("invalid request body", map[string]any{"detail": err.Error()})
	}
	if err := dec.Decode(new(json.RawMessage)); err != io.EOF {
		return nil, httpx.BadRequest("request body must contain exactly one JSON object", nil)
	}
	return &req, nil
}

// readQuery is the Appwrite TablesDB query wire shape.
type readQuery struct {
	Method    string            `json:"method"`
	Attribute string            `json:"attribute"`
	Values    []json.RawMessage `json:"values"`
}

// ValidateReadQueries rejects any client query that could move or widen the
// tenant filter, caps the list, and pulls limit(...)/offset(...) out so the
// server enforces one authoritative window. The organization_id check is
// deliberately blunt: a case-insensitive substring match on the raw string.
func ValidateReadQueries(raw []string) ([]string, *int, *int, error) {
	if len(raw) > MaxReadQueries {
		return nil, nil, nil, httpx.BadRequest("too many queries", map[string]any{"max": MaxReadQueries})
	}
	queries := make([]string, 0, len(raw))
	var qLimit, qOffset *int
	for _, entry := range raw {
		trimmed := strings.TrimSpace(entry)
		if trimmed == "" {
			return nil, nil, nil, httpx.BadRequest("query must not be empty", map[string]any{"field": "queries"})
		}
		if len(trimmed) > MaxReadQueryBytes {
			return nil, nil, nil, httpx.BadRequest("query is too long", map[string]any{"field": "queries", "max": MaxReadQueryBytes})
		}
		if strings.Contains(strings.ToLower(trimmed), tenant.OrganizationField) {
			return nil, nil, nil, httpx.BadRequest(
				"queries must not reference organization_id; the tenant filter is applied by the server",
				map[string]any{"field": "queries"})
		}
		var parsed readQuery
		if err := json.Unmarshal([]byte(trimmed), &parsed); err != nil || strings.TrimSpace(parsed.Method) == "" {
			return nil, nil, nil, httpx.BadRequest("query must be an Appwrite query object", map[string]any{"field": "queries"})
		}
		// Also check the decoded attribute: a JSON-escaped spelling must not
		// sneak past the raw substring guard.
		if strings.EqualFold(strings.TrimSpace(parsed.Attribute), tenant.OrganizationField) {
			return nil, nil, nil, httpx.BadRequest(
				"queries must not reference organization_id; the tenant filter is applied by the server",
				map[string]any{"field": "queries"})
		}
		switch parsed.Method {
		case "limit", "offset":
			value, err := readQueryInt(parsed)
			if err != nil {
				return nil, nil, nil, err
			}
			if parsed.Method == "limit" {
				if qLimit != nil {
					return nil, nil, nil, httpx.BadRequest("limit supplied more than once", map[string]any{"field": "limit"})
				}
				qLimit = &value
			} else {
				if qOffset != nil {
					return nil, nil, nil, httpx.BadRequest("offset supplied more than once", map[string]any{"field": "offset"})
				}
				qOffset = &value
			}
			continue
		case "select":
			return nil, nil, nil, httpx.BadRequest("select must be sent in the request body, not as a query", map[string]any{"field": "select"})
		}
		queries = append(queries, trimmed)
	}
	return queries, qLimit, qOffset, nil
}

func readQueryInt(parsed readQuery) (int, error) {
	if len(parsed.Values) != 1 {
		return 0, httpx.BadRequest("query pagination value is invalid", map[string]any{"field": "queries"})
	}
	var value int
	if err := json.Unmarshal(parsed.Values[0], &value); err != nil {
		return 0, httpx.BadRequest("query pagination value must be an integer", map[string]any{"field": "queries"})
	}
	if value < -1000000 || value > 1000000 {
		value = 1000000
	}
	return value, nil
}

// ResolveReadWindow enforces exactly one pagination window: body fields are
// the supported form, a query copy is accepted only when the body omits it,
// supplying both is a 400. Limit clamps to MaxReadLimit, offset to MaxReadOffset.
func ResolveReadWindow(bodyLimit, bodyOffset, queryLimit, queryOffset *int) (int, int, error) {
	if bodyLimit != nil && queryLimit != nil {
		return 0, 0, httpx.BadRequest("limit supplied through both the body and a query", map[string]any{"field": "limit"})
	}
	if bodyOffset != nil && queryOffset != nil {
		return 0, 0, httpx.BadRequest("offset supplied through both the body and a query", map[string]any{"field": "offset"})
	}
	limit := DefaultReadLimit
	if src := firstInt(bodyLimit, queryLimit); src != nil {
		limit = *src
	}
	if limit < 1 {
		return 0, 0, httpx.BadRequest("limit must be at least 1", map[string]any{"field": "limit", "min": 1})
	}
	if limit > MaxReadLimit {
		limit = MaxReadLimit
	}
	offset := 0
	if src := firstInt(bodyOffset, queryOffset); src != nil {
		offset = *src
	}
	if offset < 0 {
		return 0, 0, httpx.BadRequest("offset must not be negative", map[string]any{"field": "offset", "min": 0})
	}
	if offset > MaxReadOffset {
		offset = MaxReadOffset
	}
	return limit, offset, nil
}

func firstInt(a, b *int) *int {
	if a != nil {
		return a
	}
	return b
}

// NormalizeReadSelect validates the projection: bounded, no empty names, no
// system ($) attributes, duplicates collapsed.
func NormalizeReadSelect(fields []string) ([]string, error) {
	if len(fields) == 0 {
		return nil, nil
	}
	if len(fields) > MaxReadSelectFields {
		return nil, httpx.BadRequest("too many select fields", map[string]any{"max": MaxReadSelectFields})
	}
	seen := make(map[string]struct{}, len(fields))
	out := make([]string, 0, len(fields))
	for _, field := range fields {
		trimmed := strings.TrimSpace(field)
		if trimmed == "" {
			return nil, httpx.BadRequest("select field must not be empty", map[string]any{"field": "select"})
		}
		if len(trimmed) > MaxReadSelectFieldBytes {
			return nil, httpx.BadRequest("select field is too long", map[string]any{"field": "select"})
		}
		if strings.HasPrefix(trimmed, "$") {
			return nil, httpx.BadRequest("system fields cannot be selected", map[string]any{"field": trimmed})
		}
		if _, dup := seen[trimmed]; dup {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	return out, nil
}

// TenantFilter is the authoritative server-side tenant query. Put it first in
// every tenant-table list.
func TenantFilter(teamID string) string { return appwrite.Equal(tenant.OrganizationField, teamID) }

// SelectQuery builds a select query from validated field names, adding
// organization_id when missing so FilterTenantRows can still prove tenancy.
func SelectQuery(fields []string, tenantTable bool) string {
	if tenantTable && !containsString(fields, tenant.OrganizationField) {
		fields = append(append([]string(nil), fields...), tenant.OrganizationField)
	}
	values := make([]any, len(fields))
	for i, f := range fields {
		values[i] = f
	}
	return query.Select(values)
}

// FilterTenantRows drops every row whose organization_id is not teamID and
// reports how many were dropped. Callers must never return the dropped rows.
func FilterTenantRows(rows []map[string]any, teamID string) (kept []map[string]any, dropped int) {
	kept = make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		if !tenant.CheckRowTenant(row, teamID) {
			dropped++
			continue
		}
		kept = append(kept, row)
	}
	return kept, dropped
}

// StripSystemFields removes $permissions and $sequence from a row.
func StripSystemFields(row map[string]any) {
	delete(row, "$permissions")
	delete(row, "$sequence")
}

// ValidateSelect rejects selected fields that are on the global credential deny
// list, on deny, or (when allow is non-nil) not in allow.
func ValidateSelect(fields, allow, deny []string) error {
	allowed, denied := fieldSet(allow...), fieldSet(deny...)
	for _, field := range fields {
		_, never := neverReadableSet[field]
		_, isDenied := denied[field]
		unreadable := false
		if allow != nil {
			_, ok := allowed[field]
			unreadable = !ok
		}
		if never || isDenied || unreadable {
			return httpx.BadRequest("field is not readable", map[string]any{"field": field})
		}
	}
	return nil
}

// ProjectRow removes credential, denied and (when allow is non-nil) non-allowed
// columns from row in place and reports how many were removed.
func ProjectRow(row map[string]any, allow, deny []string) int {
	allowed, denied := fieldSet(allow...), fieldSet(deny...)
	withheld := 0
	for key := range row {
		_, never := neverReadableSet[key]
		_, isDenied := denied[key]
		drop := never || isDenied
		if !drop && allow != nil {
			_, ok := allowed[key]
			drop = !ok
		}
		if drop {
			delete(row, key)
			withheld++
		}
	}
	return withheld
}

func containsString(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

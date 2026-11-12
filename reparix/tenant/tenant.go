// Package tenant holds the Reparix tenant primitives shared by every Function:
// the canonical organisation header, the Appwrite id shape, the provisioned
// organisation registry check and same-tenant row reference validation.
//
// It is policy-light and transport-free: it imports no OpenRuntimes or
// Function packages. Headers are passed as a plain map so any runtime adapter
// (OpenRuntimes, a gateway, a test) can feed it.
package tenant

import (
	"context"
	"regexp"
	"strings"

	"github.com/ModdingFriendly/appwrite-library/httpx"
)

// OrganizationHeader is the canonical tenant claim. Clients may set it; it is
// never trusted without a verified, confirmed membership in that team.
const OrganizationHeader = "x-reparix-organization-id"

// OrganizationField is the tenant column present on every tenant table.
const OrganizationField = "organization_id"

var idPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,35}$`)

// ValidID reports whether s has the shape of an Appwrite team/user/row id.
func ValidID(s string) bool { return idPattern.MatchString(s) }

// Header reads a header case-insensitively and trims it. Missing is "".
func Header(headers map[string]string, name string) string {
	if value, ok := headers[name]; ok {
		return strings.TrimSpace(value)
	}
	for key, value := range headers {
		if strings.EqualFold(key, name) {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

// ClaimedOrganization returns the untrusted organisation claim from the
// canonical header. It must be verified against a membership before use.
func ClaimedOrganization(headers map[string]string) string {
	return Header(headers, OrganizationHeader)
}

// CheckBodyOrganization rejects a body organization_id that differs from the
// verified team. An empty body value is fine: the body is never the tenant.
func CheckBodyOrganization(verifiedTeamID, bodyOrganizationID string) error {
	body := strings.TrimSpace(bodyOrganizationID)
	if body != "" && body != verifiedTeamID {
		return httpx.Forbidden("organization_id does not match the authorized organisation", map[string]any{
			"field": OrganizationField,
		})
	}
	return nil
}

// Registry reports whether teamID is a provisioned organisation row, so a
// self-created Appwrite team alone cannot read or write business data.
type Registry func(ctx context.Context, teamID string) (bool, error)

// RequireRegistered fails closed: a nil registry is a 502 (the check cannot be
// made), a lookup error is returned as-is, and an unregistered or malformed
// team is a 403.
func RequireRegistered(ctx context.Context, teamID string, registry Registry) error {
	if registry == nil {
		return httpx.Upstream("organisation registration check is unavailable", nil)
	}
	if !ValidID(teamID) {
		return httpx.Forbidden("organisation is not provisioned", map[string]any{"field": OrganizationField})
	}
	registered, err := registry(ctx, teamID)
	if err != nil {
		return err
	}
	if !registered {
		return httpx.Forbidden("organisation is not provisioned", map[string]any{"field": OrganizationField})
	}
	return nil
}

// Ref is the minimal projection of a referenced row needed to prove tenancy.
type Ref struct {
	Table          string
	ID             string
	OrganizationID string
	// Fields optionally carries stored columns (status, flags) that workflow
	// checks need. It is never used to decide tenancy.
	Fields map[string]any
}

// RefFetcher loads a referenced row by table and id.
type RefFetcher func(ctx context.Context, table, rowID string) (*Ref, error)

// FetchSameTenant loads a referenced row and proves it belongs to teamID. A
// missing row, an empty tenant and a cross-tenant row all return the same 404,
// so the check cannot be used as a cross-tenant existence oracle. A nil
// fetcher fails closed with 502.
func FetchSameTenant(ctx context.Context, fetch RefFetcher, teamID, field, table, id string) (*Ref, error) {
	if fetch == nil {
		return nil, httpx.Upstream("row validation is unavailable", nil)
	}
	if !ValidID(id) {
		return nil, httpx.BadRequest("invalid row reference", map[string]any{"field": field})
	}
	row, err := fetch(ctx, table, id)
	if err != nil {
		return nil, err
	}
	if row == nil || row.ID == "" || row.OrganizationID == "" || row.OrganizationID != teamID {
		return nil, httpx.NotFound("referenced row not found", map[string]any{"field": field})
	}
	return row, nil
}

// CheckRowTenant is the response-side recheck for a decoded row.
func CheckRowTenant(row map[string]any, teamID string) bool {
	org, ok := row[OrganizationField].(string)
	return ok && org != "" && org == teamID
}

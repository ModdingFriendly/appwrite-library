package contract_test

// Cross-package contract tests for the Reparix authz and tenant packages. The
// authz package establishes the verified caller and the single tenant
// authority; every tenant check must use that verified team and must never
// accept an unverified or cross-tenant identity.

import (
	"context"
	"errors"
	"testing"

	"github.com/ModdingFriendly/appwrite-library/httpx"
	"github.com/ModdingFriendly/appwrite-library/reparix/authz"
	"github.com/ModdingFriendly/appwrite-library/reparix/tenant"
)

type stubLookup struct {
	identity      *authz.Identity
	identityErr   error
	membership    *authz.Membership
	membershipErr error
}

func (l *stubLookup) CurrentUser(context.Context, string) (*authz.Identity, error) {
	return l.identity, l.identityErr
}

func (l *stubLookup) Membership(context.Context, string, string, string) (*authz.Membership, error) {
	return l.membership, l.membershipErr
}

func verifiedLookup(roles ...string) *stubLookup {
	return &stubLookup{
		identity:   &authz.Identity{UserID: "u1"},
		membership: &authz.Membership{ID: "m1", UserID: "u1", TeamID: "t1", Roles: roles, Confirmed: true},
	}
}

func headers(jwt, team string) map[string]string {
	h := map[string]string{}
	if jwt != "" {
		h[authz.JWTHeader] = jwt
	}
	if team != "" {
		h[tenant.OrganizationHeader] = team
	}
	return h
}

func statusOf(t *testing.T, err error) int {
	t.Helper()
	var he *httpx.Error
	if !errors.As(err, &he) || he == nil {
		t.Fatalf("expected *httpx.Error, got %T: %v", err, err)
	}
	return he.Status
}

// TestVerifiedOwnerIsStillTenantScoped is the parity contract: the verified
// owner role authorises owner-level work, but the tenant authority is the
// verified team id, so the same owner cannot read or write another tenant.
func TestVerifiedOwnerIsStillTenantScoped(t *testing.T) {
	ctx := context.Background()
	caller, err := authz.Verify(ctx, headers("jwt-1", "t1"), verifiedLookup("owner"))
	if err != nil {
		t.Fatalf("verified owner rejected: %v", err)
	}
	teamID := caller.TeamID()
	if teamID != "t1" || caller.UserID() != "u1" {
		t.Fatalf("caller facts wrong: user=%q team=%q", caller.UserID(), teamID)
	}

	// Role matrix: owner grants owner work only.
	if err := authz.RequireAnyRole(caller, "owner"); err != nil {
		t.Fatalf("owner denied owner work: %v", err)
	}
	if s := statusOf(t, authz.RequireAnyRole(caller, "admin", "technician")); s != 403 {
		t.Fatalf("owner must not imply admin/technician, got %d", s)
	}

	// The body can confirm the verified tenant but never select another.
	if err := tenant.CheckBodyOrganization(teamID, "t1"); err != nil {
		t.Fatalf("matching body organisation rejected: %v", err)
	}
	if s := statusOf(t, tenant.CheckBodyOrganization(teamID, "t2")); s != 403 {
		t.Fatalf("forged body organisation must be 403, got %d", s)
	}

	// Only provisioned organisations pass the registry gate.
	registry := func(_ context.Context, id string) (bool, error) { return id == "t1", nil }
	if err := tenant.RequireRegistered(ctx, teamID, registry); err != nil {
		t.Fatalf("verified provisioned organisation rejected: %v", err)
	}
	if s := statusOf(t, tenant.RequireRegistered(ctx, "t2", registry)); s != 403 {
		t.Fatalf("unprovisioned organisation must be 403, got %d", s)
	}

	// Cross-tenant row recheck: a t2 row is a 404 even for a t1 owner.
	rows := map[string]*tenant.Ref{
		"c1": {Table: "customers", ID: "c1", OrganizationID: "t1"},
		"c2": {Table: "customers", ID: "c2", OrganizationID: "t2"},
	}
	fetch := func(_ context.Context, _, id string) (*tenant.Ref, error) { return rows[id], nil }

	if _, err := tenant.FetchSameTenant(ctx, fetch, teamID, "customer_id", "customers", "c1"); err != nil {
		t.Fatalf("own-tenant row rejected: %v", err)
	}
	if s := statusOf(t, mustErr(tenant.FetchSameTenant(ctx, fetch, teamID, "customer_id", "customers", "c2"))); s != 404 {
		t.Fatalf("cross-tenant row must be 404 for an owner, got %d", s)
	}
	if tenant.CheckRowTenant(map[string]any{tenant.OrganizationField: rows["c2"].OrganizationID}, teamID) {
		t.Fatal("cross-tenant row must fail the response-side recheck")
	}
	if !tenant.CheckRowTenant(map[string]any{tenant.OrganizationField: rows["c1"].OrganizationID}, teamID) {
		t.Fatal("own-tenant row must pass the response-side recheck")
	}
}

// TestUnverifiedCallerHasNoTenantAuthority proves every verification failure
// stops the caller before a team id exists to feed the tenant checks.
func TestUnverifiedCallerHasNoTenantAuthority(t *testing.T) {
	forged := verifiedLookup("owner")
	forged.membership = nil
	forged.membershipErr = httpx.Forbidden("caller is not a member of this team", nil)

	unconfirmed := verifiedLookup("owner")
	unconfirmed.membership.Confirmed = false

	otherTeam := verifiedLookup("owner")
	otherTeam.membership.TeamID = "t2"

	cases := []struct {
		name    string
		headers map[string]string
		lookup  authz.Lookup
		status  int
	}{
		{"missing claim", headers("jwt-1", ""), verifiedLookup("owner"), 401},
		{"missing jwt", headers("", "t1"), verifiedLookup("owner"), 401},
		{"forged organisation", headers("jwt-1", "victim"), forged, 403},
		{"unconfirmed membership", headers("jwt-1", "t1"), unconfirmed, 403},
		{"membership for another team", headers("jwt-1", "t1"), otherTeam, 403},
		{"nil lookup", headers("jwt-1", "t1"), nil, 502},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			caller, err := authz.Verify(context.Background(), tc.headers, tc.lookup)
			if s := statusOf(t, err); s != tc.status {
				t.Fatalf("expected %d, got %d", tc.status, s)
			}
			if !caller.IsZero() || caller.TeamID() != "" {
				t.Fatalf("failed verification must not expose a tenant authority: %+v", caller)
			}

			// Without a verified team every tenant check fails closed.
			if tenant.CheckRowTenant(map[string]any{tenant.OrganizationField: "t1"}, caller.TeamID()) {
				t.Fatal("an unverified caller must not satisfy a row recheck")
			}
			if s := statusOf(t, tenant.CheckBodyOrganization(caller.TeamID(), "t1")); s != 403 {
				t.Fatalf("an unverified caller must not confirm a body organisation, got %d", s)
			}
			if s := statusOf(t, tenant.RequireRegistered(context.Background(), caller.TeamID(), func(context.Context, string) (bool, error) {
				return true, nil
			})); s != 403 {
				t.Fatalf("an unverified caller must not pass the registry gate, got %d", s)
			}
			if s := statusOf(t, mustErr(tenant.FetchSameTenant(context.Background(), func(context.Context, string, string) (*tenant.Ref, error) {
				return &tenant.Ref{ID: "c1", OrganizationID: "t1"}, nil
			}, caller.TeamID(), "customer_id", "customers", "c1"))); s != 404 {
				t.Fatalf("an unverified caller must not fetch a row, got %d", s)
			}
		})
	}
}

func mustErr(_ *tenant.Ref, err error) error { return err }

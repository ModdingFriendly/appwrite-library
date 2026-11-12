package tenant_test

// External contract tests for the tenant package. They pin the fail-closed
// tenant rules a Function relies on: the body is never the tenant authority,
// an organisation must be provisioned, and a cross-tenant row recheck is
// indistinguishable from a missing row so it cannot be used as an existence
// oracle.

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/ModdingFriendly/appwrite-library/httpx"
	"github.com/ModdingFriendly/appwrite-library/reparix/tenant"
)

func errorOf(t *testing.T, err error) *httpx.Error {
	t.Helper()
	var he *httpx.Error
	if !errors.As(err, &he) || he == nil {
		t.Fatalf("expected *httpx.Error, got %T: %v", err, err)
	}
	return he
}

func statusOf(t *testing.T, err error) int {
	t.Helper()
	return errorOf(t, err).Status
}

// TestClaimedOrganizationContract covers missing and forged claims at the
// tenant primitive boundary. The claim is a lookup key only; it is trimmed,
// case-insensitive and empty when absent.
func TestClaimedOrganizationContract(t *testing.T) {
	cases := []struct {
		name    string
		headers map[string]string
		want    string
	}{
		{"nil map", nil, ""},
		{"absent", map[string]string{"x-appwrite-user-jwt": "jwt-1"}, ""},
		{"blank", map[string]string{"x-reparix-organization-id": "   "}, ""},
		{"exact header", map[string]string{"x-reparix-organization-id": "t1"}, "t1"},
		{"mixed-case header trimmed", map[string]string{"X-Reparix-Organization-Id": "  t1 "}, "t1"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tenant.ClaimedOrganization(tc.headers); got != tc.want {
				t.Fatalf("claim = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestCheckBodyOrganizationContract proves a client-supplied organisation can
// only confirm the verified tenant; it can never select another one.
func TestCheckBodyOrganizationContract(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		wantErr bool
	}{
		{"empty body is fine", "", false},
		{"matching body is fine", "t1", false},
		{"matching body is trimmed", " t1 ", false},
		{"forged body is refused", "t2", true},
		{"case-variant body is refused", "T1", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tenant.CheckBodyOrganization("t1", tc.body)
			if !tc.wantErr {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			he := errorOf(t, err)
			if he.Status != 403 {
				t.Fatalf("must be 403, got %d", he.Status)
			}
			if he.Params["field"] != tenant.OrganizationField {
				t.Fatalf("error must identify %q, got %v", tenant.OrganizationField, he.Params)
			}
		})
	}
}

// TestRequireRegisteredContract proves a self-created team cannot act as an
// organisation: a missing check is 502, malformed or unregistered teams are
// 403, and dependency errors propagate unchanged.
func TestRequireRegisteredContract(t *testing.T) {
	ctx := context.Background()
	sentinel := errors.New("registry unavailable")
	registered := func(context.Context, string) (bool, error) { return true, nil }
	unregistered := func(context.Context, string) (bool, error) { return false, nil }
	failing := func(context.Context, string) (bool, error) { return false, sentinel }

	if err := tenant.RequireRegistered(ctx, "t1", registered); err != nil {
		t.Fatalf("provisioned organisation rejected: %v", err)
	}

	he := errorOf(t, tenant.RequireRegistered(ctx, "t1", unregistered))
	if he.Status != 403 || he.Params["field"] != tenant.OrganizationField {
		t.Fatalf("unregistered organisation contract changed: %+v", he)
	}

	if s := statusOf(t, tenant.RequireRegistered(ctx, "t1", nil)); s != 502 {
		t.Fatalf("nil registry must fail closed with 502, got %d", s)
	}

	if !errors.Is(tenant.RequireRegistered(ctx, "t1", failing), sentinel) {
		t.Fatal("registry error must propagate so the caller keeps its cause")
	}

	called := false
	spy := func(context.Context, string) (bool, error) { called = true; return true, nil }
	if s := statusOf(t, tenant.RequireRegistered(ctx, "bad id!", spy)); s != 403 {
		t.Fatalf("malformed team must be 403, got %d", s)
	}
	if called {
		t.Fatal("malformed team must be refused before the registry is consulted")
	}
}

// TestValidIDContract pins the Appwrite id shape used for both teams and rows.
func TestValidIDContract(t *testing.T) {
	for _, ok := range []string{"a", "t1", "u_1", "A.b-c", "012345678901234567890123456789012345"} {
		if !tenant.ValidID(ok) {
			t.Errorf("%q should be a valid Appwrite id", ok)
		}
	}
	for _, bad := range []string{"", "_x", ".x", "-x", "a b", "a/b", "a\nb", "$id", "x'y", "0123456789012345678901234567890123456"} {
		if tenant.ValidID(bad) {
			t.Errorf("%q should be rejected", bad)
		}
	}
}

// TestFetchSameTenantContract is the cross-tenant row recheck contract: only
// the verified team's rows are returned, and cross-tenant, tenant-less and
// missing rows are byte-for-byte the same 404.
func TestFetchSameTenantContract(t *testing.T) {
	ctx := context.Background()
	rows := map[string]*tenant.Ref{
		"own":    {Table: "customers", ID: "own", OrganizationID: "t1"},
		"other":  {Table: "customers", ID: "other", OrganizationID: "t2"},
		"orphan": {Table: "customers", ID: "orphan"},
	}
	fetch := func(_ context.Context, table, id string) (*tenant.Ref, error) {
		if row, ok := rows[id]; ok {
			if row.Table != table {
				t.Fatalf("fetcher got table %q for %q", table, id)
			}
			return row, nil
		}
		return nil, nil
	}

	row, err := tenant.FetchSameTenant(ctx, fetch, "t1", "customer_id", "customers", "own")
	if err != nil {
		t.Fatalf("own-tenant row rejected: %v", err)
	}
	if row == nil || row.ID != "own" {
		t.Fatalf("own-tenant row not returned: %+v", row)
	}

	for _, id := range []string{"other", "orphan", "missing"} {
		row, err := tenant.FetchSameTenant(ctx, fetch, "t1", "customer_id", "customers", id)
		if row != nil {
			t.Fatalf("%s: cross-tenant or missing row must not be returned", id)
		}
		he := errorOf(t, err)
		if he.Status != 404 || he.Code != "not_found" || he.Message != "referenced row not found" {
			t.Fatalf("%s: unexpected cross-tenant error: %+v", id, he)
		}
		if !reflect.DeepEqual(he.Params, map[string]any{"field": "customer_id"}) {
			t.Fatalf("%s: error params must not leak a reason: %v", id, he.Params)
		}
	}

	// A nil fetcher means the check cannot be made: fail closed, not open.
	if s := statusOf(t, mustErr(tenant.FetchSameTenant(ctx, nil, "t1", "f", "customers", "own"))); s != 502 {
		t.Fatalf("nil fetcher must be 502, got %d", s)
	}

	// A malformed reference is a caller error and must not reach the fetcher.
	called := false
	spy := func(context.Context, string, string) (*tenant.Ref, error) {
		called = true
		return rows["own"], nil
	}
	if s := statusOf(t, mustErr(tenant.FetchSameTenant(ctx, spy, "t1", "customer_id", "customers", "bad id!"))); s != 400 {
		t.Fatalf("malformed row reference must be 400, got %d", s)
	}
	if called {
		t.Fatal("malformed row reference must be refused before the fetch")
	}
}

// TestCheckRowTenantContract is the response-side recheck: a decoded row is
// usable only when its stored organisation equals the verified team.
func TestCheckRowTenantContract(t *testing.T) {
	cases := []struct {
		name string
		row  map[string]any
		want bool
	}{
		{"own tenant", map[string]any{tenant.OrganizationField: "t1"}, true},
		{"cross tenant", map[string]any{tenant.OrganizationField: "t2"}, false},
		{"empty organisation", map[string]any{tenant.OrganizationField: ""}, false},
		{"missing organisation", map[string]any{}, false},
		{"nil row", nil, false},
		{"non-string organisation", map[string]any{tenant.OrganizationField: 5}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tenant.CheckRowTenant(tc.row, "t1"); got != tc.want {
				t.Fatalf("CheckRowTenant = %v, want %v", got, tc.want)
			}
		})
	}
}

func mustErr(_ *tenant.Ref, err error) error { return err }

package tenant

import (
	"context"
	"errors"
	"testing"

	"github.com/ModdingFriendly/appwrite-library/httpx"
)

func statusOf(t *testing.T, err error) int {
	t.Helper()
	var he *httpx.Error
	if !errors.As(err, &he) {
		t.Fatalf("expected httpx.Error, got %v", err)
	}
	return he.Status
}

func TestValidID(t *testing.T) {
	for _, ok := range []string{"a", "team1", "A.b_c-d", "0123456789012345678901234567890123456"[:36]} {
		if !ValidID(ok) {
			t.Errorf("%q should be valid", ok)
		}
	}
	for _, bad := range []string{"", "_x", ".x", "-x", "a b", "a/b", "a\nb", "$id", "x'y", "0123456789012345678901234567890123456789"} {
		if ValidID(bad) {
			t.Errorf("%q should be invalid", bad)
		}
	}
}

func TestHeaderCaseInsensitiveAndTrimmed(t *testing.T) {
	h := map[string]string{"X-Reparix-Organization-Id": "  t1 "}
	if ClaimedOrganization(h) != "t1" {
		t.Fatal("claim must be trimmed and case-insensitive")
	}
	if ClaimedOrganization(nil) != "" {
		t.Fatal("missing is empty")
	}
}

func TestCheckBodyOrganization(t *testing.T) {
	if err := CheckBodyOrganization("t1", ""); err != nil {
		t.Fatal(err)
	}
	if err := CheckBodyOrganization("t1", " t1 "); err != nil {
		t.Fatal(err)
	}
	if statusOf(t, CheckBodyOrganization("t1", "t2")) != 403 {
		t.Fatal("mismatch must be 403")
	}
}

func TestRequireRegistered(t *testing.T) {
	ctx := context.Background()
	yes := func(context.Context, string) (bool, error) { return true, nil }
	no := func(context.Context, string) (bool, error) { return false, nil }
	boom := func(context.Context, string) (bool, error) { return false, errors.New("db down") }
	if err := RequireRegistered(ctx, "t1", yes); err != nil {
		t.Fatal(err)
	}
	if statusOf(t, RequireRegistered(ctx, "t1", no)) != 403 {
		t.Fatal("unregistered must be 403")
	}
	if statusOf(t, RequireRegistered(ctx, "t1", nil)) != 502 {
		t.Fatal("nil registry must fail closed")
	}
	if err := RequireRegistered(ctx, "t1", boom); err == nil || err.Error() != "db down" {
		t.Fatalf("lookup error must propagate: %v", err)
	}
	called := false
	spy := func(context.Context, string) (bool, error) { called = true; return true, nil }
	if statusOf(t, RequireRegistered(ctx, "bad id!", spy)) != 403 || called {
		t.Fatal("malformed team must be refused without a lookup")
	}
}

func TestFetchSameTenant(t *testing.T) {
	ctx := context.Background()
	rows := map[string]*Ref{
		"own":   {ID: "own", OrganizationID: "t1"},
		"other": {ID: "other", OrganizationID: "t2"},
		"empty": {ID: "empty"},
	}
	fetch := func(_ context.Context, _, id string) (*Ref, error) {
		if r, ok := rows[id]; ok {
			return r, nil
		}
		return nil, nil
	}
	if _, err := FetchSameTenant(ctx, fetch, "t1", "customer_id", "customers", "own"); err != nil {
		t.Fatal(err)
	}
	// Cross-tenant, tenant-less and missing rows are indistinguishable.
	var bodies []int
	for _, id := range []string{"other", "empty", "missing"} {
		_, err := FetchSameTenant(ctx, fetch, "t1", "customer_id", "customers", id)
		bodies = append(bodies, statusOf(t, err))
		var he *httpx.Error
		errors.As(err, &he)
		if he.Message != "referenced row not found" || he.Params["field"] != "customer_id" {
			t.Errorf("%s: body must be identical: %+v", id, he)
		}
	}
	for _, s := range bodies {
		if s != 404 {
			t.Fatalf("expected 404, got %v", bodies)
		}
	}
	if _, err := FetchSameTenant(ctx, nil, "t1", "f", "customers", "own"); statusOf(t, err) != 502 {
		t.Fatal("nil fetcher must fail closed")
	}
	if _, err := FetchSameTenant(ctx, fetch, "t1", "f", "customers", "bad id"); statusOf(t, err) != 400 {
		t.Fatal("malformed id must be 400")
	}
}

func TestCheckRowTenant(t *testing.T) {
	if !CheckRowTenant(map[string]any{"organization_id": "t1"}, "t1") {
		t.Fatal("matching row")
	}
	for _, row := range []map[string]any{{}, {"organization_id": ""}, {"organization_id": "t2"}, {"organization_id": 5}} {
		if CheckRowTenant(row, "t1") {
			t.Fatalf("%v must fail", row)
		}
	}
}

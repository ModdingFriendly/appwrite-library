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
	value, ambiguous := Header(h, OrganizationHeader)
	if value != "t1" || ambiguous {
		t.Fatalf("single header must resolve without ambiguity: %q %v", value, ambiguous)
	}
}

func TestHeaderAmbiguity(t *testing.T) {
	cases := []struct {
		name      string
		headers   map[string]string
		want      string
		ambiguous bool
	}{
		{name: "absent", headers: nil},
		{name: "canonical only", headers: map[string]string{OrganizationHeader: " t1 "}, want: "t1"},
		{name: "other casing only", headers: map[string]string{"X-Reparix-Organization-Id": " t1 "}, want: "t1"},
		{name: "blank only", headers: map[string]string{"X-Reparix-Organization-Id": "   "}},
		{name: "duplicate agreeing values", headers: map[string]string{"X-Reparix-Organization-Id": "t1", OrganizationHeader: " t1 "}, want: "t1"},
		{
			name:      "duplicate differing values without canonical",
			headers:   map[string]string{"X-Reparix-Organization-Id": "t1", "X-REPARIX-ORGANIZATION-ID": "t2"},
			ambiguous: true,
		},
		{
			name:      "canonical wins over differing duplicate",
			headers:   map[string]string{OrganizationHeader: " t1 ", "X-Reparix-Organization-Id": "t2"},
			want:      "t1",
			ambiguous: true,
		},
		{
			name:      "blank canonical differs from value",
			headers:   map[string]string{OrganizationHeader: "  ", "X-Reparix-Organization-Id": "t2"},
			ambiguous: true,
		},
		{
			name:      "blank and value without canonical",
			headers:   map[string]string{"X-Reparix-Organization-Id": "  ", "X-REPARIX-ORGANIZATION-ID": "t2"},
			ambiguous: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			value, ambiguous := Header(tc.headers, OrganizationHeader)
			if value != tc.want || ambiguous != tc.ambiguous {
				t.Fatalf("Header() = %q, %v; want %q, %v", value, ambiguous, tc.want, tc.ambiguous)
			}
		})
	}
}

func TestHeaderAmbiguityIsDeterministic(t *testing.T) {
	// The reproduction from the original report: three case variants with
	// different values used to pick a different winner per call.
	h := map[string]string{
		"X-Reparix-Organization-Id": "t1",
		"X-REPARIX-ORGANIZATION-ID": "t2",
		"X-Reparix-Organization-ID": "t3",
	}
	for i := 0; i < 1000; i++ {
		value, ambiguous := Header(h, OrganizationHeader)
		if value != "" || !ambiguous {
			t.Fatalf("call %d: Header() = %q, %v; want \"\", true", i, value, ambiguous)
		}
	}
}

func TestClaimedOrganizationResolution(t *testing.T) {
	single := map[string]string{"X-Reparix-Organization-Id": "  t1 "}
	if got := ClaimedOrganization(single); got != "t1" {
		t.Fatalf("single value = %q; want t1", got)
	}
	canonical := map[string]string{OrganizationHeader: " t1 ", "X-Reparix-Organization-Id": "t2"}
	if got := ClaimedOrganization(canonical); got != "t1" {
		t.Fatalf("canonical value = %q; want t1", got)
	}
	differing := map[string]string{"X-Reparix-Organization-Id": "t1", "X-REPARIX-ORGANIZATION-ID": "t2"}
	if got := ClaimedOrganization(differing); got != "" {
		t.Fatalf("differing duplicates without canonical must not resolve: %q", got)
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

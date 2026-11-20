package isolation

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/open-runtimes/types-for-go/v4/openruntimes"

	"github.com/ModdingFriendly/appwrite-library/appwrite"
	libauth "github.com/ModdingFriendly/appwrite-library/auth"
)

func fixture(t *testing.T) *Fixture {
	return New(t, Options{DBDir: "testdata/db"})
}

func TestSeedsBothOrganisationsFromTheSchema(t *testing.T) {
	f := fixture(t)
	for _, org := range []Org{f.A, f.B} {
		ticket, ok := f.Row("tickets", org.IDs["tickets"])
		if !ok {
			t.Fatalf("org %s has no ticket", org.Key)
		}
		if ticket["organization_id"] != org.TeamID || ticket["customer_id"] != org.IDs["customers"] {
			t.Fatalf("ticket of org %s is not linked to its own org: %+v", org.Key, ticket)
		}
		if ticket["priority"] != "Low" || ticket["total"] != "GBP 10.00" {
			t.Fatalf("enum/money values not plausible: %+v", ticket)
		}
		if !strings.Contains(ticket["device"].(string), org.Canary) {
			t.Fatalf("text value lacks the canary: %+v", ticket)
		}
		customer, _ := f.Row("customers", org.IDs["customers"])
		if _, set := customer["merged_into_id"]; set {
			t.Fatalf("an unresolved optional reference must stay unset: %+v", customer)
		}
		if _, set := customer["deleted_at"]; set {
			t.Fatalf("an optional timestamp must stay unset: %+v", customer)
		}
		if _, ok := f.Row("organizations", org.TeamID); !ok {
			t.Fatalf("org %s has no organizations row", org.Key)
		}
	}
	if _, ok := f.Row("organizations", "a-organizations"); ok {
		t.Fatal("platform tables must not be seeded as tenant rows")
	}
}

func TestRenderPlaceholders(t *testing.T) {
	f := fixture(t)
	got := f.Render(t, `{"id":"{{tickets}}","own":"{{own:tickets}}","team":"{{team}}","user":"{{user:customer}}"}`, f.A, f.B)
	want := `{"id":"b-tickets","own":"a-tickets","team":"team-b","user":"b-customer"}`
	if got != want {
		t.Fatalf("Render = %s", got)
	}
}

func TestContextCarriesTheVerifiedCaller(t *testing.T) {
	f := fixture(t)
	ctx := f.Context(f.A, RoleTechnician, "POST", "/x?y=1", `{}`)
	lookup, err := libauth.NewJWTLookupFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	id, err := lookup.CurrentUser(ctx)
	if err != nil || id.UserID != "a-technician" {
		t.Fatalf("CurrentUser = %+v, %v", id, err)
	}
	m, err := lookup.Membership(ctx, ctx.Req.Headers[OrganizationHeader], id.UserID)
	if err != nil || m.TeamID != "team-a" || m.Roles[0] != RoleTechnician {
		t.Fatalf("Membership = %+v, %v", m, err)
	}
	if ctx.Req.Path != "/x" || ctx.Req.Query["y"] != "1" {
		t.Fatalf("query string not split: %q %v", ctx.Req.Path, ctx.Req.Query)
	}
}

func TestLeaksFindsTheOtherOrganisationsCanary(t *testing.T) {
	f := fixture(t)
	if got := f.Leaks([]byte(`{"name":"CNRYORGB customer"}`), f.B); len(got) != 1 {
		t.Fatalf("Leaks = %v", got)
	}
	if got := f.Leaks([]byte(`{"name":"cnryorga customer"}`), f.B); len(got) != 0 {
		t.Fatalf("own data reported as a leak: %v", got)
	}
}

func TestChangesSeesWritesToTheTargetOrganisationOnly(t *testing.T) {
	f := fixture(t)
	before := f.Server.Snapshot()
	f.SetFor(f.A, "tickets", map[string]any{"device": "changed"})
	if got := f.Changes(before, f.B); len(got) != 0 {
		t.Fatalf("a change to A reported against B: %v", got)
	}
	f.SetFor(f.B, "tickets", map[string]any{"device": "changed"})
	f.Server.Seed("customers", "new", map[string]any{"organization_id": f.B.TeamID})
	got := f.Changes(before, f.B)
	if len(got) != 2 || !strings.Contains(got[0], "changed tickets/b-tickets") || !strings.Contains(got[1], "created customers/new") {
		t.Fatalf("Changes = %v", got)
	}
	f.Reset()
	if got := f.Changes(before, f.B); len(got) != 0 {
		t.Fatalf("Reset did not restore the seed: %v", got)
	}
}

// listHandler lists customers with the given queries, as a handler would.
func listHandler(queries func(team string) []string) Handler {
	return func(ctx openruntimes.Context) openruntimes.Response {
		team := ctx.Req.Headers[OrganizationHeader]
		page, err := appwrite.List[map[string]any](ctx, "customers", queries(team)...)
		if err != nil {
			return ctx.Res.Json(map[string]string{"error": err.Error()}, ctx.Res.WithStatusCode(500))
		}
		raw, _ := json.Marshal(page.Rows)
		return ctx.Res.Binary(raw)
	}
}

func TestUnscopedCallsFlagsListsWithoutTheCallersTenantFilter(t *testing.T) {
	f := fixture(t)
	cases := []struct {
		name    string
		queries func(team string) []string
		want    string
	}{
		{"scoped", func(team string) []string { return []string{appwrite.Equal("organization_id", team)} }, ""},
		{"unscoped", func(string) []string { return []string{appwrite.Limit(5)} }, "has no organization_id filter"},
		{"other team", func(string) []string { return []string{appwrite.Equal("organization_id", "team-b")} }, `filters organization_id = "team-b"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f.Reset()
			listHandler(tc.queries)(f.Context(f.A, RoleAdmin, "POST", "/list", `{}`))
			got := f.unscopedCalls(f.A, Route{})
			if tc.want == "" && len(got) != 0 {
				t.Fatalf("unexpected: %v", got)
			}
			if tc.want != "" && (len(got) != 1 || !strings.Contains(got[0], tc.want)) {
				t.Fatalf("got %v, want %q", got, tc.want)
			}
		})
	}
	f.Reset()
	listHandler(func(string) []string { return nil })(f.Context(f.A, RoleAdmin, "POST", "/list", `{}`))
	if got := f.unscopedCalls(f.A, Route{Unscoped: []string{"customers: reviewed"}}); len(got) != 0 {
		t.Fatalf("an allowed table was flagged: %v", got)
	}
}

func TestRunPassesASafeRoute(t *testing.T) {
	f := fixture(t)
	safe := listHandler(func(team string) []string { return []string{appwrite.Equal("organization_id", team)} })
	Run(t, f, func(ctx openruntimes.Context) openruntimes.Response {
		lookup, err := libauth.NewJWTLookupFromEnv()
		if err != nil {
			return ctx.Res.Text("no auth", ctx.Res.WithStatusCode(500))
		}
		id, err := lookup.CurrentUser(ctx)
		if err != nil {
			return ctx.Res.Text("unauthorized", ctx.Res.WithStatusCode(401))
		}
		if _, err := lookup.Membership(ctx, ctx.Req.Headers[OrganizationHeader], id.UserID); err != nil {
			return ctx.Res.Text("forbidden", ctx.Res.WithStatusCode(403))
		}
		return safe(ctx)
	}, []Route{{Method: "POST", Path: "/list", Body: `{"id":"{{customers}}"}`}})
}

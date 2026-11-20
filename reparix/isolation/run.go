package isolation

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/open-runtimes/types-for-go/v4/openruntimes"

	"github.com/ModdingFriendly/appwrite-library/apptest"
)

// Handler is a Function entrypoint, usually the package's Main.
type Handler func(openruntimes.Context) openruntimes.Response

// Route is one route to prove.
type Route struct {
	Method, Path string
	// Body is a request template; see Fixture.Render. Placeholders without the
	// own: prefix name the target organisation's rows.
	Body string
	// Roles are the roles the route serves. Each one attacks across tenants
	// and must succeed in the control request. Empty means admin.
	Roles []string
	// ControlRoles, when set, replace Roles for the control request: the
	// route serves these roles and refuses the attacking ones (see Refused).
	ControlRoles []string
	// Refused requires every attacking request to be refused with 401 or
	// 403, for routes no tenant role may call (platform operator routes).
	Refused bool
	// Reads marks a route that returns tenant data: its control response
	// must contain the target organisation's canary, which proves the
	// attack's empty answer is isolation and not an empty fixture.
	Reads bool
	// ControlStatus is the status the control request must return. Zero means
	// any 2xx.
	ControlStatus int
	// NoControl skips the control request, with the reason. Use it only when
	// a same-tenant success cannot be produced in a unit test (for example a
	// route that needs an external provider).
	NoControl string
	// Unscoped lists tenant tables this route may list without an
	// organization_id filter, with the reason after a colon, for example
	// "tickets: looks the ticket up by its public tracking token".
	Unscoped []string
	// Headers are extra request headers (templates, like Body), for example
	// the Origin a public widget sends.
	Headers map[string]string
	// Setup runs after the fixture is reset and before each request.
	Setup func(f *Fixture)
	// IgnoresClaim marks a route that does not read the tenant header at all
	// (it derives the organisation from the caller's own record), so a forged
	// claim cannot be refused; the leak and change checks still apply.
	IgnoresClaim bool
	// Skip leaves the route out, with the reason. A skipped route still
	// counts as covered for the manifest check.
	Skip string
}

func (r Route) name() string {
	path, _, _ := strings.Cut(r.Path, "?")
	return r.Method + " " + path
}

func (r Route) roles() []string {
	if len(r.Roles) == 0 {
		return []string{RoleAdmin}
	}
	return r.Roles
}

// Run proves every route. Each route runs as its own subtest.
func Run(t *testing.T, f *Fixture, handler Handler, routes []Route) {
	t.Helper()
	for _, route := range routes {
		route := route
		t.Run(route.Method+" "+route.Path, func(t *testing.T) {
			if route.Skip != "" {
				t.Skip(route.Skip)
			}
			for _, role := range route.roles() {
				f.attack(t, handler, route, role)
			}
			if route.NoControl == "" {
				controls := route.roles()
				if len(route.ControlRoles) > 0 {
					controls = route.ControlRoles
				}
				for _, role := range controls {
					f.control(t, handler, route, role)
				}
			}
		})
	}
}

func (f *Fixture) prepare(route Route) {
	f.Reset()
	if route.Setup != nil {
		route.Setup(f)
		f.Server.ResetCalls()
	}
}

// attack sends the route as A's caller in role, aimed at B.
func (f *Fixture) attack(t *testing.T, handler Handler, route Route, role string) {
	t.Helper()
	f.prepare(route)
	before := f.Server.Snapshot()
	body := f.Render(t, route.Body, f.A, f.B)
	path := f.Render(t, route.Path, f.A, f.B)
	resp := handler(f.withHeaders(t, f.Context(f.A, role, route.Method, path, body), route, f.A, f.B))
	raw := responseBytes(resp)
	if route.Refused && resp.StatusCode != 401 && resp.StatusCode != 403 {
		t.Errorf("as org A %s: got %d, want 401 or 403 (body %s)", role, resp.StatusCode, clip(raw))
	}
	for _, leak := range f.Leaks(raw, f.B) {
		t.Errorf("as org A %s: %s", role, leak)
	}
	for _, change := range f.Changes(before, f.B) {
		t.Errorf("as org A %s (status %d): %s", role, resp.StatusCode, change)
	}
	allowRoute := route
	if role == RoleMachine {
		// The verifier finds a key by its public key id before it knows the
		// tenant; the key row's organisation is then the authority.
		allowRoute.Unscoped = append(append([]string(nil), route.Unscoped...), "api_keys: key lookup by key id")
	}
	for _, v := range f.unscopedCalls(f.A, allowRoute) {
		t.Errorf("as org A %s: %s", role, v)
	}
	if gaps := f.Server.Unhandled(); len(gaps) > 0 {
		t.Errorf("as org A %s: the fake does not implement %v, so this request proves nothing", role, gaps)
	}

	// The same caller naming B's team in the tenant header must be refused.
	if role != RoleGuest && !route.IgnoresClaim {
		f.prepare(route)
		ctx := f.withHeaders(t, f.Context(f.A, role, route.Method, path, body), route, f.A, f.B)
		ctx.Req.Headers[OrganizationHeader] = f.B.TeamID
		resp := handler(ctx)
		if resp.StatusCode < 400 || resp.StatusCode >= 500 {
			t.Errorf("as org A %s claiming org B's team: got %d, want a 4xx refusal (body %s)", role, resp.StatusCode, clip(responseBytes(resp)))
		}
		for _, leak := range f.Leaks(responseBytes(resp), f.B) {
			t.Errorf("as org A %s claiming org B's team: %s", role, leak)
		}
	}
}

// control sends the route as B's own caller in role and expects success.
func (f *Fixture) control(t *testing.T, handler Handler, route Route, role string) {
	t.Helper()
	f.prepare(route)
	body := f.Render(t, route.Body, f.B, f.B)
	path := f.Render(t, route.Path, f.B, f.B)
	resp := handler(f.withHeaders(t, f.Context(f.B, role, route.Method, path, body), route, f.B, f.B))
	ok := resp.StatusCode >= 200 && resp.StatusCode < 300
	if route.ControlStatus != 0 {
		ok = resp.StatusCode == route.ControlStatus
	}
	if !ok {
		t.Errorf("control as org B %s: got %d (body %s); the cross-tenant result above proves nothing until the same request succeeds for its own tenant", role, resp.StatusCode, clip(responseBytes(resp)))
		for _, call := range f.Server.Calls() {
			t.Logf("  appwrite %s %s -> %d %v", call.Method, call.Path, call.Status, call.Queries)
		}
	}
	if ok && route.Reads && len(f.Leaks(responseBytes(resp), f.B)) == 0 {
		t.Errorf("control as org B %s: the answer holds none of org B's data (body %s), so the empty cross-tenant answer proves nothing", role, clip(responseBytes(resp)))
	}
	if gaps := f.Server.Unhandled(); len(gaps) > 0 {
		t.Errorf("control: the fake does not implement %v", gaps)
	}
}

func (f *Fixture) withHeaders(t *testing.T, ctx openruntimes.Context, route Route, caller, target Org) openruntimes.Context {
	for k, v := range route.Headers {
		ctx.Req.Headers[strings.ToLower(k)] = f.Render(t, v, caller, target)
	}
	return ctx
}

// unscopedCalls reports server-key lists and bulk writes on tenant tables that
// are not filtered to caller's organisation.
func (f *Fixture) unscopedCalls(caller Org, route Route) []string {
	allowed := map[string]bool{}
	for _, entry := range route.Unscoped {
		name, _, _ := strings.Cut(entry, ":")
		allowed[strings.TrimSpace(name)] = true
	}
	var out []string
	for _, call := range f.Server.Calls() {
		if call.Caller != "key" || call.Table == "" || call.RowID != "" || call.Status >= 400 {
			continue
		}
		if call.Method == http.MethodPost || call.Method == http.MethodPut {
			continue
		}
		table, ok := f.Schema[call.Table]
		if !ok || allowed[call.Table] {
			continue
		}
		column := "organization_id"
		if call.Table == "organizations" {
			column = "team_id"
		} else if _, platform := PlatformTables[call.Table]; platform || !table.Tenant() {
			continue
		}
		if pointLookup(call.Queries) {
			// A lookup by row id is a read of one known row, like GetRow. The
			// leak and change checks decide whether the handler then honoured
			// the row's organisation.
			continue
		}
		teams := orgFilter(call.Queries, column)
		switch {
		case len(teams) == 0:
			out = append(out, fmt.Sprintf("%s %s has no %s filter (queries %v)", verb(call.Method), call.Table, column, call.Queries))
		default:
			for _, team := range teams {
				if team != caller.TeamID {
					out = append(out, fmt.Sprintf("%s %s filters %s = %q, not the caller's team", verb(call.Method), call.Table, column, team))
				}
			}
		}
	}
	return out
}

func verb(method string) string {
	switch method {
	case http.MethodGet:
		return "list of"
	case http.MethodPatch:
		return "bulk update of"
	case http.MethodDelete:
		return "bulk delete of"
	}
	return method
}

// orgFilter returns the organization_id values a query set is restricted to,
// looking through and() groups. An or() group does not count as a filter.
func orgFilter(queries []string, column string) []string {
	var out []string
	for _, raw := range queries {
		out = append(out, orgFilterOne(raw, column)...)
	}
	return out
}

func orgFilterOne(raw, column string) []string {
	var q struct {
		Method    string            `json:"method"`
		Attribute string            `json:"attribute"`
		Values    []json.RawMessage `json:"values"`
	}
	if json.Unmarshal([]byte(raw), &q) != nil {
		return nil
	}
	switch {
	case q.Method == "equal" && q.Attribute == column:
		var out []string
		for _, v := range q.Values {
			var s string
			_ = json.Unmarshal(v, &s)
			out = append(out, s)
		}
		if len(out) == 0 {
			return []string{""}
		}
		return out
	case q.Method == "and":
		var out []string
		for _, v := range q.Values {
			out = append(out, orgFilterOne(string(v), column)...)
		}
		return out
	}
	return nil
}

// pointLookup reports whether queries pin the result to given row ids.
func pointLookup(queries []string) bool {
	for _, raw := range queries {
		var q struct {
			Method    string `json:"method"`
			Attribute string `json:"attribute"`
		}
		if json.Unmarshal([]byte(raw), &q) == nil && q.Method == "equal" && q.Attribute == "$id" {
			return true
		}
	}
	return false
}

func responseBytes(resp openruntimes.Response) []byte {
	return resp.Body
}

func clip(b []byte) string {
	if len(b) > 300 {
		return string(b[:300]) + "…"
	}
	return string(b)
}

// RequireCoverage fails when a route of service in the ownership manifest
// (docs/service-ownership.json) has no Route. ignore lists routes proven
// elsewhere, as "METHOD /path".
func RequireCoverage(t *testing.T, manifestPath, service string, routes []Route, ignore ...string) {
	t.Helper()
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("isolation: manifest: %v", err)
	}
	var manifest struct {
		Services []struct {
			ID     string `json:"id"`
			Routes []struct {
				Method string `json:"method"`
				Path   string `json:"path"`
			} `json:"routes"`
		} `json:"services"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatalf("isolation: manifest: %v", err)
	}
	covered := map[string]bool{}
	for _, r := range routes {
		covered[r.name()] = true
	}
	for _, r := range ignore {
		covered[r] = true
	}
	found := false
	var missing []string
	for _, s := range manifest.Services {
		if s.ID != service {
			continue
		}
		found = true
		for _, r := range s.Routes {
			name := r.Method + " " + r.Path
			if !covered[name] {
				missing = append(missing, name)
			}
		}
	}
	if !found {
		t.Fatalf("isolation: service %q is not in the manifest", service)
	}
	sort.Strings(missing)
	for _, m := range missing {
		t.Errorf("route %s has no tenant isolation case", m)
	}
}

// Add stores one more generated row of table for each organisation, with
// values applied on top, and registers it under name so templates can say
// {{name}}. Its id is "<org>-<name>". Call it from Route.Setup, or call Rebase
// afterwards to keep it across Reset.
func (f *Fixture) Add(table, name string, values map[string]any) {
	for _, org := range []Org{f.A, f.B} {
		f.AddFor(org, table, name, values)
	}
}

// AddFor is Add for one organisation.
func (f *Fixture) AddFor(org Org, table, name string, values map[string]any) string {
	row := map[string]any{}
	if schema, ok := f.Schema[table]; ok {
		row = f.generate(org, schema)
	}
	for k, v := range values {
		row[k] = v
	}
	id := org.Key + "-" + name
	f.Server.Seed(table, id, row)
	org.IDs[name] = id
	return id
}

// Set changes columns of each organisation's seeded row of table. A nil value
// removes the column.
func (f *Fixture) Set(table string, values map[string]any) {
	for _, org := range []Org{f.A, f.B} {
		f.SetFor(org, table, values)
	}
}

// SetFor is Set for one organisation.
func (f *Fixture) SetFor(org Org, table string, values map[string]any) {
	id := org.IDs[table]
	row, ok := f.Server.Row(table, id)
	if !ok {
		return
	}
	for k, v := range values {
		if v == nil {
			delete(row, k)
			continue
		}
		row[k] = v
	}
	f.Server.Seed(table, id, row)
}

// Row returns a stored row.
func (f *Fixture) Row(table, id string) (apptest.Row, bool) { return f.Server.Row(table, id) }

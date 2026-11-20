// Package isolation proves tenant isolation for Reparix Functions in tests.
//
// It builds two organisations, A and B, in an apptest fake Appwrite server:
// one admin, one technician and one customer user each, and one row per
// tenant table (generated from Reparix's db/*.yaml schema) for each
// organisation. Every text value of organisation X carries X's canary (for
// example "cnryorgb"), so a response that contains B's canary was given B's
// data.
//
// Run drives a Function's real router: each route is called as a caller from
// A aimed at B's rows, and the test fails when
//
//   - B's canary appears in the response,
//   - any row of B is created, changed or deleted,
//   - a list or bulk write on a tenant table is not filtered to the caller's
//     own organisation, or
//   - the fake was asked for an endpoint it does not implement (the result
//     would prove nothing).
//
// A control request then sends the same request as B's own caller and must
// succeed, so an attack refused for an unrelated reason (a bad body, a missing
// fixture) is reported instead of counted as a pass.
package isolation

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/open-runtimes/types-for-go/v4/openruntimes"

	"github.com/ModdingFriendly/appwrite-library/apptest"
	libauth "github.com/ModdingFriendly/appwrite-library/auth"
	"github.com/ModdingFriendly/appwrite-library/reparix/operator"
)

// OrganizationHeader is the tenant claim header Reparix services read.
const OrganizationHeader = "x-reparix-organization-id"

// Roles a caller can take. Guest sends no JWT.
const (
	RoleAdmin      = "admin"
	RoleTechnician = "technician"
	RoleCustomer   = "customer"
	RoleGuest      = "guest"
	// RoleMachine calls with the organisation's scoped API key
	// (Authorization: Bearer rpx_live_...) instead of a user JWT.
	RoleMachine = "machine"
	// RoleOperator is a platform operator: a confirmed member of the operator
	// team (operator.DefaultTeamID) and of no organisation. It sends no
	// tenant header.
	RoleOperator = "operator"
)

// OperatorUserID is the platform operator New creates.
const OperatorUserID = "platform-operator"

// MachinePepper is the API key pepper New exports for the test.
const MachinePepper = "isolation-test-pepper"

// Org is one seeded organisation.
type Org struct {
	// Key is "a" or "b".
	Key    string
	TeamID string
	// Canary is the lowercase marker carried by every text value of this
	// organisation's rows.
	Canary string
	// Users holds the user id for each role.
	Users map[string]string
	// IDs maps a table to this organisation's seeded row id.
	IDs map[string]string
	// MachineKey is a working API key of this organisation with
	// Options.MachineScopes.
	MachineKey string
}

// ID returns this organisation's seeded row id for table, or fails the test.
func (o Org) ID(t testing.TB, table string) string {
	t.Helper()
	id, ok := o.IDs[table]
	if !ok {
		t.Fatalf("isolation: org %s has no seeded %s row", o.Key, table)
	}
	return id
}

// Options configures New.
type Options struct {
	// DBDir is the path to Reparix's db/ folder, usually "../../db" from a
	// Function's directory.
	DBDir string
	// Tables limits seeding to these tables. Empty seeds every tenant table.
	Tables []string
	// Customize may change a generated row before it is stored. It runs for
	// each organisation and table.
	Customize func(org Org, table string, row map[string]any)
	// TLS serves the fake on HTTPS, for services that refuse a plain-HTTP
	// endpoint (see apptest.NewTLS).
	TLS bool
	// MachineScopes are the scopes of each organisation's API key, comma
	// separated. Empty means "rows.read,rows.write".
	MachineScopes string
}

// PlatformTables are not owned by one organisation (the same list as
// scripts/check-schema-tenancy.mjs). organizations is keyed by team_id.
var PlatformTables = map[string]string{
	"organizations": "the tenant registry itself; identified by team_id",
	"plans":         "platform-level plan catalogue",
	"tac_devices":   "platform-level TAC reference data",
	"job_runs":      "platform-level scheduled job run log",
}

// Fixture is the two-organisation world.
type Fixture struct {
	Server *apptest.Server
	Schema map[string]*Table
	A, B   Org
	base   apptest.Snapshot

	requests int
}

// New starts the fake, points the environment at it and seeds both
// organisations.
func New(t testing.TB, opts Options) *Fixture {
	t.Helper()
	dir := opts.DBDir
	if dir == "" {
		dir = filepath.Join("..", "..", "db")
	}
	schema, err := LoadSchema(dir)
	if err != nil {
		t.Fatalf("isolation: %v", err)
	}
	var s *apptest.Server
	if opts.TLS {
		s = apptest.NewTLS(t)
	} else {
		s = apptest.New(t)
	}
	s.Env(t)
	f := &Fixture{Server: s, Schema: schema}
	f.A = f.newOrg("a")
	f.B = f.newOrg("b")
	s.AddUser(apptest.User{ID: OperatorUserID, Name: "Platform operator", Email: "operator@platform.test"})
	s.AddMembership(apptest.Membership{TeamID: operator.DefaultTeamID, UserID: OperatorUserID, Roles: []string{"owner"}, Confirmed: true})

	names := opts.Tables
	if len(names) == 0 {
		for _, name := range sortedNames(schema) {
			if _, platform := PlatformTables[name]; !platform && schema[name].Tenant() {
				names = append(names, name)
			}
		}
	}
	for _, name := range sortedNames(schema) {
		for _, idx := range schema[name].Indexes {
			if idx.Type == "unique" {
				s.UniqueIndex(name, idx.Columns...)
			}
		}
	}
	for _, org := range []*Org{&f.A, &f.B} {
		for _, name := range names {
			org.IDs[name] = org.Key + "-" + name
		}
	}
	for _, org := range []Org{f.A, f.B} {
		orgRow := map[string]any{}
		if table, ok := schema["organizations"]; ok {
			orgRow = f.generate(org, table)
		}
		orgRow["team_id"], orgRow["name"], orgRow["status"] = org.TeamID, org.Canary+" repairs", "active"
		// Public pages find a shop by its slug, which must be URL-safe.
		orgRow["slug"] = org.Key + "-repairs"
		if opts.Customize != nil {
			opts.Customize(org, "organizations", orgRow)
		}
		s.Seed("organizations", org.TeamID, orgRow)
		for _, name := range names {
			table, ok := schema[name]
			if !ok {
				t.Fatalf("isolation: no schema for table %q", name)
			}
			row := f.generate(org, table)
			if opts.Customize != nil {
				opts.Customize(org, name, row)
			}
			s.Seed(name, org.IDs[name], row)
		}
	}
	scopes := opts.MachineScopes
	if scopes == "" {
		scopes = "rows.read,rows.write"
	}
	t.Setenv("REPARIX_API_KEY_PEPPER", MachinePepper)
	for _, org := range []*Org{&f.A, &f.B} {
		keyID := org.Key + "isokey01"
		secret := strings.Repeat(strings.ToUpper(org.Key)+"x9", 11)
		mac := hmac.New(sha256.New, []byte(MachinePepper))
		_, _ = mac.Write([]byte(secret))
		s.Seed("api_keys", org.Key+"-machine-key", map[string]any{
			"key_name": org.Canary + " integration", "organization_id": org.TeamID,
			"key_prefix": "rpx_live_" + keyID, "key_id": keyID, "secret_hash": hex.EncodeToString(mac.Sum(nil)),
			"scopes": scopes, "is_active": true, "created_by_user_id": org.Users[RoleAdmin],
			"requests_per_minute": 100000, "requests_per_hour": 1000000,
		})
		org.MachineKey = "rpx_live_" + keyID + "_" + secret
	}
	f.base = s.Snapshot()
	return f
}

func (f *Fixture) newOrg(key string) Org {
	org := Org{
		Key:    key,
		TeamID: "team-" + key,
		Canary: "cnryorg" + key,
		Users:  map[string]string{},
		IDs:    map[string]string{},
	}
	for _, role := range []string{RoleAdmin, RoleTechnician, RoleCustomer} {
		id := key + "-" + role
		org.Users[role] = id
		// The customer's account email is the one generated rows carry, so
		// email-matched portal reads find the organisation's own rows.
		email := role + "." + org.Canary + "@example.test"
		if role == RoleCustomer {
			email = org.Canary + "@example.test"
		}
		f.Server.AddUser(apptest.User{ID: id, Name: org.Canary + " " + role, Email: email})
		membership := "mem-" + id
		f.Server.AddMembership(apptest.Membership{ID: membership, TeamID: org.TeamID, UserID: id, Roles: []string{role}, Confirmed: true})
		// Templates name a membership as {{membership_<role>}}.
		org.IDs["membership_"+role] = membership
	}
	return org
}

// Reset restores the seeded state and forgets recorded calls.
func (f *Fixture) Reset() {
	f.Server.Restore(f.base)
	f.Server.ResetCalls()
}

// Rebase makes the current store the state Reset returns to. Use it after
// adding rows to the seeded world.
func (f *Fixture) Rebase() { f.base = f.Server.Snapshot() }

// Org returns A or B by key.
func (f *Fixture) Org(key string) Org {
	if key == "b" {
		return f.B
	}
	return f.A
}

// Other returns the organisation that is not org.
func (f *Fixture) Other(org Org) Org {
	if org.Key == "a" {
		return f.B
	}
	return f.A
}

// Context builds a Function request from caller's user in role. The tenant
// header names caller's team; a guest sends neither JWT nor header.
func (f *Fixture) Context(caller Org, role, method, path, body string) openruntimes.Context {
	ctx := openruntimes.Context{}
	route, rawQuery, _ := strings.Cut(path, "?")
	ctx.Req.Method, ctx.Req.Path = method, route
	ctx.Req.QueryString = rawQuery
	ctx.Req.Query = map[string]string{}
	for _, pair := range strings.Split(rawQuery, "&") {
		if k, v, ok := strings.Cut(pair, "="); ok {
			// The runtime hands handlers decoded values, as url.ParseQuery does.
			if decoded, err := url.QueryUnescape(v); err == nil {
				v = decoded
			}
			ctx.Req.Query[k] = v
		}
	}
	ctx.Req.Headers = map[string]string{
		"x-appwrite-key": f.Server.APIKey,
		"content-type":   "application/json",
	}
	if role == RoleOperator {
		ctx.Req.Headers[libauth.JWTHeader] = f.Server.JWT(OperatorUserID)
		ctx.Req.Headers["x-appwrite-user-id"] = OperatorUserID
	} else if role == RoleMachine {
		ctx.Req.Headers["authorization"] = "Bearer " + caller.MachineKey
		ctx.Req.Headers[OrganizationHeader] = caller.TeamID
	} else if role != RoleGuest {
		user := caller.Users[role]
		ctx.Req.Headers[libauth.JWTHeader] = f.Server.JWT(user)
		ctx.Req.Headers["x-appwrite-user-id"] = user
		ctx.Req.Headers[OrganizationHeader] = caller.TeamID
	}
	// A distinct client address per request keeps per-IP rate limits from
	// tripping across a long route list.
	f.requests++
	ctx.Req.Headers["x-appwrite-client-ip"] = fmt.Sprintf("198.18.%d.%d", (f.requests/250)%250, f.requests%250+1)
	ctx.Req.Raw = httptest.NewRequest(method, route, strings.NewReader(body))
	ctx.Req.SetBodyBinary([]byte(body))
	return ctx
}

// Render replaces placeholders in a request template:
//
//	{{table}}        the target organisation's row id for table
//	{{own:table}}    the caller organisation's row id for table
//	{{team}}         the target team id; {{own:team}} the caller's
//	{{user:role}}    the target organisation's user id for role
//	{{own:user:role}} the caller's
//
// A placeholder that names nothing in the fixture is left as written.
func (f *Fixture) Render(t testing.TB, template string, caller, target Org) string {
	t.Helper()
	var out strings.Builder
	rest := template
	for {
		start := strings.Index(rest, "{{")
		if start < 0 {
			out.WriteString(rest)
			break
		}
		end := strings.Index(rest[start:], "}}")
		if end < 0 {
			t.Fatalf("isolation: unterminated placeholder in %q", template)
		}
		out.WriteString(rest[:start])
		name := strings.TrimSpace(rest[start+2 : start+end])
		org := target
		if strings.HasPrefix(name, "own:") {
			org, name = caller, strings.TrimPrefix(name, "own:")
		}
		switch {
		case name == "team":
			out.WriteString(org.TeamID)
		case strings.HasPrefix(name, "user:"):
			out.WriteString(org.Users[strings.TrimPrefix(name, "user:")])
		default:
			id, ok := org.IDs[name]
			if !ok {
				// Not a fixture name (for example a template's own
				// {{document.reference}} field): keep it as written.
				out.WriteString(rest[start : start+end+2])
				break
			}
			out.WriteString(id)
		}
		rest = rest[start+end+2:]
	}
	return out.String()
}

// Leaks returns a description when body contains org's canary.
func (f *Fixture) Leaks(body []byte, org Org) []string {
	text := strings.ToLower(string(body))
	if !strings.Contains(text, org.Canary) {
		return nil
	}
	i := strings.Index(text, org.Canary)
	from, to := i-80, i+80
	if from < 0 {
		from = 0
	}
	if to > len(text) {
		to = len(text)
	}
	return []string{fmt.Sprintf("response contains org %s data: …%s…", org.Key, string(body)[from:to])}
}

// owner returns the organisation a row belongs to: its organization_id, or
// team_id for the organizations table.
func owner(table string, row apptest.Row) string {
	if row == nil {
		return ""
	}
	if v, ok := row["organization_id"].(string); ok {
		return v
	}
	if table == "organizations" {
		v, _ := row["team_id"].(string)
		return v
	}
	if strings.HasPrefix(table, "storage:") {
		// A file belongs to the team its permissions name.
		perms, _ := row["$permissions"].([]any)
		for _, p := range perms {
			text, _ := p.(string)
			if i := strings.Index(text, "team:"); i >= 0 {
				team := text[i+len("team:"):]
				if j := strings.IndexAny(team, "/\")"); j >= 0 {
					team = team[:j]
				}
				return team
			}
		}
	}
	return ""
}

// Changes lists rows of org that differ between before and the current store:
// created, updated or deleted.
func (f *Fixture) Changes(before apptest.Snapshot, org Org) []string {
	after := f.Server.Snapshot()
	var out []string
	tables := map[string]bool{}
	for name := range before {
		tables[name] = true
	}
	for name := range after {
		tables[name] = true
	}
	for name := range tables {
		ids := map[string]bool{}
		for id := range before[name] {
			ids[id] = true
		}
		for id := range after[name] {
			ids[id] = true
		}
		for id := range ids {
			old, had := before[name][id]
			cur, has := after[name][id]
			if owner(name, old) != org.TeamID && owner(name, cur) != org.TeamID {
				continue
			}
			switch {
			case !had:
				out = append(out, fmt.Sprintf("created %s/%s in org %s", name, id, org.Key))
			case !has:
				out = append(out, fmt.Sprintf("deleted %s/%s of org %s", name, id, org.Key))
			case !sameRow(old, cur):
				out = append(out, fmt.Sprintf("changed %s/%s of org %s (%s)", name, id, org.Key, diffKeys(old, cur)))
			}
		}
	}
	sort.Strings(out)
	return out
}

func sameRow(a, b apptest.Row) bool {
	return diffKeys(a, b) == ""
}

func diffKeys(a, b apptest.Row) string {
	var keys []string
	seen := map[string]bool{}
	for k := range a {
		seen[k] = true
	}
	for k := range b {
		seen[k] = true
	}
	for k := range seen {
		if fmt.Sprint(a[k]) != fmt.Sprint(b[k]) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return strings.Join(keys, ", ")
}

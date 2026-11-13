package authz

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ModdingFriendly/appwrite-library/httpx"
)

type stubLookup struct {
	identity   *Identity
	identErr   error
	membership *Membership
	memErr     error
	gotJWT     string
	gotTeam    string
	gotUser    string
}

func (s *stubLookup) CurrentUser(_ context.Context, jwt string) (*Identity, error) {
	s.gotJWT = jwt
	return s.identity, s.identErr
}
func (s *stubLookup) Membership(_ context.Context, jwt, team, user string) (*Membership, error) {
	s.gotTeam, s.gotUser = team, user
	return s.membership, s.memErr
}

func headers(team string) map[string]string {
	h := map[string]string{"X-Appwrite-User-JWT": "jwt-1"}
	if team != "" {
		h["X-Reparix-Organization-Id"] = team
	}
	return h
}

func lookupFor(roles ...string) *stubLookup {
	return &stubLookup{
		identity:   &Identity{UserID: "u1"},
		membership: &Membership{ID: "m1", UserID: "u1", TeamID: "t1", Roles: roles, Confirmed: true},
	}
}

func status(t *testing.T, err error) int {
	t.Helper()
	var he *httpx.Error
	if !errors.As(err, &he) {
		t.Fatalf("expected httpx.Error, got %v", err)
	}
	return he.Status
}

func TestVerifyReturnsRolesWithoutInterpretingThem(t *testing.T) {
	for _, roles := range [][]string{{"admin"}, {"owner"}, {}, {" ADMIN "}, {"banana"}} {
		c, err := Verify(context.Background(), headers("t1"), lookupFor(roles...))
		if err != nil {
			t.Fatalf("%v: %v", roles, err)
		}
		if c.UserID() != "u1" || c.TeamID() != "t1" || c.MembershipID() != "m1" || len(c.Roles()) != len(roles) {
			t.Fatalf("caller facts wrong: %+v", c)
		}
	}
}

func TestRequireAnyRole(t *testing.T) {
	owner := NewCaller("u", "t", "m", []string{"Owner"})
	if err := RequireAnyRole(owner, "admin", "technician"); status(t, err) != 403 {
		t.Fatal("owner must not satisfy other roles")
	}
	if err := RequireAnyRole(owner, "OWNER"); err != nil {
		t.Fatal("case-insensitive exact match")
	}
	if status(t, RequireAnyRole(owner)) != 403 {
		t.Fatal("no roles required must deny")
	}
	if status(t, RequireAnyRole(NewCaller("u", "t", "m", nil), "admin")) != 403 {
		t.Fatal("no roles")
	}
}

func TestMissingJWTIs401EvenWithoutLookup(t *testing.T) {
	_, err := Verify(context.Background(), map[string]string{"x-reparix-organization-id": "t1"}, nil)
	if status(t, err) != 401 {
		t.Fatal("missing JWT must be 401 regardless of lookup configuration")
	}
}

func TestNilLookupFailsClosed(t *testing.T) {
	_, err := Verify(context.Background(), headers("t1"), nil)
	if status(t, err) != 502 {
		t.Fatal("nil lookup must fail closed")
	}
}

func TestMissingOrForgedOrganization(t *testing.T) {
	for _, team := range []string{"", "   "} {
		_, err := Verify(context.Background(), headers(team), lookupFor("admin"))
		if status(t, err) != 401 {
			t.Fatalf("missing org %q must be 401", team)
		}
	}
	_, err := VerifyClaim(context.Background(), headers(""), "t1\r\nx: y", lookupFor("admin"))
	if status(t, err) != 401 {
		t.Fatal("CRLF claim must be rejected")
	}

	// Forged org: the Teams API says the caller is not a member.
	forged := lookupFor("admin")
	forged.membership = nil
	forged.memErr = httpx.Forbidden("caller is not a member of this team", nil)
	_, err = Verify(context.Background(), headers("victim-team"), forged)
	if status(t, err) != 403 {
		t.Fatal("forged org must be 403")
	}
	if forged.gotTeam != "victim-team" || forged.gotUser != "u1" {
		t.Fatalf("membership must be looked up for the verified user: %q %q", forged.gotTeam, forged.gotUser)
	}

	// A lookup that returns a membership for a different team or user is refused.
	for name, m := range map[string]*Membership{
		"nil":        nil,
		"other team": {UserID: "u1", TeamID: "t2", Roles: []string{"admin"}, Confirmed: true},
		"other user": {UserID: "u2", TeamID: "t1", Roles: []string{"admin"}, Confirmed: true},
	} {
		l := lookupFor("admin")
		l.membership = m
		_, err := Verify(context.Background(), headers("t1"), l)
		if status(t, err) != 403 {
			t.Errorf("%s: mismatched membership must be 403", name)
		}
	}
}

func TestUnconfirmedMembershipDenied(t *testing.T) {
	l := lookupFor("admin")
	l.membership.Confirmed = false
	_, err := Verify(context.Background(), headers("t1"), l)
	if status(t, err) != 403 || !strings.Contains(err.Error(), "not confirmed") {
		t.Fatalf("unconfirmed must be 403: %v", err)
	}
}

func TestIdentityFailuresPropagate(t *testing.T) {
	l := lookupFor("admin")
	l.identity, l.identErr = nil, httpx.Unauthorized("invalid or expired caller token", nil)
	_, err := Verify(context.Background(), headers("t1"), l)
	if status(t, err) != 401 {
		t.Fatal("identity error must propagate")
	}
	l = lookupFor("admin")
	l.identity = &Identity{}
	_, err = Verify(context.Background(), headers("t1"), l)
	if status(t, err) != 401 {
		t.Fatal("empty user id must be 401")
	}
}

func TestCallerIsImmutable(t *testing.T) {
	roles := []string{"Admin"}
	c := NewCaller("u", "t", "m", roles)
	roles[0] = "customer"
	got := c.Roles()
	got[0] = "customer"
	if !c.HasRole("admin") || c.Roles()[0] != "admin" {
		t.Fatal("caller must not alias or expose its roles")
	}
}

func TestJWTLookupConfigNeverCarriesKey(t *testing.T) {
	if _, err := NewJWTLookup(appwriteConfig("", "p")); err == nil {
		t.Fatal("missing endpoint must fail")
	}
	if _, err := NewJWTLookup(appwriteConfig("https://x.example/v1", "")); err == nil {
		t.Fatal("missing project must fail")
	}
	l, err := NewJWTLookup(appwriteConfig("https://x.example/v1/", "p"))
	if err != nil {
		t.Fatal(err)
	}
	if l.cfg.APIKey != "" || l.cfg.DatabaseID != "" || strings.HasSuffix(l.cfg.Endpoint, "/") {
		t.Fatalf("lookup config must be key-less and trimmed: %+v", l.cfg)
	}
	if _, err := l.CurrentUser(context.Background(), ""); status(t, err) != 401 {
		t.Fatal("empty jwt must be 401")
	}
}

func TestAmbiguousOrganizationHeaderIs401(t *testing.T) {
	h := map[string]string{
		"X-Appwrite-User-JWT":       "jwt-1",
		"x-reparix-organization-id": "t1",
		"X-REPARIX-ORGANIZATION-ID": "t2",
	}
	for name, call := range map[string]func(*stubLookup) (Caller, error){
		"Verify":      func(l *stubLookup) (Caller, error) { return Verify(context.Background(), h, l) },
		"VerifyClaim": func(l *stubLookup) (Caller, error) { return VerifyClaim(context.Background(), h, "t1", l) },
	} {
		l := lookupFor("admin")
		c, err := call(l)
		if status(t, err) != 401 {
			t.Fatalf("%s: want 401, got %v", name, err)
		}
		if c.UserID() != "" || c.TeamID() != "" || l.gotJWT != "" || l.gotTeam != "" {
			t.Fatalf("%s: identity built or lookup called on ambiguous org", name)
		}
	}
}

func TestAmbiguousJWTHeaderIs401(t *testing.T) {
	h := map[string]string{
		"x-appwrite-user-jwt":       "jwt-a",
		"X-APPWRITE-USER-JWT":       "jwt-b",
		"X-Reparix-Organization-Id": "t1",
	}
	l := lookupFor("admin")
	c, err := Verify(context.Background(), h, l)
	if status(t, err) != 401 {
		t.Fatalf("want 401, got %v", err)
	}
	if c.UserID() != "" || l.gotJWT != "" {
		t.Fatal("identity built or lookup called on ambiguous JWT")
	}
}

func TestCanonicalAndSingleValueHeadersStillVerify(t *testing.T) {
	cases := map[string]map[string]string{
		"single": headers("t1"),
		"canonical exact match": {
			"x-appwrite-user-jwt": "jwt-1", "X-APPWRITE-USER-JWT": " jwt-1 ",
			"X-Reparix-Organization-Id": "t1", "x-reparix-organization-id": "t1 ",
		},
	}
	for name, h := range cases {
		l := lookupFor("admin")
		c, err := Verify(context.Background(), h, l)
		if err != nil || c.UserID() != "u1" || c.TeamID() != "t1" || l.gotJWT != "jwt-1" {
			t.Fatalf("%s: %+v %v", name, c, err)
		}
	}
}

package authz_test

// External contract tests for the authz package. They exercise only the
// exported API from a consumer's point of view: role matching is exact (an
// owner never implies another role), the organisation claim must resolve to a
// confirmed membership for the verified user, and every failure is a stable
// httpx error that a Function, gateway or test can rely on.

import (
	"context"
	"errors"
	"testing"

	"github.com/ModdingFriendly/appwrite-library/httpx"
	"github.com/ModdingFriendly/appwrite-library/reparix/authz"
	"github.com/ModdingFriendly/appwrite-library/reparix/tenant"
)

type fakeLookup struct {
	identity      *authz.Identity
	identityErr   error
	membership    *authz.Membership
	membershipErr error

	userCalls       int
	membershipCalls int
	gotJWT          string
	gotTeam         string
	gotUser         string
}

func (l *fakeLookup) CurrentUser(_ context.Context, jwt string) (*authz.Identity, error) {
	l.userCalls++
	l.gotJWT = jwt
	return l.identity, l.identityErr
}

func (l *fakeLookup) Membership(_ context.Context, _, team, user string) (*authz.Membership, error) {
	l.membershipCalls++
	l.gotTeam, l.gotUser = team, user
	return l.membership, l.membershipErr
}

func verifiedLookup(roles ...string) *fakeLookup {
	return &fakeLookup{
		identity:   &authz.Identity{UserID: "u1"},
		membership: &authz.Membership{ID: "m1", UserID: "u1", TeamID: "t1", Roles: roles, Confirmed: true},
	}
}

// requestHeaders mirrors the runtime adapter: JWT and organisation claim are
// plain map entries, with mixed casing to prove the contract is
// case-insensitive.
func requestHeaders(team string) map[string]string {
	h := map[string]string{"X-Appwrite-User-Jwt": "jwt-1"}
	if team != "" {
		h["X-Reparix-Organization-Id"] = team
	}
	return h
}

func domainError(t *testing.T, err error) *httpx.Error {
	t.Helper()
	var he *httpx.Error
	if !errors.As(err, &he) || he == nil {
		t.Fatalf("expected *httpx.Error, got %T: %v", err, err)
	}
	return he
}

func requireStatus(t *testing.T, err error, status int) *httpx.Error {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %d error, got nil", status)
	}
	he := domainError(t, err)
	if he.Status != status {
		t.Fatalf("expected status %d, got %d (%s)", status, he.Status, he.Message)
	}
	return he
}

// TestRequireAnyRoleMatrix pins the role contract: matching is exact and
// case-insensitive, "owner" is not a superuser, unknown roles grant nothing,
// and an empty requirement list denies.
func TestRequireAnyRoleMatrix(t *testing.T) {
	cases := []struct {
		name     string
		held     []string
		required []string
		allow    bool
	}{
		{"owner satisfies owner", []string{"owner"}, []string{"owner"}, true},
		{"owner does not satisfy admin", []string{"owner"}, []string{"admin"}, false},
		{"owner does not satisfy technician", []string{"owner"}, []string{"technician"}, false},
		{"owner alone denies staff union", []string{"owner"}, []string{"admin", "technician", "customer"}, false},
		{"admin does not satisfy owner", []string{"admin"}, []string{"owner"}, false},
		{"admin satisfies admin", []string{"admin"}, []string{"admin"}, true},
		{"technician satisfies any-of", []string{"technician"}, []string{"admin", "technician"}, true},
		{"customer denies staff union", []string{"customer"}, []string{"admin", "owner", "technician"}, false},
		{"no held roles denies", nil, []string{"admin"}, false},
		{"unknown role grants nothing", []string{"banana"}, []string{"owner", "admin", "technician", "customer"}, false},
		{"held role is case-insensitive", []string{"OWNER"}, []string{"owner"}, true},
		{"required role is trimmed", []string{"owner"}, []string{"  owner  "}, true},
		{"empty requirement list denies", []string{"owner"}, nil, false},
		{"blank required role denies", []string{"owner"}, []string{""}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			caller := authz.NewCaller("u1", "t1", "m1", tc.held)
			err := authz.RequireAnyRole(caller, tc.required...)
			if tc.allow {
				if err != nil {
					t.Fatalf("expected allow, got %v", err)
				}
				return
			}
			he := requireStatus(t, err, 403)
			if he.Code != "forbidden" {
				t.Fatalf("denial code must be forbidden, got %q", he.Code)
			}
		})
	}
}

// TestMissingOrganizationContract proves a missing or blank claim is rejected
// as 401 before any membership lookup, independent of the caller's roles.
func TestMissingOrganizationContract(t *testing.T) {
	cases := []struct {
		name    string
		headers map[string]string
	}{
		{"absent", map[string]string{"x-appwrite-user-jwt": "jwt-1"}},
		{"blank", map[string]string{"x-appwrite-user-jwt": "jwt-1", "x-reparix-organization-id": "   "}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lookup := verifiedLookup("owner")
			caller, err := authz.Verify(context.Background(), tc.headers, lookup)
			he := requireStatus(t, err, 401)
			if he.Code != "unauthorized" {
				t.Fatalf("missing claim code must be unauthorized, got %q", he.Code)
			}
			if he.Params["header"] != tenant.OrganizationHeader {
				t.Fatalf("error must identify %q, got %v", tenant.OrganizationHeader, he.Params)
			}
			if !caller.IsZero() {
				t.Fatalf("failed verification must not return a caller: %+v", caller)
			}
			if lookup.membershipCalls != 0 {
				t.Fatal("membership must not be looked up without a claim")
			}
		})
	}
}

// TestForgedOrganizationContract covers a claim the JWT holder cannot back with
// a confirmed membership in that exact team.
func TestForgedOrganizationContract(t *testing.T) {
	t.Run("not a member", func(t *testing.T) {
		lookup := verifiedLookup("owner")
		lookup.membership = nil
		lookup.membershipErr = httpx.Forbidden("caller is not a member of this team", nil)

		caller, err := authz.Verify(context.Background(), requestHeaders("victim-team"), lookup)
		he := requireStatus(t, err, 403)
		if he.Code != "forbidden" {
			t.Fatalf("forged claim code must be forbidden, got %q", he.Code)
		}
		if !caller.IsZero() {
			t.Fatalf("forged claim must not produce a caller: %+v", caller)
		}
		if lookup.gotTeam != "victim-team" || lookup.gotUser != "u1" {
			t.Fatalf("membership must be checked for the verified user and claimed team, got team=%q user=%q", lookup.gotTeam, lookup.gotUser)
		}
	})

	t.Run("mismatched membership", func(t *testing.T) {
		cases := []struct {
			name string
			mem  *authz.Membership
		}{
			{"nil", nil},
			{"other team", &authz.Membership{ID: "m2", UserID: "u1", TeamID: "t2", Roles: []string{"owner"}, Confirmed: true}},
			{"other user", &authz.Membership{ID: "m2", UserID: "u2", TeamID: "t1", Roles: []string{"owner"}, Confirmed: true}},
			{"empty team", &authz.Membership{ID: "m2", UserID: "u1", TeamID: "", Roles: []string{"owner"}, Confirmed: true}},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				lookup := verifiedLookup("owner")
				lookup.membership = tc.mem
				caller, err := authz.Verify(context.Background(), requestHeaders("t1"), lookup)
				he := requireStatus(t, err, 403)
				if he.Message != "membership does not match the caller" {
					t.Fatalf("unexpected message %q", he.Message)
				}
				if !caller.IsZero() {
					t.Fatalf("mismatched membership must not produce a caller: %+v", caller)
				}
			})
		}
	})

	t.Run("crlf claim", func(t *testing.T) {
		lookup := verifiedLookup("owner")
		caller, err := authz.VerifyClaim(context.Background(), requestHeaders(""), "t1\r\nx-injected: 1", lookup)
		requireStatus(t, err, 401)
		if !caller.IsZero() {
			t.Fatal("a header-injection claim must not produce a caller")
		}
		if lookup.membershipCalls != 0 {
			t.Fatal("a header-injection claim must be rejected before membership lookup")
		}
	})
}

// TestUnconfirmedMembershipContract proves a role, even owner, never overrides
// the confirmed-membership requirement.
func TestUnconfirmedMembershipContract(t *testing.T) {
	lookup := verifiedLookup("owner")
	lookup.membership.Confirmed = false

	caller, err := authz.Verify(context.Background(), requestHeaders("t1"), lookup)
	he := requireStatus(t, err, 403)
	if he.Code != "forbidden" || he.Message != "membership is not confirmed" {
		t.Fatalf("unconfirmed membership contract changed: %+v", he)
	}
	if !caller.IsZero() {
		t.Fatalf("unconfirmed membership must not produce a caller: %+v", caller)
	}
}

// TestIdentityIsTakenOnlyFromTheJWT proves the caller identity and tenant come
// from the validated JWT and confirmed membership, never from request-supplied
// user ids.
func TestIdentityIsTakenOnlyFromTheJWT(t *testing.T) {
	headers := requestHeaders(" t1 ")
	headers["X-Appwrite-User-Id"] = "victim-user"
	headers["x-appwrite-user-id"] = "victim-user"

	lookup := verifiedLookup("owner")
	caller, err := authz.Verify(context.Background(), headers, lookup)
	if err != nil {
		t.Fatal(err)
	}
	if lookup.gotJWT != "jwt-1" {
		t.Fatalf("JWT must be read case-insensitively, got %q", lookup.gotJWT)
	}
	if caller.UserID() != "u1" || caller.TeamID() != "t1" || caller.MembershipID() != "m1" {
		t.Fatalf("identity must come from the lookup, got %+v", caller)
	}
	if lookup.gotTeam != "t1" || lookup.gotUser != "u1" {
		t.Fatalf("membership must be checked against the verified user and trimmed claim, got %q %q", lookup.gotTeam, lookup.gotUser)
	}
	if !caller.HasRole("owner") || caller.HasRole("admin") {
		t.Fatalf("verified caller roles are wrong: %v", caller.Roles())
	}
}

// TestCallerValueContract pins the small exported value semantics Functions
// rely on: normalised roles, defensive copies, and id-shape validation as a
// separate explicit step.
func TestCallerValueContract(t *testing.T) {
	roles := []string{" OWNER ", "Admin"}
	caller := authz.NewCaller("u1", "t1", "m1", roles)

	if got := caller.Roles(); len(got) != 2 || got[0] != "owner" || got[1] != "admin" {
		t.Fatalf("roles must be trimmed and lower-cased: %v", got)
	}

	roles[0] = "customer"
	exposed := caller.Roles()
	exposed[0] = "customer"
	if !caller.HasRole("owner") || !caller.HasRole("admin") || caller.HasRole("customer") {
		t.Fatal("caller must not alias or expose its roles")
	}

	if err := authz.RequireValidCaller(caller); err != nil {
		t.Fatalf("valid caller rejected: %v", err)
	}
	for name, bad := range map[string]authz.Caller{
		"bad user id": authz.NewCaller("bad id", "t1", "m1", nil),
		"bad team id": authz.NewCaller("u1", "bad/team", "m1", nil),
		"empty ids":   {},
	} {
		if err := authz.RequireValidCaller(bad); err == nil {
			t.Fatalf("%s must be rejected", name)
		} else if he := domainError(t, err); he.Status != 403 {
			t.Fatalf("%s must be 403, got %d", name, he.Status)
		}
	}
	if !(authz.Caller{}).IsZero() || caller.IsZero() {
		t.Fatal("IsZero must distinguish an unverified caller")
	}
}

// TestLookupFailuresAreStable proves dependency failures are surfaced rather
// than converted into an authenticated or forbidden result.
func TestLookupFailuresAreStable(t *testing.T) {
	t.Run("identity", func(t *testing.T) {
		lookup := verifiedLookup("owner")
		lookup.identity = nil
		lookup.identityErr = httpx.Unauthorized("invalid or expired caller token", nil)
		caller, err := authz.Verify(context.Background(), requestHeaders("t1"), lookup)
		requireStatus(t, err, 401)
		if !caller.IsZero() {
			t.Fatal("identity failure must not produce a caller")
		}

		lookup = verifiedLookup("owner")
		lookup.identity = &authz.Identity{}
		if _, err := authz.Verify(context.Background(), requestHeaders("t1"), lookup); err == nil {
			t.Fatal("empty identity must fail")
		} else {
			requireStatus(t, err, 401)
		}
	})

	t.Run("membership dependency", func(t *testing.T) {
		lookup := verifiedLookup("owner")
		lookup.membership = nil
		lookup.membershipErr = httpx.Upstream("could not verify caller membership", nil)
		caller, err := authz.Verify(context.Background(), requestHeaders("t1"), lookup)
		requireStatus(t, err, 502)
		if !caller.IsZero() {
			t.Fatal("dependency failure must not produce a caller")
		}
	})

	t.Run("nil lookup", func(t *testing.T) {
		caller, err := authz.Verify(context.Background(), requestHeaders("t1"), nil)
		requireStatus(t, err, 502)
		if !caller.IsZero() {
			t.Fatal("missing lookup must fail closed")
		}
	})

	t.Run("missing jwt", func(t *testing.T) {
		caller, err := authz.Verify(context.Background(), map[string]string{tenant.OrganizationHeader: "t1"}, nil)
		he := requireStatus(t, err, 401)
		if he.Params["header"] != authz.JWTHeader {
			t.Fatalf("error must identify %q, got %v", authz.JWTHeader, he.Params)
		}
		if !caller.IsZero() {
			t.Fatal("missing JWT must fail closed even without a lookup")
		}
	})
}

package operator

import (
	"errors"
	"testing"

	"github.com/open-runtimes/types-for-go/v4/openruntimes"

	"github.com/ModdingFriendly/appwrite-library/auth"
	"github.com/ModdingFriendly/appwrite-library/httpx"
)

type fakeLookup struct {
	identity   *auth.Identity
	idErr      error
	membership map[string]*auth.Membership
	memErr     error
}

func (f fakeLookup) CurrentUser(openruntimes.Context) (*auth.Identity, error) {
	return f.identity, f.idErr
}

func (f fakeLookup) Membership(_ openruntimes.Context, teamID, _ string) (*auth.Membership, error) {
	if f.memErr != nil {
		return nil, f.memErr
	}
	if m, ok := f.membership[teamID]; ok {
		return m, nil
	}
	return nil, httpx.Forbidden("caller is not a member of this team", nil)
}

func statusCode(err error) (int, string) {
	var he *httpx.Error
	if errors.As(err, &he) && he != nil {
		return he.Status, he.Code
	}
	return 0, ""
}

func TestRequire(t *testing.T) {
	user := &auth.Identity{UserID: "u1", Name: "Kyle"}
	confirmed := &auth.Membership{UserID: "u1", TeamID: DefaultTeamID, Confirmed: true}
	cases := []struct {
		name   string
		lookup fakeLookup
		status int
		code   string
	}{
		{"operator", fakeLookup{identity: user, membership: map[string]*auth.Membership{DefaultTeamID: confirmed}}, 0, ""},
		{"tenant admin is not an operator", fakeLookup{identity: user, membership: map[string]*auth.Membership{
			"shop-team": {UserID: "u1", TeamID: "shop-team", Roles: []string{"admin", "owner"}, Confirmed: true},
		}}, 403, Code},
		{"unconfirmed invite", fakeLookup{identity: user, membership: map[string]*auth.Membership{
			DefaultTeamID: {UserID: "u1", TeamID: DefaultTeamID},
		}}, 403, Code},
		{"membership for someone else", fakeLookup{identity: user, membership: map[string]*auth.Membership{
			DefaultTeamID: {UserID: "u2", TeamID: DefaultTeamID, Confirmed: true},
		}}, 403, Code},
		{"signed out", fakeLookup{idErr: httpx.Unauthorized("authentication required", nil)}, 401, ""},
		{"upstream failure passes through", fakeLookup{identity: user, memErr: httpx.Upstream("down", nil)}, 502, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			op, err := Require(openruntimes.Context{}, tc.lookup)
			status, code := statusCode(err)
			if tc.status == 0 {
				if err != nil || op == nil || op.UserID != "u1" || op.Name != "Kyle" {
					t.Fatalf("got %+v, %v", op, err)
				}
				return
			}
			if status != tc.status || (tc.code != "" && code != tc.code) {
				t.Fatalf("got %d %q (%v), want %d %q", status, code, err, tc.status, tc.code)
			}
		})
	}
}

func TestTeamIDOverride(t *testing.T) {
	t.Setenv(EnvTeamID, " ops-team ")
	if got := TeamID(); got != "ops-team" {
		t.Fatalf("TeamID = %q", got)
	}
	t.Setenv(EnvTeamID, "")
	if got := TeamID(); got != DefaultTeamID {
		t.Fatalf("TeamID = %q", got)
	}
}

func TestNilLookup(t *testing.T) {
	if _, err := Require(openruntimes.Context{}, nil); err == nil {
		t.Fatal("want error")
	}
}

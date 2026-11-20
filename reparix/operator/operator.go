// Package operator decides whether a caller is a Reparix platform operator
// (PAR-1301).
//
// A platform operator is a confirmed member of one dedicated Appwrite team,
// "reparix-platform-operators" unless REPARIX_OPERATOR_TEAM_ID names another.
// Membership of a tenant team, and any tenant role including admin or the
// Appwrite owner role, is never operator authority. The check is made on the
// server for every operator route, with the caller's own JWT, so it cannot be
// forged by a header or body.
//
// A caller who is not an operator gets 403 operator_required; the response
// does not say whether the operator team exists.
package operator

import (
	"errors"
	"os"
	"strings"

	"github.com/open-runtimes/types-for-go/v4/openruntimes"

	"github.com/ModdingFriendly/appwrite-library/auth"
	"github.com/ModdingFriendly/appwrite-library/httpx"
)

const (
	// DefaultTeamID is the operator team in every Reparix environment.
	DefaultTeamID = "reparix-platform-operators"
	// EnvTeamID overrides the operator team id.
	EnvTeamID = "REPARIX_OPERATOR_TEAM_ID"
	// Code is the error code for a caller who is not an operator.
	Code = "operator_required"
)

// TeamID returns the configured operator team id.
func TeamID() string {
	if v := strings.TrimSpace(os.Getenv(EnvTeamID)); v != "" {
		return v
	}
	return DefaultTeamID
}

// Operator is a verified platform operator.
type Operator struct {
	UserID string
	Name   string
}

// Require verifies the caller's JWT and their confirmed membership of the
// operator team. It returns 401 when the caller is not signed in and 403
// operator_required when they are not an operator.
func Require(ctx openruntimes.Context, lookup auth.Lookup) (*Operator, error) {
	return RequireTeam(ctx, lookup, TeamID())
}

// RequireTeam is Require with an explicit operator team id.
func RequireTeam(ctx openruntimes.Context, lookup auth.Lookup, teamID string) (*Operator, error) {
	if lookup == nil {
		return nil, httpx.Upstream("authentication is not configured", nil)
	}
	identity, err := lookup.CurrentUser(ctx)
	if err != nil {
		return nil, err
	}
	if identity == nil || identity.UserID == "" {
		return nil, httpx.Unauthorized("invalid caller identity", nil)
	}
	membership, err := lookup.Membership(ctx, teamID, identity.UserID)
	if err != nil {
		var he *httpx.Error
		if errors.As(err, &he) && he != nil && (he.Status == 403 || he.Status == 404) {
			return nil, refused()
		}
		return nil, err
	}
	if membership == nil || !membership.Confirmed ||
		membership.UserID != identity.UserID || membership.TeamID != teamID {
		return nil, refused()
	}
	return &Operator{UserID: identity.UserID, Name: identity.Name}, nil
}

func refused() error {
	return &httpx.Error{Status: 403, Code: Code, Message: "This area is for Reparix platform operators."}
}

// Package authz verifies who a caller is and which team they belong to. It is
// deliberately generic: it contains no product role names, route policies or
// guards. A Function decides what a role means with Caller.HasRole or
// RequireAnyRole.
//
// Trust rules:
//   - Identity comes ONLY from the platform JWT, validated with Account.Get()
//     on a JWT-only client. x-appwrite-user-id and body user ids are ignored.
//   - The organisation header is only a lookup key. The same JWT must show a
//     confirmed membership in that team; roles come from that membership.
//   - Anything missing or ambiguous fails closed.
//
// The package imports no OpenRuntimes or Function packages; headers are a plain
// map and calls take context.Context.
package authz

import (
	"context"
	"strings"

	"github.com/ModdingFriendly/appwrite-library/httpx"
	"github.com/ModdingFriendly/appwrite-library/reparix/tenant"
)

const (
	// JWTHeader is injected by the Appwrite runtime for user executions.
	JWTHeader = "x-appwrite-user-jwt"
	// OrganizationHeader is the canonical tenant claim header.
	OrganizationHeader = tenant.OrganizationHeader
)

// Caller is a verified identity. It is an immutable value: all fields are
// unexported and Roles returns a copy. Keep it out of responses.
type Caller struct {
	userID       string
	teamID       string
	membershipID string
	roles        []string
}

// NewCaller builds a Caller from already-verified facts. Roles are trimmed and
// lower-cased.
func NewCaller(userID, teamID, membershipID string, roles []string) Caller {
	clean := make([]string, 0, len(roles))
	for _, role := range roles {
		clean = append(clean, strings.ToLower(strings.TrimSpace(role)))
	}
	return Caller{userID: userID, teamID: teamID, membershipID: membershipID, roles: clean}
}

func (c Caller) UserID() string       { return c.userID }
func (c Caller) TeamID() string       { return c.teamID }
func (c Caller) MembershipID() string { return c.membershipID }

// IsZero reports a Caller that carries no verified identity.
func (c Caller) IsZero() bool { return c.userID == "" && c.teamID == "" }

// Roles returns a copy of the lower-cased roles.
func (c Caller) Roles() []string { return append([]string(nil), c.roles...) }

// HasRole is case-insensitive. It matches exactly: "owner" does not imply any
// other role.
func (c Caller) HasRole(role string) bool {
	for _, r := range c.roles {
		if strings.EqualFold(r, strings.TrimSpace(role)) {
			return true
		}
	}
	return false
}

// RequireAnyRole returns a 403 unless the caller holds at least one of roles.
// With no roles it denies (fail closed).
func RequireAnyRole(c Caller, roles ...string) error {
	for _, role := range roles {
		if c.HasRole(role) {
			return nil
		}
	}
	return httpx.Forbidden("insufficient role for this operation", map[string]any{"required": roles})
}

// Identity is the verified account, before any team is resolved.
type Identity struct{ UserID string }

// Membership is the verified Teams membership.
type Membership struct {
	ID        string
	UserID    string
	TeamID    string
	Roles     []string
	Confirmed bool
}

// Lookup is the verification boundary. Production uses JWTLookup; tests stub
// it. Membership must be called with the UserID returned by CurrentUser.
type Lookup interface {
	CurrentUser(ctx context.Context, jwt string) (*Identity, error)
	Membership(ctx context.Context, jwt, teamID, userID string) (*Membership, error)
}

// Verify resolves the JWT and the claimed team's confirmed membership using
// the canonical organisation header. It applies no role policy.
func Verify(ctx context.Context, headers map[string]string, lookup Lookup) (Caller, error) {
	return VerifyClaim(ctx, headers, tenant.ClaimedOrganization(headers), lookup)
}

// VerifyClaim is Verify with an explicit organisation claim.
//
// Order: missing JWT (401, independent of configuration) → nil lookup (502) →
// identity (401) → missing claim or CR/LF in it (401) → membership (a
// non-member, i.e. a forged organisation, is 403) → membership/identity/team
// mismatch (403) → unconfirmed (403).
func VerifyClaim(ctx context.Context, headers map[string]string, claimedTeamID string, lookup Lookup) (Caller, error) {
	jwt, _ := tenant.Header(headers, JWTHeader)
	if jwt == "" {
		return Caller{}, httpx.Unauthorized("authentication required", map[string]any{"header": JWTHeader})
	}
	if lookup == nil {
		return Caller{}, httpx.Upstream("authentication is not configured", nil)
	}

	identity, err := lookup.CurrentUser(ctx, jwt)
	if err != nil {
		return Caller{}, err
	}
	if identity == nil || identity.UserID == "" {
		return Caller{}, httpx.Unauthorized("invalid caller identity", nil)
	}

	teamID := strings.TrimSpace(claimedTeamID)
	if teamID == "" {
		return Caller{}, httpx.Unauthorized("organization header required", map[string]any{"header": OrganizationHeader})
	}
	if strings.ContainsAny(teamID, "\r\n") {
		return Caller{}, httpx.Unauthorized("invalid organization claim", nil)
	}

	membership, err := lookup.Membership(ctx, jwt, teamID, identity.UserID)
	if err != nil {
		return Caller{}, err
	}
	if membership == nil || membership.UserID != identity.UserID || membership.TeamID != teamID {
		return Caller{}, httpx.Forbidden("membership does not match the caller", nil)
	}
	if !membership.Confirmed {
		return Caller{}, httpx.Forbidden("membership is not confirmed", nil)
	}
	return NewCaller(identity.UserID, membership.TeamID, membership.ID, membership.Roles), nil
}

// RequireValidCaller checks the verified team and user ids have Appwrite id
// shape.
func RequireValidCaller(c Caller) error {
	if !tenant.ValidID(c.teamID) || !tenant.ValidID(c.userID) {
		return httpx.Forbidden("verified caller identity is invalid", nil)
	}
	return nil
}

// Package auth verifies an Appwrite caller's identity and team membership
// using the platform-injected user JWT.
//
// It is deliberately generic: it contains no product role names, tenant header
// names, or application policy. Callers keep their own roles, guards and
// header conventions and use this package only for the verified facts:
//
//   - CurrentUser validates the JWT with Account.Get() using a JWT-only client
//     (no privileged execution key).
//   - Membership lists a team membership with the same JWT, so no API-key scope
//     is needed. Callers must pass the verified UserID returned by CurrentUser,
//     never a request-supplied user id.
//
// Endpoint and project configuration is explicit, either through Config or
// ConfigFromEnv. No endpoint, project or API key is embedded in this package.
package auth

import (
	"errors"
	"os"
	"strings"

	"github.com/appwrite/sdk-for-go/account"
	sdk "github.com/appwrite/sdk-for-go/client"
	"github.com/appwrite/sdk-for-go/query"
	"github.com/appwrite/sdk-for-go/teams"
	"github.com/open-runtimes/types-for-go/v4/openruntimes"

	"github.com/ModdingFriendly/appwrite-library/appwrite"
	"github.com/ModdingFriendly/appwrite-library/httpx"
)

// JWTHeader is the header injected by the Appwrite runtime for user-scoped
// function executions.
const JWTHeader = "x-appwrite-user-jwt"

// Config is the explicit Appwrite connection configuration for JWT lookups.
// It intentionally has no APIKey field: this package must never use the
// privileged function execution key.
type Config struct {
	Endpoint       string
	ProjectID      string
	ResponseFormat string
}

// Validate checks that the endpoint and project are present.
func (c Config) Validate() error {
	if strings.TrimSpace(c.Endpoint) == "" {
		return appwrite.ErrMissingEndpoint
	}
	if strings.TrimSpace(c.ProjectID) == "" {
		return appwrite.ErrMissingProjectID
	}
	return nil
}

// ConfigFromEnv reads the same explicit environment variables as the appwrite
// package. There is no fallback to a hard-coded project or endpoint.
func ConfigFromEnv() Config {
	return Config{
		Endpoint:  firstNonEmpty(os.Getenv(appwrite.EnvEndpoint), os.Getenv(appwrite.EnvFunctionEndpoint)),
		ProjectID: firstNonEmpty(os.Getenv(appwrite.EnvProjectID), os.Getenv(appwrite.EnvFunctionProjectID)),
	}
}

// Identity is the verified account, before any team is resolved.
type Identity struct {
	UserID string
}

// Membership is the verified team membership returned by the Teams API.
type Membership struct {
	ID        string
	UserID    string
	TeamID    string
	Roles     []string
	Confirmed bool
}

// Lookup is the boundary a caller can stub in tests. Production uses
// JWTLookup.
type Lookup interface {
	CurrentUser(ctx openruntimes.Context) (*Identity, error)
	Membership(ctx openruntimes.Context, teamID, userID string) (*Membership, error)
}

// JWTLookup verifies a caller with a JWT-only Appwrite client.
type JWTLookup struct {
	cfg Config
}

// NewJWTLookup builds a lookup from explicit configuration.
func NewJWTLookup(cfg Config) (*JWTLookup, error) {
	cfg.Endpoint = strings.TrimRight(strings.TrimSpace(cfg.Endpoint), "/")
	cfg.ProjectID = strings.TrimSpace(cfg.ProjectID)
	cfg.ResponseFormat = strings.TrimSpace(cfg.ResponseFormat)
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &JWTLookup{cfg: cfg}, nil
}

// NewJWTLookupFromEnv builds a lookup from ConfigFromEnv.
func NewJWTLookupFromEnv() (*JWTLookup, error) {
	return NewJWTLookup(ConfigFromEnv())
}

// CurrentUser validates the platform JWT with Account.Get() and returns the
// verified user id. It never trusts x-appwrite-user-id or a body user_id.
func (l *JWTLookup) CurrentUser(ctx openruntimes.Context) (*Identity, error) {
	clt, err := l.client(ctx)
	if err != nil {
		return nil, err
	}
	user, err := account.New(clt).Get()
	if err != nil {
		return nil, lookupError(ctx, err, "account")
	}
	if user.Id == "" {
		return nil, httpx.Unauthorized("invalid caller identity", nil)
	}
	if !user.Status {
		return nil, httpx.Unauthorized("account is disabled", nil)
	}
	return &Identity{UserID: user.Id}, nil
}

// Membership lists the membership for userID in teamID using the same JWT.
// Callers must pass the verified UserID returned by CurrentUser, never a
// request-supplied user id. A returned membership is not necessarily confirmed;
// policy layers decide whether Confirm is required. Not finding a membership is
// a Forbidden error.
func (l *JWTLookup) Membership(ctx openruntimes.Context, teamID, userID string) (*Membership, error) {
	teamID = strings.TrimSpace(teamID)
	userID = strings.TrimSpace(userID)
	if teamID == "" || userID == "" {
		return nil, httpx.Unauthorized("invalid membership lookup", nil)
	}
	if strings.ContainsAny(teamID, "\r\n") || strings.ContainsAny(userID, "\r\n") {
		return nil, httpx.BadRequest("invalid membership lookup", nil)
	}

	clt, err := l.client(ctx)
	if err != nil {
		return nil, err
	}
	teamsSvc := teams.New(clt)
	res, err := teamsSvc.ListMemberships(teamID,
		teamsSvc.WithListMembershipsQueries([]string{
			query.Equal("userId", userID),
			query.Limit(1),
		}),
	)
	if err != nil {
		return nil, lookupError(ctx, err, "membership")
	}
	for _, m := range res.Memberships {
		if m.UserId != userID {
			continue
		}
		if m.TeamId != "" && m.TeamId != teamID {
			continue
		}
		return &Membership{
			ID:        m.Id,
			UserID:    m.UserId,
			TeamID:    teamID,
			Roles:     append([]string(nil), m.Roles...),
			Confirmed: m.Confirm,
		}, nil
	}
	// The Teams API only returns memberships visible to this caller; not finding
	// one means the caller is not a member of this team.
	return nil, httpx.Forbidden("caller is not a member of this team", nil)
}

func (l *JWTLookup) client(ctx openruntimes.Context) (sdk.Client, error) {
	jwt := Header(ctx, JWTHeader)
	if jwt == "" {
		return sdk.Client{}, httpx.Unauthorized("authentication required", map[string]any{"header": JWTHeader})
	}
	if l == nil {
		return sdk.Client{}, httpx.Upstream("authentication is not configured", nil)
	}

	// appwrite.NewClient validates and normalises endpoint/project. The zero
	// APIKey is intentional: this is a JWT-only client, never a privileged one.
	clt, err := appwrite.NewClient(appwrite.Config{
		Endpoint:       l.cfg.Endpoint,
		ProjectID:      l.cfg.ProjectID,
		ResponseFormat: l.cfg.ResponseFormat,
	})
	if err != nil {
		return sdk.Client{}, httpx.Upstream("authentication is not configured", nil)
	}
	clt.AddHeader("X-Appwrite-JWT", jwt)
	return clt, nil
}

func lookupError(ctx openruntimes.Context, err error, stage string) error {
	var ae *sdk.AppwriteError
	if errors.As(err, &ae) {
		switch ae.GetStatusCode() {
		case 401:
			return httpx.Unauthorized("invalid or expired caller token", nil)
		case 403, 404:
			if stage == "membership" {
				return httpx.Forbidden("caller is not a member of this team", nil)
			}
			return httpx.Unauthorized("invalid or expired caller token", nil)
		}
	}
	// Log the provider detail internally; never expose it to the caller.
	ctx.Error("auth: " + stage + " lookup failed: " + err.Error())
	message := "could not verify caller identity"
	if stage == "membership" {
		message = "could not verify caller membership"
	}
	return httpx.Upstream(message, map[string]any{"stage": stage})
}

// Header reads a request header case-insensitively. Appwrite normally
// lower-cases request headers, but callers may run this package in tests or
// gateways that preserve case.
func Header(ctx openruntimes.Context, name string) string {
	if value, ok := ctx.Req.Headers[name]; ok {
		return strings.TrimSpace(value)
	}
	for key, value := range ctx.Req.Headers {
		if strings.EqualFold(key, name) {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}

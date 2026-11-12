package authz

import (
	"context"
	"errors"
	"strings"

	"github.com/appwrite/sdk-for-go/account"
	sdk "github.com/appwrite/sdk-for-go/client"
	"github.com/appwrite/sdk-for-go/query"
	"github.com/appwrite/sdk-for-go/teams"

	"github.com/ModdingFriendly/appwrite-library/appwrite"
	"github.com/ModdingFriendly/appwrite-library/httpx"
)

// JWTLookup is the production Lookup: a JWT-only Appwrite client (never an API
// key) that calls Account.Get() and Teams.ListMemberships with the caller's
// own permissions. It inherits the hardened appwrite transport.
type JWTLookup struct {
	cfg appwrite.Config
	// Log receives private operator diagnostics. Nil discards them.
	Log func(string)
}

// NewJWTLookup builds a lookup from explicit endpoint/project configuration.
// Any APIKey or DatabaseID in cfg is discarded.
func NewJWTLookup(cfg appwrite.Config) (*JWTLookup, error) {
	cfg = appwrite.Config{
		Endpoint:       strings.TrimRight(strings.TrimSpace(cfg.Endpoint), "/"),
		ProjectID:      strings.TrimSpace(cfg.ProjectID),
		ResponseFormat: strings.TrimSpace(cfg.ResponseFormat),
	}
	if cfg.Endpoint == "" {
		return nil, appwrite.ErrMissingEndpoint
	}
	if cfg.ProjectID == "" {
		return nil, appwrite.ErrMissingProjectID
	}
	return &JWTLookup{cfg: cfg}, nil
}

func (l *JWTLookup) client(jwt string) (sdk.Client, error) {
	if l == nil {
		return sdk.Client{}, httpx.Upstream("authentication is not configured", nil)
	}
	if jwt == "" {
		return sdk.Client{}, httpx.Unauthorized("authentication required", map[string]any{"header": JWTHeader})
	}
	clt, err := appwrite.NewClient(l.cfg)
	if err != nil {
		return sdk.Client{}, httpx.Upstream("authentication is not configured", nil)
	}
	clt.AddHeader("X-Appwrite-JWT", jwt)
	return clt, nil
}

func (l *JWTLookup) logf(msg string) {
	if l != nil && l.Log != nil {
		l.Log(msg)
	}
}

// CurrentUser validates the JWT with Account.Get().
func (l *JWTLookup) CurrentUser(_ context.Context, jwt string) (*Identity, error) {
	clt, err := l.client(jwt)
	if err != nil {
		return nil, err
	}
	user, err := account.New(clt).Get()
	if err != nil {
		return nil, l.lookupError(err, "account")
	}
	if user.Id == "" {
		return nil, httpx.Unauthorized("invalid caller identity", nil)
	}
	if !user.Status {
		return nil, httpx.Unauthorized("account is disabled", nil)
	}
	return &Identity{UserID: user.Id}, nil
}

// Membership lists userID's membership in teamID using the caller's JWT. Not
// finding one is a 403.
func (l *JWTLookup) Membership(_ context.Context, jwt, teamID, userID string) (*Membership, error) {
	teamID, userID = strings.TrimSpace(teamID), strings.TrimSpace(userID)
	if teamID == "" || userID == "" {
		return nil, httpx.Unauthorized("invalid membership lookup", nil)
	}
	if strings.ContainsAny(teamID, "\r\n") || strings.ContainsAny(userID, "\r\n") {
		return nil, httpx.BadRequest("invalid membership lookup", nil)
	}
	clt, err := l.client(jwt)
	if err != nil {
		return nil, err
	}
	svc := teams.New(clt)
	res, err := svc.ListMemberships(teamID, svc.WithListMembershipsQueries([]string{
		query.Equal("userId", userID),
		query.Limit(1),
	}))
	if err != nil {
		return nil, l.lookupError(err, "membership")
	}
	for _, m := range res.Memberships {
		if m.UserId != userID || (m.TeamId != "" && m.TeamId != teamID) {
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
	return nil, httpx.Forbidden("caller is not a member of this team", nil)
}

func (l *JWTLookup) lookupError(err error, stage string) error {
	var ae *sdk.AppwriteError
	if errors.As(err, &ae) && ae != nil {
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
	l.logf("authz: " + stage + " lookup failed: " + err.Error())
	message := "could not verify caller identity"
	if stage == "membership" {
		message = "could not verify caller membership"
	}
	return httpx.Upstream(message, map[string]any{"stage": stage})
}

package apikeys

// Scoped API keys: management endpoints (T98) and the reusable verifier (T99).
//
// This package owns the security policy; package handler owns the route table
// and supplies the product authorizer/organisation authority through New, so
// the routes stay in main.go and this package never imports the root package.
//
// Route contract (wired in the root adapter, each handler self-guards, so the
// router must call it directly):
//
//	POST /staff/api-keys         Service.Create
//	GET  /staff/api-keys         Service.List
//	POST /staff/api-keys/rotate  Service.Rotate
//	POST /staff/api-keys/revoke  Service.Revoke
//	GET  /staff/api-keys/usage   Service.Usage
//
// Management trust rules:
//   - The injected Authorizer resolves a platform JWT, a confirmed team
//     membership and the admin role. A body tenant is never accepted.
//   - The organisation must be a provisioned `organizations` row, so a
//     self-created Appwrite team cannot mint keys.
//   - Every query is filtered by the verified team. A key id from another
//     organisation is a 404, so these routes are not a tenant oracle.
//   - Only HMAC-SHA256(pepper, secret) is stored. Plaintext is returned exactly
//     once (create/rotate) and never appears in list/usage responses, errors or
//     function logs.
//
// Key format: rpx_live_<keyId>_<secret>
//   - keyId is an 8-character base62 public lookup id.
//   - secret is a 32-character base62 CSPRNG value.
//   - the displayed prefix is rpx_live_ plus six keyId characters (15 chars),
//     which fits the key_prefix varchar(16) column.
//
// Verification (T99) lives in verify.go. It resolves the key by its public
// key id alone and takes the organisation from the stored row, never from a
// request header: the key's own tenant is the only authority. It then rejects
// inactive/revoked/expired keys, compares the HMAC in constant time, enforces
// the per-key rate limit and returns a typed principal with scopes. The route
// adapters in package handler wire it to the four row-gateway routes only.

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	sdk "github.com/appwrite/sdk-for-go/client"
	"github.com/open-runtimes/types-for-go/v4/openruntimes"

	"github.com/ModdingFriendly/appwrite-library/appwrite"
	"github.com/ModdingFriendly/appwrite-library/httpx"
)

const (
	apiKeysTable = "api_keys"
	apiLogsTable = "api_logs"

	// APIKeyPepperEnv is the Function Variable holding the server-side HMAC
	// pepper. When it is unset, issuance and verification fail closed.
	APIKeyPepperEnv = "REPARIX_API_KEY_PEPPER"

	apiKeyEnvLive = "live"

	apiKeyTokenScheme    = "Bearer "
	apiKeyTokenPrefix    = "rpx"
	apiKeyIDLength       = 8
	apiKeySecretLength   = 32
	apiKeyIDAttempts     = 3
	apiKeyMaxScopes      = 20
	apiKeyMaxNameRunes   = 255
	apiKeyMaxLifetimeDay = 365
	apiKeyListLimit      = 200
	apiKeyUsageLimit     = 50

	defaultRequestsPerMinute = 10
	defaultRequestsPerHour   = 100
	maxRequestsPerMinute     = 600
	maxRequestsPerHour       = 10000

	apiKeyStatusActive  = "active"
	apiKeyStatusExpired = "expired"
	apiKeyStatusRevoked = "revoked"

	// apiKeyLegacyPlaceholder keeps the legacy NOT NULL api_key column
	// satisfied without storing credential material. The column is cleared by
	// T101 once every plaintext key has been revoked and reissued.
	apiKeyLegacyPlaceholder = "[hash-only]"

	apiKeyUsageMissingNote = "api_logs is not provisioned; no usage history is available"

	// roleAdmin mirrors the product admin role name. The value is part of the
	// error contract; the root package owns role resolution.
	roleAdmin = "admin"
)

var (
	// errAPILogsTableMissing is a private store signal, never returned directly.
	errAPILogsTableMissing = errors.New("api_logs table is not provisioned")

	apiKeyBase62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

	// apiKeyScopeAllowlist is intentionally explicit and excludes wildcards.
	apiKeyScopeAllowlist = []string{
		"tickets:read", "tickets:write",
		"customers:read", "customers:write",
		"inventory:read", "inventory:write",
		"invoices:read", "invoices:write",
		"quotes:read", "quotes:write",
		"bookings:read", "bookings:write",
		"messages:read", "messages:write",
		"reports:read",
		"webhooks:manage",
		// Row-gateway scopes. These gate /staff/rows/{create,update,delete,list}
		// for machine callers; the gateway still applies its own table/field
		// policy and tenant checks after the key is verified.
		"rows.read", "rows.write",
	}
	apiKeyScopeAllowed = func() map[string]struct{} {
		out := make(map[string]struct{}, len(apiKeyScopeAllowlist))
		for _, scope := range apiKeyScopeAllowlist {
			out[scope] = struct{}{}
		}
		return out
	}()
)

// apiKeyRow is the server-side projection of an api_keys row. Rate-limit and
// last-used fields are optional so the code keeps working whether or not those
// additive columns exist yet.
type apiKeyRow struct {
	ID                string `json:"$id"`
	Name              string `json:"key_name"`
	OrgID             string `json:"organization_id"`
	Prefix            string `json:"key_prefix"`
	KeyID             string `json:"key_id"`
	SecretHash        string `json:"secret_hash"`
	Scopes            string `json:"scopes"`
	CreatedBy         string `json:"created_by_user_id"`
	RevokedBy         string `json:"revoked_by_user_id"`
	RevokedAt         string `json:"revoked_at"`
	ExpiresAt         string `json:"expires_at"`
	LastUsedAt        string `json:"last_used_at"`
	RequestsPerMinute int    `json:"requests_per_minute"`
	RequestsPerHour   int    `json:"requests_per_hour"`
	IsActive          bool   `json:"is_active"`
	CreatedAt         string `json:"$createdAt"`
}

// apiKeyStore is the persistence seam. Production uses appwriteAPIKeyStore.
type apiKeyStore interface {
	List(ctx openruntimes.Context, orgID string) ([]apiKeyRow, error)
	Find(ctx openruntimes.Context, orgID, keyID string) (*apiKeyRow, error)
	// FindByKeyID is the verifier lookup: it is deliberately not tenant-scoped
	// because the request has no trusted tenant yet. The returned row's
	// organization_id is the authority for the rest of the request.
	FindByKeyID(ctx openruntimes.Context, keyID string) (*apiKeyRow, error)
	Create(ctx openruntimes.Context, orgID string, data map[string]any, permissions []string) (*apiKeyRow, error)
	Update(ctx openruntimes.Context, orgID, rowID string, data map[string]any) (*apiKeyRow, error)
	ListUsage(ctx openruntimes.Context, orgID, keyID string, limit int) ([]apiLogRow, error)
	// RecordUse writes last_used_at and one metadata-only api_logs row.
	RecordUse(ctx openruntimes.Context, use APIKeyUse) error
}

// Caller is the verified identity project this package needs. The root package
// converts its own AuthCaller into this shape, so the domain package stays
// independent of the product auth implementation.
type Caller struct {
	UserID string
	TeamID string
	Roles  []string
}

// IsAdmin reports whether the verified membership carries the admin role.
func (c *Caller) IsAdmin() bool {
	if c == nil {
		return false
	}
	for _, role := range c.Roles {
		if strings.EqualFold(role, roleAdmin) {
			return true
		}
	}
	return false
}

// Authorizer verifies the caller. Production wiring is AuthorizeAdmin.
type Authorizer func(openruntimes.Context) (*Caller, error)

// OrganizationLookup verifies that a team is a provisioned organisation row.
type OrganizationLookup func(teamID string) (bool, error)

type apiKeyDeps struct {
	authorize    Authorizer
	organization OrganizationLookup
	store        apiKeyStore
	now          func() time.Time
	pepper       string
}

func (d apiKeyDeps) withDefaults() apiKeyDeps {
	if d.authorize == nil {
		d.authorize = func(openruntimes.Context) (*Caller, error) {
			// Fail closed: a request without an injected authorizer is denied.
			return nil, httpx.Unauthorized("authentication required", nil)
		}
	}
	if d.organization == nil {
		d.organization = func(teamID string) (bool, error) {
			// withDefaults has no context; New sets this explicitly.
			return false, nil
		}
	}
	if d.store == nil {
		d.store = appwriteAPIKeyStore{}
	}
	if d.now == nil {
		d.now = func() time.Time { return time.Now().UTC() }
	}
	if d.pepper == "" {
		d.pepper = strings.TrimSpace(os.Getenv(APIKeyPepperEnv))
	}
	return d
}

// Service is the API-key management surface. Build one per execution with New;
// it is cheap and stateless apart from the injected dependencies.
type Service struct {
	deps apiKeyDeps
}

// New wires the production dependencies for one execution. The root adapter
// supplies the product authorizer and the organisation-registration authority;
// store, clock and pepper come from the runtime environment.
func New(authorize Authorizer, organization OrganizationLookup) *Service {
	return &Service{deps: apiKeyDeps{
		authorize:    authorize,
		organization: organization,
		store:        appwriteAPIKeyStore{},
		now:          func() time.Time { return time.Now().UTC() },
		pepper:       strings.TrimSpace(os.Getenv(APIKeyPepperEnv)),
	}}
}

// Create issues a key and returns the plaintext exactly once.
func (s *Service) Create(ctx openruntimes.Context, req *APIKeyCreateRequest) (*APIKeyCreateResponse, error) {
	return apiKeyCreateWith(ctx, req, s.deps)
}

// List returns metadata only; it never contains secret material.
func (s *Service) List(ctx openruntimes.Context, req *struct{}) (*APIKeyListResponse, error) {
	return apiKeyListWith(ctx, s.deps)
}

// Rotate replaces the stored hash and invalidates the previous secret.
func (s *Service) Rotate(ctx openruntimes.Context, req *APIKeyRotateRequest) (*APIKeyRotateResponse, error) {
	return apiKeyRotateWith(ctx, req, s.deps)
}

// Revoke deactivates a key. Repeating it is idempotent.
func (s *Service) Revoke(ctx openruntimes.Context, req *APIKeyRevokeRequest) (*APIKeyRevokeResponse, error) {
	return apiKeyRevokeWith(ctx, req, s.deps)
}

// Usage returns the tenant-filtered audit entries for one key.
func (s *Service) Usage(ctx openruntimes.Context, req *APIKeyUsageRequest) (*APIKeyUsageResponse, error) {
	return apiKeyUsageWith(ctx, req, s.deps)
}

// APIKeyCreateRequest is the complete create contract. There is no tenant,
// row id, hash or ACL field.
type APIKeyCreateRequest struct {
	Name              string   `json:"name"`
	Scopes            []string `json:"scopes"`
	ExpiresAt         string   `json:"expires_at,omitempty"`
	RequestsPerMinute int      `json:"requests_per_minute,omitempty"`
	RequestsPerHour   int      `json:"requests_per_hour,omitempty"`
}

// APIKeyCreateResponse carries the only copy of the plaintext key.
type APIKeyCreateResponse struct {
	OK                bool     `json:"ok"`
	ID                string   `json:"id"`
	Key               string   `json:"key"`
	KeyID             string   `json:"key_id"`
	Prefix            string   `json:"prefix"`
	Name              string   `json:"name"`
	OrganizationID    string   `json:"organization_id"`
	Scopes            []string `json:"scopes"`
	ExpiresAt         string   `json:"expires_at,omitempty"`
	RequestsPerMinute int      `json:"requests_per_minute"`
	RequestsPerHour   int      `json:"requests_per_hour"`
	CreatedAt         string   `json:"created_at,omitempty"`
}

// APIKeyMetadata is the list projection. It never contains secret_hash, the
// plaintext key, the legacy api_key column or any body data.
type APIKeyMetadata struct {
	ID                string   `json:"id"`
	Name              string   `json:"name"`
	KeyID             string   `json:"key_id"`
	Prefix            string   `json:"prefix"`
	Scopes            []string `json:"scopes"`
	Status            string   `json:"status"`
	LastUsedAt        string   `json:"last_used_at,omitempty"`
	ExpiresAt         string   `json:"expires_at,omitempty"`
	RevokedAt         string   `json:"revoked_at,omitempty"`
	RequestsPerMinute int      `json:"requests_per_minute,omitempty"`
	RequestsPerHour   int      `json:"requests_per_hour,omitempty"`
	CreatedAt         string   `json:"created_at,omitempty"`
}

type APIKeyListResponse struct {
	OK   bool             `json:"ok"`
	Keys []APIKeyMetadata `json:"keys"`
}

type APIKeyRotateRequest struct {
	KeyID string `json:"key_id"`
}

type APIKeyRotateResponse struct {
	OK             bool     `json:"ok"`
	ID             string   `json:"id"`
	Key            string   `json:"key"`
	KeyID          string   `json:"key_id"`
	Prefix         string   `json:"prefix"`
	Scopes         []string `json:"scopes"`
	ExpiresAt      string   `json:"expires_at,omitempty"`
	RotatedAt      string   `json:"rotated_at"`
	OrganizationID string   `json:"organization_id"`
}

type APIKeyRevokeRequest struct {
	KeyID string `json:"key_id"`
}

type APIKeyRevokeResponse struct {
	OK             bool   `json:"ok"`
	ID             string `json:"id"`
	KeyID          string `json:"key_id"`
	Status         string `json:"status"`
	AlreadyRevoked bool   `json:"already_revoked"`
	RevokedAt      string `json:"revoked_at,omitempty"`
	OrganizationID string `json:"organization_id"`
}

// APIKeyUsageRequest binds the usage key id from the query string because the
// route is a GET.
type APIKeyUsageRequest struct {
	KeyID string
}

func (r *APIKeyUsageRequest) Bind(ctx openruntimes.Context) error {
	r.KeyID = ctx.Req.Query["key_id"]
	return nil
}

type APIKeyUsageEntry struct {
	ID        string `json:"id,omitempty"`
	At        string `json:"at,omitempty"`
	Method    string `json:"method,omitempty"`
	Path      string `json:"path,omitempty"`
	Status    int    `json:"status,omitempty"`
	IPAddress string `json:"ip_address,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`
}

type APIKeyUsageResponse struct {
	OK      bool               `json:"ok"`
	KeyID   string             `json:"key_id"`
	Entries []APIKeyUsageEntry `json:"entries"`
	Note    string             `json:"note,omitempty"`
}

func apiKeyCreateWith(ctx openruntimes.Context, req *APIKeyCreateRequest, deps apiKeyDeps) (*APIKeyCreateResponse, error) {
	deps = deps.withDefaults()
	caller, err := beginAPIKeyManagement(ctx, deps)
	if err != nil {
		return nil, err
	}
	if deps.pepper == "" {
		return nil, httpx.Upstream("API key issuance is not configured", nil)
	}
	now := deps.now().UTC()
	input, err := normalizeAPIKeyCreate(req, now)
	if err != nil {
		return nil, err
	}

	for attempt := 0; attempt < apiKeyIDAttempts; attempt++ {
		keyID, err := randomAPIKeyToken(apiKeyIDLength)
		if err != nil {
			return nil, httpx.Upstream("could not generate an API key", nil)
		}
		secret, err := randomAPIKeyToken(apiKeySecretLength)
		if err != nil {
			return nil, httpx.Upstream("could not generate an API key", nil)
		}
		plaintext := apiKeyPlaintext(keyID, secret)
		data := map[string]any{
			"key_name":            input.Name,
			"api_key":             apiKeyLegacyPlaceholder,
			"key_prefix":          apiKeyPrefix(keyID),
			"key_id":              keyID,
			"secret_hash":         hashAPIKeySecret(deps.pepper, secret),
			"scopes":              strings.Join(input.Scopes, ","),
			"organization_id":     caller.TeamID,
			"created_by_user_id":  caller.UserID,
			"is_active":           true,
			"requests_per_minute": input.RequestsPerMinute,
			"requests_per_hour":   input.RequestsPerHour,
		}
		if input.ExpiresAt != "" {
			data["expires_at"] = input.ExpiresAt
		}

		row, err := deps.store.Create(ctx, caller.TeamID, data, []string{})
		if err != nil {
			// The unique (organization_id, key_id) index is the only expected
			// create conflict; retry with a fresh public id.
			if appwriteErrorStatus(err) == 409 && attempt+1 < apiKeyIDAttempts {
				continue
			}
			return nil, err
		}
		if row == nil {
			return nil, httpx.Upstream("API key was not created", nil)
		}

		// Audit at the metadata level only. Never log the secret or hash.
		ctx.Log("api-keys: created key_id=" + keyID + " organization_id=" + caller.TeamID + " actor=" + caller.UserID)
		return &APIKeyCreateResponse{
			OK:                true,
			ID:                row.ID,
			Key:               plaintext,
			KeyID:             keyID,
			Prefix:            apiKeyPrefix(keyID),
			Name:              input.Name,
			OrganizationID:    caller.TeamID,
			Scopes:            input.Scopes,
			ExpiresAt:         input.ExpiresAt,
			RequestsPerMinute: input.RequestsPerMinute,
			RequestsPerHour:   input.RequestsPerHour,
			CreatedAt:         row.CreatedAt,
		}, nil
	}
	return nil, httpx.Conflict("could not allocate a unique API key id", nil)
}

func apiKeyListWith(ctx openruntimes.Context, deps apiKeyDeps) (*APIKeyListResponse, error) {
	deps = deps.withDefaults()
	caller, err := beginAPIKeyManagement(ctx, deps)
	if err != nil {
		return nil, err
	}
	rows, err := deps.store.List(ctx, caller.TeamID)
	if err != nil {
		return nil, err
	}
	now := deps.now().UTC()
	out := make([]APIKeyMetadata, 0, len(rows))
	for _, row := range rows {
		if row.OrgID != caller.TeamID {
			// The store must org-filter; this is defense in depth. A row
			// without a tenant is never shown to an arbitrary admin.
			continue
		}
		out = append(out, apiKeyMetadataFromRow(&row, now))
	}
	return &APIKeyListResponse{OK: true, Keys: out}, nil
}

func apiKeyRotateWith(ctx openruntimes.Context, req *APIKeyRotateRequest, deps apiKeyDeps) (*APIKeyRotateResponse, error) {
	deps = deps.withDefaults()
	caller, err := beginAPIKeyManagement(ctx, deps)
	if err != nil {
		return nil, err
	}
	if deps.pepper == "" {
		return nil, httpx.Upstream("API key issuance is not configured", nil)
	}
	keyID, err := normalizeAPIKeyKeyID(apiKeyRequestKeyID(req))
	if err != nil {
		return nil, err
	}

	row, err := deps.store.Find(ctx, caller.TeamID, keyID)
	if err != nil {
		return nil, err
	}
	if row == nil || row.ID == "" || row.OrgID != caller.TeamID || row.KeyID != keyID {
		return nil, httpx.NotFound("API key not found", nil)
	}
	if apiKeyIsRevoked(row) {
		return nil, httpx.Conflict("revoked API keys cannot be rotated", map[string]any{"key_id": keyID})
	}
	now := deps.now().UTC()
	if apiKeyExpired(row.ExpiresAt, now) {
		return nil, httpx.Conflict("expired API keys cannot be rotated; create a new key", map[string]any{"key_id": keyID})
	}

	secret, err := randomAPIKeyToken(apiKeySecretLength)
	if err != nil {
		return nil, httpx.Upstream("could not generate an API key", nil)
	}
	// Replacing the only stored hash invalidates the previous secret
	// immediately. There is deliberately no grace window (single hash column).
	updated, err := deps.store.Update(ctx, caller.TeamID, row.ID, map[string]any{
		"secret_hash": hashAPIKeySecret(deps.pepper, secret),
	})
	if err != nil {
		return nil, err
	}
	if updated == nil {
		updated = row
	}

	ctx.Log("api-keys: rotated key_id=" + keyID + " organization_id=" + caller.TeamID + " actor=" + caller.UserID)
	return &APIKeyRotateResponse{
		OK:             true,
		ID:             row.ID,
		Key:            apiKeyPlaintext(keyID, secret),
		KeyID:          keyID,
		Prefix:         apiKeyPrefix(keyID),
		Scopes:         splitAPIKeyScopes(updated.Scopes),
		ExpiresAt:      updated.ExpiresAt,
		RotatedAt:      now.Format(time.RFC3339),
		OrganizationID: caller.TeamID,
	}, nil
}

func apiKeyRevokeWith(ctx openruntimes.Context, req *APIKeyRevokeRequest, deps apiKeyDeps) (*APIKeyRevokeResponse, error) {
	deps = deps.withDefaults()
	caller, err := beginAPIKeyManagement(ctx, deps)
	if err != nil {
		return nil, err
	}
	keyID, err := normalizeAPIKeyKeyID(apiKeyRevokeKeyID(req))
	if err != nil {
		return nil, err
	}

	row, err := deps.store.Find(ctx, caller.TeamID, keyID)
	if err != nil {
		return nil, err
	}
	if row == nil || row.ID == "" || row.OrgID != caller.TeamID || row.KeyID != keyID {
		return nil, httpx.NotFound("API key not found", nil)
	}
	if apiKeyIsRevoked(row) {
		return &APIKeyRevokeResponse{
			OK:             true,
			ID:             row.ID,
			KeyID:          keyID,
			Status:         apiKeyStatusRevoked,
			AlreadyRevoked: true,
			RevokedAt:      row.RevokedAt,
			OrganizationID: caller.TeamID,
		}, nil
	}

	now := deps.now().UTC()
	revokedAt := now.Format(time.RFC3339)
	updated, err := deps.store.Update(ctx, caller.TeamID, row.ID, map[string]any{
		"revoked_at":         revokedAt,
		"revoked_by_user_id": caller.UserID,
		"is_active":          false,
	})
	if err != nil {
		return nil, err
	}
	if updated != nil && updated.RevokedAt != "" {
		revokedAt = updated.RevokedAt
	}

	ctx.Log("api-keys: revoked key_id=" + keyID + " organization_id=" + caller.TeamID + " actor=" + caller.UserID)
	return &APIKeyRevokeResponse{
		OK:             true,
		ID:             row.ID,
		KeyID:          keyID,
		Status:         apiKeyStatusRevoked,
		AlreadyRevoked: false,
		RevokedAt:      revokedAt,
		OrganizationID: caller.TeamID,
	}, nil
}

func apiKeyUsageWith(ctx openruntimes.Context, req *APIKeyUsageRequest, deps apiKeyDeps) (*APIKeyUsageResponse, error) {
	deps = deps.withDefaults()
	caller, err := beginAPIKeyManagement(ctx, deps)
	if err != nil {
		return nil, err
	}
	keyID, err := normalizeAPIKeyKeyID(apiKeyUsageRequestKeyID(req))
	if err != nil {
		return nil, err
	}
	row, err := deps.store.Find(ctx, caller.TeamID, keyID)
	if err != nil {
		return nil, err
	}
	if row == nil || row.ID == "" || row.OrgID != caller.TeamID || row.KeyID != keyID {
		return nil, httpx.NotFound("API key not found", nil)
	}

	rows, err := deps.store.ListUsage(ctx, caller.TeamID, keyID, apiKeyUsageLimit)
	if err != nil {
		if errors.Is(err, errAPILogsTableMissing) {
			return &APIKeyUsageResponse{
				OK:      true,
				KeyID:   keyID,
				Entries: []APIKeyUsageEntry{},
				Note:    apiKeyUsageMissingNote,
			}, nil
		}
		return nil, err
	}
	entries := make([]APIKeyUsageEntry, 0, len(rows))
	for _, entry := range rows {
		if entry.OrgID != "" && entry.OrgID != caller.TeamID {
			continue
		}
		if entry.APIKeyID != "" && entry.APIKeyID != keyID && entry.KeyID != keyID {
			continue
		}
		if entry.APIKeyID == "" && entry.KeyID == "" {
			continue
		}
		entries = append(entries, apiKeyUsageEntryFromRow(&entry))
	}
	return &APIKeyUsageResponse{OK: true, KeyID: keyID, Entries: entries}, nil
}

// beginAPIKeyManagement applies the shared management policy after the
// injected authorizer: verified admin identity and a provisioned organisation.
func beginAPIKeyManagement(ctx openruntimes.Context, deps apiKeyDeps) (*Caller, error) {
	caller, err := deps.authorize(ctx)
	if err != nil {
		return nil, err
	}
	if caller == nil {
		return nil, httpx.Unauthorized("authentication required", nil)
	}
	if !validRowID(strings.TrimSpace(caller.TeamID)) || !validRowID(strings.TrimSpace(caller.UserID)) {
		return nil, httpx.Forbidden("verified caller identity is invalid", nil)
	}
	if !caller.IsAdmin() {
		return nil, httpx.Forbidden("admin role required", map[string]any{"required": roleAdmin})
	}
	if err := requireRegisteredOrganization(caller.TeamID, deps.organization); err != nil {
		return nil, err
	}
	return caller, nil
}

// normalizedAPIKeyCreate is the validated, server-normalised create input.
type normalizedAPIKeyCreate struct {
	Name              string
	Scopes            []string
	ExpiresAt         string
	RequestsPerMinute int
	RequestsPerHour   int
}

func normalizeAPIKeyCreate(req *APIKeyCreateRequest, now time.Time) (*normalizedAPIKeyCreate, error) {
	if req == nil {
		return nil, httpx.BadRequest("request body is required", nil)
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return nil, httpx.BadRequest("name is required", map[string]any{"field": "name"})
	}
	if utf8.RuneCountInString(name) > apiKeyMaxNameRunes {
		return nil, httpx.BadRequest("name is too long", map[string]any{"field": "name", "max": apiKeyMaxNameRunes})
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return nil, httpx.BadRequest("name contains control characters", map[string]any{"field": "name"})
		}
	}

	scopes, err := validateAPIKeyScopes(req.Scopes)
	if err != nil {
		return nil, err
	}
	expiresAt, err := normalizeAPIKeyExpiry(req.ExpiresAt, now)
	if err != nil {
		return nil, err
	}
	perMinute, perHour, err := normalizeAPIKeyRateLimits(req.RequestsPerMinute, req.RequestsPerHour)
	if err != nil {
		return nil, err
	}
	return &normalizedAPIKeyCreate{
		Name:              name,
		Scopes:            scopes,
		ExpiresAt:         expiresAt,
		RequestsPerMinute: perMinute,
		RequestsPerHour:   perHour,
	}, nil
}

func validateAPIKeyScopes(input []string) ([]string, error) {
	if len(input) == 0 {
		return nil, httpx.BadRequest("at least one scope is required", map[string]any{"field": "scopes"})
	}
	if len(input) > apiKeyMaxScopes {
		return nil, httpx.BadRequest("too many scopes", map[string]any{"field": "scopes", "max": apiKeyMaxScopes})
	}
	seen := make(map[string]struct{}, len(input))
	out := make([]string, 0, len(input))
	for _, raw := range input {
		scope := strings.TrimSpace(raw)
		if scope == "" {
			return nil, httpx.BadRequest("scope may not be empty", map[string]any{"field": "scopes"})
		}
		if _, allowed := apiKeyScopeAllowed[scope]; !allowed {
			return nil, httpx.Forbidden("scope is not allowed", map[string]any{"field": "scopes", "scope": scope})
		}
		if _, duplicate := seen[scope]; duplicate {
			continue
		}
		seen[scope] = struct{}{}
		out = append(out, scope)
	}
	if len(out) == 0 {
		return nil, httpx.BadRequest("at least one scope is required", map[string]any{"field": "scopes"})
	}
	if len(strings.Join(out, ",")) > 500 {
		return nil, httpx.BadRequest("scopes exceed the storage limit", map[string]any{"field": "scopes", "max_bytes": 500})
	}
	return out, nil
}

func normalizeAPIKeyExpiry(raw string, now time.Time) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	expires, ok := parseAPIKeyTime(raw)
	if !ok {
		return "", httpx.BadRequest("invalid expires_at", map[string]any{"field": "expires_at"})
	}
	if !expires.After(now) {
		return "", httpx.BadRequest("expires_at must be in the future", map[string]any{"field": "expires_at"})
	}
	if expires.After(now.Add(apiKeyMaxLifetimeDay * 24 * time.Hour)) {
		return "", httpx.BadRequest("expires_at exceeds the maximum key lifetime", map[string]any{
			"field":    "expires_at",
			"max_days": apiKeyMaxLifetimeDay,
		})
	}
	return expires.UTC().Format(time.RFC3339), nil
}

func normalizeAPIKeyRateLimits(perMinute, perHour int) (int, int, error) {
	if perMinute == 0 {
		perMinute = defaultRequestsPerMinute
	}
	if perHour == 0 {
		perHour = defaultRequestsPerHour
		if perMinute > perHour {
			perHour = perMinute
		}
	}
	if perMinute < 1 || perMinute > maxRequestsPerMinute {
		return 0, 0, httpx.BadRequest("invalid requests_per_minute", map[string]any{
			"field": "requests_per_minute", "min": 1, "max": maxRequestsPerMinute,
		})
	}
	if perHour < 1 || perHour > maxRequestsPerHour {
		return 0, 0, httpx.BadRequest("invalid requests_per_hour", map[string]any{
			"field": "requests_per_hour", "min": 1, "max": maxRequestsPerHour,
		})
	}
	if perMinute > perHour {
		return 0, 0, httpx.BadRequest("requests_per_minute may not exceed requests_per_hour", map[string]any{
			"field": "requests_per_minute",
		})
	}
	return perMinute, perHour, nil
}

func apiKeyRequestKeyID(req *APIKeyRotateRequest) string {
	if req == nil {
		return ""
	}
	return req.KeyID
}

func apiKeyUsageRequestKeyID(req *APIKeyUsageRequest) string {
	if req == nil {
		return ""
	}
	return req.KeyID
}

func apiKeyRevokeKeyID(req *APIKeyRevokeRequest) string {
	if req == nil {
		return ""
	}
	return req.KeyID
}

func normalizeAPIKeyKeyID(raw string) (string, error) {
	keyID := strings.TrimSpace(raw)
	if keyID == "" {
		return "", httpx.BadRequest("key_id is required", map[string]any{"field": "key_id"})
	}
	if !validAPIKeyID(keyID) {
		return "", httpx.BadRequest("invalid key_id", map[string]any{"field": "key_id"})
	}
	return keyID, nil
}

func apiKeyMetadataFromRow(row *apiKeyRow, now time.Time) APIKeyMetadata {
	return APIKeyMetadata{
		ID:                row.ID,
		Name:              row.Name,
		KeyID:             row.KeyID,
		Prefix:            row.Prefix,
		Scopes:            splitAPIKeyScopes(row.Scopes),
		Status:            apiKeyStatus(row, now),
		LastUsedAt:        row.LastUsedAt,
		ExpiresAt:         row.ExpiresAt,
		RevokedAt:         row.RevokedAt,
		RequestsPerMinute: row.RequestsPerMinute,
		RequestsPerHour:   row.RequestsPerHour,
		CreatedAt:         row.CreatedAt,
	}
}

func apiKeyUsageEntryFromRow(row *apiLogRow) APIKeyUsageEntry {
	path := row.Endpoint
	if path == "" {
		path = row.Path
	}
	status := row.Status
	if status == 0 {
		status = row.HTTPStatus
	}
	at := row.CreatedAt
	if at == "" {
		at = row.CreatedAtLegacy
	}
	return APIKeyUsageEntry{
		ID:        row.ID,
		At:        at,
		Method:    row.Method,
		Path:      path,
		Status:    status,
		IPAddress: row.IPAddress,
		UserAgent: row.UserAgent,
	}
}

func apiKeyStatus(row *apiKeyRow, now time.Time) string {
	if row == nil {
		return ""
	}
	if apiKeyIsRevoked(row) {
		return apiKeyStatusRevoked
	}
	if apiKeyExpired(row.ExpiresAt, now) {
		return apiKeyStatusExpired
	}
	return apiKeyStatusActive
}

func apiKeyIsRevoked(row *apiKeyRow) bool {
	if row == nil {
		return true
	}
	return !row.IsActive || strings.TrimSpace(row.RevokedAt) != ""
}

func apiKeyExpired(raw string, now time.Time) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return false
	}
	expires, ok := parseAPIKeyTime(raw)
	if !ok {
		// An unparseable expiry fails closed.
		return true
	}
	return !expires.After(now)
}

func parseAPIKeyTime(raw string) (time.Time, bool) {
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05.999999999",
		"2006-01-02T15:04:05",
		"2006-01-02",
	}
	for _, layout := range layouts {
		if parsed, err := time.Parse(layout, raw); err == nil {
			return parsed, true
		}
	}
	return time.Time{}, false
}

func splitAPIKeyScopes(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return []string{}
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		scope := strings.TrimSpace(part)
		if scope == "" {
			continue
		}
		if _, duplicate := seen[scope]; duplicate {
			continue
		}
		seen[scope] = struct{}{}
		out = append(out, scope)
	}
	return out
}

func apiKeyPrefix(keyID string) string {
	short := keyID
	if len(short) > 6 {
		short = short[:6]
	}
	return apiKeyTokenPrefix + "_" + apiKeyEnvLive + "_" + short
}

func apiKeyPlaintext(keyID, secret string) string {
	return apiKeyTokenPrefix + "_" + apiKeyEnvLive + "_" + keyID + "_" + secret
}

func validAPIKeyID(keyID string) bool {
	if len(keyID) < 4 || len(keyID) > 32 {
		return false
	}
	for _, r := range keyID {
		if !strings.ContainsRune(apiKeyBase62, r) {
			return false
		}
	}
	return true
}

// randomAPIKeyToken returns n unbiased base62 characters from crypto/rand.
func randomAPIKeyToken(n int) (string, error) {
	if n <= 0 {
		return "", errors.New("invalid token length")
	}
	out := make([]byte, n)
	// Rejection sampling keeps the distribution uniform: 256 % 62 != 0, so
	// bytes >= 248 are discarded instead of folded.
	buf := make([]byte, n*2)
	filled := 0
	for filled < n {
		if _, err := rand.Read(buf); err != nil {
			return "", err
		}
		for _, b := range buf {
			if int(b) >= 248 {
				continue
			}
			out[filled] = apiKeyBase62[int(b)%len(apiKeyBase62)]
			filled++
			if filled == n {
				break
			}
		}
	}
	return string(out), nil
}

// hashAPIKeySecret returns HMAC-SHA256(pepper, secret) as lowercase hex.
func hashAPIKeySecret(pepper, secret string) string {
	mac := hmac.New(sha256.New, []byte(pepper))
	_, _ = mac.Write([]byte(secret))
	return hex.EncodeToString(mac.Sum(nil))
}

// apiKeySecretMatches compares the expected HMAC with the stored hash in
// constant time. Missing inputs never match.
func apiKeySecretMatches(pepper, secret, storedHash string) bool {
	if pepper == "" || secret == "" || storedHash == "" {
		return false
	}
	expected := hashAPIKeySecret(pepper, secret)
	return hmac.Equal([]byte(expected), []byte(storedHash))
}

// apiLogRow is the usage projection. Body-bearing legacy columns
// (request_data/response_message) are intentionally not decoded.
type apiLogRow struct {
	ID              string `json:"$id"`
	OrgID           string `json:"organization_id"`
	APIKeyID        string `json:"api_key_id"`
	KeyID           string `json:"key_id"`
	Method          string `json:"method"`
	Endpoint        string `json:"endpoint"`
	Path            string `json:"path"`
	Status          int    `json:"response_code"`
	HTTPStatus      int    `json:"status"`
	IPAddress       string `json:"ip_address"`
	UserAgent       string `json:"user_agent"`
	CreatedAt       string `json:"$createdAt"`
	CreatedAtLegacy string `json:"created_at"`
}

// appwriteAPIKeyStore is the production adapter. Every read is tenant-filtered.
type appwriteAPIKeyStore struct{}

func (appwriteAPIKeyStore) List(ctx openruntimes.Context, orgID string) ([]apiKeyRow, error) {
	page, err := appwrite.List[apiKeyRow](ctx, apiKeysTable,
		appwrite.Equal("organization_id", orgID),
		appwrite.OrderDesc("$createdAt"),
		appwrite.Limit(apiKeyListLimit),
	)
	if err != nil {
		return nil, err
	}
	if page == nil {
		return []apiKeyRow{}, nil
	}
	return page.Rows, nil
}

func (appwriteAPIKeyStore) Find(ctx openruntimes.Context, orgID, keyID string) (*apiKeyRow, error) {
	page, err := appwrite.List[apiKeyRow](ctx, apiKeysTable,
		appwrite.Equal("organization_id", orgID),
		appwrite.Equal("key_id", keyID),
		appwrite.Limit(2),
	)
	if err != nil {
		return nil, err
	}
	if page == nil || len(page.Rows) == 0 {
		return nil, nil
	}
	if len(page.Rows) > 1 {
		return nil, httpx.Upstream("API key lookup returned multiple rows", nil)
	}
	return &page.Rows[0], nil
}

// FindByKeyID resolves a key without a tenant filter. The verifier has no
// trusted tenant before the lookup, so the row's organization_id becomes the
// authority. key_id is only unique per organisation, so more than one match is
// ambiguous and must fail closed rather than pick a tenant.
func (appwriteAPIKeyStore) FindByKeyID(ctx openruntimes.Context, keyID string) (*apiKeyRow, error) {
	page, err := appwrite.List[apiKeyRow](ctx, apiKeysTable,
		appwrite.Equal("key_id", keyID),
		appwrite.Limit(2),
	)
	if err != nil {
		return nil, err
	}
	if page == nil || len(page.Rows) == 0 {
		return nil, nil
	}
	if len(page.Rows) > 1 {
		return nil, errAPIKeyAmbiguous
	}
	return &page.Rows[0], nil
}

// RecordUse updates last_used_at and appends one api_logs row. Only routing
// metadata is stored: never a request/response body, the plaintext key or the
// secret hash. A missing api_logs table is reported as errAPILogsTableMissing
// so the caller can keep the request working without inventing history.
func (appwriteAPIKeyStore) RecordUse(ctx openruntimes.Context, use APIKeyUse) error {
	if !validRowID(strings.TrimSpace(use.KeyRowID)) || !validRowID(strings.TrimSpace(use.OrganizationID)) {
		return httpx.Forbidden("API key usage record is invalid", nil)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := appwrite.Update[apiKeyRow](ctx, apiKeysTable, use.KeyRowID, map[string]any{
		"last_used_at": now,
	}); err != nil {
		return err
	}
	_, err := appwrite.Create[apiLogRow](ctx, apiLogsTable, map[string]any{
		"organization_id": use.OrganizationID,
		"api_key_id":      use.KeyID,
		"endpoint":        truncateAPIKeyField(use.Endpoint, 255),
		"method":          truncateAPIKeyField(use.Method, 10),
		"response_code":   use.Status,
		"ip_address":      truncateAPIKeyField(use.IPAddress, 45),
		"user_agent":      truncateAPIKeyField(use.UserAgent, 255),
	}, []string{})
	if err != nil {
		if appwriteErrorStatus(err) == 404 {
			return errAPILogsTableMissing
		}
		return err
	}
	return nil
}

func (appwriteAPIKeyStore) Create(ctx openruntimes.Context, _ string, data map[string]any, permissions []string) (*apiKeyRow, error) {
	return appwrite.Create[apiKeyRow](ctx, apiKeysTable, data, permissions)
}

func (appwriteAPIKeyStore) Update(ctx openruntimes.Context, _ string, rowID string, data map[string]any) (*apiKeyRow, error) {
	return appwrite.Update[apiKeyRow](ctx, apiKeysTable, rowID, data)
}

func (appwriteAPIKeyStore) ListUsage(ctx openruntimes.Context, orgID, keyID string, limit int) ([]apiLogRow, error) {
	page, err := appwrite.List[apiLogRow](ctx, apiLogsTable,
		appwrite.Equal("organization_id", orgID),
		appwrite.OrderDesc("$createdAt"),
		appwrite.Limit(limit),
	)
	if err != nil {
		// A missing api_logs table is not an error for callers: usage history
		// is optional. Every other failure is surfaced.
		if appwriteErrorStatus(err) == 404 {
			return nil, errAPILogsTableMissing
		}
		return nil, err
	}
	if page == nil {
		return []apiLogRow{}, nil
	}
	out := make([]apiLogRow, 0, len(page.Rows))
	for _, row := range page.Rows {
		if row.OrgID != "" && row.OrgID != orgID {
			continue
		}
		if row.APIKeyID != keyID && row.KeyID != keyID {
			continue
		}
		out = append(out, row)
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}

// apiKeyRowIDPattern mirrors the Appwrite row-id contract. It is applied only
// to verified caller ids supplied by the injected authorizer.
var apiKeyRowIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,35}$`)

func validRowID(rowID string) bool {
	return apiKeyRowIDPattern.MatchString(rowID)
}

// requireRegisteredOrganization fails closed unless the verified team has a
// provisioned organisations row. The lookup is supplied by the root adapter.
func requireRegisteredOrganization(teamID string, lookup OrganizationLookup) error {
	if lookup == nil {
		return httpx.Upstream("organisation registration check is unavailable", nil)
	}
	registered, err := lookup(teamID)
	if err != nil {
		return err
	}
	if !registered {
		return httpx.Forbidden("organisation is not provisioned", map[string]any{"field": "organization_id"})
	}
	return nil
}

// appwriteErrorStatus maps a storage error to its HTTP status when known. This
// stays local to the pilot slice; the planned shared apperr package will own it
// once another domain package needs the same mapping.
func appwriteErrorStatus(err error) int {
	var ae *sdk.AppwriteError
	if errors.As(err, &ae) {
		return ae.GetStatusCode()
	}
	var he *httpx.Error
	if errors.As(err, &he) {
		return he.Status
	}
	return 0
}

package apikeys

// Machine-key verification (T99).
//
// Trust rules, in order:
//   - The bearer token is parsed strictly: rpx_<env>_<keyId>_<secret>.
//   - The key is resolved by its public key id ALONE. A request header such as
//     x-reparix-organization-id is only an optional assertion; it is never the
//     lookup scope. The organization_id stored on the key row is the single
//     tenant authority for the request.
//   - More than one row for the same key id is ambiguous across tenants and
//     fails closed.
//   - Revoked, inactive, expired and unparseable-expiry keys are rejected with
//     the same 401 as a wrong secret, so the route is not a key-state oracle.
//   - The secret is compared as HMAC-SHA256(pepper, secret) with hmac.Equal,
//     never with ==.
//   - A missing pepper fails closed with 503 before any lookup.
//   - Rate limits come from the key row and are consumed only after the secret
//     proves valid, so unauthenticated guesses cannot exhaust a real key's
//     budget.
//   - Scope failures are 403 and a claimed organisation mismatch is 403.
//   - Usage recording stores metadata only: no bodies, plaintext or hashes.

import (
	"errors"
	"math"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/open-runtimes/types-for-go/v4/openruntimes"

	"github.com/ModdingFriendly/appwrite-library/httpx"
)

// errAPIKeyAmbiguous reports that one public key id exists in more than one
// organisation. It is mapped to a generic 401, never to a tenant choice.
var errAPIKeyAmbiguous = errors.New("API key id is ambiguous across organisations")

// APIKeyPrincipal is the trusted result of API key verification. It is bound to
// exactly one organisation and carries only the scopes on the key row.
type APIKeyPrincipal struct {
	KeyID          string
	RowID          string
	OrganizationID string
	Scopes         []string
	Environment    string
	ExpiresAt      string
}

func (p *APIKeyPrincipal) HasScope(scope string) bool {
	if p == nil {
		return false
	}
	if scope == "" {
		return true
	}
	for _, candidate := range p.Scopes {
		if candidate == scope {
			return true
		}
	}
	return false
}

func (p *APIKeyPrincipal) RequireScope(scope string) error {
	if p.HasScope(scope) {
		return nil
	}
	return httpx.Forbidden("API key is missing the required scope", map[string]any{"required_scope": scope})
}

// APIKeyVerifyOptions describes the target route.
//
// ClaimedOrganizationID is the optional, untrusted x-reparix-organization-id
// header. When present it must equal the key's stored organisation; it never
// selects the lookup scope. RequiredScope may be empty for a metadata-only
// machine route.
type APIKeyVerifyOptions struct {
	ClaimedOrganizationID string
	RequiredScope         string
}

// APIKeyLookup resolves a key by its public key id. Implementations must return
// errAPIKeyAmbiguous when more than one organisation row matches.
type APIKeyLookup func(openruntimes.Context, string) (*apiKeyRow, error)

// APIKeyUse is the metadata recorded for one verified machine request. It never
// carries a request/response body or credential material.
type APIKeyUse struct {
	KeyRowID       string
	KeyID          string
	OrganizationID string
	Method         string
	Endpoint       string
	Status         int
	IPAddress      string
	UserAgent      string
}

// APIKeyUseRecorder persists last_used_at plus one api_logs row.
type APIKeyUseRecorder func(openruntimes.Context, APIKeyUse) error

// APIKeyVerifier is reusable and safe for concurrent use. Its rate limiter is
// in-memory per function instance, as specified by T99.
type APIKeyVerifier struct {
	lookup  APIKeyLookup
	record  APIKeyUseRecorder
	now     func() time.Time
	pepper  string
	limiter *apiKeyRateLimiter
}

// NewAPIKeyVerifier builds a verifier from the runtime environment. The
// instance is shared per function execution isolate by package handler; the
// rate limiter is intentionally process-local.
func NewAPIKeyVerifier() *APIKeyVerifier {
	return &APIKeyVerifier{
		lookup:  liveAPIKeyLookup,
		record:  liveAPIKeyUseRecorder,
		now:     func() time.Time { return time.Now().UTC() },
		pepper:  strings.TrimSpace(os.Getenv(APIKeyPepperEnv)),
		limiter: defaultAPIKeyRateLimiter,
	}
}

func (v *APIKeyVerifier) Verify(ctx openruntimes.Context, authorization string, opts APIKeyVerifyOptions) (*APIKeyPrincipal, error) {
	if v == nil {
		return nil, apiKeyUnavailableError()
	}
	// Configuration comes first: an unset pepper denies every machine request
	// with 503 rather than falling back to some weaker check.
	if strings.TrimSpace(v.pepper) == "" {
		return nil, apiKeyUnavailableError()
	}
	if v.lookup == nil {
		return nil, apiKeyUnavailableError()
	}

	token, err := parseAPIKeyAuthorization(authorization)
	if err != nil {
		return nil, err
	}

	row, err := v.lookup(ctx, token.KeyID)
	if err != nil {
		if errors.Is(err, errAPIKeyAmbiguous) {
			return nil, apiKeyInvalidError()
		}
		return nil, err
	}
	now := time.Now().UTC()
	if v.now != nil {
		now = v.now().UTC()
	}

	// Missing, malformed, revoked, expired and wrong-secret keys all produce
	// the same 401 so a caller cannot use these routes as a key-state oracle.
	// Tenant and scope violations (403) are only reported to a caller who has
	// already proved possession of the secret.
	if row == nil || row.ID == "" {
		ctx.Log("api-keys: verify rejected: key not found")
		return nil, apiKeyInvalidError()
	}
	if row.KeyID != token.KeyID {
		ctx.Log("api-keys: verify rejected: key id mismatch")
		return nil, apiKeyInvalidError()
	}
	orgID := strings.TrimSpace(row.OrgID)
	if orgID == "" {
		ctx.Log("api-keys: verify rejected: key row has no organisation")
		return nil, apiKeyInvalidError()
	}
	if apiKeyIsRevoked(row) {
		ctx.Log("api-keys: verify rejected: key inactive or revoked")
		return nil, apiKeyInvalidError()
	}
	if apiKeyExpired(row.ExpiresAt, now) {
		ctx.Log("api-keys: verify rejected: key expired")
		return nil, apiKeyInvalidError()
	}

	// Authenticate before revealing a tenant mismatch or spending the key's
	// rate-limit budget: an unauthenticated caller who merely knows the public
	// key id gets the same 401 and cannot exhaust a real integration's quota.
	if !apiKeySecretMatches(v.pepper, token.Secret, row.SecretHash) {
		ctx.Log("api-keys: verify rejected: secret mismatch")
		return nil, apiKeyInvalidError()
	}

	claimed := strings.TrimSpace(opts.ClaimedOrganizationID)
	if claimed != "" && claimed != orgID {
		// A key can never act on another tenant, even when the caller presents
		// a valid secret. This is a tenant-boundary violation, not a bad
		// credential.
		return nil, httpx.Forbidden("API key does not belong to this organisation", map[string]any{
			"field": "organization_id",
		})
	}

	limiter := v.limiter
	if limiter == nil {
		limiter = defaultAPIKeyRateLimiter
	}
	perMinute := row.RequestsPerMinute
	if perMinute <= 0 {
		perMinute = defaultRequestsPerMinute
	}
	perHour := row.RequestsPerHour
	if perHour <= 0 {
		perHour = defaultRequestsPerHour
	}
	allowed, retryAfter := limiter.allow(row.KeyID, perMinute, perHour, now)
	if !allowed {
		return nil, &httpx.Error{
			Status:  429,
			Code:    "rate_limited",
			Message: "API key rate limit exceeded",
			Params:  map[string]any{"retry_after_seconds": int(math.Ceil(retryAfter.Seconds()))},
		}
	}

	principal := &APIKeyPrincipal{
		KeyID:          row.KeyID,
		RowID:          row.ID,
		OrganizationID: orgID,
		Scopes:         splitAPIKeyScopes(row.Scopes),
		Environment:    token.Environment,
		ExpiresAt:      row.ExpiresAt,
	}
	if err := principal.RequireScope(opts.RequiredScope); err != nil {
		return nil, err
	}
	return principal, nil
}

// Record persists one metadata-only usage entry. Callers treat a recording
// failure as audit noise, never as an authentication failure: the request has
// already been authorized.
func (v *APIKeyVerifier) Record(ctx openruntimes.Context, use APIKeyUse) error {
	if v == nil || v.record == nil {
		return nil
	}
	return v.record(ctx, use)
}

func apiKeyInvalidError() error {
	return httpx.Unauthorized("invalid API key", nil)
}

// apiKeyUnavailableError is the fail-closed response when the pepper or the
// verifier dependency is missing. It is deliberately distinct from 401 so an
// operator can see a misconfiguration instead of silently locking every
// integration out as "invalid key".
func apiKeyUnavailableError() error {
	return &httpx.Error{
		Status:  503,
		Code:    "api_key_unavailable",
		Message: "API key verification is not configured",
	}
}

type apiKeyToken struct {
	Environment string
	KeyID       string
	Secret      string
}

func parseAPIKeyAuthorization(header string) (*apiKeyToken, error) {
	header = strings.TrimSpace(header)
	if header == "" {
		return nil, apiKeyInvalidError()
	}
	parts := strings.Fields(header)
	// `Bearer <token>` is the documented form. A bare token is accepted from
	// the dedicated x-reparix-api-key header, where no scheme prefix is needed.
	if len(parts) == 1 {
		return parseAPIKeyToken(parts[0])
	}
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
		return nil, apiKeyInvalidError()
	}
	return parseAPIKeyToken(parts[1])
}

func parseAPIKeyToken(raw string) (*apiKeyToken, error) {
	parts := strings.Split(strings.TrimSpace(raw), "_")
	if len(parts) != 4 || parts[0] != apiKeyTokenPrefix {
		return nil, apiKeyInvalidError()
	}
	env := parts[1]
	// test keys are accepted by the parser; production issuance is always live.
	if env != apiKeyEnvLive && env != "test" {
		return nil, apiKeyInvalidError()
	}
	keyID := parts[2]
	if !validAPIKeyID(keyID) {
		return nil, apiKeyInvalidError()
	}
	secret := parts[3]
	if len(secret) < 16 || len(secret) > 128 {
		return nil, apiKeyInvalidError()
	}
	for _, r := range secret {
		if !strings.ContainsRune(apiKeyBase62, r) {
			return nil, apiKeyInvalidError()
		}
	}
	return &apiKeyToken{Environment: env, KeyID: keyID, Secret: secret}, nil
}

// apiKeyRateLimiter is an in-memory fixed-window limiter per key id. Appwrite
// may run more than one function instance, so this is a best-effort local
// guard, not a global quota.
type apiKeyRateLimiter struct {
	mu      sync.Mutex
	entries map[string]*apiKeyRateWindow
}

type apiKeyRateWindow struct {
	minuteStart time.Time
	minuteCount int
	hourStart   time.Time
	hourCount   int
	lastSeen    time.Time
}

var defaultAPIKeyRateLimiter = newAPIKeyRateLimiter()

func newAPIKeyRateLimiter() *apiKeyRateLimiter {
	return &apiKeyRateLimiter{entries: make(map[string]*apiKeyRateWindow)}
}

// allow counts a request and reports whether it fits both windows. retryAfter
// is the time until the blocked window resets.
func (l *apiKeyRateLimiter) allow(keyID string, perMinute, perHour int, now time.Time) (bool, time.Duration) {
	if keyID == "" {
		return false, time.Minute
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if perMinute <= 0 {
		perMinute = defaultRequestsPerMinute
	}
	if perHour <= 0 {
		perHour = defaultRequestsPerHour
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.entries == nil {
		l.entries = make(map[string]*apiKeyRateWindow)
	}
	l.pruneLocked(now)

	entry, ok := l.entries[keyID]
	if !ok {
		entry = &apiKeyRateWindow{minuteStart: now, hourStart: now}
		l.entries[keyID] = entry
	}
	if now.Sub(entry.minuteStart) >= time.Minute {
		entry.minuteStart = now
		entry.minuteCount = 0
	}
	if now.Sub(entry.hourStart) >= time.Hour {
		entry.hourStart = now
		entry.hourCount = 0
	}
	entry.lastSeen = now

	if entry.minuteCount >= perMinute {
		return false, entry.minuteStart.Add(time.Minute).Sub(now)
	}
	if entry.hourCount >= perHour {
		return false, entry.hourStart.Add(time.Hour).Sub(now)
	}
	entry.minuteCount++
	entry.hourCount++
	return true, 0
}

func (l *apiKeyRateLimiter) pruneLocked(now time.Time) {
	if len(l.entries) <= 1024 {
		return
	}
	cutoff := now.Add(-2 * time.Hour)
	for key, entry := range l.entries {
		if entry.lastSeen.Before(cutoff) {
			delete(l.entries, key)
		}
	}
}

// liveAPIKeyLookup is the production lookup used by APIKeyVerifier.
func liveAPIKeyLookup(ctx openruntimes.Context, keyID string) (*apiKeyRow, error) {
	return appwriteAPIKeyStore{}.FindByKeyID(ctx, keyID)
}

// liveAPIKeyUseRecorder is the production usage writer.
func liveAPIKeyUseRecorder(ctx openruntimes.Context, use APIKeyUse) error {
	return appwriteAPIKeyStore{}.RecordUse(ctx, use)
}

// truncateAPIKeyField bounds a value to its storage column without splitting a
// UTF-8 sequence.
func truncateAPIKeyField(value string, max int) string {
	value = strings.TrimSpace(value)
	if max <= 0 || len(value) <= max {
		return value
	}
	cut := max
	for cut > 0 && (value[cut]&0xC0) == 0x80 {
		cut--
	}
	return strings.TrimSpace(value[:cut])
}

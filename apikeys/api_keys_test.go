package apikeys

// API key tests (T98/T99).
//
// The handler tests inject the authorizer, the organisation lookup, the store
// and the clock, so they assert behaviour without Appwrite access:
//   - create validation (name, scopes, expiry, rate limits);
//   - the plaintext is returned once and only the HMAC is stored;
//   - list/usage responses never contain the hash or plaintext;
//   - admin + provisioned-organisation policy;
//   - cross-tenant key ids are 404s;
//   - rotation invalidates the previous secret immediately;
//   - revocation is idempotent;
//   - verification rejects inactive/expired/revoked keys and wrong secrets;
//   - scope checks and per-key rate limits;
//   - constant-time comparison behaviour and no secrets in errors.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/open-runtimes/types-for-go/v4/openruntimes"

	"github.com/ModdingFriendly/appwrite-library/httpx"
)

const (
	// roleTechnician mirrors the product technician role name for the
	// non-admin denial case.
	roleTechnician = "technician"

	apiKeyTestTeam   = "team-a"
	apiKeyTestOther  = "team-b"
	apiKeyTestUser   = "user-admin"
	apiKeyTestPepper = "test-pepper-not-a-real-secret"
)

var apiKeyTestNow = time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)

type apiKeyTestStore struct {
	mu sync.Mutex

	rows  map[string]*apiKeyRow
	order []string

	createCalls int
	updateCalls int
	updates     []map[string]any
	createErr   error

	usage    []apiLogRow
	usageErr error
	uses     []APIKeyUse
}

func newAPIKeyTestStore() *apiKeyTestStore {
	return &apiKeyTestStore{rows: make(map[string]*apiKeyRow)}
}

func (s *apiKeyTestStore) put(row *apiKeyRow) {
	s.mu.Lock()
	defer s.mu.Unlock()
	copied := *row
	s.rows[row.ID] = &copied
	s.order = append(s.order, row.ID)
}

func (s *apiKeyTestStore) List(_ openruntimes.Context, orgID string) ([]apiKeyRow, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]apiKeyRow, 0, len(s.order))
	for i := len(s.order) - 1; i >= 0; i-- {
		row := s.rows[s.order[i]]
		if row != nil && row.OrgID == orgID {
			out = append(out, *row)
		}
	}
	return out, nil
}

func (s *apiKeyTestStore) Find(_ openruntimes.Context, orgID, keyID string) (*apiKeyRow, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, row := range s.rows {
		if row.OrgID == orgID && row.KeyID == keyID {
			copied := *row
			return &copied, nil
		}
	}
	return nil, nil
}

// FindByKeyID mirrors the production verifier lookup: no tenant filter, and two
// rows with the same public id are ambiguous rather than a tenant choice.
func (s *apiKeyTestStore) FindByKeyID(_ openruntimes.Context, keyID string) (*apiKeyRow, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var found *apiKeyRow
	for _, row := range s.rows {
		if row.KeyID != keyID {
			continue
		}
		if found != nil {
			return nil, errAPIKeyAmbiguous
		}
		copied := *row
		found = &copied
	}
	return found, nil
}

func (s *apiKeyTestStore) RecordUse(_ openruntimes.Context, use APIKeyUse) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.uses = append(s.uses, use)
	row, ok := s.rows[use.KeyRowID]
	if !ok || row.OrgID != use.OrganizationID {
		return httpx.NotFound("API key not found", nil)
	}
	row.LastUsedAt = apiKeyTestNow.Format(time.RFC3339)
	return nil
}

func (s *apiKeyTestStore) Create(_ openruntimes.Context, orgID string, data map[string]any, _ []string) (*apiKeyRow, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.createCalls++
	if s.createErr != nil {
		return nil, s.createErr
	}
	keyID := stringField(data, "key_id")
	row := &apiKeyRow{
		ID:                "row-" + keyID,
		Name:              stringField(data, "key_name"),
		OrgID:             orgID,
		Prefix:            stringField(data, "key_prefix"),
		KeyID:             keyID,
		SecretHash:        stringField(data, "secret_hash"),
		Scopes:            stringField(data, "scopes"),
		CreatedBy:         stringField(data, "created_by_user_id"),
		ExpiresAt:         stringField(data, "expires_at"),
		RequestsPerMinute: int(int64Field(data, "requests_per_minute")),
		RequestsPerHour:   int(int64Field(data, "requests_per_hour")),
		IsActive:          apiKeyTestBool(data, "is_active"),
		CreatedAt:         apiKeyTestNow.Format(time.RFC3339),
	}
	copied := *row
	s.rows[row.ID] = &copied
	s.order = append(s.order, row.ID)
	return row, nil
}

func (s *apiKeyTestStore) Update(_ openruntimes.Context, orgID, rowID string, data map[string]any) (*apiKeyRow, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.updateCalls++
	patch := make(map[string]any, len(data))
	for key, value := range data {
		patch[key] = value
	}
	s.updates = append(s.updates, patch)

	row, ok := s.rows[rowID]
	if !ok || row.OrgID != orgID {
		return nil, httpx.NotFound("API key not found", nil)
	}
	if value := stringField(data, "secret_hash"); value != "" {
		row.SecretHash = value
	}
	if value := stringField(data, "revoked_at"); value != "" {
		row.RevokedAt = value
	}
	if value := stringField(data, "revoked_by_user_id"); value != "" {
		row.RevokedBy = value
	}
	if value, present := data["is_active"].(bool); present {
		row.IsActive = value
	}
	copied := *row
	return &copied, nil
}

func (s *apiKeyTestStore) ListUsage(_ openruntimes.Context, orgID, keyID string, limit int) ([]apiLogRow, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.usageErr != nil {
		return nil, s.usageErr
	}
	out := make([]apiLogRow, 0, len(s.usage))
	for _, row := range s.usage {
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

func apiKeyTestBool(data map[string]any, key string) bool {
	value, _ := data[key].(bool)
	return value
}

func apiKeyTestAdmin(userID, teamID string) *Caller {
	return &Caller{
		UserID: userID,
		TeamID: teamID,
		Roles:  []string{roleAdmin},
	}
}

func apiKeyTestDeps(store apiKeyStore, caller *Caller) apiKeyDeps {
	return apiKeyDeps{
		authorize: func(openruntimes.Context) (*Caller, error) {
			return caller, nil
		},
		organization: func(string) (bool, error) { return true, nil },
		store:        store,
		now:          func() time.Time { return apiKeyTestNow },
		pepper:       apiKeyTestPepper,
	}
}

func apiKeyTestVerifier(store *apiKeyTestStore, now func() time.Time) *APIKeyVerifier {
	return &APIKeyVerifier{
		lookup:  store.FindByKeyID,
		record:  store.RecordUse,
		now:     now,
		pepper:  apiKeyTestPepper,
		limiter: newAPIKeyRateLimiter(),
	}
}

func validAPIKeyCreateRequest() *APIKeyCreateRequest {
	return &APIKeyCreateRequest{
		Name:              "Warehouse integration",
		Scopes:            []string{"tickets:read", "inventory:read"},
		ExpiresAt:         apiKeyTestNow.Add(30 * 24 * time.Hour).Format(time.RFC3339),
		RequestsPerMinute: 20,
		RequestsPerHour:   200,
	}
}

func createAPIKeyForTest(t *testing.T, store *apiKeyTestStore, deps apiKeyDeps) *APIKeyCreateResponse {
	t.Helper()
	res, err := apiKeyCreateWith(testContext(apiKeyTestTeam, "jwt"), validAPIKeyCreateRequest(), deps)
	if err != nil {
		t.Fatalf("create API key: %v", err)
	}
	if res == nil || !res.OK || res.Key == "" || res.KeyID == "" {
		t.Fatalf("unexpected create response: %+v", res)
	}
	return res
}

func TestAPIKeyCreateStoresOnlyHashAndReturnsPlaintextOnce(t *testing.T) {
	store := newAPIKeyTestStore()
	deps := apiKeyTestDeps(store, apiKeyTestAdmin(apiKeyTestUser, apiKeyTestTeam))

	res := createAPIKeyForTest(t, store, deps)
	if !strings.HasPrefix(res.Key, "rpx_live_"+res.KeyID+"_") {
		t.Fatalf("key format = %q", res.Key)
	}
	if len(res.Prefix) > 16 || !strings.HasPrefix(res.Key, res.Prefix) {
		t.Fatalf("prefix = %q (len %d), key = %q", res.Prefix, len(res.Prefix), res.Key)
	}
	if res.OrganizationID != apiKeyTestTeam {
		t.Fatalf("organization = %q, want %q", res.OrganizationID, apiKeyTestTeam)
	}
	if got := res.ExpiresAt; got != apiKeyTestNow.Add(30*24*time.Hour).Format(time.RFC3339) {
		t.Fatalf("expires_at = %q", got)
	}

	token, err := parseAPIKeyToken(res.Key)
	if err != nil {
		t.Fatalf("parse returned key: %v", err)
	}
	row := store.rows["row-"+res.KeyID]
	if row == nil {
		t.Fatal("api key row was not stored")
	}
	if row.OrgID != apiKeyTestTeam || row.CreatedBy != apiKeyTestUser {
		t.Fatalf("stored ownership = %+v", row)
	}
	if row.SecretHash == "" || row.SecretHash == token.Secret {
		t.Fatal("stored secret_hash must be a hash, not the secret")
	}
	if !apiKeySecretMatches(apiKeyTestPepper, token.Secret, row.SecretHash) {
		t.Fatal("stored hash does not verify the returned secret")
	}
	if row.IsActive != true {
		t.Fatal("new key must be active")
	}

	encoded, _ := json.Marshal(res)
	if strings.Contains(string(encoded), row.SecretHash) || strings.Contains(string(encoded), "secret_hash") {
		t.Fatalf("create response leaked the hash: %s", encoded)
	}
}

func TestAPIKeyListNeverReturnsSecretMaterial(t *testing.T) {
	store := newAPIKeyTestStore()
	deps := apiKeyTestDeps(store, apiKeyTestAdmin(apiKeyTestUser, apiKeyTestTeam))
	created := createAPIKeyForTest(t, store, deps)
	secret := strings.TrimPrefix(created.Key, "rpx_live_"+created.KeyID+"_")

	store.put(&apiKeyRow{
		ID:         "row-expired",
		Name:       "Old export",
		OrgID:      apiKeyTestTeam,
		KeyID:      "expired1",
		Prefix:     "rpx_live_expire",
		SecretHash: "deadbeef",
		Scopes:     "reports:read",
		IsActive:   true,
		ExpiresAt:  apiKeyTestNow.Add(-time.Hour).Format(time.RFC3339),
	})
	store.put(&apiKeyRow{
		ID:         "row-revoked",
		Name:       "Revoked integration",
		OrgID:      apiKeyTestTeam,
		KeyID:      "revoked1",
		Prefix:     "rpx_live_revoke",
		SecretHash: "cafebabe",
		Scopes:     "reports:read",
		IsActive:   false,
		RevokedAt:  apiKeyTestNow.Add(-time.Minute).Format(time.RFC3339),
	})

	list, err := apiKeyListWith(testContext(apiKeyTestTeam, "jwt"), deps)
	if err != nil {
		t.Fatalf("list API keys: %v", err)
	}
	if len(list.Keys) != 3 {
		t.Fatalf("keys = %d, want 3", len(list.Keys))
	}

	statuses := map[string]string{}
	for _, key := range list.Keys {
		statuses[key.KeyID] = key.Status
	}
	if statuses[created.KeyID] != apiKeyStatusActive {
		t.Fatalf("created status = %q", statuses[created.KeyID])
	}
	if statuses["expired1"] != apiKeyStatusExpired {
		t.Fatalf("expired status = %q", statuses["expired1"])
	}
	if statuses["revoked1"] != apiKeyStatusRevoked {
		t.Fatalf("revoked status = %q", statuses["revoked1"])
	}

	encoded, _ := json.Marshal(list)
	for _, forbidden := range []string{secret, "deadbeef", "cafebabe", "secret_hash", "api_key"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("list response leaked %q: %s", forbidden, encoded)
		}
	}
}

func TestAPIKeyCreateValidation(t *testing.T) {
	valid := func() *APIKeyCreateRequest { return validAPIKeyCreateRequest() }

	cases := []struct {
		name string
		req  *APIKeyCreateRequest
		want int
	}{
		{"missing body", nil, 400},
		{"missing name", func() *APIKeyCreateRequest { r := valid(); r.Name = "   "; return r }(), 400},
		{"name has control chars", func() *APIKeyCreateRequest { r := valid(); r.Name = "bad\nname"; return r }(), 400},
		{"no scopes", func() *APIKeyCreateRequest { r := valid(); r.Scopes = nil; return r }(), 400},
		{"unknown scope", func() *APIKeyCreateRequest { r := valid(); r.Scopes = []string{"tickets:delete"}; return r }(), 403},
		{"admin wildcard scope", func() *APIKeyCreateRequest { r := valid(); r.Scopes = []string{"admin:*"}; return r }(), 403},
		{"empty scope", func() *APIKeyCreateRequest { r := valid(); r.Scopes = []string{"tickets:read", " "}; return r }(), 400},
		{"invalid expiry", func() *APIKeyCreateRequest { r := valid(); r.ExpiresAt = "tomorrow"; return r }(), 400},
		{"past expiry", func() *APIKeyCreateRequest {
			r := valid()
			r.ExpiresAt = apiKeyTestNow.Add(-time.Minute).Format(time.RFC3339)
			return r
		}(), 400},
		{"expiry beyond 365 days", func() *APIKeyCreateRequest {
			r := valid()
			r.ExpiresAt = apiKeyTestNow.Add(366 * 24 * time.Hour).Format(time.RFC3339)
			return r
		}(), 400},
		{"negative minute limit", func() *APIKeyCreateRequest { r := valid(); r.RequestsPerMinute = -1; return r }(), 400},
		{"hour limit too high", func() *APIKeyCreateRequest { r := valid(); r.RequestsPerHour = 999999; return r }(), 400},
		{"minute above hour", func() *APIKeyCreateRequest {
			r := valid()
			r.RequestsPerMinute = 200
			r.RequestsPerHour = 100
			return r
		}(), 400},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := newAPIKeyTestStore()
			deps := apiKeyTestDeps(store, apiKeyTestAdmin(apiKeyTestUser, apiKeyTestTeam))
			_, err := apiKeyCreateWith(testContext(apiKeyTestTeam, "jwt"), tc.req, deps)
			requireStatus(t, err, tc.want)
			if store.createCalls != 0 {
				t.Fatalf("invalid request reached the store (%d creates)", store.createCalls)
			}
		})
	}
}

func TestAPIKeyCreateRequiresAdminAndProvisionedOrganisation(t *testing.T) {
	store := newAPIKeyTestStore()

	technician := &Caller{UserID: "user-tech", TeamID: apiKeyTestTeam, Roles: []string{roleTechnician}}
	_, err := apiKeyCreateWith(testContext(apiKeyTestTeam, "jwt"), validAPIKeyCreateRequest(),
		apiKeyTestDeps(store, technician))
	requireStatus(t, err, 403)

	nilCallerDeps := apiKeyTestDeps(store, nil)
	_, err = apiKeyCreateWith(testContext(apiKeyTestTeam, "jwt"), validAPIKeyCreateRequest(), nilCallerDeps)
	requireStatus(t, err, 401)

	unregistered := apiKeyTestDeps(store, apiKeyTestAdmin(apiKeyTestUser, apiKeyTestTeam))
	unregistered.organization = func(string) (bool, error) { return false, nil }
	_, err = apiKeyCreateWith(testContext(apiKeyTestTeam, "jwt"), validAPIKeyCreateRequest(), unregistered)
	requireStatus(t, err, 403)

	if store.createCalls != 0 {
		t.Fatalf("rejected callers reached the store (%d creates)", store.createCalls)
	}
}

func TestAPIKeyRotateInvalidatesThePreviousSecret(t *testing.T) {
	store := newAPIKeyTestStore()
	deps := apiKeyTestDeps(store, apiKeyTestAdmin(apiKeyTestUser, apiKeyTestTeam))
	created := createAPIKeyForTest(t, store, deps)

	verifier := apiKeyTestVerifier(store, func() time.Time { return apiKeyTestNow })
	opts := APIKeyVerifyOptions{ClaimedOrganizationID: apiKeyTestTeam, RequiredScope: "tickets:read"}
	if _, err := verifier.Verify(testContext(apiKeyTestTeam, ""), "Bearer "+created.Key, opts); err != nil {
		t.Fatalf("created key should verify: %v", err)
	}
	oldHash := store.rows["row-"+created.KeyID].SecretHash

	rotated, err := apiKeyRotateWith(testContext(apiKeyTestTeam, "jwt"),
		&APIKeyRotateRequest{KeyID: created.KeyID}, deps)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if rotated.KeyID != created.KeyID {
		t.Fatalf("key id changed: %q -> %q", created.KeyID, rotated.KeyID)
	}
	if rotated.Key == created.Key {
		t.Fatal("rotation returned the old secret")
	}
	if got := store.rows["row-"+created.KeyID].SecretHash; got == oldHash {
		t.Fatal("rotation did not replace the stored hash")
	}
	if store.updateCalls != 1 {
		t.Fatalf("update calls = %d, want 1", store.updateCalls)
	}

	_, err = verifier.Verify(testContext(apiKeyTestTeam, ""), "Bearer "+created.Key, opts)
	requireStatus(t, err, 401)
	principal, err := verifier.Verify(testContext(apiKeyTestTeam, ""), "Bearer "+rotated.Key, opts)
	if err != nil {
		t.Fatalf("rotated key should verify: %v", err)
	}
	if principal.KeyID != created.KeyID {
		t.Fatalf("principal key id = %q", principal.KeyID)
	}
}

func TestAPIKeyRevokeIsIdempotent(t *testing.T) {
	store := newAPIKeyTestStore()
	deps := apiKeyTestDeps(store, apiKeyTestAdmin(apiKeyTestUser, apiKeyTestTeam))
	created := createAPIKeyForTest(t, store, deps)

	first, err := apiKeyRevokeWith(testContext(apiKeyTestTeam, "jwt"),
		&APIKeyRevokeRequest{KeyID: created.KeyID}, deps)
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if !first.OK || first.AlreadyRevoked || first.RevokedAt == "" {
		t.Fatalf("unexpected first revoke response: %+v", first)
	}

	second, err := apiKeyRevokeWith(testContext(apiKeyTestTeam, "jwt"),
		&APIKeyRevokeRequest{KeyID: created.KeyID}, deps)
	if err != nil {
		t.Fatalf("second revoke: %v", err)
	}
	if !second.OK || !second.AlreadyRevoked {
		t.Fatalf("unexpected second revoke response: %+v", second)
	}
	if store.updateCalls != 1 {
		t.Fatalf("update calls = %d, want 1 (idempotent revoke)", store.updateCalls)
	}
	row := store.rows["row-"+created.KeyID]
	if row.IsActive || row.RevokedBy != apiKeyTestUser || row.RevokedAt == "" {
		t.Fatalf("revoked row = %+v", row)
	}

	verifier := apiKeyTestVerifier(store, func() time.Time { return apiKeyTestNow })
	_, err = verifier.Verify(testContext(apiKeyTestTeam, ""), "Bearer "+created.Key,
		APIKeyVerifyOptions{ClaimedOrganizationID: apiKeyTestTeam})
	requireStatus(t, err, 401)
}

func TestAPIKeyManagementIsTenantScoped(t *testing.T) {
	store := newAPIKeyTestStore()
	store.put(&apiKeyRow{
		ID:         "row-abcdefgh",
		Name:       "Team A key",
		OrgID:      apiKeyTestTeam,
		KeyID:      "abcdefgh",
		Prefix:     "rpx_live_abcdef",
		SecretHash: hashAPIKeySecret(apiKeyTestPepper, "secretsecretsecret"),
		Scopes:     "tickets:read",
		IsActive:   true,
	})

	otherDeps := apiKeyTestDeps(store, apiKeyTestAdmin("other-admin", apiKeyTestOther))
	ctx := testContext(apiKeyTestOther, "jwt")

	_, err := apiKeyRotateWith(ctx, &APIKeyRotateRequest{KeyID: "abcdefgh"}, otherDeps)
	requireStatus(t, err, 404)
	_, err = apiKeyRevokeWith(ctx, &APIKeyRevokeRequest{KeyID: "abcdefgh"}, otherDeps)
	requireStatus(t, err, 404)
	_, err = apiKeyUsageWith(ctx, &APIKeyUsageRequest{KeyID: "abcdefgh"}, otherDeps)
	requireStatus(t, err, 404)

	list, err := apiKeyListWith(ctx, otherDeps)
	if err != nil {
		t.Fatalf("list for other org: %v", err)
	}
	if len(list.Keys) != 0 {
		t.Fatalf("cross-tenant list returned %d keys", len(list.Keys))
	}

	verifier := apiKeyTestVerifier(store, func() time.Time { return apiKeyTestNow })
	// The key's stored organisation is the authority, so a valid secret
	// presented with another tenant's header is a 403 boundary violation, not
	// a hidden 401. The key can never resolve to the caller's tenant.
	_, err = verifier.Verify(ctx, "Bearer "+apiKeyPlaintext("abcdefgh", "secretsecretsecret"),
		APIKeyVerifyOptions{ClaimedOrganizationID: apiKeyTestOther})
	requireStatus(t, err, 403)
}

func TestAPIKeyVerificationRejectsBadStateAndSecrets(t *testing.T) {
	const secret = "secretsecretsecret"

	cases := []struct {
		name   string
		mutate func(*apiKeyRow)
		header string
		want   int
	}{
		{name: "valid", want: 0},
		{name: "wrong secret", header: "Bearer " + apiKeyPlaintext("abcdefgh", "wrongwrongwrong"), want: 401},
		{name: "inactive", mutate: func(row *apiKeyRow) { row.IsActive = false }, want: 401},
		{name: "revoked", mutate: func(row *apiKeyRow) {
			row.RevokedAt = apiKeyTestNow.Add(-time.Minute).Format(time.RFC3339)
		}, want: 401},
		{name: "expired", mutate: func(row *apiKeyRow) {
			row.ExpiresAt = apiKeyTestNow.Add(-time.Minute).Format(time.RFC3339)
		}, want: 401},
		{name: "unparseable expiry fails closed", mutate: func(row *apiKeyRow) {
			row.ExpiresAt = "not-a-date"
		}, want: 401},
		{name: "missing hash", mutate: func(row *apiKeyRow) { row.SecretHash = "" }, want: 401},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			row := &apiKeyRow{
				ID:         "row-abcdefgh",
				Name:       "Integration",
				OrgID:      apiKeyTestTeam,
				KeyID:      "abcdefgh",
				Prefix:     "rpx_live_abcdef",
				SecretHash: hashAPIKeySecret(apiKeyTestPepper, secret),
				Scopes:     "tickets:read",
				IsActive:   true,
			}
			if tc.mutate != nil {
				tc.mutate(row)
			}
			store := newAPIKeyTestStore()
			store.put(row)
			verifier := apiKeyTestVerifier(store, func() time.Time { return apiKeyTestNow })

			header := tc.header
			if header == "" {
				header = "Bearer " + apiKeyPlaintext("abcdefgh", secret)
			}
			principal, err := verifier.Verify(testContext(apiKeyTestTeam, ""), header,
				APIKeyVerifyOptions{ClaimedOrganizationID: apiKeyTestTeam, RequiredScope: "tickets:read"})
			if tc.want == 0 {
				if err != nil {
					t.Fatalf("expected valid key: %v", err)
				}
				if principal == nil || principal.OrganizationID != apiKeyTestTeam ||
					principal.KeyID != "abcdefgh" || !principal.HasScope("tickets:read") {
					t.Fatalf("unexpected principal: %+v", principal)
				}
				return
			}
			requireStatus(t, err, tc.want)
		})
	}
}

func TestAPIKeyVerificationRejectsMalformedAuthorization(t *testing.T) {
	store := newAPIKeyTestStore()
	verifier := apiKeyTestVerifier(store, func() time.Time { return apiKeyTestNow })

	headers := []string{
		"",
		"Bearer",
		"Basic abc",
		"Bearer abc",
		"Bearer rpx_live_abcdefgh",
		"Bearer rpx_live_abcdefgh_short",
		"Bearer rpx_prod_abcdefgh_secretsecretsecret",
		"Bearer rpx_live_ab!defgh_secretsecretsecret",
		"Bearer rpx_live_abcdefgh_secretsecretsecret_extra",
		"Bearer  rpx_live_abcdefgh  ",
	}
	for _, header := range headers {
		_, err := verifier.Verify(testContext(apiKeyTestTeam, ""), header,
			APIKeyVerifyOptions{ClaimedOrganizationID: apiKeyTestTeam})
		requireStatus(t, err, 401)
	}

	_, err := verifier.Verify(testContext(apiKeyTestTeam, ""),
		"Bearer "+apiKeyPlaintext("abcdefgh", "secretsecretsecret"),
		APIKeyVerifyOptions{})
	// No claimed org is allowed: the stored key row supplies the tenant. The
	// empty test store means the key is simply unknown.
	requireStatus(t, err, 401)
}

func TestAPIKeyVerificationEnforcesScopes(t *testing.T) {
	const secret = "secretsecretsecret"
	store := newAPIKeyTestStore()
	store.put(&apiKeyRow{
		ID:         "row-abcdefgh",
		OrgID:      apiKeyTestTeam,
		KeyID:      "abcdefgh",
		SecretHash: hashAPIKeySecret(apiKeyTestPepper, secret),
		Scopes:     "tickets:read,customers:read",
		IsActive:   true,
	})
	verifier := apiKeyTestVerifier(store, func() time.Time { return apiKeyTestNow })
	header := "Bearer " + apiKeyPlaintext("abcdefgh", secret)

	principal, err := verifier.Verify(testContext(apiKeyTestTeam, ""), header,
		APIKeyVerifyOptions{ClaimedOrganizationID: apiKeyTestTeam, RequiredScope: "tickets:read"})
	if err != nil {
		t.Fatalf("expected scope match: %v", err)
	}
	if principal.HasScope("tickets:write") || principal.HasScope("admin:*") {
		t.Fatal("principal must not gain unlisted scopes")
	}
	if err := principal.RequireScope("tickets:write"); err == nil {
		t.Fatal("RequireScope must reject a missing scope")
	}

	_, err = verifier.Verify(testContext(apiKeyTestTeam, ""), header,
		APIKeyVerifyOptions{ClaimedOrganizationID: apiKeyTestTeam, RequiredScope: "tickets:write"})
	requireStatus(t, err, 403)
}

func TestAPIKeyVerificationRateLimitsPerKey(t *testing.T) {
	const secret = "secretsecretsecret"
	now := apiKeyTestNow
	store := newAPIKeyTestStore()
	store.put(&apiKeyRow{
		ID:                "row-abcdefgh",
		OrgID:             apiKeyTestTeam,
		KeyID:             "abcdefgh",
		SecretHash:        hashAPIKeySecret(apiKeyTestPepper, secret),
		Scopes:            "tickets:read",
		IsActive:          true,
		RequestsPerMinute: 2,
		RequestsPerHour:   100,
	})
	verifier := apiKeyTestVerifier(store, func() time.Time { return now })
	header := "Bearer " + apiKeyPlaintext("abcdefgh", secret)
	opts := APIKeyVerifyOptions{ClaimedOrganizationID: apiKeyTestTeam}

	for i := 0; i < 2; i++ {
		if _, err := verifier.Verify(testContext(apiKeyTestTeam, ""), header, opts); err != nil {
			t.Fatalf("request %d should pass: %v", i+1, err)
		}
	}
	_, err := verifier.Verify(testContext(apiKeyTestTeam, ""), header, opts)
	requireStatus(t, err, 429)

	now = now.Add(61 * time.Second)
	if _, err := verifier.Verify(testContext(apiKeyTestTeam, ""), header, opts); err != nil {
		t.Fatalf("request after window reset should pass: %v", err)
	}

	// A second verifier has its own limiter, matching the per-instance contract.
	now = apiKeyTestNow
	other := apiKeyTestVerifier(store, func() time.Time { return now })
	if _, err := other.Verify(testContext(apiKeyTestTeam, ""), header, opts); err != nil {
		t.Fatalf("independent limiter should start fresh: %v", err)
	}
}

func TestAPIKeySecretComparisonBehaviour(t *testing.T) {
	const secret = "secretsecretsecret"
	hash := hashAPIKeySecret(apiKeyTestPepper, secret)
	if !apiKeySecretMatches(apiKeyTestPepper, secret, hash) {
		t.Fatal("correct secret should match")
	}
	if apiKeySecretMatches(apiKeyTestPepper, secret, hash[:len(hash)-1]) {
		t.Fatal("a truncated hash must not match")
	}
	if apiKeySecretMatches("", secret, hash) {
		t.Fatal("empty pepper must never match")
	}
	if apiKeySecretMatches(apiKeyTestPepper, "", hash) {
		t.Fatal("empty secret must never match")
	}

	// Change each position in the hash: no prefix/suffix comparison shortcut
	// may accept a corrupted value.
	for i := 0; i < len(hash); i++ {
		for _, replacement := range []byte{'0', 'f'} {
			if hash[i] == replacement {
				continue
			}
			corrupted := []byte(hash)
			corrupted[i] = replacement
			if apiKeySecretMatches(apiKeyTestPepper, secret, string(corrupted)) {
				t.Fatalf("corrupted hash position %d matched", i)
			}
		}
	}
}

func TestAPIKeyErrorsNeverContainSecretMaterial(t *testing.T) {
	const secret = "secretsecretsecret"
	const wrong = "wrongwrongwrong"
	store := newAPIKeyTestStore()
	store.put(&apiKeyRow{
		ID:         "row-abcdefgh",
		OrgID:      apiKeyTestTeam,
		KeyID:      "abcdefgh",
		SecretHash: hashAPIKeySecret(apiKeyTestPepper, secret),
		Scopes:     "tickets:read",
		IsActive:   true,
	})
	verifier := apiKeyTestVerifier(store, func() time.Time { return apiKeyTestNow })

	_, err := verifier.Verify(testContext(apiKeyTestTeam, ""),
		"Bearer "+apiKeyPlaintext("abcdefgh", wrong),
		APIKeyVerifyOptions{ClaimedOrganizationID: apiKeyTestTeam})
	if err == nil {
		t.Fatal("wrong secret must fail")
	}
	rendered := fmt.Sprintf("%v|%#v", err, err)
	for _, forbidden := range []string{secret, wrong, hashAPIKeySecret(apiKeyTestPepper, secret)} {
		if strings.Contains(rendered, forbidden) {
			t.Fatalf("error leaked %q: %s", forbidden, rendered)
		}
	}
	var he *httpx.Error
	if !errors.As(err, &he) || he.Code != "unauthorized" {
		t.Fatalf("unexpected error: %#v", err)
	}
}

func TestAPIKeyUsageHandlesMissingLogsTable(t *testing.T) {
	store := newAPIKeyTestStore()
	deps := apiKeyTestDeps(store, apiKeyTestAdmin(apiKeyTestUser, apiKeyTestTeam))
	created := createAPIKeyForTest(t, store, deps)

	store.usageErr = errAPILogsTableMissing
	res, err := apiKeyUsageWith(testContext(apiKeyTestTeam, "jwt"),
		&APIKeyUsageRequest{KeyID: created.KeyID}, deps)
	if err != nil {
		t.Fatalf("missing api_logs must not fail: %v", err)
	}
	if !res.OK || len(res.Entries) != 0 || res.Note == "" {
		t.Fatalf("unexpected usage response: %+v", res)
	}

	store.usageErr = nil
	store.usage = []apiLogRow{
		{ID: "log-1", OrgID: apiKeyTestTeam, APIKeyID: created.KeyID, Method: "GET", Endpoint: "/tickets", Status: 200, IPAddress: "203.0.113.10", CreatedAt: apiKeyTestNow.Format(time.RFC3339)},
		{ID: "log-2", OrgID: apiKeyTestTeam, APIKeyID: "otherkey", Method: "GET", Endpoint: "/customers", Status: 200},
	}
	res, err = apiKeyUsageWith(testContext(apiKeyTestTeam, "jwt"),
		&APIKeyUsageRequest{KeyID: created.KeyID}, deps)
	if err != nil {
		t.Fatalf("usage with logs: %v", err)
	}
	if len(res.Entries) != 1 || res.Entries[0].Path != "/tickets" || res.Entries[0].Status != 200 {
		t.Fatalf("usage entries = %+v", res.Entries)
	}

	store.usageErr = errors.New("database unavailable")
	if _, err := apiKeyUsageWith(testContext(apiKeyTestTeam, "jwt"),
		&APIKeyUsageRequest{KeyID: created.KeyID}, deps); err == nil {
		t.Fatal("unexpected storage errors must still fail")
	}
}

// testContext builds a request context with the platform identity headers. The
// header names are the stable runtime contract; this package does not import
// the root auth package.
func testContext(org, jwt string) openruntimes.Context {
	headers := map[string]string{}
	if org != "" {
		headers["x-reparix-organization-id"] = org
	}
	if jwt != "" {
		headers["x-appwrite-user-jwt"] = jwt
	}
	return openruntimes.Context{
		Req: openruntimes.ContextRequest{
			Headers: headers,
			Method:  "POST",
			Path:    "/staff/api-keys",
			Raw:     httptest.NewRequest("POST", "/staff/api-keys", nil),
		},
	}
}

func stringField(row map[string]any, key string) string {
	if row == nil {
		return ""
	}
	value, _ := row[key].(string)
	return value
}

func int64Field(row map[string]any, key string) int64 {
	if row == nil {
		return 0
	}
	switch value := row[key].(type) {
	case int64:
		return value
	case int:
		return int64(value)
	case float64:
		return int64(value)
	default:
		return 0
	}
}

func requireStatus(t *testing.T, err error, status int) {
	t.Helper()
	var he *httpx.Error
	if !errors.As(err, &he) {
		t.Fatalf("expected httpx error with status %d, got %v", status, err)
	}
	if he.Status != status {
		t.Fatalf("expected status %d, got %d (%s)", status, he.Status, he.Message)
	}
}

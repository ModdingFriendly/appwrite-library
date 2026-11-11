package apikeys

// Machine-key verification contract (T99).
//
// These tests pin the security boundaries the row-gateway middleware relies on:
// fail-closed configuration, the key row as the only tenant authority, ambiguity
// across tenants, rate-limit accounting, and metadata-only usage recording.

import (
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/open-runtimes/types-for-go/v4/openruntimes"

	"github.com/ModdingFriendly/appwrite-library/httpx"
)

const apiKeyVerifySecret = "secretsecretsecret"

func apiKeyVerifyRow(orgID, keyID, scopes string) *apiKeyRow {
	return &apiKeyRow{
		ID:                "row-" + keyID,
		Name:              "Integration",
		OrgID:             orgID,
		KeyID:             keyID,
		Prefix:            "rpx_live_abcdef",
		SecretHash:        hashAPIKeySecret(apiKeyTestPepper, apiKeyVerifySecret),
		Scopes:            scopes,
		IsActive:          true,
		RequestsPerMinute: 10,
		RequestsPerHour:   100,
	}
}

func TestAPIKeyVerificationFailsClosedWithoutPepper(t *testing.T) {
	lookups := 0
	verifier := &APIKeyVerifier{
		lookup: func(openruntimes.Context, string) (*apiKeyRow, error) {
			lookups++
			return apiKeyVerifyRow(apiKeyTestTeam, "abcdefgh", "rows.read"), nil
		},
		now:     func() time.Time { return apiKeyTestNow },
		pepper:  "",
		limiter: newAPIKeyRateLimiter(),
	}

	_, err := verifier.Verify(testContext(apiKeyTestTeam, ""),
		"Bearer "+apiKeyPlaintext("abcdefgh", apiKeyVerifySecret),
		APIKeyVerifyOptions{RequiredScope: "rows.read"})
	requireStatus(t, err, 503)
	var he *httpx.Error
	if !errors.As(err, &he) || he.Code != "api_key_unavailable" {
		t.Fatalf("unexpected error: %#v", err)
	}
	if lookups != 0 {
		t.Fatalf("lookup must not run without a pepper (%d calls)", lookups)
	}

	// A whitespace-only pepper is the same misconfiguration.
	verifier.pepper = "   "
	_, err = verifier.Verify(testContext(apiKeyTestTeam, ""),
		"Bearer "+apiKeyPlaintext("abcdefgh", apiKeyVerifySecret), APIKeyVerifyOptions{})
	requireStatus(t, err, 503)
}

func TestAPIKeyVerificationUsesStoredOrganizationAsAuthority(t *testing.T) {
	store := newAPIKeyTestStore()
	store.put(apiKeyVerifyRow(apiKeyTestTeam, "abcdefgh", "rows.read,rows.write"))
	verifier := apiKeyTestVerifier(store, func() time.Time { return apiKeyTestNow })
	header := "Bearer " + apiKeyPlaintext("abcdefgh", apiKeyVerifySecret)

	// No organisation header: the key row supplies the tenant.
	principal, err := verifier.Verify(testContext("", ""), header,
		APIKeyVerifyOptions{RequiredScope: "rows.read"})
	if err != nil {
		t.Fatalf("key without a claim should verify: %v", err)
	}
	if principal.OrganizationID != apiKeyTestTeam {
		t.Fatalf("principal organisation = %q, want %q", principal.OrganizationID, apiKeyTestTeam)
	}

	// A matching claim is metadata, not authority, and is accepted.
	if _, err := verifier.Verify(testContext(apiKeyTestTeam, ""), header,
		APIKeyVerifyOptions{ClaimedOrganizationID: apiKeyTestTeam}); err != nil {
		t.Fatalf("matching claim should verify: %v", err)
	}

	// A different claim is a tenant-boundary violation.
	_, err = verifier.Verify(testContext(apiKeyTestOther, ""), header,
		APIKeyVerifyOptions{ClaimedOrganizationID: apiKeyTestOther})
	requireStatus(t, err, 403)

	// A wrong secret plus a different claim stays 401: the tenant mismatch is
	// only revealed after the secret proves the caller holds the key.
	_, err = verifier.Verify(testContext(apiKeyTestOther, ""),
		"Bearer "+apiKeyPlaintext("abcdefgh", "wrongwrongwrongwrong"),
		APIKeyVerifyOptions{ClaimedOrganizationID: apiKeyTestOther})
	requireStatus(t, err, 401)
}

func TestAPIKeyVerificationAmbiguousKeyIDFailsClosed(t *testing.T) {
	store := newAPIKeyTestStore()
	// The same public id in two organisations is ambiguous. The verifier must
	// not pick one tenant or reveal that both exist. Row ids differ, as they
	// do in Appwrite; only key_id collides.
	first := apiKeyVerifyRow(apiKeyTestTeam, "abcdefgh", "rows.read")
	first.ID = "row-team-a"
	second := apiKeyVerifyRow(apiKeyTestOther, "abcdefgh", "rows.read")
	second.ID = "row-team-b"
	store.put(first)
	store.put(second)
	verifier := apiKeyTestVerifier(store, func() time.Time { return apiKeyTestNow })

	_, err := verifier.Verify(testContext("", ""),
		"Bearer "+apiKeyPlaintext("abcdefgh", apiKeyVerifySecret), APIKeyVerifyOptions{})
	requireStatus(t, err, 401)
}

func TestAPIKeyVerificationRateLimitOnlyCountsValidSecrets(t *testing.T) {
	store := newAPIKeyTestStore()
	row := apiKeyVerifyRow(apiKeyTestTeam, "abcdefgh", "rows.read")
	row.RequestsPerMinute = 1
	row.RequestsPerHour = 100
	store.put(row)
	verifier := apiKeyTestVerifier(store, func() time.Time { return apiKeyTestNow })
	ctx := testContext("", "")

	// An unauthenticated guess must not spend the real key's budget.
	_, err := verifier.Verify(ctx, "Bearer "+apiKeyPlaintext("abcdefgh", "wrongwrongwrongwrong"),
		APIKeyVerifyOptions{})
	requireStatus(t, err, 401)

	if _, err := verifier.Verify(ctx, "Bearer "+apiKeyPlaintext("abcdefgh", apiKeyVerifySecret),
		APIKeyVerifyOptions{}); err != nil {
		t.Fatalf("first valid request should pass: %v", err)
	}
	_, err = verifier.Verify(ctx, "Bearer "+apiKeyPlaintext("abcdefgh", apiKeyVerifySecret),
		APIKeyVerifyOptions{})
	requireStatus(t, err, 429)

	var he *httpx.Error
	if !errors.As(err, &he) {
		t.Fatalf("expected typed error: %v", err)
	}
	retry, ok := he.Params["retry_after_seconds"].(int)
	if !ok || retry <= 0 || retry > 60 {
		t.Fatalf("retry_after_seconds = %#v", he.Params["retry_after_seconds"])
	}
	if strings.Contains(he.Message, apiKeyVerifySecret) {
		t.Fatal("rate-limit error leaked the secret")
	}
}

func TestAPIKeyVerificationRecordsMetadataOnlyUsage(t *testing.T) {
	store := newAPIKeyTestStore()
	store.put(apiKeyVerifyRow(apiKeyTestTeam, "abcdefgh", "rows.write"))
	verifier := apiKeyTestVerifier(store, func() time.Time { return apiKeyTestNow })

	principal, err := verifier.Verify(testContext("", ""),
		"Bearer "+apiKeyPlaintext("abcdefgh", apiKeyVerifySecret),
		APIKeyVerifyOptions{RequiredScope: "rows.write"})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	use := APIKeyUse{
		KeyRowID:       principal.RowID,
		KeyID:          principal.KeyID,
		OrganizationID: principal.OrganizationID,
		Method:         "POST",
		Endpoint:       "/staff/rows/update",
		Status:         200,
		IPAddress:      "203.0.113.7",
		UserAgent:      "integration/1.0",
	}
	if err := verifier.Record(testContext("", ""), use); err != nil {
		t.Fatalf("record: %v", err)
	}

	if len(store.uses) != 1 {
		t.Fatalf("usage rows = %d, want 1", len(store.uses))
	}
	if store.uses[0] != use {
		t.Fatalf("recorded use = %+v, want %+v", store.uses[0], use)
	}
	if row := store.rows[principal.RowID]; row == nil || row.LastUsedAt == "" {
		t.Fatalf("last_used_at was not updated: %+v", row)
	}

	// The persisted record must be metadata only. Marshal it and prove no
	// credential material (plaintext secret, stored hash) is present. The
	// public key id and row id are safe routing metadata and are expected.
	encoded, err := json.Marshal(store.uses[0])
	if err != nil {
		t.Fatalf("marshal usage: %v", err)
	}
	for _, forbidden := range []string{
		apiKeyVerifySecret,
		hashAPIKeySecret(apiKeyTestPepper, apiKeyVerifySecret),
	} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("usage record leaked credential material: %s", encoded)
		}
	}

	// A verifier without a recorder must not panic.
	noRecorder := &APIKeyVerifier{}
	if err := noRecorder.Record(testContext("", ""), use); err != nil {
		t.Fatalf("nil recorder should be a no-op: %v", err)
	}
}

func TestAPIKeyCreateAcceptsRowGatewayScopes(t *testing.T) {
	store := newAPIKeyTestStore()
	deps := apiKeyTestDeps(store, apiKeyTestAdmin(apiKeyTestUser, apiKeyTestTeam))
	req := validAPIKeyCreateRequest()
	req.Scopes = []string{"rows.read", "rows.write"}

	res, err := apiKeyCreateWith(testContext(apiKeyTestTeam, "jwt"), req, deps)
	if err != nil {
		t.Fatalf("rows.* scopes must be issuable: %v", err)
	}
	if len(res.Scopes) != 2 {
		t.Fatalf("issued scopes = %v", res.Scopes)
	}
}

// TestAPIKeyVerificationTrustsNoRequestHeaderForLookup guards the shape of the
// verifier API: there is no organisation argument anywhere in the lookup or
// options that could be confused with a trusted tenant.
func TestAPIKeyVerificationTrustsNoRequestHeaderForLookup(t *testing.T) {
	ctx := testContext(apiKeyTestTeam, "jwt")
	ctx.Req = openruntimes.ContextRequest{
		Headers: map[string]string{
			"x-reparix-organization-id": apiKeyTestTeam,
			"x-appwrite-user-id":        "spoofed-admin",
		},
		Method: "POST",
		Path:   "/staff/rows/list",
		Raw:    httptest.NewRequest("POST", "/staff/rows/list", nil),
	}

	store := newAPIKeyTestStore()
	store.put(apiKeyVerifyRow(apiKeyTestOther, "abcdefgh", "rows.read"))
	verifier := apiKeyTestVerifier(store, func() time.Time { return apiKeyTestNow })

	// The key belongs to team-b; a spoofed header naming team-a must not make
	// the verifier resolve it as team-a.
	_, err := verifier.Verify(ctx, "Bearer "+apiKeyPlaintext("abcdefgh", apiKeyVerifySecret),
		APIKeyVerifyOptions{ClaimedOrganizationID: apiKeyTestTeam})
	requireStatus(t, err, 403)
}

package rows

// End-to-end contract parity across the Reparix policy packages: the same
// verified caller that authz resolves is accepted by the tenant registry check
// and then drives the read and mutation engines. The assertion is that the
// boundaries agree: a 401/403/404 from one package keeps its status and public
// body when it reaches the gateway, and the tenant/ACL/credential contracts hold
// without any Function-specific glue.

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/ModdingFriendly/appwrite-library/httpx"
	"github.com/ModdingFriendly/appwrite-library/reparix/authz"
	"github.com/ModdingFriendly/appwrite-library/reparix/tenant"
)

type contractLookup struct {
	identity   *authz.Identity
	identErr   error
	membership *authz.Membership
	memErr     error
}

func (l contractLookup) CurrentUser(context.Context, string) (*authz.Identity, error) {
	return l.identity, l.identErr
}

func (l contractLookup) Membership(context.Context, string, string, string) (*authz.Membership, error) {
	return l.membership, l.memErr
}

func contractHeaders() map[string]string {
	return map[string]string{
		authz.JWTHeader:           "jwt-1",
		tenant.OrganizationHeader: "t1",
	}
}

func contractVerifiedLookup() contractLookup {
	return contractLookup{
		identity:   &authz.Identity{UserID: "u1"},
		membership: &authz.Membership{ID: "m1", UserID: "u1", TeamID: "t1", Roles: []string{"Admin", "technician"}, Confirmed: true},
	}
}

func contractPolicySets() (ReadPolicySet, MutationPolicySet) {
	read := ReadPolicySet{
		Tables: map[string]ReadPolicy{
			"tickets": {
				// A deliberately wrong projection: it names credential columns,
				// which must still never leave the server.
				Allow: MetadataFields("subject", "status", "api_key", "secret_hash"),
				Deny:  []string{"internal_note"},
			},
		},
		Denied: map[string]string{"organizations": "authoritative organisation identity"},
	}
	mutate := MutationPolicySet{
		Tables: map[string]MutationPolicy{
			"tickets": {
				Fields: map[string]FieldSpec{
					"subject":     {Type: FieldVarchar, MaxLen: 40, Required: true},
					"status":      {Type: FieldEnum, Enum: []string{"open", "closed"}},
					"customer_id": {Type: FieldVarchar, MaxLen: 36},
				},
				Operations: []Operation{OpCreate},
				Derived: map[string]Deriver{
					"customer_user_id": func(_ MutationCaller, data map[string]any) (any, error) {
						id, ok := data["customer_id"].(string)
						if !ok || id == "" {
							return nil, nil
						}
						return "user-" + id, nil
					},
				},
				ReadRoles:      []string{"admin", "technician"},
				ReadUserFields: []string{"customer_user_id"},
			},
		},
	}
	return read, mutate
}

// TestContractVerifiedCallerDrivesBothEngines is the happy-path parity test:
// authz-verified identity -> tenant registry check -> read plan -> mutation plan.
func TestContractVerifiedCallerDrivesBothEngines(t *testing.T) {
	ctx := context.Background()
	caller, err := authz.Verify(ctx, contractHeaders(), contractVerifiedLookup())
	if err != nil {
		t.Fatal(err)
	}
	if caller.UserID() != "u1" || caller.TeamID() != "t1" || !caller.HasRole("admin") {
		t.Fatalf("verified caller: %+v", caller)
	}
	// The tenant is the confirmed membership's team, never a request value.
	if caller.TeamID() == "t2" {
		t.Fatal("the tenant must come from the verified membership")
	}

	if err := tenant.RequireRegistered(ctx, caller.TeamID(), func(context.Context, string) (bool, error) {
		return true, nil
	}); err != nil {
		t.Fatalf("registered organisation: %v", err)
	}

	readSet, mutationSet := contractPolicySets()

	// Read: the engine owns the tenant filter and the response recheck.
	plan, err := ReadEngine{Policies: readSet}.Prepare(caller.TeamID(), &ReadRequest{
		TableID: "tickets",
		Queries: []string{`{"method":"equal","attribute":"status","values":["open"]}`},
		Select:  []string{"subject", "status"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Queries) == 0 || !strings.Contains(plan.Queries[0], `"organization_id"`) || !strings.Contains(plan.Queries[0], `"t1"`) {
		t.Fatalf("authoritative tenant filter must be first: %v", plan.Queries)
	}
	rows := []map[string]any{
		{"$id": "own", "organization_id": "t1", "subject": "s", "status": "open", "api_key": "SECRET", "secret_hash": "HASH", "internal_note": "private", "$permissions": []string{`read("any")`}},
		{"$id": "foreign", "organization_id": "t2", "subject": "other"},
		{"$id": "tenantless", "subject": "orphan"},
	}
	kept, dropped := plan.Apply(rows)
	if len(kept) != 1 || dropped != 2 || kept[0]["$id"] != "own" {
		t.Fatalf("tenant recheck: kept=%v dropped=%d", kept, dropped)
	}
	for _, field := range []string{"api_key", "secret_hash", "internal_note", "$permissions", "$sequence"} {
		if _, leaked := kept[0][field]; leaked {
			t.Fatalf("%s leaked after projection: %v", field, kept[0])
		}
	}
	for _, field := range []string{"$id", "organization_id", "subject", "status"} {
		if _, ok := kept[0][field]; !ok {
			t.Fatalf("%s must survive projection: %v", field, kept[0])
		}
	}

	// Mutation: the tenant column and the ACL are derived, never client input.
	mutation, err := MutationEngine{Policies: mutationSet}.Prepare(
		MutationCaller{TeamID: caller.TeamID(), UserID: caller.UserID()},
		OpCreate,
		&MutationRequest{
			TableID:        "tickets",
			OrganizationID: "t1",
			Data: mutationData(map[string]any{
				"subject":     "printer offline",
				"status":      "open",
				"customer_id": "c1",
			}),
		})
	if err != nil {
		t.Fatal(err)
	}
	if mutation.Data["organization_id"] != "t1" {
		t.Fatalf("tenant must come from the verified caller: %v", mutation.Data)
	}
	wantACL := []string{
		`read("team:t1/admin")`,
		`read("team:t1/technician")`,
		`read("user:user-c1")`,
	}
	if !reflect.DeepEqual(mutation.ACL, wantACL) {
		t.Fatalf("ACL parity: got %v want %v", mutation.ACL, wantACL)
	}
	for _, grant := range mutation.ACL {
		if !strings.HasPrefix(grant, `read("`) {
			t.Fatalf("only read grants are allowed: %s", grant)
		}
	}
}

// TestContractCrossPackageErrorParity pins the status and public body of the
// same failure classes as they cross package boundaries.
func TestContractCrossPackageErrorParity(t *testing.T) {
	ctx := context.Background()

	// Missing JWT: authz is 401 independent of configuration.
	_, err := authz.Verify(ctx, map[string]string{tenant.OrganizationHeader: "t1"}, nil)
	if status, body := ErrorBody(err); status != 401 || body["code"] != "unauthorized" {
		t.Fatalf("missing JWT parity: %d %v", status, body)
	}

	// Forged organisation: a non-member is 403.
	forged := contractVerifiedLookup()
	forged.membership = nil
	forged.memErr = httpx.Forbidden("caller is not a member of this team", nil)
	_, err = authz.Verify(ctx, contractHeaders(), forged)
	if status, body := ErrorBody(err); status != 403 || body["code"] != "forbidden" {
		t.Fatalf("forged org parity: %d %v", status, body)
	}

	// Unconfirmed membership is 403.
	unconfirmed := contractVerifiedLookup()
	unconfirmed.membership.Confirmed = false
	_, err = authz.Verify(ctx, contractHeaders(), unconfirmed)
	if status, body := ErrorBody(err); status != 403 || body["code"] != "forbidden" {
		t.Fatalf("unconfirmed parity: %d %v", status, body)
	}

	// Unregistered tenant: 403; registry unavailable: fail closed with 502.
	if err := tenant.RequireRegistered(ctx, "t1", func(context.Context, string) (bool, error) { return false, nil }); err == nil {
		t.Fatal("unregistered tenant must fail")
	} else if status, body := ErrorBody(err); status != 403 || body["code"] != "forbidden" {
		t.Fatalf("unregistered parity: %d %v", status, body)
	}
	if err := tenant.RequireRegistered(ctx, "t1", nil); err == nil {
		t.Fatal("a nil registry must fail closed")
	} else if status, body := ErrorBody(err); status != 502 || body["code"] != "upstream_error" {
		t.Fatalf("nil registry parity: %d %v", status, body)
	}

	// Cross-tenant and missing referenced rows must be the same 404 body; the
	// check is not an existence oracle.
	fetch := func(_ context.Context, _, id string) (*tenant.Ref, error) {
		switch id {
		case "own":
			return &tenant.Ref{ID: "own", OrganizationID: "t1"}, nil
		case "foreign":
			return &tenant.Ref{ID: "foreign", OrganizationID: "t2"}, nil
		default:
			return nil, nil
		}
	}
	expected := map[string]any(nil)
	for _, id := range []string{"foreign", "missing", "tenantless"} {
		_, err := tenant.FetchSameTenant(ctx, fetch, "t1", "customer_id", "customers", id)
		status, body := ErrorBody(err)
		if status != 404 || body["code"] != "not_found" {
			t.Fatalf("%s parity: %d %v", id, status, body)
		}
		if expected == nil {
			expected = body
			continue
		}
		if !reflect.DeepEqual(body, expected) {
			t.Fatalf("%s: 404 bodies must be identical: %v vs %v", id, body, expected)
		}
	}

	// Row gateway admission: an unknown table is a fail-closed 403; a denied
	// table carries the consumer's explicit reason but the same public code.
	readSet, _ := contractPolicySets()
	_, err = ReadEngine{Policies: readSet}.Prepare("t1", &ReadRequest{TableID: "billing_accounts"})
	if status, body := ErrorBody(err); status != 403 || body["code"] != "forbidden" {
		t.Fatalf("unknown table parity: %d %v", status, body)
	}
	_, err = ReadEngine{Policies: readSet}.Prepare("t1", &ReadRequest{TableID: "organizations"})
	status, body := ErrorBody(err)
	if status != 403 || body["params"].(map[string]any)["reason"] != "authoritative organisation identity" {
		t.Fatalf("denied table parity: %d %v", status, body)
	}

	// Store errors keep appwrite's mapping: an SDK 404 is a public 404, never a
	// 502 leak of the upstream text.
	mapped := MapError(sdkErr(404, "row_not_found"), "tickets")
	if status, body := ErrorBody(mapped); status != 404 || body["code"] != "not_found" {
		t.Fatalf("sdk error parity: %d %v", status, body)
	}
	if strings.Contains(contractBodyJSON(t, mapped), "secret upstream text") {
		t.Fatal("upstream text leaked into the public body")
	}

	// A domain error is never re-wrapped as 502 on its way through MapError.
	domain := httpx.PreconditionFailed("stale write", map[string]any{"field": "status"})
	if got := MapError(domain, "tickets"); !errors.Is(got, domain) {
		t.Fatalf("domain error identity lost: %v", got)
	} else if status, _ := ErrorBody(got); status != 412 {
		t.Fatalf("domain status changed: %d", status)
	}
}

// contractBodyJSON renders the public body so a substring assertion does not
// depend on map ordering.
func contractBodyJSON(t *testing.T, err error) string {
	t.Helper()
	_, body := ErrorBody(err)
	encoded, marshalErr := json.Marshal(body)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	return string(encoded)
}

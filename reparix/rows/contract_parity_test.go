package rows

// Contract parity tests for the query/projection, ACL and error surfaces of the
// Reparix row gateway. They pin the security decisions a consumer Function
// relies on, independently of any particular table policy:
//
//   - forbidden fields (system, server-owned, blocked, derived) and their
//     precedence over the writable allowlist;
//   - the credential deny list and the allow/deny projection rules;
//   - the exact read-only ACL shape and its id bounds;
//   - error extraction precedence (SDK before httpx) and the public error body
//     shapes, including private Detail/Cause never leaking.
//
// These are contract assertions, not implementation white-box tests: a change
// that still satisfies them keeps every consumer safe.

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/ModdingFriendly/appwrite-library/appwrite"
	"github.com/ModdingFriendly/appwrite-library/httpx"
)

// contractPolicy returns a policy containing every class of non-client-writable
// field so precedence between the classes can be pinned.
func contractPolicy() MutationPolicy {
	return MutationPolicy{
		Table: "tickets",
		Fields: map[string]FieldSpec{
			"subject":      {Type: FieldVarchar, MaxLen: 40, Required: true},
			"status":       {Type: FieldEnum, Enum: []string{"open", "closed"}},
			"reader_id":    {Type: FieldVarchar, MaxLen: 36},
			"blocked_both": {Type: FieldVarchar},
			"derived_both": {Type: FieldVarchar},
			"org_both":     {Type: FieldVarchar},
		},
		Blocked:   map[string]string{"blocked_both": "consumer-owned column"},
		Derived:   map[string]Deriver{"derived_both": func(MutationCaller, map[string]any) (any, error) { return "x", nil }},
		Immutable: []string{"subject"},
		Operations: []Operation{
			OpCreate, OpUpdate, OpDelete,
		},
		ReadRoles: []string{"admin", "technician"},
	}
}

// contractForbidden is one non-client-writable field and the exact reason the
// contract promises for it.
type contractForbidden struct {
	field  string
	reason string
}

func contractForbiddenFields() []contractForbidden {
	return []contractForbidden{
		{"$id", "system field"},
		{"$permissions", "system field"},
		{"$createdAt", "system field"},
		{"$updatedAt", "system field"},
		{"$sequence", "system field"},
		{"$databaseId", "system field"},
		{"$tableId", "system field"},
		{"organization_id", "derived from the verified team"},
		{"blocked_both", "consumer-owned column"},
		{"derived_both", "derived server-side"},
	}
}

// TestContractForbiddenFieldPrecedence pins that every server-owned, blocked or
// derived field is a 403 with the exact contract body, even when the consumer's
// allowlist/derived map also names it. A client must never win that race.
func TestContractForbiddenFieldPrecedence(t *testing.T) {
	engine := MutationEngine{Policies: MutationPolicySet{Tables: map[string]MutationPolicy{"tickets": contractPolicy()}}}
	caller := MutationCaller{TeamID: "t1", UserID: "u1"}

	for _, tc := range contractForbiddenFields() {
		req := &MutationRequest{
			TableID: "tickets",
			Data:    mutationData(map[string]any{"subject": "s", tc.field: "injected"}),
		}
		_, err := engine.Prepare(caller, OpCreate, req)
		he := contractHE(t, err)
		if he.Status != 403 || he.Code != "forbidden" || he.Message != "field is not client-writable" {
			t.Errorf("%s: want 403 forbidden, got %+v", tc.field, he)
		}
		if he.Params["field"] != tc.field || he.Params["reason"] != tc.reason {
			t.Errorf("%s: want reason %q, got %+v", tc.field, tc.reason, he.Params)
		}
	}

	// An immutable field is only refused on update, with its own reason.
	if _, err := engine.Prepare(caller, OpCreate, mutationReq(map[string]any{"subject": "s"})); err != nil {
		t.Fatalf("create with an immutable field must be allowed: %v", err)
	}
	_, err := engine.Prepare(caller, OpUpdate, &MutationRequest{
		TableID: "tickets", RowID: "r1", Data: mutationData(map[string]any{"subject": "new"}),
	})
	he := contractHE(t, err)
	if he.Status != 403 || he.Params["field"] != "subject" || !strings.Contains(he.Params["reason"].(string), "immutable") {
		t.Fatalf("immutable field contract: %+v", he)
	}

	// A field outside the allowlist is a 400 unknown field, not an oracle.
	_, err = engine.Prepare(caller, OpCreate, mutationReq(map[string]any{"subject": "s", "not_allowed": "x"}))
	he = contractHE(t, err)
	if he.Status != 400 || he.Code != "bad_request" || he.Message != "unknown field" || he.Params["field"] != "not_allowed" {
		t.Fatalf("unknown field contract: %+v", he)
	}
}

// TestContractForbiddenFieldOrderIsDeterministic pins that when several fields
// are forbidden the first forbidden key in sorted order is reported. Stable
// output matters because consumers surface the params.field to operators.
func TestContractForbiddenFieldOrderIsDeterministic(t *testing.T) {
	engine := MutationEngine{Policies: MutationPolicySet{Tables: map[string]MutationPolicy{"tickets": contractPolicy()}}}
	caller := MutationCaller{TeamID: "t1", UserID: "u1"}
	for i := 0; i < 10; i++ {
		_, err := engine.Prepare(caller, OpCreate, &MutationRequest{
			TableID: "tickets",
			Data: mutationData(map[string]any{
				"subject":         "s",
				"organization_id": "t2",
				"$permissions":    []string{`read("any")`},
			}),
		})
		he := contractHE(t, err)
		// "$permissions" sorts before "organization_id".
		if he.Params["field"] != "$permissions" {
			t.Fatalf("iteration %d: field order changed: %+v", i, he.Params)
		}
	}
}

// TestContractCredentialDenyList pins the global never-readable list and proves
// it applies with and without a consumer projection. This is the defence in
// depth net for a new credential column or a widened query.
func TestContractCredentialDenyList(t *testing.T) {
	want := []string{
		"api_key", "secret", "secret_hash", "token", "token_hash",
		"password_hash", "password_fingerprint", "private_key",
		"webhook_secret", "signing_secret",
	}
	if got := NeverReadableFields(); !contractSameStrings(got, want) {
		t.Fatalf("credential deny list drifted: %v", got)
	}

	// The exported list is a copy: a consumer must not be able to widen the
	// deny list's backing storage.
	got := NeverReadableFields()
	got[0] = "tampered"
	if NeverReadableFields()[0] != want[0] {
		t.Fatal("NeverReadableFields must return a copy")
	}

	for _, field := range want {
		if err := ValidateSelect([]string{field}, nil, nil); err == nil {
			t.Errorf("%s must never be selectable", field)
			continue
		} else if he := contractHE(t, err); he.Status != 400 || he.Params["field"] != field {
			t.Errorf("%s select contract: %+v", field, he)
		}

		row := map[string]any{"$id": "r", field: "SECRET", "business": "visible"}
		if n := ProjectRow(row, nil, nil); n != 1 {
			t.Errorf("%s: withheld=%d", field, n)
		}
		if _, leaked := row[field]; leaked {
			t.Errorf("%s leaked through an unprojected row", field)
		}
		if row["business"] != "visible" {
			t.Errorf("%s: business column must survive", field)
		}
	}

	// Even a consumer allowlist cannot re-enable a credential field.
	allow := MetadataFields("api_key")
	if err := ValidateSelect([]string{"api_key"}, allow, nil); err == nil {
		t.Fatal("an allowlist must not widen the global deny list")
	}
}

// TestContractProjectionPrecedence pins allow-vs-deny precedence and the
// in-place projection contract: deny and the global list always win, a non-nil
// allow is a closed projection, and nil allow only applies deny/global.
func TestContractProjectionPrecedence(t *testing.T) {
	field := "danger"
	if err := ValidateSelect([]string{field}, []string{field}, []string{field}); err == nil {
		t.Fatal("deny must win over allow")
	}
	if err := ValidateSelect([]string{"tampered"}, []string{"api_key"}, nil); err == nil {
		t.Fatal("the global deny list must win over allow")
	}

	row := map[string]any{
		"$id": "r", "organization_id": "t1", "name": "n",
		"danger": "d", "secret": "s", "extra": "e",
	}
	// allow names danger so only the deny list can remove it.
	withheld := ProjectRow(row, MetadataFields("name", "danger"), []string{"danger"})
	if withheld != 3 {
		t.Fatalf("want danger+secret+extra withheld, got %d: %v", withheld, row)
	}
	if _, ok := row["danger"]; ok {
		t.Fatal("deny must win over allow on projection")
	}
	if _, ok := row["secret"]; ok {
		t.Fatal("global deny must win over allow on projection")
	}
	if _, ok := row["extra"]; ok {
		t.Fatal("a non-nil allow is a closed projection")
	}
	if row["name"] != "n" || row["organization_id"] != "t1" {
		t.Fatalf("metadata must survive: %v", row)
	}

	// nil allow leaves business columns readable but still removes deny/global.
	open := map[string]any{"device": "d", "token": "T", "danger": "D"}
	if n := ProjectRow(open, nil, []string{"danger"}); n != 2 {
		t.Fatalf("nil allow withheld %d", n)
	}
	if _, ok := open["device"]; !ok {
		t.Fatal("nil allow must not close the projection")
	}

	// MetadataFields is the common projection prefix: system metadata plus the
	// tenant column the response recheck requires.
	for _, required := range []string{"$id", "$createdAt", "$updatedAt", "$tableId", "$databaseId", "organization_id"} {
		if !contractContains(MetadataFields(), required) {
			t.Errorf("MetadataFields missing %q", required)
		}
	}
}

// TestContractACLShape pins the exact read-only ACL contract: one read grant per
// valid role and per valid user, deduplicated, never a write/any/users grant and
// never broader than a valid team id.
func TestContractACLShape(t *testing.T) {
	acl := TeamReadACL("t1", []string{"admin", "technician", "admin", "bad role"}, "u1", "u1", "bad id", `x")`, "u2")
	want := []string{
		`read("team:t1/admin")`,
		`read("team:t1/technician")`,
		`read("user:u1")`,
		`read("user:u2")`,
	}
	if !contractSameStrings(acl, want) {
		t.Fatalf("ACL shape drifted:\n got %v\nwant %v", acl, want)
	}

	grant := regexp.MustCompile(`^read\("(team:[A-Za-z0-9][A-Za-z0-9._-]{0,35}/[A-Za-z0-9][A-Za-z0-9._-]{0,35}|user:[A-Za-z0-9][A-Za-z0-9._-]{0,35})"\)$`)
	for _, got := range acl {
		if !grant.MatchString(got) {
			t.Fatalf("grant is not a valid read grant: %q", got)
		}
		for _, forbidden := range []string{"update(", "delete(", "create(", "write(", "users", "any", "guests", "role:"} {
			if strings.Contains(got, forbidden) {
				t.Fatalf("ACL leaked a broader grant %q: %s", forbidden, got)
			}
		}
	}

	// A malformed team id yields an explicit empty, non-nil slice, never a
	// default or broader grant.
	for _, bad := range []string{"", "a b", `t1")`, strings.Repeat("a", 37)} {
		if got := TeamReadACL(bad, []string{"admin"}, "u1"); got == nil || len(got) != 0 {
			t.Fatalf("invalid team %q -> %#v", bad, got)
		}
	}
	if got := TeamReadACL("t1", nil); got == nil || len(got) != 0 {
		t.Fatal("no roles/users must be an explicit empty ACL")
	}

	// Created rows use exactly TeamReadACL for the verified tenant; updates and
	// deletes never rewrite ACLs.
	engine := MutationEngine{Policies: MutationPolicySet{Tables: map[string]MutationPolicy{"tickets": contractPolicy()}}}
	caller := MutationCaller{TeamID: "t1", UserID: "u1"}
	plan, err := engine.Prepare(caller, OpCreate, mutationReq(map[string]any{"subject": "s"}))
	if err != nil {
		t.Fatal(err)
	}
	if !contractSameStrings(plan.ACL, TeamReadACL("t1", []string{"admin", "technician"})) {
		t.Fatalf("create ACL must be the contract builder: %v", plan.ACL)
	}
	if _, ok := plan.Data["organization_id"]; !ok || plan.Data["organization_id"] != "t1" {
		t.Fatalf("tenant must be derived from the caller: %v", plan.Data)
	}
	for _, op := range []Operation{OpUpdate, OpDelete} {
		plan, err := engine.Prepare(caller, op, &MutationRequest{
			TableID: "tickets", RowID: "r1", Data: mutationData(map[string]any{"status": "closed"}),
		})
		if err != nil {
			t.Fatalf("%s: %v", op, err)
		}
		if len(plan.ACL) != 0 {
			t.Fatalf("%s must not rewrite ACLs: %v", op, plan.ACL)
		}
	}
}

// TestContractErrorPrecedence pins the extraction order across a chain of
// wrappers: an Appwrite SDK error anywhere wins, then an httpx domain error,
// then no status.
func TestContractErrorPrecedence(t *testing.T) {
	sdk := sdkErr(404, "row_not_found")
	domain := httpx.Conflict("domain conflict", map[string]any{"field": "f"})

	cases := []struct {
		name   string
		err    error
		status int
	}{
		{"sdk", sdk, 404},
		{"wrapped sdk", fmt.Errorf("outer: %w", sdk), 404},
		{"httpx", domain, 409},
		{"wrapped httpx", fmt.Errorf("outer: %w", domain), 409},
		{"httpx cause sdk", &httpx.Error{Status: 502, Code: "upstream_error", Message: "m", Cause: sdk}, 404},
		{"three layers", fmt.Errorf("outer: %w", &httpx.Error{Status: 502, Code: "upstream_error", Message: "m", Cause: fmt.Errorf("inner: %w", sdk)}), 404},
		{"plain", errors.New("boom"), 0},
		{"nil", nil, 0},
	}
	for _, tc := range cases {
		if got := ErrorStatus(tc.err); got != tc.status {
			t.Errorf("%s: ErrorStatus=%d want %d", tc.name, got, tc.status)
		}
	}

	// MapError follows the same order and never re-wraps a domain error.
	if MapError(nil, "tickets") != nil {
		t.Fatal("nil must map to nil")
	}
	if MapError(domain, "tickets") != domain {
		t.Fatal("a domain error must pass through unchanged")
	}
	wrappedDomain := fmt.Errorf("outer: %w", domain)
	if MapError(wrappedDomain, "tickets") != wrappedDomain {
		t.Fatal("a wrapped domain error must pass through unchanged")
	}
	mapped := contractHE(t, MapError(sdk, "tickets"))
	if mapped.Status != 404 || mapped.Code != "not_found" || mapped.Message != appwrite.MessageNotFound ||
		mapped.Params["table"] != "tickets" || mapped.Params["reason"] != "row_not_found" {
		t.Fatalf("sdk mapping contract: %+v", mapped)
	}
	if strings.Contains(mapped.Message, "secret upstream text") || mapped.Detail == "" {
		t.Fatal("upstream text is private Detail only")
	}
	// An httpx wrapper around an SDK error maps the SDK error, not the wrapper.
	outer := &httpx.Error{Status: 502, Code: "upstream_error", Message: "m", Cause: sdk}
	if got := contractHE(t, MapError(outer, "tickets")); got.Status != 404 {
		t.Fatalf("SDK error must map before the httpx wrapper: %+v", got)
	}
	// A plain error becomes a generic 502 whose cause is still discoverable.
	cause := errors.New("dial tcp: refused")
	plain := contractHE(t, MapError(cause, "tickets"))
	if plain.Status != 502 || plain.Code != "upstream_error" || !errors.Is(plain, cause) {
		t.Fatalf("plain error contract: %+v", plain)
	}
}

// TestContractErrorBodyShapes pins the public JSON body for every domain status
// and the generic 500 fallback. Detail/Cause must never reach the body.
func TestContractErrorBodyShapes(t *testing.T) {
	cases := []struct {
		name   string
		err    error
		status int
		code   string
		msg    string
	}{
		{"bad request", httpx.BadRequest("bad", nil), 400, "bad_request", "bad"},
		{"unauthorized", httpx.Unauthorized("auth", nil), 401, "unauthorized", "auth"},
		{"forbidden", httpx.Forbidden("denied", nil), 403, "forbidden", "denied"},
		{"not found", httpx.NotFound("gone", nil), 404, "not_found", "gone"},
		{"conflict", httpx.Conflict("clash", nil), 409, "conflict", "clash"},
		{"precondition", httpx.PreconditionFailed("stale", nil), 412, "precondition_failed", "stale"},
		{"upstream", httpx.Upstream("down", nil), 502, "upstream_error", "down"},
	}
	for _, tc := range cases {
		status, body := ErrorBody(tc.err)
		if status != tc.status || body["error"] != tc.msg || body["code"] != tc.code {
			t.Errorf("%s: %d %v", tc.name, status, body)
		}
		if _, has := body["params"]; has {
			t.Errorf("%s: empty params must be omitted: %v", tc.name, body)
		}
	}

	// Params are included only when present, and are the exact domain params.
	status, body := ErrorBody(httpx.BadRequest("bad", map[string]any{"field": "x"}))
	if status != 400 {
		t.Fatal(status)
	}
	params, ok := body["params"].(map[string]any)
	if !ok || params["field"] != "x" {
		t.Fatalf("params: %v", body)
	}

	// A status outside 400-599 is an internal bug and becomes a 500; the domain
	// body is kept because the error is still a domain error.
	for _, invalid := range []int{0, 200, 399, 600} {
		status, body := ErrorBody(&httpx.Error{Status: invalid, Code: "weird", Message: "m"})
		if status != 500 || body["code"] != "weird" || body["error"] != "m" {
			t.Errorf("invalid status %d: %d %v", invalid, status, body)
		}
	}

	// Detail and Cause are operator-only. Marshal the body and prove no secret
	// substring survives.
	private := &httpx.Error{
		Status:  502,
		Code:    "upstream_error",
		Message: "appwrite request failed",
		Params:  map[string]any{"table": "tickets"},
		Detail:  "SECRET-DETAIL",
		Cause:   errors.New("SECRET-CAUSE"),
	}
	_, body = ErrorBody(private)
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "SECRET") {
		t.Fatalf("private fields leaked: %s", encoded)
	}
	if strings.Contains(string(encoded), "detail") || strings.Contains(string(encoded), "cause") {
		t.Fatalf("private keys leaked: %s", encoded)
	}

	// Anything that is not a domain error is the fixed generic 500.
	for _, generic := range []error{nil, errors.New("boom"), fmt.Errorf("wrapped: %w", errors.New("x"))} {
		status, body := ErrorBody(generic)
		if status != 500 || body["error"] != "internal server error" || body["code"] != "internal_error" {
			t.Errorf("%v -> %d %v", generic, status, body)
		}
	}
}

// TestContractTransactionConflictPrecedence pins that only a raw Appwrite 409 or
// a transaction-tagged httpx 409 counts as a transaction conflict; a domain 409
// must reach the caller unchanged.
func TestContractTransactionConflictPrecedence(t *testing.T) {
	if !IsTransactionConflict(sdkErr(409, "row_conflict")) {
		t.Fatal("a raw Appwrite 409 is a transaction conflict")
	}
	if !IsTransactionConflict(httpx.Conflict("tx", map[string]any{"table": "transaction"})) {
		t.Fatal("a transaction-tagged httpx 409 is a transaction conflict")
	}
	if IsTransactionConflict(httpx.Conflict("domain", map[string]any{"field": "f"})) {
		t.Fatal("a domain 409 must not be treated as a transaction conflict")
	}
	if IsTransactionConflict(httpx.Conflict("tx", map[string]any{"table": 5})) {
		t.Fatal("a non-string table param must not match")
	}
	if IsTransactionConflict(nil) || IsTransactionConflict(sdkErr(500, "x")) {
		t.Fatal("non-conflicts must not match")
	}
}

// TestContractReadValidationPrecedence pins the order in which the read engine
// reports failures, so a consumer sees a stable error for an ambiguous request:
// caller identity -> table admission -> client queries -> window -> projection.
func TestContractReadValidationPrecedence(t *testing.T) {
	set := ReadPolicySet{
		Tables: map[string]ReadPolicy{
			"tickets":  {},
			"api_keys": {Allow: MetadataFields("key_name")},
		},
		Denied: map[string]string{"organizations": "authoritative organisation identity"},
	}
	engine := ReadEngine{Policies: set}

	// An invalid verified caller is refused before table admission.
	_, err := engine.Prepare("bad team", &ReadRequest{TableID: "unknown"})
	if he := contractHE(t, err); he.Status != 403 || he.Message != "verified caller identity is invalid" {
		t.Fatalf("caller precedence: %+v", he)
	}

	// Table admission happens before the client query is parsed.
	_, err = engine.Prepare("t1", &ReadRequest{
		TableID: "unknown",
		Queries: []string{`{"method":"equal","attribute":"organization_id","values":["t2"]}`},
	})
	if he := contractHE(t, err); he.Status != 403 || he.Params["table"] != "unknown" {
		t.Fatalf("admission precedence: %+v", he)
	}

	// A client tenant filter is a 400 for an admitted table.
	_, err = engine.Prepare("t1", &ReadRequest{
		TableID: "tickets",
		Queries: []string{`{"method":"equal","attribute":"organization_id","values":["t2"]}`},
	})
	if he := contractHE(t, err); he.Status != 400 || he.Params["field"] != "queries" {
		t.Fatalf("tenant query precedence: %+v", he)
	}

	// The window is resolved before the projection is validated.
	zero := 0
	_, err = engine.Prepare("t1", &ReadRequest{TableID: "tickets", Limit: &zero, Select: []string{"$id"}})
	if he := contractHE(t, err); he.Status != 400 || he.Params["field"] != "limit" {
		t.Fatalf("window precedence: %+v", he)
	}

	// A denied table carries its explicit reason.
	_, err = engine.Prepare("t1", &ReadRequest{TableID: "organizations"})
	if he := contractHE(t, err); he.Status != 403 || he.Params["reason"] != "authoritative organisation identity" {
		t.Fatalf("denied table reason: %+v", he)
	}
}

func contractHE(t *testing.T, err error) *httpx.Error {
	t.Helper()
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	var he *httpx.Error
	if !errors.As(err, &he) || he == nil {
		t.Fatalf("expected httpx.Error, got %T: %v", err, err)
	}
	return he
}

func contractSameStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range want {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func contractContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

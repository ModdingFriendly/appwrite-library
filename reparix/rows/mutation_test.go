package rows

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/ModdingFriendly/appwrite-library/httpx"
)

func mutationPolicySet() MutationPolicySet {
	return MutationPolicySet{
		Tables: map[string]MutationPolicy{
			"tickets": {
				Fields: map[string]FieldSpec{
					"subject":     {Type: FieldVarchar, MaxLen: 40, Required: true},
					"status":      {Type: FieldEnum, Enum: []string{"open", "closed"}},
					"priority":    {Type: FieldInteger, HasMin: true, Min: 0, HasMax: true, Max: 5},
					"amount":      {Type: FieldMoney, Money: MoneyNonNegative},
					"notes":       {Type: FieldText},
					"customer_id": {Type: FieldVarchar, MaxLen: 36},
				},
				Blocked:   map[string]string{"created_by_user_id": "derived from the verified caller"},
				Immutable: []string{"subject"},
				Operations: []Operation{
					OpCreate, OpUpdate, OpDelete,
				},
				Derived: map[string]Deriver{
					"customer_user_id": func(_ MutationCaller, data map[string]any) (any, error) {
						if _, ok := data["customer_id"]; !ok {
							return nil, nil
						}
						return "user-1", nil
					},
				},
				ReadRoles:      []string{"admin", "technician"},
				ReadUserFields: []string{"customer_user_id"},
			},
			"audit_logs": {
				Fields:     map[string]FieldSpec{"message": {Type: FieldText, Required: true}},
				Operations: []Operation{OpCreate},
				Global:     true,
			},
		},
		Denied: map[string]string{"api_keys": "credential state"},
	}
}

func mutationData(values map[string]any) map[string]json.RawMessage {
	data := make(map[string]json.RawMessage, len(values))
	for key, value := range values {
		data[key] = raw(value)
	}
	return data
}

func mutationReq(values map[string]any) *MutationRequest {
	return &MutationRequest{TableID: "tickets", Data: mutationData(values)}
}

func TestMutationEngineFailClosed(t *testing.T) {
	engine := MutationEngine{Policies: mutationPolicySet()}
	caller := MutationCaller{TeamID: "t1", UserID: "u1"}
	for name, tc := range map[string]struct {
		caller MutationCaller
		op     Operation
		req    *MutationRequest
	}{
		"unknown table": {caller, OpCreate, &MutationRequest{TableID: "billing_accounts"}},
		"denied table":  {caller, OpCreate, &MutationRequest{TableID: "api_keys"}},
		"empty table":   {caller, OpCreate, &MutationRequest{}},
		"bad op":        {caller, "read", &MutationRequest{TableID: "tickets"}},
		"bad caller":    {MutationCaller{TeamID: "t1"}, OpCreate, &MutationRequest{TableID: "tickets"}},
		"nil request":   {caller, OpCreate, nil},
	} {
		if _, err := engine.Prepare(tc.caller, tc.op, tc.req); err == nil {
			t.Errorf("%s must be refused", name)
		}
	}
	if _, err := (MutationEngine{}).Prepare(caller, OpCreate, mutationReq(map[string]any{"subject": "s"})); err == nil {
		t.Fatal("a nil policy set must deny everything")
	}
	if _, err := engine.Prepare(caller, OpUpdate, &MutationRequest{TableID: "audit_logs", RowID: "r1"}); err == nil {
		t.Fatal("an operation outside the policy must be refused")
	}
}

func TestMutationCreateDerivesTenantAndACL(t *testing.T) {
	engine := MutationEngine{Policies: mutationPolicySet()}
	caller := MutationCaller{TeamID: "t1", UserID: "u1"}
	req := mutationReq(map[string]any{
		"subject":     "broken screen",
		"status":      "open",
		"priority":    3,
		"amount":      "GBP 1.50",
		"customer_id": "c1",
	})
	req.OrganizationID = "t1"
	plan, err := engine.Prepare(caller, OpCreate, req)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Data["organization_id"] != "t1" {
		t.Fatalf("tenant must be derived from the caller: %v", plan.Data)
	}
	if plan.Data["customer_user_id"] != "user-1" {
		t.Fatalf("derived field missing: %v", plan.Data)
	}
	if plan.Data["amount"] != "GBP 1.50" || plan.Data["priority"] != 3 {
		t.Fatalf("parsed data: %v", plan.Data)
	}
	want := []string{`read("team:t1/admin")`, `read("team:t1/technician")`, `read("user:user-1")`}
	if !reflect.DeepEqual(plan.ACL, want) {
		t.Fatalf("ACL: %v", plan.ACL)
	}
	for _, grant := range plan.ACL {
		if !strings.HasPrefix(grant, `read("`) {
			t.Fatalf("only read grants are allowed: %s", grant)
		}
		if strings.Contains(grant, `update(`) || strings.Contains(grant, `delete(`) ||
			strings.Contains(grant, `users`) || strings.Contains(grant, `any`) {
			t.Fatalf("broader grant leaked: %s", grant)
		}
	}

	// A global policy writes no organization_id and gets no grants unless the
	// consumer supplies read roles.
	globalPlan, err := engine.Prepare(caller, OpCreate, &MutationRequest{
		TableID: "audit_logs",
		Data:    mutationData(map[string]any{"message": "x"}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := globalPlan.Data["organization_id"]; ok {
		t.Fatal("global table must not get an organization_id")
	}
	if len(globalPlan.ACL) != 0 {
		t.Fatalf("a global policy with no read roles gets no grants: %v", globalPlan.ACL)
	}
}

func TestMutationRejectsCrossTenantAndServerFields(t *testing.T) {
	engine := MutationEngine{Policies: mutationPolicySet()}
	caller := MutationCaller{TeamID: "t1", UserID: "u1"}
	for name, req := range map[string]*MutationRequest{
		"body org":         {TableID: "tickets", OrganizationID: "t2", Data: mutationData(map[string]any{"subject": "s"})},
		"client org":       {TableID: "tickets", Data: mutationData(map[string]any{"organization_id": "t2", "subject": "s"})},
		"permissions":      {TableID: "tickets", Data: mutationData(map[string]any{"$permissions": []string{`read("any")`}})},
		"derived":          {TableID: "tickets", Data: mutationData(map[string]any{"customer_user_id": "user-1", "subject": "s"})},
		"blocked":          {TableID: "tickets", Data: mutationData(map[string]any{"created_by_user_id": "u1", "subject": "s"})},
		"unknown field":    {TableID: "tickets", Data: mutationData(map[string]any{"subject": "s", "secret": "x"})},
		"bad enum":         {TableID: "tickets", Data: mutationData(map[string]any{"subject": "s", "status": "pending"})},
		"bad int":          {TableID: "tickets", Data: mutationData(map[string]any{"subject": "s", "priority": 6})},
		"bad money":        {TableID: "tickets", Data: mutationData(map[string]any{"subject": "s", "amount": "GBP 1.5"})},
		"missing required": {TableID: "tickets", Data: mutationData(map[string]any{"status": "open"})},
		"empty required":   {TableID: "tickets", Data: mutationData(map[string]any{"subject": "  "})},
	} {
		if _, err := engine.Prepare(caller, OpCreate, req); err == nil {
			t.Errorf("%s must be refused", name)
		}
	}
	if _, err := engine.Prepare(caller, OpCreate, &MutationRequest{
		TableID: "tickets", RowID: "bad id", Data: mutationData(map[string]any{"subject": "s"}),
	}); err == nil {
		t.Fatal("invalid row id")
	}
}

func TestMutationACLOnlyUsesDerivedUserFields(t *testing.T) {
	caller := MutationCaller{TeamID: "t1", UserID: "u1"}
	base := MutationPolicy{
		Table: "tickets",
		Fields: map[string]FieldSpec{
			"subject":   {Type: FieldVarchar, Required: true},
			"reader_id": {Type: FieldVarchar, MaxLen: 36},
		},
		Operations:     []Operation{OpCreate},
		ReadRoles:      []string{"admin"},
		ReadUserFields: []string{"reader_id"},
	}
	engine := MutationEngine{Policies: MutationPolicySet{Tables: map[string]MutationPolicy{"tickets": base}}}
	plan, err := engine.Prepare(caller, OpCreate, &MutationRequest{
		TableID: "tickets",
		Data:    mutationData(map[string]any{"subject": "s", "reader_id": "user-2"}),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, grant := range plan.ACL {
		if strings.Contains(grant, "user-2") {
			t.Fatalf("a client-writable field must never choose a read ACL principal: %v", plan.ACL)
		}
	}

	// A derived user field does grant read access.
	base.Derived = map[string]Deriver{"reader_id": func(MutationCaller, map[string]any) (any, error) { return "user-3", nil }}
	engine = MutationEngine{Policies: MutationPolicySet{Tables: map[string]MutationPolicy{"tickets": base}}}
	plan, err = engine.Prepare(caller, OpCreate, &MutationRequest{
		TableID: "tickets",
		Data:    mutationData(map[string]any{"subject": "s"}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !containsString(plan.ACL, `read("user:user-3")`) {
		t.Fatalf("derived user must get a read grant: %v", plan.ACL)
	}
}

func TestMutationUpdateAndDelete(t *testing.T) {
	engine := MutationEngine{Policies: mutationPolicySet()}
	caller := MutationCaller{TeamID: "t1", UserID: "u1"}
	if _, err := engine.Prepare(caller, OpUpdate, &MutationRequest{TableID: "tickets"}); err == nil {
		t.Fatal("update requires a row id")
	}
	plan, err := engine.Prepare(caller, OpUpdate, &MutationRequest{
		TableID: "tickets",
		RowID:   "r1",
		Data: mutationData(map[string]any{
			"status": "closed",
			"notes":  nil,
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Data["status"] != "closed" {
		t.Fatalf("update data: %v", plan.Data)
	}
	if value, ok := plan.Data["notes"]; !ok || value != nil {
		t.Fatalf("an optional null must clear the column: %v", plan.Data)
	}
	if _, ok := plan.Data["organization_id"]; ok {
		t.Fatal("updates must not rewrite the tenant column")
	}
	if len(plan.ACL) != 0 {
		t.Fatal("updates must not rewrite row ACLs")
	}
	if _, err := engine.Prepare(caller, OpUpdate, &MutationRequest{
		TableID: "tickets", RowID: "r1", Data: mutationData(map[string]any{"subject": "new"}),
	}); err == nil {
		t.Fatal("immutable field must be refused")
	}
	if _, err := engine.Prepare(caller, OpUpdate, &MutationRequest{
		TableID: "tickets", RowID: "r1", Data: mutationData(map[string]any{"subject": nil}),
	}); err == nil {
		t.Fatal("a required field may not be cleared")
	}

	del, err := engine.Prepare(caller, OpDelete, &MutationRequest{
		TableID: "tickets", RowID: "r1", Data: mutationData(map[string]any{"subject": "ignored"}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if del.Data != nil || len(del.ACL) != 0 {
		t.Fatalf("delete must not carry data or ACLs: %+v", del)
	}
}

func TestMutationDeriverFailures(t *testing.T) {
	caller := MutationCaller{TeamID: "t1", UserID: "u1"}
	for name, policy := range map[string]MutationPolicy{
		"nil deriver": {
			Table:      "tickets",
			Fields:     map[string]FieldSpec{"subject": {Type: FieldVarchar, Required: true}},
			Operations: []Operation{OpCreate},
			Derived:    map[string]Deriver{"x": nil},
		},
		"deriver error": {
			Table:      "tickets",
			Fields:     map[string]FieldSpec{"subject": {Type: FieldVarchar, Required: true}},
			Operations: []Operation{OpCreate},
			Derived:    map[string]Deriver{"x": func(MutationCaller, map[string]any) (any, error) { return nil, httpx.Conflict("conflict", nil) }},
		},
		"required derived missing": {
			Table: "tickets",
			Fields: map[string]FieldSpec{
				"subject": {Type: FieldVarchar, Required: true},
				"x":       {Type: FieldVarchar, Required: true},
			},
			Operations: []Operation{OpCreate},
			Derived:    map[string]Deriver{"x": func(MutationCaller, map[string]any) (any, error) { return nil, nil }},
		},
		"cross tenant org deriver": {
			Table:      "tickets",
			Fields:     map[string]FieldSpec{"subject": {Type: FieldVarchar, Required: true}},
			Operations: []Operation{OpCreate},
			Derived:    map[string]Deriver{"organization_id": func(MutationCaller, map[string]any) (any, error) { return "t2", nil }},
		},
	} {
		engine := MutationEngine{Policies: MutationPolicySet{Tables: map[string]MutationPolicy{"tickets": policy}}}
		_, err := engine.Prepare(caller, OpCreate, &MutationRequest{TableID: "tickets", Data: mutationData(map[string]any{"subject": "s"})})
		if err == nil {
			t.Errorf("%s must fail closed", name)
			continue
		}
		if name == "deriver error" {
			if _, ok := err.(*httpx.Error); !ok {
				t.Errorf("deriver error must propagate: %v", err)
			}
		}
	}

	// A nil derived value on an optional field simply omits the column.
	optional := MutationEngine{Policies: MutationPolicySet{Tables: map[string]MutationPolicy{"tickets": {
		Table:      "tickets",
		Fields:     map[string]FieldSpec{"subject": {Type: FieldVarchar, Required: true}},
		Operations: []Operation{OpCreate},
		Derived:    map[string]Deriver{"x": func(MutationCaller, map[string]any) (any, error) { return nil, nil }},
	}}}}
	plan, err := optional.Prepare(caller, OpCreate, &MutationRequest{TableID: "tickets", Data: mutationData(map[string]any{"subject": "s"})})
	if err != nil {
		t.Fatal(err)
	}
	if _, present := plan.Data["x"]; present {
		t.Fatalf("an unavailable optional field must be omitted: %v", plan.Data)
	}
}

func TestParseMutationRequest(t *testing.T) {
	req, err := ParseMutationRequest([]byte(`{"table_id":"tickets","row_id":"r1","data":{"priority":0}}`))
	if err != nil || req.TableID != "tickets" || string(req.Data["priority"]) != "0" {
		t.Fatalf("%+v %v", req, err)
	}
	for name, body := range map[string]string{
		"empty":     " ",
		"unknown":   `{"table_id":"t","permissions":[]}`,
		"two docs":  `{"table_id":"t"}{}`,
		"not obj":   `[]`,
		"too large": `{"table_id":"` + strings.Repeat("a", MaxMutationBytes) + `"}`,
	} {
		if _, err := ParseMutationRequest([]byte(body)); err == nil || he(t, err).Status != 400 {
			t.Errorf("%s must be 400: %v", name, err)
		}
	}
}

func TestMutationErrorPrecedence(t *testing.T) {
	// A consumer-wrapped SDK error keeps the SDK status even when the outer
	// error is an httpx 502; ErrorStatus/MapError must extract the SDK error
	// first.
	sdk := sdkErr(409, "row_conflict")
	wrapped := &httpx.Error{Status: 502, Code: "upstream_error", Message: "m", Cause: sdk}
	if ErrorStatus(wrapped) != 409 {
		t.Fatal("sdk error must win over httpx.Error")
	}
	mapped := MapError(wrapped, "tickets")
	if he(t, mapped).Status != 409 || he(t, mapped).Code != "conflict" {
		t.Fatalf("mapped: %+v", mapped)
	}
	domain := httpx.Forbidden("domain", map[string]any{"field": "f"})
	if MapError(domain, "tickets") != domain {
		t.Fatal("domain error must pass through")
	}
	if !errors.Is(MapError(domain, "tickets"), domain) {
		t.Fatal("domain error identity")
	}
}

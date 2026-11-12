package rows

import (
	"reflect"
	"strings"
	"testing"
)

func readPolicySet() ReadPolicySet {
	return ReadPolicySet{
		Tables: map[string]ReadPolicy{
			"tickets": {},
			"api_keys": {
				Allow: MetadataFields("key_name", "key_prefix"),
				Deny:  []string{"key_hash"},
			},
			"plans": {Global: true, Allow: MetadataFields("name")},
		},
		Denied: map[string]string{"organizations": "authoritative organisation identity"},
	}
}

func TestReadEngineFailClosed(t *testing.T) {
	engine := ReadEngine{Policies: readPolicySet()}
	for name, req := range map[string]*ReadRequest{
		"unknown": {TableID: "billing_accounts"},
		"denied":  {TableID: "organizations"},
		"empty":   {},
	} {
		if _, err := engine.Prepare("t1", req); err == nil {
			t.Errorf("%s table must be refused", name)
		}
	}
	if _, err := (ReadEngine{}).Prepare("t1", &ReadRequest{TableID: "tickets"}); err == nil {
		t.Fatal("a nil policy set must deny everything")
	}
	// The denied reason is explicit and the unknown table is not an oracle.
	if _, err := engine.Prepare("t1", &ReadRequest{TableID: "organizations"}); he(t, err).Params["reason"] != "authoritative organisation identity" {
		t.Fatal("denied reason missing")
	}
	if _, err := engine.Prepare("bad team", &ReadRequest{TableID: "tickets"}); he(t, err).Status != 403 {
		t.Fatal("invalid verified team")
	}
	if _, err := engine.Prepare("t1", nil); he(t, err).Status != 400 {
		t.Fatal("nil request")
	}
}

func TestReadEngineBuildsAuthoritativeQuery(t *testing.T) {
	engine := ReadEngine{Policies: readPolicySet()}
	limit, offset := 500, 99999999
	plan, err := engine.Prepare("t1", &ReadRequest{
		TableID: "tickets",
		Queries: []string{`{"method":"equal","attribute":"status","values":["open"]}`},
		Select:  []string{"status", " status "},
		Limit:   &limit,
		Offset:  &offset,
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Limit != MaxReadLimit || plan.Offset != MaxReadOffset {
		t.Fatalf("window not bounded: %d %d", plan.Limit, plan.Offset)
	}
	if !reflect.DeepEqual(plan.Select, []string{"status"}) {
		t.Fatalf("select not normalised: %v", plan.Select)
	}
	if len(plan.Queries) != 5 {
		t.Fatalf("queries: %v", plan.Queries)
	}
	if !strings.Contains(plan.Queries[0], `"organization_id"`) || !strings.Contains(plan.Queries[0], `"t1"`) {
		t.Fatalf("tenant filter must be first: %v", plan.Queries)
	}
	if !strings.Contains(plan.Queries[1], `"status"`) {
		t.Fatalf("client query must follow the tenant filter: %v", plan.Queries)
	}
	if !strings.Contains(plan.Queries[2], "organization_id") {
		t.Fatalf("tenant projection must survive: %v", plan.Queries)
	}
	if !strings.Contains(plan.Queries[3], `"limit"`) || !strings.Contains(plan.Queries[4], `"offset"`) {
		t.Fatalf("window must be last: %v", plan.Queries)
	}
}

func TestReadEngineRejectsTenantAndProjectionEscapes(t *testing.T) {
	engine := ReadEngine{Policies: readPolicySet()}
	for name, req := range map[string]*ReadRequest{
		"client tenant filter": {TableID: "tickets", Queries: []string{`{"method":"equal","attribute":"organization_id","values":["t2"]}`}},
		"client select query":  {TableID: "tickets", Queries: []string{`{"method":"select","values":["status"]}`}},
		"forbidden select":     {TableID: "api_keys", Select: []string{"key_hash"}},
		"unlisted select":      {TableID: "api_keys", Select: []string{"scopes"}},
		"credential select":    {TableID: "tickets", Select: []string{"secret_hash"}},
		"system select":        {TableID: "tickets", Select: []string{"$permissions"}},
	} {
		if _, err := engine.Prepare("t1", req); err == nil {
			t.Errorf("%s must be refused", name)
		}
	}
}

func TestReadEngineApplyRechecksTenantAndProjects(t *testing.T) {
	engine := ReadEngine{Policies: readPolicySet()}
	plan, err := engine.Prepare("t1", &ReadRequest{TableID: "api_keys", Select: []string{"key_name"}})
	if err != nil {
		t.Fatal(err)
	}
	rows := []map[string]any{
		{"$id": "a", "organization_id": "t1", "key_name": "k", "key_prefix": "p", "key_hash": "H", "api_key": "plain", "$permissions": []string{"any"}, "$sequence": 3, "unlisted": 1},
		{"$id": "b", "organization_id": "t2", "key_name": "other"},
		{"$id": "c", "key_name": "tenantless"},
		{"$id": "d", "organization_id": ""},
	}
	kept, dropped := plan.Apply(rows)
	if len(kept) != 1 || dropped != 3 {
		t.Fatalf("kept=%d dropped=%d", len(kept), dropped)
	}
	if !reflect.DeepEqual(kept[0], map[string]any{
		"$id": "a", "organization_id": "t1", "key_name": "k", "key_prefix": "p",
	}) {
		t.Fatalf("projected row: %#v", kept[0])
	}
	if _, ok := kept[0]["$permissions"]; ok {
		t.Fatal("$permissions leaked")
	}
	if _, ok := kept[0]["$sequence"]; ok {
		t.Fatal("$sequence leaked")
	}

	// Global tables skip the tenant query and the row recheck.
	globalPlan, err := engine.Prepare("t1", &ReadRequest{TableID: "plans"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(globalPlan.Queries[0], "organization_id") {
		t.Fatalf("global table must not get a tenant filter: %v", globalPlan.Queries)
	}
	globalRows, globalDropped := globalPlan.Apply([]map[string]any{{"$id": "p", "name": "pro", "secret": "S"}})
	if globalDropped != 0 || len(globalRows) != 1 || globalRows[0]["name"] != "pro" {
		t.Fatalf("global apply: %v %d", globalRows, globalDropped)
	}
	if _, ok := globalRows[0]["secret"]; ok {
		t.Fatal("credential deny list must still apply to global tables")
	}

	// A nil plan and an empty page stay non-nil so JSON is [].
	if kept, dropped := (&ReadPlan{}).Apply(nil); kept == nil || dropped != 0 {
		t.Fatal("nil rows must marshal as []")
	}
	if kept, _ := plan.Apply(nil); kept == nil {
		t.Fatal("empty tenant page must be non-nil")
	}
}

func TestRequireRowTenant(t *testing.T) {
	if err := RequireRowTenant("tickets", map[string]any{"$id": "r", "organization_id": "t1"}, "t1"); err != nil {
		t.Fatal(err)
	}
	for name, row := range map[string]map[string]any{
		"cross tenant": {"$id": "r", "organization_id": "t2"},
		"tenantless":   {"$id": "r"},
		"empty":        {"$id": "r", "organization_id": ""},
		"nil":          nil,
	} {
		err := RequireRowTenant("tickets", row, "t1")
		if err == nil || he(t, err).Status != 404 {
			t.Errorf("%s must be the same 404: %v", name, err)
		}
	}
}

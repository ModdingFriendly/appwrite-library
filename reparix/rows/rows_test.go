package rows

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/ModdingFriendly/appwrite-library/httpx"
)

func he(t *testing.T, err error) *httpx.Error {
	t.Helper()
	var e *httpx.Error
	if !errors.As(err, &e) {
		t.Fatalf("expected httpx.Error, got %v", err)
	}
	return e
}

func ip(i int) *int { return &i }

func raw(v any) json.RawMessage { b, _ := json.Marshal(v); return b }

func TestParseFieldValidation(t *testing.T) {
	ok := []struct {
		spec FieldSpec
		in   any
		want any
	}{
		{FieldSpec{Type: FieldVarchar, MaxLen: 5}, "abcde", "abcde"},
		{FieldSpec{Type: FieldEnum, Enum: []string{"a", "b"}}, "b", "b"},
		{FieldSpec{Type: FieldInteger, HasMin: true, Min: 0, HasMax: true, Max: 10}, 10, 10},
		{FieldSpec{Type: FieldDouble, HasMax: true, Max: 1.5}, 1.5, 1.5},
		{FieldSpec{Type: FieldMoney, Money: MoneyPositive}, "GBP 1.50", "GBP 1.50"},
		{FieldSpec{Type: FieldBoolean}, true, true},
		{FieldSpec{Type: FieldDatetime}, "2026-01-02", "2026-01-02"},
		{FieldSpec{Type: FieldEmail}, "a@b.io", "a@b.io"},
		{FieldSpec{Type: FieldVarchar, Array: true, MaxLen: 3}, []string{"a", "b"}, []string{"a", "b"}},
	}
	for _, tc := range ok {
		got, err := ParseField("f", tc.spec, raw(tc.in))
		if err != nil || !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%v: got %v, %v", tc.in, got, err)
		}
	}
	bad := []struct {
		name string
		spec FieldSpec
		in   any
	}{
		{"too long", FieldSpec{Type: FieldVarchar, MaxLen: 2}, "abc"},
		{"bad enum", FieldSpec{Type: FieldEnum, Enum: []string{"a"}}, "z"},
		{"int as string", FieldSpec{Type: FieldInteger}, "1"},
		{"int above max", FieldSpec{Type: FieldInteger, HasMax: true, Max: 5}, 6},
		{"int below min", FieldSpec{Type: FieldInteger, HasMin: true, Min: 0}, -1},
		{"fractional int", FieldSpec{Type: FieldInteger}, 1.5},
		{"double above max", FieldSpec{Type: FieldDouble, HasMax: true, Max: 1}, 1.1},
		{"money short", FieldSpec{Type: FieldMoney}, "GBP 1.5"},
		{"money number", FieldSpec{Type: FieldMoney}, 1.5},
		{"money negative", FieldSpec{Type: FieldMoney, Money: MoneyNonNegative}, "GBP -1.00"},
		{"money zero positive", FieldSpec{Type: FieldMoney, Money: MoneyPositive}, "GBP 0.00"},
		{"bool string", FieldSpec{Type: FieldBoolean}, "yes"},
		{"bad datetime", FieldSpec{Type: FieldDatetime}, "tomorrow"},
		{"display-name email", FieldSpec{Type: FieldEmail}, "Bob <b@x.io>"},
		{"null", FieldSpec{Type: FieldVarchar}, nil},
		{"array item long", FieldSpec{Type: FieldVarchar, Array: true, MaxLen: 2}, []string{"abc"}},
		{"not an array", FieldSpec{Type: FieldVarchar, Array: true}, "a"},
		{"unknown type", FieldSpec{}, "a"},
	}
	for _, tc := range bad {
		if _, err := ParseField("f", tc.spec, raw(tc.in)); err == nil || he(t, err).Status != 400 {
			t.Errorf("%s: want 400, got %v", tc.name, err)
		}
	}
	tags := make([]string, MaxArrayItems+1)
	for i := range tags {
		tags[i] = "a"
	}
	if _, err := ParseField("f", FieldSpec{Type: FieldVarchar, Array: true}, raw(tags)); he(t, err).Message != "too many array items" {
		t.Fatal("array cap")
	}
}

func TestClientQueriesCannotTouchTenant(t *testing.T) {
	bad := []string{
		`{"method":"equal","attribute":"organization_id","values":["t2"]}`,
		`{"method":"equal","attribute":"ORGANIZATION_ID","values":["t2"]}`,
		`{"method":"equal","attribute":"status","values":["organization_id"]}`,
		`{"method":"or","values":[{"method":"equal","attribute":"Organization_Id","values":["t2"]}]}`,
		`{"method":"equal","attribute":"organization\u005fid","values":["t2"]}`,
		`{"method":"select","values":["a"]}`,
		`not json`, `{"values":[]}`, ``,
		strings.Repeat("x", MaxReadQueryBytes+1),
	}
	for _, q := range bad {
		if _, _, _, err := ValidateReadQueries([]string{q}); err == nil || he(t, err).Status != 400 {
			t.Errorf("query %q must be 400: %v", q, err)
		}
	}
	many := make([]string, MaxReadQueries+1)
	for i := range many {
		many[i] = `{"method":"isNull","attribute":"a"}`
	}
	if _, _, _, err := ValidateReadQueries(many); err == nil {
		t.Fatal("too many queries")
	}
	if _, _, _, err := ValidateReadQueries([]string{`{"method":"limit","values":[1]}`, `{"method":"limit","values":[2]}`}); err == nil {
		t.Fatal("duplicate limit")
	}
	q, l, o, err := ValidateReadQueries([]string{`{"method":"equal","attribute":"status","values":["open"]}`, `{"method":"limit","values":[5]}`, `{"method":"offset","values":[2]}`})
	if err != nil || len(q) != 1 || *l != 5 || *o != 2 {
		t.Fatalf("%v %v %v %v", q, l, o, err)
	}
}

func TestReadWindow(t *testing.T) {
	l, o, err := ResolveReadWindow(nil, nil, nil, nil)
	if err != nil || l != DefaultReadLimit || o != 0 {
		t.Fatal(l, o, err)
	}
	l, o, _ = ResolveReadWindow(ip(100000), ip(99999999), nil, nil)
	if l != MaxReadLimit || o != MaxReadOffset {
		t.Fatalf("clamp: %d %d", l, o)
	}
	if l, _, _ = ResolveReadWindow(nil, nil, ip(7), nil); l != 7 {
		t.Fatal("query copy accepted when body omits it")
	}
	for name, a := range map[string][4]*int{
		"limit twice": {ip(1), nil, ip(2), nil}, "offset twice": {nil, ip(1), nil, ip(2)},
		"zero limit": {ip(0), nil, nil, nil}, "neg offset": {nil, ip(-1), nil, nil},
	} {
		if _, _, err := ResolveReadWindow(a[0], a[1], a[2], a[3]); err == nil {
			t.Errorf("%s must be rejected", name)
		}
	}
}

func TestSelectAndProjection(t *testing.T) {
	for _, bad := range [][]string{{"$permissions"}, {"$id"}, {""}, {strings.Repeat("a", MaxReadSelectFieldBytes+1)}} {
		if _, err := NormalizeReadSelect(bad); err == nil {
			t.Errorf("select %v must be rejected", bad)
		}
	}
	if got, _ := NormalizeReadSelect([]string{"a", " a ", "b"}); !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Fatal(got)
	}
	allow := MetadataFields("key_name")
	for _, sel := range []string{"key_hash", "secret_hash", "api_key", "scopes"} {
		if err := ValidateSelect([]string{sel}, allow, []string{"key_hash"}); err == nil || he(t, err).Status != 400 {
			t.Errorf("select %s must be 400", sel)
		}
	}
	if err := ValidateSelect([]string{"key_name"}, allow, nil); err != nil {
		t.Fatal(err)
	}
	if err := ValidateSelect([]string{"password_hash"}, nil, nil); err == nil {
		t.Fatal("global deny list applies without a projection")
	}
	if err := ValidateSelect([]string{"anything"}, nil, nil); err != nil {
		t.Fatal("nil allow means business columns are readable")
	}
}

func TestFilterAndProjectRows(t *testing.T) {
	rows := []map[string]any{
		{"$id": "a", "organization_id": "t1", "key_name": "k", "key_hash": "H", "api_key": "plain", "$permissions": []string{"any"}, "$sequence": 4, "unlisted": 1},
		{"$id": "b", "organization_id": "t2"}, {"$id": "c"}, {"$id": "d", "organization_id": ""},
	}
	kept, dropped := FilterTenantRows(rows, "t1")
	if len(kept) != 1 || kept[0]["$id"] != "a" || dropped != 3 {
		t.Fatalf("%v %d", kept, dropped)
	}
	StripSystemFields(kept[0])
	if n := ProjectRow(kept[0], MetadataFields("key_name"), []string{"key_hash"}); n != 3 {
		t.Fatalf("withheld %d", n)
	}
	if !reflect.DeepEqual(kept[0], map[string]any{"$id": "a", "organization_id": "t1", "key_name": "k"}) {
		t.Fatal(kept[0])
	}
	// No projection: only credentials are removed.
	row := map[string]any{"device": "d", "token": "T"}
	ProjectRow(row, nil, nil)
	if !reflect.DeepEqual(row, map[string]any{"device": "d"}) {
		t.Fatal(row)
	}
	if k, _ := FilterTenantRows(nil, "t1"); k == nil {
		t.Fatal("empty page must be non-nil so it marshals as []")
	}
}

func TestTenantFilterAndSelectQuery(t *testing.T) {
	if q := TenantFilter("t1"); !strings.Contains(q, `"organization_id"`) || !strings.Contains(q, `"t1"`) {
		t.Fatal(q)
	}
	if q := SelectQuery([]string{"a"}, true); !strings.Contains(q, "organization_id") {
		t.Fatal("tenant tables keep organization_id in the projection")
	}
	if q := SelectQuery([]string{"a"}, false); strings.Contains(q, "organization_id") {
		t.Fatal("global tables do not")
	}
}

func TestParseReadRequest(t *testing.T) {
	if r, err := ParseReadRequest([]byte(`{"table_id":"tickets","limit":0}`)); err != nil || r.Limit == nil || *r.Limit != 0 {
		t.Fatalf("explicit zero must be distinguishable: %v %v", r, err)
	}
	for name, body := range map[string]string{
		"empty": "  ", "unknown": `{"table_id":"t","organization_id":"t2"}`, "two docs": `{"table_id":"t"}{}`,
		"trailing": `{"table_id":"t"} x`, "not obj": `[]`,
		"too large": `{"table_id":"` + strings.Repeat("a", MaxReadBodyBytes) + `"}`,
	} {
		if _, err := ParseReadRequest([]byte(body)); err == nil || he(t, err).Status != 400 {
			t.Errorf("%s must be 400: %v", name, err)
		}
	}
}

func TestTeamReadACL(t *testing.T) {
	got := TeamReadACL("t1", []string{"admin", "technician", "admin", "bad role"}, "u1", "u1", "bad id", `x")`, "u2")
	want := []string{`read("team:t1/admin")`, `read("team:t1/technician")`, `read("user:u1")`, `read("user:u2")`}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%v", got)
	}
	for _, bad := range []string{"", "a b", `t1")`} {
		if a := TeamReadACL(bad, []string{"admin"}, "u1"); a == nil || len(a) != 0 {
			t.Fatalf("%q -> %#v", bad, a)
		}
	}
	if a := TeamReadACL("t1", nil); a == nil || len(a) != 0 {
		t.Fatal("no roles or users, no grants")
	}
	for _, p := range TeamReadACL("t1", []string{"admin"}, "u1") {
		if !strings.HasPrefix(p, "read(") {
			t.Fatalf("only read grants: %s", p)
		}
	}
}

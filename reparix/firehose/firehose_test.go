package firehose

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestBuildChangesCarriesTextAndSkipsNoOps(t *testing.T) {
	before := map[string]any{"fault_description": "screen cracked", "status": "New", "device": "iPhone"}
	data := map[string]any{"fault_description": "screen cracked and battery swollen", "status": "New", "device": "iPhone"}
	after := map[string]any{"fault_description": "screen cracked and battery swollen", "status": "New", "device": "iPhone"}
	got := BuildChanges(data, before, after)
	if len(got) != 1 || got[0].Kind != KindText || got[0].Before != "screen cracked" || !strings.Contains(got[0].After, "battery") {
		t.Fatalf("changes: %+v", got)
	}
}

func TestSecretsNeverLeak(t *testing.T) {
	for _, field := range []string{"passcode", "api_key", "consent_signature", "access_token", "password_hash"} {
		got := BuildChanges(map[string]any{field: "9999"}, map[string]any{field: "1234"}, map[string]any{field: "9999"})
		raw, _ := json.Marshal(got)
		if len(got) != 1 || got[0].Kind != KindRedacted || strings.Contains(string(raw), "1234") || strings.Contains(string(raw), "9999") {
			t.Fatalf("%s leaked: %s", field, raw)
		}
	}
}

func TestCreateListsWrittenFieldsAndHidesServerFields(t *testing.T) {
	data := map[string]any{"name": "Acme", "organization_id": "o", "created_by_user_id": "u"}
	got := BuildChanges(data, nil, map[string]any{"name": "Acme", "$id": "x"})
	if len(got) != 1 || got[0].Field != "name" || got[0].After != "Acme" {
		t.Fatalf("changes: %+v", got)
	}
	long := strings.Repeat("x", MaxValueRunes+5)
	capped := BuildChanges(map[string]any{"notes": long}, map[string]any{"notes": ""}, map[string]any{"notes": long})
	if len([]rune(capped[0].After)) != MaxValueRunes {
		t.Fatal("not capped")
	}
}

func TestSummarySpellsOutStatusMovesOnly(t *testing.T) {
	changes := []Change{
		{Field: "status", Kind: KindValue, Before: "Draft", After: "Ordered"},
		{Field: "notes", Kind: KindText, Before: "a", After: "b"},
		{Field: "supplier_id", Kind: KindValue, Before: "", After: "sup1"},
	}
	got := Summary("purchase_order", OpUpdate, map[string]any{"po_number": "PO-7", "email": "x@y.z"}, changes)
	if !strings.HasPrefix(got, "Purchase order updated — PO-7") || !strings.Contains(got, "status Draft → Ordered") || strings.Contains(got, "x@y.z") {
		t.Fatalf("summary: %q", got)
	}
	if strings.Contains(got, "sup1") {
		t.Fatalf("id fields must not be spelled out: %q", got)
	}
	if strings.Contains(got, "notes") {
		t.Fatalf("free text must not be spelled out: %q", got)
	}
}

func TestNamingAndRefs(t *testing.T) {
	if DefaultNaming("customer").For(OpUpdate) != "customer.updated" || ChildNaming("ticket.line").For(OpCreate) != "ticket.line.added" || ChildNaming("ticket.line").For(OpDelete) != "ticket.line.removed" {
		t.Fatal("naming")
	}
	refs := Refs("purchase_order_item", "i1", map[string]any{"purchase_order_id": "po1", "inventory_id": "inv1", "name": "x"})
	want := []string{"purchase_order_item:i1", "inventory:inv1", "purchase_order:po1"}
	if strings.Join(refs, ",") != strings.Join(want, ",") {
		t.Fatalf("refs %v", refs)
	}
}

func TestBuildGatewayEventUsesTheVerifiedCaller(t *testing.T) {
	now := time.Date(2026, 11, 16, 10, 0, 0, 0, time.UTC)
	ev := BuildGatewayEvent(Spec{
		Caller: Caller{TeamID: "org1", UserID: "u1", Role: "technician"}, Op: OpUpdate, Table: "ticket_line_items",
		Entity: "ticket.line", Naming: ChildNaming("ticket.line"), Version: 1, RowID: "l1",
		Data:   map[string]any{"quantity": 2},
		Before: map[string]any{"quantity": 1, "ticket_id": "t1", "organization_id": "forged"},
		After:  map[string]any{"quantity": 2, "ticket_id": "t1", "organization_id": "org1"}, CorrelationID: "c1", Now: now,
	})
	row, err := ev.RowData()
	if err != nil {
		t.Fatal(err)
	}
	if ev.Name != "ticket.line.updated" || row["organization_id"] != "org1" || row["ticket_id"] != "t1" || row["actor_user_id"] != "u1" || row["occurred_at"] != "2026-11-16T10:00:00Z" {
		t.Fatalf("event: %+v row: %v", ev, row)
	}
	refs := row["refs"].([]string)
	if strings.Join(refs, ",") != "ticket.line:l1,ticket:t1" {
		t.Fatalf("refs: %v", refs)
	}
	del := BuildGatewayEvent(Spec{Caller: Caller{TeamID: "o", UserID: "u"}, Op: OpDelete, Table: "customers", Entity: "customer", Naming: DefaultNaming("customer"), RowID: "c1", Before: map[string]any{"name": "Sam"}, Now: now})
	if del.Name != "customer.deleted" || len(del.Payload.(ChangePayload).Changes) != 0 {
		t.Fatalf("delete: %+v", del)
	}
}

package firehose

import "testing"

// TestGatewayEventRecordsTheCallerName proves the caller's display name reaches
// the event row: the audit timeline shows who made the change, not only an id.
func TestGatewayEventRecordsTheCallerName(t *testing.T) {
	ev := BuildGatewayEvent(Spec{
		Caller:  Caller{TeamID: "org1", UserID: "u1", Role: "admin", Name: "Kyle Campbell"},
		Op:      OpUpdate,
		Table:   "shifts",
		Entity:  "shift",
		Naming:  DefaultNaming("shift"),
		Version: 1,
		RowID:   "s1",
		Data:    map[string]any{"notes": "x"},
		Before:  map[string]any{"notes": "y"},
		After:   map[string]any{"notes": "x"},
	})
	row, err := ev.RowData()
	if err != nil {
		t.Fatal(err)
	}
	if row["actor_name"] != "Kyle Campbell" {
		t.Fatalf("actor_name = %v, want the caller name", row["actor_name"])
	}

	anonymous := BuildGatewayEvent(Spec{Caller: Caller{TeamID: "o", UserID: "u", Role: "admin"}, Op: OpDelete, Table: "shifts", Entity: "shift", Naming: DefaultNaming("shift"), Version: 1, RowID: "s1"})
	anonRow, err := anonymous.RowData()
	if err != nil {
		t.Fatal(err)
	}
	if _, present := anonRow["actor_name"]; present {
		t.Fatalf("an empty name must not be written: %v", anonRow["actor_name"])
	}
}

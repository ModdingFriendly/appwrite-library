package activity

// Tests for the shared activity vocabulary: the envelope, the redaction and
// caps, the shared event names and sources, and the best-effort writer.
//
// The trust rules under test:
//   - the envelope carries the verified organisation and actor only;
//   - a summary carries the allowlisted display column and nothing else;
//   - an event that is not writable is rejected instead of stored;
//   - a failed activity write is reported to the caller and never turned into
//     a business failure.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"unicode/utf8"
)

const (
	testOrganization = "team-a"
	testActor        = "user-1"
)

func TestPayloadUsesVerifiedTenantAndActor(t *testing.T) {
	event := Event{
		OrganizationID: testOrganization,
		ActorUserID:    testActor,
		Event:          "ticket.created",
		TableID:        "tickets",
		RowID:          "ticket-1",
		Summary:        "Ticket created — iPhone 15",
		Source:         SourceGateway,
	}
	payload, ok := event.Payload()
	if !ok {
		t.Fatal("a well-formed event must be writable")
	}
	if payload["organization_id"] != testOrganization {
		t.Fatalf("tenant = %v", payload["organization_id"])
	}
	if payload["actor_user_id"] != testActor {
		t.Fatalf("actor = %v", payload["actor_user_id"])
	}
	if payload["event"] != "ticket.created" {
		t.Fatalf("event = %v", payload["event"])
	}
	if payload["source"] != SourceGateway {
		t.Fatalf("source = %v", payload["source"])
	}
	if payload["table_id"] != "tickets" || payload["row_id"] != "ticket-1" {
		t.Fatalf("reference = %v/%v", payload["table_id"], payload["row_id"])
	}
	if _, present := payload["actor_name"]; present {
		t.Fatalf("actor_name must be omitted when unavailable, got %v", payload["actor_name"])
	}
}

func TestPayloadRejectsUnwritableEvents(t *testing.T) {
	cases := []struct {
		name  string
		event Event
	}{
		{"no organisation", Event{Event: "ticket.created", Source: SourceGateway}},
		{"invalid organisation", Event{OrganizationID: "bad team", Event: "ticket.created", Source: SourceGateway}},
		{"empty event", Event{OrganizationID: testOrganization, Event: "  ", Source: SourceGateway}},
		{"invalid event name", Event{OrganizationID: testOrganization, Event: "Ticket.Created", Source: SourceGateway}},
		{"empty source", Event{OrganizationID: testOrganization, Event: "ticket.created", Source: " "}},
		{"unknown source", Event{OrganizationID: testOrganization, Event: "ticket.created", Source: "guest"}},
	}
	for _, tc := range cases {
		if _, ok := tc.event.Payload(); ok {
			t.Fatalf("%s: event must be rejected: %+v", tc.name, tc.event)
		}
	}
}

func TestPayloadSanitisesSummaryAndTokens(t *testing.T) {
	event := Event{
		OrganizationID: testOrganization,
		ActorUserID:    testActor,
		ActorName:      "Bob Smith <bob@example.com>",
		Event:          "ticket.created",
		TableID:        "tick ets!",
		RowID:          "row-1",
		Summary:        "Ticket created — iPhone 15\nbob@example.com",
		Source:         SourceGateway,
	}
	payload, ok := event.Payload()
	if !ok {
		t.Fatal("a well-formed event must be writable")
	}
	if payload["table_id"] != "tickets" {
		t.Fatalf("table id = %v", payload["table_id"])
	}
	summary, _ := payload["summary"].(string)
	if strings.ContainsAny(summary, "\n") {
		t.Fatalf("summary kept a line break: %q", summary)
	}
	if strings.Contains(summary, "bob@example.com") {
		t.Fatalf("summary leaked an email address: %q", summary)
	}
	if summary != "Ticket created — iPhone 15 [redacted]" {
		t.Fatalf("summary = %q", summary)
	}
	// The email itself is redacted; the surrounding angle brackets stay
	// because they are ordinary text, matching the core-go redaction rule.
	if payload["actor_name"] != "Bob Smith <[redacted]>" {
		t.Fatalf("actor name = %v", payload["actor_name"])
	}
}

func TestEventNameMapsTableAndOperation(t *testing.T) {
	cases := map[string]string{
		"ticket.created":          EventName("tickets", OperationCreate),
		"ticket.updated":          EventName("tickets", OperationUpdate),
		"customer.deleted":        EventName("customers", OperationDelete),
		"stock_take_item.created": EventName("stock_take_items", OperationCreate),
		"invoice.changed":         EventName("invoices", Operation("unknown")),
	}
	for want, got := range cases {
		if got != want {
			t.Fatalf("event name = %q, want %q", got, want)
		}
		if !ValidEventName(got) {
			t.Fatalf("event name %q is not filterable", got)
		}
	}

	// A table that is not in the shared vocabulary yet still produces a
	// filterable name.
	fallback := EventName("widgets", OperationCreate)
	if fallback != "widgets.created" {
		t.Fatalf("fallback event name = %q", fallback)
	}
	if !ValidEventName(fallback) {
		t.Fatalf("fallback event name %q is not filterable", fallback)
	}
}

func TestSummaryUsesAllowlistedDisplayColumn(t *testing.T) {
	summary := Summary("tickets", OperationCreate, map[string]any{
		"$id":    "ticket-1",
		"device": "iPhone 15",
	})
	if summary != "Ticket created — iPhone 15" {
		t.Fatalf("summary = %q", summary)
	}

	// A deleted row has no row to read a display value from.
	if got := Summary("customers", OperationDelete, nil); got != "Customer deleted" {
		t.Fatalf("summary = %q", got)
	}

	// invoices.display is the number only: the price is never copied.
	invoice := Summary("invoices", OperationUpdate, map[string]any{
		"number": "INV-1042",
		"total":  "GBP 1250.00",
	})
	if strings.Contains(invoice, "1250") || strings.Contains(invoice, "GBP") {
		t.Fatalf("summary leaked a price: %q", invoice)
	}
	if invoice != "Invoice updated — INV-1042" {
		t.Fatalf("summary = %q", invoice)
	}

	// payments has no display column at all.
	if got := Summary("payments", OperationCreate, map[string]any{"amount": "GBP 20.00"}); got != "Payment created" {
		t.Fatalf("summary = %q", got)
	}
}

func TestSummaryStripsControlsAndRedactsEmail(t *testing.T) {
	summary := Summary("tickets", OperationUpdate, map[string]any{
		"device": "iPhone\x00 15\nbob@example.com\tPro",
	})
	if strings.ContainsAny(summary, "\x00\n\t") {
		t.Fatalf("summary kept control characters: %q", summary)
	}
	if strings.Contains(summary, "bob@example.com") {
		t.Fatalf("summary leaked an email address: %q", summary)
	}
	if summary != "Ticket updated — iPhone 15 [redacted] Pro" {
		t.Fatalf("summary = %q", summary)
	}
}

func TestSummaryIsCappedAtColumnLength(t *testing.T) {
	summary := SanitizeText(strings.Repeat("A", 400))
	if got := utf8.RuneCountInString(summary); got != MaxSummaryRunes {
		t.Fatalf("summary length = %d, want %d", got, MaxSummaryRunes)
	}

	// A very long display name is capped through the full builder.
	long := Summary("tickets", OperationCreate, map[string]any{"device": strings.Repeat("B", 300)})
	if got := utf8.RuneCountInString(long); got > MaxSummaryRunes {
		t.Fatalf("built summary length = %d", got)
	}
}

func TestSanitizeTextCollapsesWhitespaceAndDropsInvalidUTF8(t *testing.T) {
	if got := SanitizeText("  Ticket   created  "); got != "Ticket created" {
		t.Fatalf("sanitized text = %q", got)
	}
	got := SanitizeText("iPhone \xff 15")
	if !utf8.ValidString(got) {
		t.Fatalf("sanitized text is not valid UTF-8: %q", got)
	}
	if got != "iPhone 15" {
		t.Fatalf("sanitized text = %q", got)
	}
}

func TestSanitizeTokenKeepsOnlySafeCharacters(t *testing.T) {
	if got := SanitizeToken("row id 1!"); got != "rowid1" {
		t.Fatalf("token = %q", got)
	}
	if got := SanitizeToken("ticket-1.row_2"); got != "ticket-1.row_2" {
		t.Fatalf("token = %q", got)
	}
	if got := SanitizeToken("  "); got != "" {
		t.Fatalf("token = %q", got)
	}
}

func TestRowPermissionsAreReadOnlyStaff(t *testing.T) {
	permissions := RowPermissions(testOrganization)
	want := []string{
		`read("team:team-a/admin")`,
		`read("team:team-a/technician")`,
	}
	if strings.Join(permissions, "|") != strings.Join(want, "|") {
		t.Fatalf("permissions = %v", permissions)
	}
	for _, permission := range permissions {
		if strings.HasPrefix(permission, "update(") || strings.HasPrefix(permission, "delete(") ||
			strings.Contains(permission, "user:") || strings.Contains(permission, "any") ||
			strings.Contains(permission, "guests") {
			t.Fatalf("forbidden activity grant: %s", permission)
		}
	}
	if len(RowPermissions("bad team")) != 0 {
		t.Fatal("an invalid organisation must produce no grant")
	}
}

func TestRecordIsBestEffort(t *testing.T) {
	var written []map[string]any
	var granted []string
	writer := func(_ context.Context, data map[string]any, permissions []string) error {
		written = append(written, data)
		granted = permissions
		return nil
	}

	event := Event{
		OrganizationID: testOrganization,
		ActorUserID:    testActor,
		Event:          "ticket.created",
		TableID:        "tickets",
		RowID:          "ticket-1",
		Summary:        "Ticket created — iPhone 15",
		Source:         SourceGateway,
	}
	if err := Record(context.Background(), writer, event); err != nil {
		t.Fatalf("record: %v", err)
	}
	if len(written) != 1 {
		t.Fatalf("wrote %d rows", len(written))
	}
	if written[0]["organization_id"] != testOrganization {
		t.Fatalf("written tenant = %v", written[0]["organization_id"])
	}
	if strings.Join(granted, "|") != strings.Join(RowPermissions(testOrganization), "|") {
		t.Fatalf("granted = %v", granted)
	}
}

func TestRecordReportsWriteFailureWithoutFailingTheCaller(t *testing.T) {
	failure := errors.New("activity store is offline")
	writer := func(context.Context, map[string]any, []string) error {
		return failure
	}
	err := Record(context.Background(), writer, Event{
		OrganizationID: testOrganization,
		Event:          "ticket.created",
		Summary:        "Ticket created",
		Source:         SourceGateway,
	})
	if !errors.Is(err, failure) {
		t.Fatalf("record error = %v, want the writer failure", err)
	}
}

func TestRecordRejectsUnwritableEvent(t *testing.T) {
	called := false
	writer := func(context.Context, map[string]any, []string) error {
		called = true
		return nil
	}
	err := Record(context.Background(), writer, Event{
		OrganizationID: testOrganization,
		Event:          "ticket.created",
		Summary:        "Ticket created",
		Source:         "guest",
	})
	if !errors.Is(err, ErrNotWritable) {
		t.Fatalf("record error = %v, want ErrNotWritable", err)
	}
	if called {
		t.Fatal("an unwritable event must not reach the writer")
	}
}

func TestRecordWithoutWriterIsNoOp(t *testing.T) {
	if err := Record(context.Background(), nil, Event{
		OrganizationID: testOrganization,
		Event:          "ticket.created",
		Summary:        "Ticket created",
		Source:         SourceGateway,
	}); err != nil {
		t.Fatalf("a nil writer must be a no-op: %v", err)
	}
}

func TestSourcesAreClosed(t *testing.T) {
	sources := Sources()
	if len(sources) != 4 {
		t.Fatalf("sources = %v", sources)
	}
	for _, source := range sources {
		if !SourceAllowed(source) {
			t.Fatalf("source %q must be allowed", source)
		}
	}
	for _, source := range []string{"", "guest", "GATEWAY", "admin"} {
		if SourceAllowed(source) {
			t.Fatalf("source %q must be rejected", source)
		}
	}
}

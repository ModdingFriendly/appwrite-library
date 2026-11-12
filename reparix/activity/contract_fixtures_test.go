package activity_test

// Contract fixtures for the activity vocabulary. They exercise only the
// exported API and pin the behaviour the Reparix ledger depends on:
//
//   - summaries and actor names redact email addresses and strip controls;
//   - text and token columns are capped in runes, never splitting a character;
//   - the envelope carries only verified tenant/actor facts;
//   - the ledger is staff-readable and never client-writable;
//   - the source and event vocabularies stay closed and filterable.

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/ModdingFriendly/appwrite-library/reparix/activity"
)

type redactionFixture struct {
	Name  string `json:"name"`
	Kind  string `json:"kind"`
	Input string `json:"input"`
	Want  string `json:"want"`
}

type capFixture struct {
	Name       string `json:"name"`
	Kind       string `json:"kind"`
	Prefix     string `json:"prefix"`
	Repeat     string `json:"repeat"`
	Count      int    `json:"count"`
	Limit      int    `json:"limit"`
	WantRunes  int    `json:"want_runes"`
	WantPrefix string `json:"want_prefix"`
}

func loadFixtures[T any](t *testing.T, path string) []T {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", path, err)
	}
	var fixtures []T
	if err := json.Unmarshal(raw, &fixtures); err != nil {
		t.Fatalf("decode fixture %s: %v", path, err)
	}
	if len(fixtures) == 0 {
		t.Fatalf("fixture %s is empty", path)
	}
	return fixtures
}

func TestRedactionFixtures(t *testing.T) {
	for _, tc := range loadFixtures[redactionFixture](t, "testdata/redaction.json") {
		t.Run(tc.Name, func(t *testing.T) {
			var got string
			switch tc.Kind {
			case "text":
				got = activity.SanitizeText(tc.Input)
			case "token":
				got = activity.SanitizeToken(tc.Input)
			default:
				t.Fatalf("unknown fixture kind %q", tc.Kind)
			}
			if got != tc.Want {
				t.Fatalf("got %q, want %q", got, tc.Want)
			}
			if !utf8.ValidString(got) {
				t.Fatalf("sanitized value is not valid UTF-8: %q", got)
			}
			if tc.Kind == "text" && strings.ContainsAny(got, "\x00\n\r\t") {
				t.Fatalf("sanitized text kept a control character: %q", got)
			}
		})
	}
}

func TestCapFixtures(t *testing.T) {
	for _, tc := range loadFixtures[capFixture](t, "testdata/caps.json") {
		t.Run(tc.Name, func(t *testing.T) {
			input := tc.Prefix + strings.Repeat(tc.Repeat, tc.Count)
			var got string
			switch tc.Kind {
			case "text":
				got = activity.SanitizeTextLimit(input, tc.Limit)
			case "token":
				got = activity.SanitizeTokenLimit(input, tc.Limit)
			default:
				t.Fatalf("unknown fixture kind %q", tc.Kind)
			}
			if !utf8.ValidString(got) {
				t.Fatalf("capped value is not valid UTF-8: %q", got)
			}
			if runes := utf8.RuneCountInString(got); runes != tc.WantRunes {
				t.Fatalf("runes = %d, want %d", runes, tc.WantRunes)
			}
			if !strings.HasPrefix(got, tc.WantPrefix) {
				t.Fatalf("value %q does not start with %q", got, tc.WantPrefix)
			}
			if tc.Kind == "text" && strings.ContainsAny(got, "\x00\n\r\t") {
				t.Fatalf("capped text kept a control character: %q", got)
			}
		})
	}
}

func TestCapConstantsMatchLedgerColumns(t *testing.T) {
	caps := map[string]struct {
		got  int
		want int
	}{
		"summary": {activity.MaxSummaryRunes, 255},
		"event":   {activity.MaxEventRunes, 64},
		"token":   {activity.MaxTokenRunes, 64},
		"actor":   {activity.MaxActorRunes, 255},
		"display": {activity.MaxDisplayRunes, 120},
	}
	for name, c := range caps {
		if c.got != c.want {
			t.Fatalf("%s cap = %d, want %d", name, c.got, c.want)
		}
	}
}

func TestPayloadAppliesRedactionAndCaps(t *testing.T) {
	const email = "customer@example.com"
	payload, ok := (activity.Event{
		OrganizationID: "team-a",
		ActorUserID:    "user-1",
		ActorName:      "Name <" + email + "> " + strings.Repeat("N", 300),
		Event:          activity.EventPOSSale,
		TableID:        "invoices",
		RowID:          strings.Repeat("r", 100),
		Summary:        "POS sale — " + email + " " + strings.Repeat("S", 400),
		Source:         activity.SourcePOS,
	}).Payload()
	if !ok {
		t.Fatal("a well-formed event must be writable")
	}

	summary, _ := payload["summary"].(string)
	if strings.Contains(summary, email) {
		t.Fatalf("summary leaked an email address: %q", summary)
	}
	if strings.ContainsAny(summary, "\x00\n\r\t") {
		t.Fatalf("summary kept a control character: %q", summary)
	}
	if runes := utf8.RuneCountInString(summary); runes > activity.MaxSummaryRunes {
		t.Fatalf("summary runes = %d, cap = %d", runes, activity.MaxSummaryRunes)
	}

	actorName, _ := payload["actor_name"].(string)
	if strings.Contains(actorName, email) {
		t.Fatalf("actor name leaked an email address: %q", actorName)
	}
	if runes := utf8.RuneCountInString(actorName); runes > activity.MaxActorRunes {
		t.Fatalf("actor name runes = %d, cap = %d", runes, activity.MaxActorRunes)
	}

	rowID, _ := payload["row_id"].(string)
	if runes := utf8.RuneCountInString(rowID); runes != activity.MaxTokenRunes {
		t.Fatalf("row id runes = %d, cap = %d", runes, activity.MaxTokenRunes)
	}
	if payload["organization_id"] != "team-a" || payload["actor_user_id"] != "user-1" {
		t.Fatalf("verified attribution was lost: %v", payload)
	}
	if payload["source"] != activity.SourcePOS || payload["event"] != activity.EventPOSSale {
		t.Fatalf("event vocabulary was lost: %v", payload)
	}
}

func TestSanitizeTextDropsInvalidUTF8(t *testing.T) {
	got := activity.SanitizeText("iPhone \xff 15")
	if !utf8.ValidString(got) {
		t.Fatalf("sanitized text is not valid UTF-8: %q", got)
	}
	if got != "iPhone 15" {
		t.Fatalf("sanitized text = %q", got)
	}
}

func TestSourceVocabularyIsClosed(t *testing.T) {
	want := []string{
		activity.SourceGateway,
		activity.SourcePOS,
		activity.SourceStock,
		activity.SourcePortal,
	}
	if got := activity.Sources(); !slices.Equal(got, want) {
		t.Fatalf("sources = %v, want %v", got, want)
	}
	for _, source := range want {
		if !activity.SourceAllowed(source) {
			t.Fatalf("source %q must be allowed", source)
		}
	}
	for _, source := range []string{"", " ", "guest", "GATEWAY", "admin", "gateway\n"} {
		if activity.SourceAllowed(source) {
			t.Fatalf("source %q must be rejected", source)
		}
	}
}

func TestEventVocabularyIsStableAndFilterable(t *testing.T) {
	cases := map[string]string{
		"ticket.created":          activity.EventName("tickets", activity.OperationCreate),
		"customer.updated":        activity.EventName("customers", activity.OperationUpdate),
		"invoice.deleted":         activity.EventName("invoices", activity.OperationDelete),
		"stock_take_item.created": activity.EventName("stock_take_items", activity.OperationCreate),
		"invoice.changed":         activity.EventName("invoices", activity.Operation("unknown")),
		"widgets.created":         activity.EventName("widgets", activity.OperationCreate),
	}
	for want, got := range cases {
		if got != want {
			t.Fatalf("event name = %q, want %q", got, want)
		}
		if !activity.ValidEventName(got) {
			t.Fatalf("event name %q is not filterable", got)
		}
	}

	fixed := map[string]string{
		activity.EventPOSSale:               "pos.sale",
		activity.EventStockAdjusted:         "stock.adjusted",
		activity.EventPortalRepairRequested: "portal.repair_requested",
	}
	for got, want := range fixed {
		if got != want {
			t.Fatalf("fixed event = %q, want %q", got, want)
		}
		if !activity.ValidEventName(got) {
			t.Fatalf("fixed event %q is not filterable", got)
		}
	}

	for _, invalid := range []string{"", "Ticket.Created", "ticket created", "ticket/created", strings.Repeat("a", activity.MaxEventRunes+1)} {
		if activity.ValidEventName(invalid) {
			t.Fatalf("event name %q must be rejected", invalid)
		}
	}
}

func TestRowPermissionsAreReadOnlyStaff(t *testing.T) {
	want := []string{
		`read("team:team-a/admin")`,
		`read("team:team-a/technician")`,
	}
	if got := activity.RowPermissions("team-a"); !slices.Equal(got, want) {
		t.Fatalf("permissions = %v, want %v", got, want)
	}
	for _, permission := range activity.RowPermissions("team-a") {
		if !strings.HasPrefix(permission, `read("`) {
			t.Fatalf("activity grant must be read-only: %s", permission)
		}
		for _, forbidden := range []string{"update(", "delete(", "create(", "user:", `read("any")`, "guests"} {
			if strings.Contains(permission, forbidden) {
				t.Fatalf("forbidden activity grant %q in %s", forbidden, permission)
			}
		}
	}
	for _, invalid := range []string{"", "   ", "bad team", "team\nb"} {
		if got := activity.RowPermissions(invalid); len(got) != 0 {
			t.Fatalf("invalid organisation %q produced grants: %v", invalid, got)
		}
	}
}

func TestRecordContract(t *testing.T) {
	event := activity.Event{
		OrganizationID: "team-a",
		ActorUserID:    "user-1",
		Event:          "ticket.created",
		TableID:        "tickets",
		RowID:          "ticket-1",
		Summary:        "Ticket created — customer@example.com",
		Source:         activity.SourceGateway,
	}

	var gotData map[string]any
	var gotPermissions []string
	writer := func(_ context.Context, data map[string]any, permissions []string) error {
		gotData = data
		gotPermissions = permissions
		return nil
	}
	if err := activity.Record(context.Background(), writer, event); err != nil {
		t.Fatalf("record: %v", err)
	}
	if gotData["organization_id"] != "team-a" || gotData["actor_user_id"] != "user-1" {
		t.Fatalf("writer received untrusted attribution: %v", gotData)
	}
	if summary, _ := gotData["summary"].(string); strings.Contains(summary, "customer@example.com") {
		t.Fatalf("writer received an unredacted summary: %q", summary)
	}
	if !slices.Equal(gotPermissions, activity.RowPermissions("team-a")) {
		t.Fatalf("writer permissions = %v", gotPermissions)
	}

	failure := errors.New("activity store is offline")
	if err := activity.Record(context.Background(), func(context.Context, map[string]any, []string) error {
		return failure
	}, event); !errors.Is(err, failure) {
		t.Fatalf("writer failure = %v, want %v", err, failure)
	}

	called := false
	err := activity.Record(context.Background(), func(context.Context, map[string]any, []string) error {
		called = true
		return nil
	}, activity.Event{
		OrganizationID: "team-a",
		Event:          "ticket.created",
		Source:         "guest",
	})
	if !errors.Is(err, activity.ErrNotWritable) {
		t.Fatalf("unwritable event error = %v, want ErrNotWritable", err)
	}
	if called {
		t.Fatal("an unwritable event must not reach the writer")
	}

	if err := activity.Record(context.Background(), nil, event); err != nil {
		t.Fatalf("nil writer must be a no-op: %v", err)
	}
}

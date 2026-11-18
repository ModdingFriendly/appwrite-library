// Package firehose is the shared publisher side of the Reparix event firehose.
//
// A Function that changes business data appends an event row to the
// firehose_events table in the SAME TablesDB transaction as the change, so an
// action is never saved without its event (transactional outbox). A router
// Function later pushes committed events to subscribers; this package only
// builds and appends them.
//
// It owns:
//
//   - the event envelope and the change payload;
//   - the field diff with secret redaction and length caps;
//   - the generic event naming (<entity>.created|updated|deleted) and the
//     entity refs that let one entity's log include events about its children;
//   - the transactional Create/Update/Delete helpers.
//
// Trust rules: the organisation, actor and role come from the verified caller
// the Function passes in, never from a request body or from the row. Secrets
// (passcodes, patterns, tokens, keys, signatures) are recorded as "changed"
// without their values.
package firehose

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/appwrite/sdk-for-go/id"
	"github.com/appwrite/sdk-for-go/tablesdb"

	"github.com/ModdingFriendly/appwrite-library/appwrite"
	"github.com/ModdingFriendly/appwrite-library/httpx"
	"github.com/open-runtimes/types-for-go/v4/openruntimes"
)

const (
	// Table is the append-only event log. Rows carry no permissions.
	Table = "firehose_events"

	// MaxValueRunes caps one before/after value.
	MaxValueRunes = 20000
	// MaxChanges caps the fields listed on one event.
	MaxChanges = 64
	// MaxRefs caps the entity refs on one event.
	MaxRefs = 12

	KindText     = "text"
	KindValue    = "value"
	KindRedacted = "redacted"

	SourceGateway = "gateway"
)

// Change is one field that moved. KindText carries both values so a reader can
// render a word diff; KindValue is a short scalar; KindRedacted records that a
// secret changed without ever copying what it held.
type Change struct {
	Field  string `json:"field"`
	Kind   string `json:"kind"`
	Before string `json:"before,omitempty"`
	After  string `json:"after,omitempty"`
}

// ChangePayload is the payload of every "change" event.
type ChangePayload struct {
	Summary string   `json:"summary"`
	Changes []Change `json:"changes"`
	Source  string   `json:"source,omitempty"`
}

// Event is one event row, ready to append.
type Event struct {
	Name           string
	Version        int
	OrganizationID string
	ActorUserID    string
	ActorRole      string
	SubjectTable   string
	SubjectID      string
	// TicketID is kept for the ticket-specific indexes and views.
	TicketID      string
	Refs          []string
	CorrelationID string
	Source        string
	OccurredAt    time.Time
	Payload       any
}

// Op is a gateway operation.
type Op string

const (
	OpCreate Op = "create"
	OpUpdate Op = "update"
	OpDelete Op = "delete"
)

// Naming says what an entity's three events are called.
type Naming struct {
	Created, Updated, Deleted string
}

// For returns the event name for an operation.
func (n Naming) For(op Op) string {
	switch op {
	case OpCreate:
		return n.Created
	case OpDelete:
		return n.Deleted
	}
	return n.Updated
}

// DefaultNaming is "<entity>.created|updated|deleted".
func DefaultNaming(entity string) Naming {
	return Naming{Created: entity + ".created", Updated: entity + ".updated", Deleted: entity + ".deleted"}
}

// ChildNaming is "<entity>.added|updated|removed" for rows that belong to a
// parent, such as a ticket line.
func ChildNaming(entity string) Naming {
	return Naming{Created: entity + ".added", Updated: entity + ".updated", Deleted: entity + ".removed"}
}

// secretFragments name fields that are never copied into an event.
var secretFragments = []string{"passcode", "pattern", "password", "secret", "token", "api_key", "apikey", "signature", "hash", "pepper", "encryption"}

// serverFields are bookkeeping columns, not user changes.
var serverFields = map[string]bool{
	"organization_id": true, "created_by_user_id": true, "customer_user_id": true, "public_token": true,
}

// textHints marks free-text fields that deserve a word-level diff even when a
// given value is short.
var textHints = []string{"note", "description", "comment", "body", "message", "issue", "fault", "explanation", "reason", "details", "address", "terms"}

// IsSecret reports whether a field must never have its value recorded.
func IsSecret(field string) bool {
	lower := strings.ToLower(field)
	for _, bad := range secretFragments {
		if strings.Contains(lower, bad) {
			return true
		}
	}
	return false
}

func kindFor(field, before, after string) string {
	lower := strings.ToLower(field)
	for _, hint := range textHints {
		if strings.Contains(lower, hint) {
			return KindText
		}
	}
	if strings.Contains(before+after, "\n") || utf8.RuneCountInString(before) > 80 || utf8.RuneCountInString(after) > 80 {
		return KindText
	}
	return KindValue
}

// Text renders a stored value as text.
func Text(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case bool, int, int64, float64, json.Number:
		return fmt.Sprint(x)
	default:
		raw, err := json.Marshal(x)
		if err != nil {
			return ""
		}
		return string(raw)
	}
}

// Clip caps a value at MaxValueRunes.
func Clip(s string) string {
	if utf8.RuneCountInString(s) <= MaxValueRunes {
		return s
	}
	return string([]rune(s)[:MaxValueRunes])
}

// BuildChanges lists the fields a write actually changed. data is the
// validated payload that was written; before and after are the full rows
// around it (before is nil on create, after is nil on delete). Unchanged
// fields are omitted and secrets are recorded without values.
func BuildChanges(data, before, after map[string]any) []Change {
	keys := make([]string, 0, len(data))
	for key := range data {
		if serverFields[key] || strings.HasPrefix(key, "$") {
			continue
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	changes := make([]Change, 0, len(keys))
	for _, key := range keys {
		b := Text(before[key])
		a := Text(after[key])
		if after == nil {
			a = Text(data[key])
		}
		if before != nil && a == b {
			continue
		}
		if IsSecret(key) {
			changes = append(changes, Change{Field: key, Kind: KindRedacted})
		} else {
			changes = append(changes, Change{Field: key, Kind: kindFor(key, b, a), Before: Clip(b), After: Clip(a)})
		}
		if len(changes) == MaxChanges {
			break
		}
	}
	return changes
}

// displayColumns are the only columns read into a summary: short, non-personal
// labels. Never money, email, phone, address or message bodies.
var displayColumns = []string{"name", "title", "device", "file_name", "quote_number", "invoice_number", "po_number", "order_number", "ticket_number", "number", "sku", "description"}

// Label turns an entity such as "purchase_order" into "Purchase order".
func Label(entity string) string {
	words := strings.Fields(strings.NewReplacer("_", " ", ".", " ").Replace(entity))
	if len(words) == 0 {
		return "Record"
	}
	words[0] = strings.ToUpper(words[0][:1]) + words[0][1:]
	return strings.Join(words, " ")
}

// Summary is "<Label> <verb> — <display> · field old → new". At most two short
// scalar changes are spelled out, which covers status and assignee moves; the
// full diff is in the changes.
func Summary(entity string, op Op, row map[string]any, changes []Change) string {
	verb := map[Op]string{OpCreate: "created", OpUpdate: "updated", OpDelete: "deleted"}[op]
	out := Label(entity) + " " + verb
	for _, col := range displayColumns {
		if v, ok := row[col].(string); ok && strings.TrimSpace(v) != "" {
			out += " — " + shorten(v, 80)
			break
		}
	}
	if op == OpUpdate {
		shown := 0
		ordered := append([]Change{}, changes...)
		sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].Field == "status" && ordered[j].Field != "status" })
		for _, c := range ordered {
			if strings.HasSuffix(c.Field, "_id") {
				continue // ids are noise in a one-line summary
			}
			if c.Kind != KindValue || c.After == "" || utf8.RuneCountInString(c.Before) > 32 || utf8.RuneCountInString(c.After) > 32 {
				continue
			}
			from := c.Before
			if from == "" {
				from = "none"
			}
			out += " · " + strings.ReplaceAll(c.Field, "_", " ") + " " + from + " → " + c.After
			if shown++; shown == 2 {
				break
			}
		}
	}
	return shorten(oneLine(out), 255)
}

func oneLine(s string) string {
	return strings.Join(strings.Fields(strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)), " ")
}

func shorten(s string, max int) string {
	s = oneLine(s)
	if utf8.RuneCountInString(s) <= max {
		return s
	}
	return string([]rune(s)[:max])
}

// refColumns turns a foreign-key column into the entity it points at. A log
// for that entity includes events carrying its ref.
var refColumns = map[string]string{
	"ticket_id": "ticket", "customer_id": "customer", "invoice_id": "invoice", "purchase_order_id": "purchase_order",
	"supplier_id": "supplier", "inventory_id": "inventory", "device_id": "device", "register_id": "cash_register",
	"quote_id": "quote", "onsite_id": "onsite", "stock_take_id": "stock_take", "dispatch_id": "dispatch",
	"booking_id": "booking", "lead_id": "lead", "shift_id": "shift", "payout_id": "payout",
}

// Refs lists "<entity>:<id>" for the row itself and for each known parent
// column it carries, so a customer's log can include its tickets' events and a
// purchase order's log its lines.
func Refs(entity, rowID string, rows ...map[string]any) []string {
	seen := map[string]bool{}
	var out []string
	add := func(entity, id string) {
		id = strings.TrimSpace(id)
		if id == "" || len(id) > 36 || entity == "" {
			return
		}
		ref := entity + ":" + id
		if !seen[ref] {
			seen[ref] = true
			out = append(out, ref)
		}
	}
	add(entity, rowID)
	for _, row := range rows {
		keys := make([]string, 0, len(row))
		for k := range row {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, col := range keys {
			if target, ok := refColumns[col]; ok {
				if v, ok := row[col].(string); ok {
					add(target, v)
				}
			}
		}
	}
	if len(out) > MaxRefs {
		out = out[:MaxRefs]
	}
	return out
}

// Caller is the verified identity behind a write.
type Caller struct {
	TeamID string
	UserID string
	Role   string
}

// Spec describes one gateway write for BuildGatewayEvent.
type Spec struct {
	Caller         Caller
	Op             Op
	Table          string
	Entity         string
	Naming         Naming
	Version        int
	RowID          string
	Data           map[string]any
	Before, After  map[string]any
	CorrelationID  string
	Now            time.Time
	TicketIDColumn string // optional: column that names the ticket for child rows
}

// BuildGatewayEvent builds the event for a committed gateway write.
func BuildGatewayEvent(s Spec) Event {
	row := s.After
	if row == nil {
		row = s.Before
	}
	changes := BuildChanges(s.Data, s.Before, s.After)
	if s.Op == OpDelete {
		changes = []Change{}
	}
	ticket := ""
	if s.Entity == "ticket" {
		ticket = s.RowID
	} else if v, ok := row["ticket_id"].(string); ok {
		ticket = v
	}
	return Event{
		Name: s.Naming.For(s.Op), Version: s.Version, OrganizationID: s.Caller.TeamID,
		ActorUserID: s.Caller.UserID, ActorRole: s.Caller.Role,
		SubjectTable: s.Table, SubjectID: s.RowID, TicketID: ticket,
		Refs: Refs(s.Entity, s.RowID, s.Before, s.After), CorrelationID: s.CorrelationID,
		Source: SourceGateway, OccurredAt: s.Now,
		Payload: ChangePayload{Summary: Summary(s.Entity, s.Op, row, changes), Changes: changes, Source: SourceGateway},
	}
}

// RowData is the firehose_events row for the event.
func (e Event) RowData() (map[string]any, error) {
	payload, err := json.Marshal(e.Payload)
	if err != nil {
		return nil, err
	}
	data := map[string]any{
		"organization_id": e.OrganizationID,
		"event_name":      e.Name,
		"event_version":   e.Version,
		"occurred_at":     e.OccurredAt.UTC().Format(time.RFC3339),
		"source":          e.Source,
		"payload":         string(payload),
	}
	for key, value := range map[string]string{
		"actor_user_id": e.ActorUserID, "actor_role": e.ActorRole, "subject_table": e.SubjectTable,
		"subject_id": e.SubjectID, "ticket_id": e.TicketID, "correlation_id": e.CorrelationID,
	} {
		if strings.TrimSpace(value) != "" {
			data[key] = value
		}
	}
	if len(e.Refs) > 0 {
		data["refs"] = e.Refs
	}
	return data, nil
}

// Append writes the event inside an open transaction. The row has no
// permissions: only the server reads or routes it.
func Append(t *tablesdb.TablesDB, databaseID, txID string, e Event) error {
	data, err := e.RowData()
	if err != nil {
		return httpx.Upstream("could not encode the audit event", nil)
	}
	if _, err := t.CreateRow(databaseID, Table, id.Unique(), data,
		t.WithCreateRowPermissions([]string{}),
		t.WithCreateRowTransactionId(txID),
	); err != nil {
		return appwrite.MapError(err, Table)
	}
	return nil
}

// Correlation ties every event one request causes together: the platform
// execution id when present, a fresh id otherwise.
func Correlation(ctx openruntimes.Context) string {
	for key, value := range ctx.Req.Headers {
		if strings.EqualFold(key, "x-appwrite-execution-id") {
			if v := strings.TrimSpace(value); v != "" && len(v) <= 64 {
				return v
			}
		}
	}
	return id.Unique()
}

func decode(row interface{ Decode(any) error }) (map[string]any, error) {
	var out map[string]any
	if err := row.Decode(&out); err != nil {
		return nil, httpx.Upstream("could not decode row", nil)
	}
	return out, nil
}

func config(ctx openruntimes.Context) (appwrite.Config, error) {
	cfg := appwrite.ConfigFromEnv(ctx)
	if err := cfg.Validate(); err != nil {
		return cfg, httpx.Upstream("database configuration is unavailable", nil)
	}
	return cfg, nil
}

// committedRow re-reads a row after its transaction has committed.
//
// Appwrite leaves the server-generated fields ($sequence, $createdAt,
// $updatedAt) blank on a row written inside a transaction: they only exist once
// the transaction commits. A caller that hands the staged row to a browser is
// handing over a row that fails every "is this a complete row" check, so the
// committed row is read back instead. Re-reading is best effort: the write has
// already committed, so a failed read logs and falls back to the staged row
// rather than turning a successful mutation into an error.
func committedRow(ctx openruntimes.Context, cfg appwrite.Config, table, rowID string, staged map[string]any) map[string]any {
	if rowID == "" {
		return staged
	}
	row, err := appwrite.GetWith[map[string]any](ctx, cfg, table, rowID)
	if err != nil {
		ctx.Error("firehose: re-read " + table + "/" + rowID + ": " + err.Error())
		return staged
	}
	return *row
}

// Update writes the change and its event in one transaction. build receives
// the full row before and after the write.
func Update(ctx openruntimes.Context, table, rowID string, data map[string]any, build func(before, after map[string]any) Event) (map[string]any, error) {
	cfg, err := config(ctx)
	if err != nil {
		return nil, err
	}
	var updated map[string]any
	err = appwrite.InTransactionWith(ctx, cfg, func(t *tablesdb.TablesDB, txID string) error {
		beforeRow, err := t.GetRow(cfg.DatabaseID, table, rowID, t.WithGetRowTransactionId(txID))
		if err != nil {
			return appwrite.MapError(err, table)
		}
		before, err := decode(beforeRow)
		if err != nil {
			return err
		}
		row, err := t.UpdateRow(cfg.DatabaseID, table, rowID, t.WithUpdateRowData(data), t.WithUpdateRowTransactionId(txID))
		if err != nil {
			return appwrite.MapError(err, table)
		}
		if updated, err = decode(row); err != nil {
			return err
		}
		return Append(t, cfg.DatabaseID, txID, build(before, updated))
	})
	if err != nil {
		return nil, err
	}
	return committedRow(ctx, cfg, table, rowID, updated), nil
}

// Delete removes the row and records its event in one transaction.
func Delete(ctx openruntimes.Context, table, rowID string, build func(before map[string]any) Event) error {
	cfg, err := config(ctx)
	if err != nil {
		return err
	}
	return appwrite.InTransactionWith(ctx, cfg, func(t *tablesdb.TablesDB, txID string) error {
		beforeRow, err := t.GetRow(cfg.DatabaseID, table, rowID, t.WithGetRowTransactionId(txID))
		if err != nil {
			return appwrite.MapError(err, table)
		}
		before, err := decode(beforeRow)
		if err != nil {
			return err
		}
		if _, err := t.DeleteRow(cfg.DatabaseID, table, rowID, t.WithDeleteRowTransactionId(txID)); err != nil {
			return appwrite.MapError(err, table)
		}
		return Append(t, cfg.DatabaseID, txID, build(before))
	})
}

// Create writes the new row and its event in one transaction.
func Create(ctx openruntimes.Context, table string, data map[string]any, permissions []string, build func(created map[string]any) Event) (map[string]any, error) {
	cfg, err := config(ctx)
	if err != nil {
		return nil, err
	}
	var created map[string]any
	err = appwrite.InTransactionWith(ctx, cfg, func(t *tablesdb.TablesDB, txID string) error {
		row, err := t.CreateRow(cfg.DatabaseID, table, id.Unique(), data,
			t.WithCreateRowPermissions(permissions), t.WithCreateRowTransactionId(txID))
		if err != nil {
			return appwrite.MapError(err, table)
		}
		if created, err = decode(row); err != nil {
			return err
		}
		return Append(t, cfg.DatabaseID, txID, build(created))
	})
	if err != nil {
		return nil, err
	}
	rowID, _ := created["$id"].(string)
	return committedRow(ctx, cfg, table, rowID, created), nil
}

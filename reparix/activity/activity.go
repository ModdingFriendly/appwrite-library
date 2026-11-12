// Package activity is the shared activity-stream vocabulary for Reparix.
//
// It owns four things and nothing else:
//
//   - the event envelope that is appended to the activity ledger;
//   - the redaction and length caps applied to every stored value;
//   - the best-effort writer a business handler calls after its mutation has
//     committed;
//   - the shared event names, table labels and sources.
//
// The package is runtime independent: it imports nothing from the Appwrite
// Function runtime, performs no I/O, and embeds no endpoint, project, database
// or table identifier. A consumer injects the writer, so every Function that
// appends to the ledger shares one envelope, one redaction policy and one set
// of caps.
//
// Trust rules:
//
//   - the organisation and the actor come from the verified caller, never from
//     a request body or from an upstream row;
//   - a summary carries only the row's own short display name: email addresses
//     are redacted, control characters are stripped, whitespace is collapsed
//     and every value is capped at its column length;
//   - prices, tokens and message bodies are never copied into a summary;
//   - a failed activity write is best-effort noise. It must never fail, retry
//     or roll back the business mutation that produced it.
package activity

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

const (
	// MaxSummaryRunes caps a stored summary at the ledger's summary column.
	MaxSummaryRunes = 255
	// MaxEventRunes caps an event name at the ledger's event column.
	MaxEventRunes = 64
	// MaxTokenRunes caps an id-like column: table id, row id, actor id and
	// source.
	MaxTokenRunes = 64
	// MaxActorRunes caps the actor display name at the ledger's actor column.
	MaxActorRunes = 255
	// MaxDisplayRunes leaves room for the "<label> <verb> — " prefix so a long
	// display name is truncated before the whole summary is capped.
	MaxDisplayRunes = 120
)

// The closed set of event producers. A source identifies which part of the
// product wrote the event, so the reader can filter the stream by producer.
const (
	// SourceGateway is the generic row mutation gateway.
	SourceGateway = "gateway"
	// SourcePOS is the point-of-sale checkout.
	SourcePOS = "pos"
	// SourceStock is the stock adjustment flow.
	SourceStock = "stock"
	// SourcePortal is the customer-facing portal.
	SourcePortal = "portal"
)

// Event names that are not derived from a table and operation.
const (
	// EventPOSSale is a recorded point-of-sale settlement.
	EventPOSSale = "pos.sale"
	// EventStockAdjusted is a stock adjustment.
	EventStockAdjusted = "stock.adjusted"
	// EventPortalRepairRequested is a customer repair request.
	EventPortalRepairRequested = "portal.repair_requested"
)

// organizationIDPattern is the Appwrite row-id contract. It is applied to the
// verified organisation id, so a request-supplied value can never widen it.
var organizationIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,35}$`)

// eventNamePattern bounds an event name to the vocabulary the reader accepts
// as a filter: lowercase, starting with an alphanumeric, then letters,
// digits, dot, underscore or dash.
var eventNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`)

// Sources returns the closed set of accepted event sources.
func Sources() []string {
	return []string{SourceGateway, SourcePOS, SourceStock, SourcePortal}
}

// SourceAllowed reports whether source is one of the accepted sources.
func SourceAllowed(source string) bool {
	for _, allowed := range Sources() {
		if allowed == source {
			return true
		}
	}
	return false
}

// ValidEventName reports whether name is an event name the reader can filter
// on.
func ValidEventName(name string) bool {
	return eventNamePattern.MatchString(name)
}

// ValidOrganizationID reports whether an organisation id is a well-formed
// Appwrite row id.
func ValidOrganizationID(organizationID string) bool {
	return organizationIDPattern.MatchString(strings.TrimSpace(organizationID))
}

// Operation is the row mutation an event describes.
type Operation string

const (
	// OperationCreate is a row creation.
	OperationCreate Operation = "create"
	// OperationUpdate is a row update.
	OperationUpdate Operation = "update"
	// OperationDelete is a row deletion.
	OperationDelete Operation = "delete"
)

// Verb is the past-tense word used in a summary. An unknown operation is
// reported as a change, never as a guess.
func (o Operation) Verb() string {
	switch o {
	case OperationCreate:
		return "created"
	case OperationUpdate:
		return "updated"
	case OperationDelete:
		return "deleted"
	default:
		return "changed"
	}
}

// Event is the activity envelope written to the ledger. Optional string fields
// stay empty rather than being written as an empty column.
type Event struct {
	// OrganizationID is the verified caller's team.
	OrganizationID string
	// ActorUserID is the verified caller.
	ActorUserID string
	// ActorName is the actor's display name, when the identity exposes one.
	ActorName string
	// Event is the stable event name, for example "ticket.created".
	Event string
	// TableID is the business table the event is about.
	TableID string
	// RowID is the row the event is about.
	RowID string
	// Summary is the one-line, human-readable description.
	Summary string
	// Source is the producer of the event.
	Source string
}

// Payload converts the event into the exact writable row. It reports false
// when the event is not safe to store: it has no verified organisation, no
// usable event name, or a source outside the shared set.
//
// The payload applies the shared vocabulary, so a stored event can always be
// filtered and displayed by the reader.
func (e Event) Payload() (map[string]any, bool) {
	orgID := strings.TrimSpace(e.OrganizationID)
	if !organizationIDPattern.MatchString(orgID) {
		return nil, false
	}
	event := SanitizeToken(e.Event)
	if !ValidEventName(event) {
		return nil, false
	}
	source := SanitizeToken(e.Source)
	if !SourceAllowed(source) {
		return nil, false
	}

	data := map[string]any{
		"organization_id": orgID,
		"event":           event,
		"summary":         SanitizeText(e.Summary),
		"source":          source,
	}
	if tableID := SanitizeToken(e.TableID); tableID != "" {
		data["table_id"] = tableID
	}
	if rowID := SanitizeToken(e.RowID); rowID != "" {
		data["row_id"] = rowID
	}
	if actor := SanitizeToken(e.ActorUserID); actor != "" {
		data["actor_user_id"] = actor
	}
	if name := SanitizeTextLimit(e.ActorName, MaxActorRunes); name != "" {
		data["actor_name"] = name
	}
	return data, true
}

// TableSpec describes how one business table is named in the stream.
//
// Display is an explicit allowlist: only these short display columns are read
// into a summary, never money, email, phone, address, notes or message bodies.
type TableSpec struct {
	// Label is the human label used in a summary, for example "Ticket".
	Label string
	// Event is the event-name prefix, for example "ticket".
	Event string
	// Display is the allowlisted display column, empty when the table has no
	// safe display value.
	Display string
}

// tableSpecs is the shared vocabulary of the activity stream. It is the single
// place that decides how a business table is named and which column may be
// shown in a summary.
var tableSpecs = map[string]TableSpec{
	"tickets":              {Label: "Ticket", Event: "ticket", Display: "device"},
	"customers":            {Label: "Customer", Event: "customer", Display: "name"},
	"devices":              {Label: "Device", Event: "device", Display: "name"},
	"inventory":            {Label: "Inventory item", Event: "inventory", Display: "name"},
	"suppliers":            {Label: "Supplier", Event: "supplier", Display: "name"},
	"purchase_orders":      {Label: "Purchase order", Event: "purchase_order", Display: "po_number"},
	"services":             {Label: "Service", Event: "service", Display: "name"},
	"fedex_shipments":      {Label: "Shipment", Event: "shipment", Display: "tracking_number"},
	"invoices":             {Label: "Invoice", Event: "invoice", Display: "number"},
	"payments":             {Label: "Payment", Event: "payment"},
	"leads":                {Label: "Lead", Event: "lead", Display: "name"},
	"notifications":        {Label: "Notification", Event: "notification"},
	"bookings":             {Label: "Booking", Event: "booking", Display: "device"},
	"onsite":               {Label: "On-site job", Event: "onsite", Display: "device"},
	"quote_items":          {Label: "Quote line", Event: "quote_item"},
	"ticket_comments":      {Label: "Ticket comment", Event: "ticket_comment"},
	"ticket_attachments":   {Label: "Attachment", Event: "ticket_attachment", Display: "file_name"},
	"ticket_line_items":    {Label: "Ticket line", Event: "ticket_line_item", Display: "description"},
	"purchase_order_items": {Label: "Order line", Event: "purchase_order_item", Display: "name"},
	"customer_reward_logs": {Label: "Reward entry", Event: "reward"},
	"quotes":               {Label: "Quote", Event: "quote", Display: "quote_number"},
	"expenses":             {Label: "Expense", Event: "expense", Display: "category"},
	"marketing_campaigns":  {Label: "Campaign", Event: "campaign", Display: "name"},
	"payouts":              {Label: "Payout", Event: "payout"},
	"rma_returns":          {Label: "RMA", Event: "rma_return", Display: "rma_number"},
	"shifts":               {Label: "Shift", Event: "shift"},
	"stock_take_items":     {Label: "Stock count line", Event: "stock_take_item", Display: "sku"},
	"stock_takes":          {Label: "Stock take", Event: "stock_take", Display: "name"},
	"storage_locations":    {Label: "Storage location", Event: "storage_location", Display: "location_code"},
	"cash_movements":       {Label: "Cash movement", Event: "cash_movement"},
	"cash_registers":       {Label: "Cash register", Event: "cash_register"},
	"dispatches":           {Label: "Dispatch", Event: "dispatch", Display: "dispatch_number"},
	"device_listings":      {Label: "Device listing", Event: "device_listing", Display: "device_name"},
	"messages":             {Label: "Message", Event: "message"},
	"customer_display":     {Label: "Customer display", Event: "customer_display"},
	"reviews":              {Label: "Review", Event: "review", Display: "ticket_number"},
}

// TableSpecFor returns the spec of a business table. A table that is not in
// the shared vocabulary yet falls back to a humanised name: the table id is
// not secret, so a label derived from it is safe.
func TableSpecFor(tableID string) TableSpec {
	if spec, ok := tableSpecs[tableID]; ok {
		return spec
	}
	label := strings.ReplaceAll(SanitizeToken(tableID), "_", " ")
	if label == "" {
		label = "Record"
	} else {
		label = strings.ToUpper(label[:1]) + label[1:]
	}
	// An event name is always lowercase, so the name this package builds is
	// always one the reader can filter on.
	return TableSpec{Label: label, Event: strings.ToLower(SanitizeToken(tableID))}
}

// EventName maps a table and an operation to the stable event vocabulary:
// "ticket.created", "invoice.updated", "stock_take_item.deleted", ...
//
// The name is lowercase, so it always matches the pattern the reader accepts
// as a filter.
func EventName(tableID string, op Operation) string {
	spec := TableSpecFor(tableID)
	name := strings.ToLower(spec.Event + "." + op.Verb())
	if utf8.RuneCountInString(name) > MaxEventRunes {
		name = spec.Event
	}
	return SanitizeToken(name)
}

// Summary builds "Ticket created — iPhone 15". The display value is the row's
// own short label, read only from the allowlisted display column.
func Summary(tableID string, op Operation, row map[string]any) string {
	spec := TableSpecFor(tableID)
	summary := spec.Label + " " + op.Verb()
	if display := displayName(spec, row); display != "" {
		summary += " — " + display
	}
	return SanitizeText(summary)
}

// displayName reads only the spec's allowlisted display column.
func displayName(spec TableSpec, row map[string]any) string {
	if spec.Display == "" || row == nil {
		return ""
	}
	value, ok := row[spec.Display].(string)
	if !ok {
		return ""
	}
	return SanitizeTextLimit(value, MaxDisplayRunes)
}

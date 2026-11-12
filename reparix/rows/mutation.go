package rows

import (
	"bytes"
	"encoding/json"
	"io"
	"sort"
	"strings"

	"github.com/ModdingFriendly/appwrite-library/httpx"
	"github.com/ModdingFriendly/appwrite-library/reparix/tenant"
)

// MutationCaller is the verified caller facts the mutation engine needs. It
// contains no role policy: the consumer decides which tables and operations a
// role may use by choosing the policy set it passes in.
type MutationCaller struct {
	TeamID string
	UserID string
}

// MutationRequest is the strict body of a row create/update/delete. A body
// organization_id is optional and may only confirm the verified team.
type MutationRequest struct {
	TableID        string                     `json:"table_id"`
	RowID          string                     `json:"row_id,omitempty"`
	OrganizationID string                     `json:"organization_id,omitempty"`
	Data           map[string]json.RawMessage `json:"data"`
}

// ParseMutationRequest strictly decodes a mutation body: non-empty, bounded,
// no unknown fields, exactly one JSON object.
func ParseMutationRequest(body []byte) (*MutationRequest, error) {
	if len(bytes.TrimSpace(body)) == 0 {
		return nil, httpx.BadRequest("request body is required", nil)
	}
	if len(body) > MaxMutationBytes {
		return nil, httpx.BadRequest("request body is too large", map[string]any{"max_bytes": MaxMutationBytes})
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	var req MutationRequest
	if err := dec.Decode(&req); err != nil {
		return nil, httpx.BadRequest("invalid request body", map[string]any{"detail": err.Error()})
	}
	if err := dec.Decode(new(json.RawMessage)); err != io.EOF {
		return nil, httpx.BadRequest("request body must contain exactly one JSON object", nil)
	}
	return &req, nil
}

// Deriver produces a server-owned field value. It runs after the client payload
// has been parsed, so it may inspect validated reference ids in data. A nil
// value omits the optional column; a required field with no value is rejected.
// It is called on create only.
type Deriver func(caller MutationCaller, data map[string]any) (any, error)

// MutationPolicy is the consumer-supplied policy for one writable table.
type MutationPolicy struct {
	// Table is the Appwrite table id. MutationPolicySet.Admit fills it from the
	// map key when empty.
	Table string
	// Global marks a table without an organization_id column. Tenant tables
	// (the default) always write organization_id from the verified caller.
	Global bool
	// Fields is the complete client-writable allowlist.
	Fields map[string]FieldSpec
	// Blocked names fields that must be refused with a consumer reason even if
	// they are not in Fields.
	Blocked map[string]string
	// Immutable names fields that may be set on create but never changed.
	Immutable []string
	// Operations is the table's allowed operations. It is fail closed: nil or
	// empty permits none.
	Operations []Operation
	// Derived names server-owned columns written on create. The client may
	// never supply one. organization_id is derived automatically for every
	// non-Global table and does not need to be listed.
	Derived map[string]Deriver
	// ReadRoles are the consumer's team roles that get read access to a created
	// row. Empty means no team grant.
	ReadRoles []string
	// ReadUserFields name derived fields that carry a verified Appwrite user id;
	// that user gets a read grant on the created row.
	ReadUserFields []string
}

// Allows reports whether the policy permits op.
func (p MutationPolicy) Allows(op Operation) bool {
	for _, allowed := range p.Operations {
		if allowed == op {
			return true
		}
	}
	return false
}

// MutationPolicySet is the subset of tables one consumer exposes for mutation.
// Unknown tables fail closed. Denied names an explicit refusal reason.
type MutationPolicySet struct {
	Tables map[string]MutationPolicy
	Denied map[string]string
}

// Admit resolves table and operation against the supplied policy set. It is
// fail closed: unknown tables and unknown operations are refused.
func (set MutationPolicySet) Admit(table string, op Operation) (MutationPolicy, error) {
	table = strings.TrimSpace(table)
	if table == "" {
		return MutationPolicy{}, httpx.BadRequest("table_id is required", map[string]any{"field": "table_id"})
	}
	if !op.Allow() {
		return MutationPolicy{}, httpx.BadRequest("invalid operation", map[string]any{"operation": string(op)})
	}
	if reason, denied := set.Denied[table]; denied {
		return MutationPolicy{}, httpx.Forbidden("table is protected from gateway writes", map[string]any{
			"table":  table,
			"reason": reason,
		})
	}
	policy, ok := set.Tables[table]
	if !ok {
		return MutationPolicy{}, httpx.Forbidden("table is not writable through the row gateway", map[string]any{
			"table": table,
		})
	}
	if policy.Table == "" {
		policy.Table = table
	}
	if !policy.Allows(op) {
		return MutationPolicy{}, httpx.Forbidden("role is not permitted for this table operation", map[string]any{
			"table":     table,
			"operation": string(op),
		})
	}
	return policy, nil
}

// MutationPlan is the validated mutation produced by MutationEngine.Prepare.
// Data and ACL are the exact values the consumer writes: a client can never
// supply either. ACL is populated for create only (an update preserves the
// row's existing grants).
type MutationPlan struct {
	Operation Operation
	Table     string
	TeamID    string
	RowID     string
	Data      map[string]any
	ACL       []string
	Policy    MutationPolicy
}

// MutationEngine applies consumer-supplied mutation policies to a request.
type MutationEngine struct {
	Policies MutationPolicySet
}

// serverManagedFields can never be written by a client, on any table or
// policy. organization_id is included because it is always derived from the
// verified caller, never accepted from the body.
var serverManagedFields = map[string]string{
	"$id":             "system field",
	"$permissions":    "row ACLs are generated by the server",
	"$createdAt":      "system field",
	"$updatedAt":      "system field",
	"$sequence":       "system field",
	"$databaseId":     "system field",
	"$tableId":        "system field",
	"organization_id": "derived from the verified team",
}

// Prepare validates the request and builds the exact row data and read ACL:
// caller/table admission, field allowlist, types, required fields, immutable
// fields, derived server-owned fields and the tenant column. It performs no
// I/O; a consumer Deriver may use an injected fetcher.
func (e MutationEngine) Prepare(caller MutationCaller, op Operation, req *MutationRequest) (*MutationPlan, error) {
	if req == nil {
		return nil, httpx.BadRequest("request body is required", nil)
	}
	if !tenant.ValidID(caller.TeamID) || !tenant.ValidID(caller.UserID) {
		return nil, httpx.Forbidden("verified caller identity is invalid", nil)
	}
	if err := tenant.CheckBodyOrganization(caller.TeamID, req.OrganizationID); err != nil {
		return nil, err
	}
	policy, err := e.Policies.Admit(req.TableID, op)
	if err != nil {
		return nil, err
	}

	rowID := strings.TrimSpace(req.RowID)
	switch op {
	case OpCreate:
		if rowID != "" && !tenant.ValidID(rowID) {
			return nil, httpx.BadRequest("invalid row id", map[string]any{"field": "row_id"})
		}
	case OpUpdate, OpDelete:
		if !tenant.ValidID(rowID) {
			return nil, httpx.BadRequest("row_id is required", map[string]any{"field": "row_id"})
		}
	}

	var data map[string]any
	if op != OpDelete {
		data, err = validateMutationData(policy, op, req.Data)
		if err != nil {
			return nil, err
		}
	}

	acl := []string{}
	if op == OpCreate {
		if !policy.Global {
			// The authoritative tenant, independent of any consumer Deriver.
			data[tenant.OrganizationField] = caller.TeamID
		}
		if err := applyDerivedFields(policy, caller, data); err != nil {
			return nil, err
		}
		if err := requireMutationFields(policy, data); err != nil {
			return nil, err
		}
		userIDs := readUserIDs(policy, data)
		acl = TeamReadACL(caller.TeamID, policy.ReadRoles, userIDs...)
	}

	return &MutationPlan{
		Operation: op,
		Table:     policy.Table,
		TeamID:    caller.TeamID,
		RowID:     rowID,
		Data:      data,
		ACL:       acl,
		Policy:    policy,
	}, nil
}

// PrepareMutation is the package-level form of MutationEngine.Prepare.
func PrepareMutation(set MutationPolicySet, caller MutationCaller, op Operation, req *MutationRequest) (*MutationPlan, error) {
	return MutationEngine{Policies: set}.Prepare(caller, op, req)
}

func validateMutationData(policy MutationPolicy, op Operation, raw map[string]json.RawMessage) (map[string]any, error) {
	if raw == nil {
		raw = map[string]json.RawMessage{}
	}
	if len(raw) > MaxMutationFields {
		return nil, httpx.BadRequest("too many fields", map[string]any{"max": MaxMutationFields})
	}
	totalBytes := 0
	keys := make([]string, 0, len(raw))
	for key, value := range raw {
		totalBytes += len(value)
		keys = append(keys, key)
	}
	if totalBytes > MaxMutationBytes {
		return nil, httpx.BadRequest("request body is too large", map[string]any{"max_bytes": MaxMutationBytes})
	}
	sort.Strings(keys)

	data := make(map[string]any, len(raw))
	for _, key := range keys {
		if strings.HasPrefix(key, "$") {
			return nil, forbiddenField(key, "system field")
		}
		if reason, managed := serverManagedFields[key]; managed {
			return nil, forbiddenField(key, reason)
		}
		if reason, blocked := policy.Blocked[key]; blocked {
			return nil, forbiddenField(key, reason)
		}
		if _, derived := policy.Derived[key]; derived {
			return nil, forbiddenField(key, "derived server-side")
		}
		spec, ok := policy.Fields[key]
		if !ok {
			return nil, httpx.BadRequest("unknown field", map[string]any{"field": key})
		}
		if op == OpUpdate && containsString(policy.Immutable, key) {
			return nil, forbiddenField(key, "field is immutable after creation")
		}
		if op == OpUpdate && isNull(raw[key]) {
			if spec.Required {
				return nil, httpx.BadRequest("required field may not be cleared", map[string]any{"field": key})
			}
			// Null clears the optional column; create stays strict.
			data[key] = nil
			continue
		}
		value, err := ParseField(key, spec, raw[key])
		if err != nil {
			return nil, err
		}
		data[key] = value
	}

	return data, nil
}

// requireMutationFields enforces create-time required fields after derivation,
// so a required field supplied by a Deriver is validated exactly like a client
// field.
func requireMutationFields(policy MutationPolicy, data map[string]any) error {
	for _, key := range sortedSpecKeys(policy.Fields) {
		spec := policy.Fields[key]
		if !spec.Required {
			continue
		}
		value, present := data[key]
		if !present || value == nil {
			return missingField(key)
		}
		if text, ok := value.(string); ok && strings.TrimSpace(text) == "" {
			return missingField(key)
		}
	}
	return nil
}

func applyDerivedFields(policy MutationPolicy, caller MutationCaller, data map[string]any) error {
	for _, key := range sortedDeriverKeys(policy.Derived) {
		derive := policy.Derived[key]
		if derive == nil {
			return httpx.Upstream("derived field is not configured", map[string]any{"field": key})
		}
		value, err := derive(caller, data)
		if err != nil {
			return err
		}
		if value == nil {
			// An optional derived field may legitimately have no value; a
			// required derived field is rejected by requireMutationFields.
			continue
		}
		if key == tenant.OrganizationField && value != caller.TeamID {
			return httpx.Forbidden("organization_id does not match the authorized organisation", map[string]any{
				"field": tenant.OrganizationField,
			})
		}
		if spec, hasSpec := policy.Fields[key]; hasSpec {
			raw, err := json.Marshal(value)
			if err != nil {
				return httpx.Upstream("derived field is invalid", map[string]any{"field": key})
			}
			normalised, err := ParseField(key, spec, raw)
			if err != nil {
				return httpx.Upstream("derived field is invalid", map[string]any{"field": key})
			}
			value = normalised
		}
		data[key] = value
	}
	return nil
}

func readUserIDs(policy MutationPolicy, data map[string]any) []string {
	ids := make([]string, 0, len(policy.ReadUserFields))
	for _, field := range policy.ReadUserFields {
		// Only server-derived ids may grant a read ACL. A client-writable field
		// must never let a caller choose who can read the new row.
		if _, derived := policy.Derived[field]; !derived {
			continue
		}
		if id, ok := data[field].(string); ok && tenant.ValidID(id) {
			ids = append(ids, id)
		}
	}
	return ids
}

func sortedSpecKeys(fields map[string]FieldSpec) []string {
	keys := make([]string, 0, len(fields))
	for key := range fields {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func sortedDeriverKeys(fields map[string]Deriver) []string {
	keys := make([]string, 0, len(fields))
	for key := range fields {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

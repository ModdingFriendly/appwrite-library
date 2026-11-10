package appwrite

import (
	"encoding/json"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	sdk "github.com/appwrite/sdk-for-go/client"
	"github.com/appwrite/sdk-for-go/id"
	"github.com/appwrite/sdk-for-go/query"
	"github.com/open-runtimes/types-for-go/v4/openruntimes"

	"github.com/ModdingFriendly/appwrite-library/httpx"
)

// Page is a typed page of rows plus the total count.
type Page[T any] struct {
	Total int `json:"total"`
	Rows  []T `json:"rows"`
}

// List returns rows for a table using configuration from the environment.
// Prefer ListWith for explicit configuration.
func List[T any](ctx openruntimes.Context, table string, queries ...string) (*Page[T], error) {
	return ListWith[T](ctx, ConfigFromEnv(ctx), table, queries...)
}

// ListWith returns rows for a table filtered by Appwrite query strings.
func ListWith[T any](ctx openruntimes.Context, cfg Config, table string, queries ...string) (*Page[T], error) {
	cfg = cfg.withDefaults()
	t, err := NewTables(cfg)
	if err != nil {
		return nil, err
	}
	res, err := t.ListRows(cfg.DatabaseID, table, t.WithListRowsQueries(queries))
	if err != nil {
		ctx.Error("appwrite: list " + table + ": " + err.Error())
		return nil, MapError(err, table)
	}
	var out Page[T]
	if err := res.Decode(&out); err != nil {
		ctx.Error("appwrite: decode list " + table + ": " + err.Error())
		return nil, httpx.Upstream("could not decode appwrite response", map[string]any{"table": table})
	}
	return &out, nil
}

// Get returns one row by id using configuration from the environment.
// Prefer GetWith for explicit configuration.
func Get[T any](ctx openruntimes.Context, table, rowID string) (*T, error) {
	return GetWith[T](ctx, ConfigFromEnv(ctx), table, rowID)
}

// GetWith returns one row by id.
func GetWith[T any](ctx openruntimes.Context, cfg Config, table, rowID string) (*T, error) {
	cfg = cfg.withDefaults()
	t, err := NewTables(cfg)
	if err != nil {
		return nil, err
	}
	row, err := t.GetRow(cfg.DatabaseID, table, rowID)
	if err != nil {
		ctx.Error("appwrite: get " + table + "/" + rowID + ": " + err.Error())
		return nil, MapError(err, table)
	}
	var out T
	if err := row.Decode(&out); err != nil {
		ctx.Error("appwrite: decode get " + table + "/" + rowID + ": " + err.Error())
		return nil, httpx.Upstream("could not decode appwrite response", map[string]any{"table": table})
	}
	return &out, nil
}

// Create inserts a row with explicit row permissions using configuration from
// the environment. Prefer CreateWith for explicit configuration.
func Create[T any](ctx openruntimes.Context, table string, data map[string]any, permissions []string) (*T, error) {
	return CreateWith[T](ctx, ConfigFromEnv(ctx), table, data, permissions)
}

// CreateWith inserts a row with explicit row permissions.
func CreateWith[T any](ctx openruntimes.Context, cfg Config, table string, data map[string]any, permissions []string) (*T, error) {
	cfg = cfg.withDefaults()
	t, err := NewTables(cfg)
	if err != nil {
		return nil, err
	}
	row, err := t.CreateRow(cfg.DatabaseID, table, id.Unique(), data, t.WithCreateRowPermissions(permissions))
	if err != nil {
		ctx.Error("appwrite: create " + table + ": " + err.Error())
		return nil, MapError(err, table)
	}
	var out T
	if err := row.Decode(&out); err != nil {
		ctx.Error("appwrite: decode create " + table + ": " + err.Error())
		return nil, httpx.Upstream("could not decode appwrite response", map[string]any{"table": table})
	}
	return &out, nil
}

// Update patches a row using configuration from the environment. Prefer
// UpdateWith for explicit configuration.
func Update[T any](ctx openruntimes.Context, table, rowID string, data map[string]any) (*T, error) {
	return UpdateWith[T](ctx, ConfigFromEnv(ctx), table, rowID, data)
}

// UpdateWith patches a row.
func UpdateWith[T any](ctx openruntimes.Context, cfg Config, table, rowID string, data map[string]any) (*T, error) {
	cfg = cfg.withDefaults()
	t, err := NewTables(cfg)
	if err != nil {
		return nil, err
	}
	row, err := t.UpdateRow(cfg.DatabaseID, table, rowID, t.WithUpdateRowData(data))
	if err != nil {
		ctx.Error("appwrite: update " + table + "/" + rowID + ": " + err.Error())
		return nil, MapError(err, table)
	}
	var out T
	if err := row.Decode(&out); err != nil {
		ctx.Error("appwrite: decode update " + table + "/" + rowID + ": " + err.Error())
		return nil, httpx.Upstream("could not decode appwrite response", map[string]any{"table": table})
	}
	return &out, nil
}

// Delete removes a row using configuration from the environment. Prefer
// DeleteWith for explicit configuration.
func Delete(ctx openruntimes.Context, table, rowID string) error {
	return DeleteWith(ctx, ConfigFromEnv(ctx), table, rowID)
}

// DeleteWith removes a row.
func DeleteWith(ctx openruntimes.Context, cfg Config, table, rowID string) error {
	cfg = cfg.withDefaults()
	t, err := NewTables(cfg)
	if err != nil {
		return err
	}
	if _, err := t.DeleteRow(cfg.DatabaseID, table, rowID); err != nil {
		ctx.Error("appwrite: delete " + table + "/" + rowID + ": " + err.Error())
		return MapError(err, table)
	}
	return nil
}

// Public messages returned by MapError. They are stable, status-derived strings
// that a client can rely on; the Appwrite message is never returned because it
// can echo document content, column names, query fragments or provider text.
const (
	MessageBadRequest   = "request rejected"
	MessageUnauthorized = "authentication required"
	MessageForbidden    = "permission denied"
	MessageNotFound     = "record not found"
	MessageConflict     = "conflict"
	MessageStale        = "record changed"
	MessageUpstream     = "appwrite request failed"
)

// MapError converts an Appwrite SDK error into the httpx error contract.
//
// Each status maps to a stable public message and code; the status and the
// table stay in params, plus a sanitised Appwrite error type as "reason" when
// the server supplied one (for example "row_not_found"). The upstream message
// is never returned to the caller: it is sanitised into the error's private
// Detail field, which httpx.Fail logs and which never reaches the response
// body. Non-SDK errors (dial failures, timeouts, a rejected redirect) keep their
// cause attached so callers can still use errors.Is, while exposing nothing.
func MapError(err error, table string) error {
	if err == nil {
		return nil
	}

	var ae *sdk.AppwriteError
	if !errors.As(err, &ae) || ae == nil {
		return &httpx.Error{
			Status:  502,
			Code:    "upstream_error",
			Message: MessageUpstream,
			Params:  map[string]any{"table": table},
			Cause:   err,
		}
	}

	status := ae.GetStatusCode()
	params := map[string]any{"table": table, "status": status}
	reason := sanitizeReason(ae.GetResponse())
	if reason != "" {
		params["reason"] = reason
	}
	detail := "appwrite " + table + " status " + strconv.Itoa(status)
	if reason != "" {
		detail += " (" + reason + ")"
	}
	if message := sanitizeDetail(ae.GetMessage()); message != "" {
		detail += ": " + message
	}

	switch status {
	case 400:
		return &httpx.Error{Status: 400, Code: "bad_request", Message: MessageBadRequest, Params: params, Detail: detail}
	case 401:
		return &httpx.Error{Status: 401, Code: "unauthorized", Message: MessageUnauthorized, Params: params, Detail: detail}
	case 403:
		return &httpx.Error{Status: 403, Code: "forbidden", Message: MessageForbidden, Params: params, Detail: detail}
	case 404:
		return &httpx.Error{Status: 404, Code: "not_found", Message: MessageNotFound, Params: params, Detail: detail}
	case 409:
		return &httpx.Error{Status: 409, Code: "conflict", Message: MessageConflict, Params: params, Detail: detail}
	case 412:
		return &httpx.Error{Status: 412, Code: "precondition_failed", Message: MessageStale, Params: params, Detail: detail}
	default:
		return &httpx.Error{Status: 502, Code: "upstream_error", Message: MessageUpstream, Params: params, Detail: detail}
	}
}

// errorTypePattern bounds the Appwrite error "type" values that may be exposed
// as a machine-readable reason.
var errorTypePattern = regexp.MustCompile(`^[a-z0-9_.-]{1,64}$`)

// sanitizeReason extracts the stable Appwrite error type from the raw response
// body. Anything that does not look like a machine code is dropped.
func sanitizeReason(rawResponse string) string {
	if rawResponse == "" {
		return ""
	}
	var body struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal([]byte(rawResponse), &body); err != nil {
		return ""
	}
	if !errorTypePattern.MatchString(body.Type) {
		return ""
	}
	return body.Type
}

// sanitizeDetail flattens a private diagnostic string: control characters are
// removed so a newline cannot forge a log line, and the length is capped so one
// bad response cannot flood the function log.
func sanitizeDetail(raw string) string {
	const limit = 512
	var builder strings.Builder
	for _, char := range raw {
		if char == '\n' || char == '\r' || char == '\t' {
			builder.WriteByte(' ')
		} else if !unicode.IsControl(char) {
			builder.WriteRune(char)
		}
		if builder.Len() >= limit {
			break
		}
	}
	return strings.TrimSpace(builder.String())
}

// Query builders re-exported so handlers import one package.
func Equal(attribute string, value any) string    { return query.Equal(attribute, value) }
func NotEqual(attribute string, value any) string { return query.NotEqual(attribute, value) }
func OrderAsc(attribute string) string            { return query.OrderAsc(attribute) }
func OrderDesc(attribute string) string           { return query.OrderDesc(attribute) }
func Limit(n int) string                          { return query.Limit(n) }
func Offset(n int) string                         { return query.Offset(n) }
func Search(attribute string, value any) string   { return query.Search(attribute, value) }
func Contains(attribute string, value any) string { return query.Contains(attribute, value) }

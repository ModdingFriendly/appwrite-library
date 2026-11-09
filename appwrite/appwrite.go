package appwrite

import (
	"errors"

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

// MapError converts an Appwrite SDK error into the httpx error contract.
//
// Appwrite client errors keep the server's message because it describes the
// caller-visible problem. Upstream/server failures and non-SDK errors return a
// generic public message; callers log the raw error privately.
func MapError(err error, table string) error {
	if err == nil {
		return nil
	}
	var ae *sdk.AppwriteError
	if errors.As(err, &ae) {
		params := map[string]any{"table": table, "status": ae.GetStatusCode()}
		switch ae.GetStatusCode() {
		case 400:
			return httpx.BadRequest(ae.GetMessage(), params)
		case 401:
			return httpx.Unauthorized(ae.GetMessage(), params)
		case 403:
			return httpx.Forbidden(ae.GetMessage(), params)
		case 404:
			return httpx.NotFound(ae.GetMessage(), params)
		case 409:
			return httpx.Conflict(ae.GetMessage(), params)
		case 412:
			return httpx.PreconditionFailed(ae.GetMessage(), params)
		default:
			return httpx.Upstream("appwrite request failed", params)
		}
	}
	return httpx.Upstream("appwrite request failed", map[string]any{"table": table})
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

// Package appwrite is the shared server-side Appwrite access layer for Reparix
// Functions. It wraps the official Appwrite Go SDK so handlers never hand-roll
// REST calls: typed list/get/create/update/delete, query builders, and SDK
// errors mapped to the httpx error contract.
package appwrite

import (
	"errors"
	"os"

	sdk "github.com/appwrite/sdk-for-go/client"
	"github.com/appwrite/sdk-for-go/id"
	"github.com/appwrite/sdk-for-go/query"
	"github.com/appwrite/sdk-for-go/tablesdb"
	"github.com/open-runtimes/types-for-go/v4/openruntimes"

	"github.com/ModdingFriendly/appwrite-library/httpx"
)

// DatabaseID is the shared TablesDB database (public config, not a secret).
const DatabaseID = "6af1e5760014a0163fd6"

// ResponseFormat is the Appwrite server API version this instance reports.
const ResponseFormat = "2.6.1"

// Client builds a server client from the function's short-lived execution key.
func Client(ctx openruntimes.Context) sdk.Client {
	endpoint := os.Getenv("APPWRITE_FUNCTION_API_ENDPOINT")
	if endpoint == "" {
		endpoint = "https://appwrite.moddingfriendly.com/v1"
	}
	project := os.Getenv("APPWRITE_FUNCTION_PROJECT_ID")
	key := ctx.Req.Headers["x-appwrite-key"]

	clt := sdk.New()
	clt.Endpoint = endpoint
	clt.AddHeader("X-Appwrite-Project", project)
	clt.AddHeader("X-Appwrite-Key", key)
	clt.AddHeader("X-Appwrite-Response-Format", ResponseFormat)
	return clt
}

// Tables returns the TablesDB service bound to the execution key.
func Tables(ctx openruntimes.Context) *tablesdb.TablesDB {
	return tablesdb.New(Client(ctx))
}

// Page is a typed page of rows plus the total count.
type Page[T any] struct {
	Total int `json:"total"`
	Rows  []T `json:"rows"`
}

// List returns rows for a table filtered by Appwrite query strings.
func List[T any](ctx openruntimes.Context, table string, queries ...string) (*Page[T], error) {
	t := Tables(ctx)
	res, err := t.ListRows(DatabaseID, table, t.WithListRowsQueries(queries))
	if err != nil {
		return nil, MapError(err, table)
	}
	var out Page[T]
	if err := res.Decode(&out); err != nil {
		return nil, httpx.Upstream("could not decode rows", map[string]any{"table": table, "detail": err.Error()})
	}
	return &out, nil
}

// Get returns one row by id.
func Get[T any](ctx openruntimes.Context, table, rowID string) (*T, error) {
	row, err := Tables(ctx).GetRow(DatabaseID, table, rowID)
	if err != nil {
		return nil, MapError(err, table)
	}
	var out T
	if err := row.Decode(&out); err != nil {
		return nil, httpx.Upstream("could not decode row", map[string]any{"table": table, "detail": err.Error()})
	}
	return &out, nil
}

// Create inserts a row with explicit row permissions.
func Create[T any](ctx openruntimes.Context, table string, data map[string]any, permissions []string) (*T, error) {
	t := Tables(ctx)
	row, err := t.CreateRow(DatabaseID, table, id.Unique(), data, t.WithCreateRowPermissions(permissions))
	if err != nil {
		return nil, MapError(err, table)
	}
	var out T
	if err := row.Decode(&out); err != nil {
		return nil, httpx.Upstream("could not decode row", map[string]any{"table": table, "detail": err.Error()})
	}
	return &out, nil
}

// Update patches a row.
func Update[T any](ctx openruntimes.Context, table, rowID string, data map[string]any) (*T, error) {
	t := Tables(ctx)
	row, err := t.UpdateRow(DatabaseID, table, rowID, t.WithUpdateRowData(data))
	if err != nil {
		return nil, MapError(err, table)
	}
	var out T
	if err := row.Decode(&out); err != nil {
		return nil, httpx.Upstream("could not decode row", map[string]any{"table": table, "detail": err.Error()})
	}
	return &out, nil
}

// Delete removes a row.
func Delete(ctx openruntimes.Context, table, rowID string) error {
	_, err := Tables(ctx).DeleteRow(DatabaseID, table, rowID)
	return MapError(err, table)
}

// MapError converts an Appwrite SDK error into the httpx error contract.
func MapError(err error, table string) error {
	if err == nil {
		return nil
	}
	var ae *sdk.AppwriteError
	if errors.As(err, &ae) {
		params := map[string]any{"table": table, "status": ae.GetStatusCode()}
		switch ae.GetStatusCode() {
		case 401:
			return httpx.Unauthorized(ae.GetMessage(), params)
		case 403:
			return httpx.Forbidden(ae.GetMessage(), params)
		case 404:
			return httpx.NotFound(ae.GetMessage(), params)
		case 409:
			return httpx.Conflict(ae.GetMessage(), params)
		}
		return httpx.Upstream(ae.GetMessage(), params)
	}
	return httpx.Upstream(err.Error(), map[string]any{"table": table})
}

// Query builders re-exported so handlers import one package.
func Equal(attribute string, value any) string  { return query.Equal(attribute, value) }
func NotEqual(attribute string, value any) string { return query.NotEqual(attribute, value) }
func OrderAsc(attribute string) string         { return query.OrderAsc(attribute) }
func OrderDesc(attribute string) string        { return query.OrderDesc(attribute) }
func Limit(n int) string                       { return query.Limit(n) }
func Offset(n int) string                      { return query.Offset(n) }
func Search(attribute string, value any) string { return query.Search(attribute, value) }
func Contains(attribute string, value any) string { return query.Contains(attribute, value) }

package rows

import (
	"errors"

	sdk "github.com/appwrite/sdk-for-go/client"

	"github.com/ModdingFriendly/appwrite-library/appwrite"
	"github.com/ModdingFriendly/appwrite-library/httpx"
)

// ErrorStatus extracts the HTTP status from err. Extraction order is part of
// the contract: an *sdk.AppwriteError anywhere in the chain wins, then an
// *httpx.Error, otherwise 0.
func ErrorStatus(err error) int {
	var ae *sdk.AppwriteError
	if errors.As(err, &ae) && ae != nil {
		return ae.GetStatusCode()
	}
	var he *httpx.Error
	if errors.As(err, &he) && he != nil {
		return he.Status
	}
	return 0
}

// MapError converts a store error into the httpx contract, in the same order
// as ErrorStatus: an Appwrite SDK error is mapped through appwrite.MapError
// (stable message, code, table/status/reason params, private Detail); an
// existing *httpx.Error is returned unchanged so domain errors are never
// re-wrapped as 502; anything else becomes a generic 502 whose cause is kept
// for errors.Is. nil maps to nil.
func MapError(err error, table string) error {
	if err == nil {
		return nil
	}
	var ae *sdk.AppwriteError
	if errors.As(err, &ae) && ae != nil {
		return appwrite.MapError(err, table)
	}
	var he *httpx.Error
	if errors.As(err, &he) && he != nil {
		return err
	}
	return appwrite.MapError(err, table)
}

// ErrorBody renders err as the public (status, body) pair, with the same
// shapes httpx.Fail writes: a domain error is {"error","code"[,"params"]} at
// its status (a status outside 400-599 becomes 500); anything else, including
// nil, is the generic 500 {"error":"internal server error","code":
// "internal_error"}. Detail and Cause are never part of the body.
func ErrorBody(err error) (int, map[string]any) {
	var he *httpx.Error
	if errors.As(err, &he) && he != nil {
		status := he.Status
		if status < 400 || status > 599 {
			status = 500
		}
		body := map[string]any{"error": he.Message, "code": he.Code}
		if len(he.Params) > 0 {
			body["params"] = he.Params
		}
		return status, body
	}
	return 500, map[string]any{"error": "internal server error", "code": "internal_error"}
}

// IsTransactionConflict reports a raw store 409 (optimistic/commit conflict)
// as opposed to a domain 409: an Appwrite 409, or an httpx 409 whose
// params.table is "transaction". Domain conflicts must reach the caller
// unchanged.
func IsTransactionConflict(err error) bool {
	if err == nil {
		return false
	}
	var ae *sdk.AppwriteError
	if errors.As(err, &ae) && ae != nil {
		return ae.GetStatusCode() == 409
	}
	var he *httpx.Error
	if !errors.As(err, &he) || he == nil || he.Status != 409 {
		return false
	}
	table, _ := he.Params["table"].(string)
	return table == "transaction"
}

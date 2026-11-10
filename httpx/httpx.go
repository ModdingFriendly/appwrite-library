// Package httpx is the shared typed-handler contract for Appwrite Go Functions.
//
//	func handler(ctx, req *Request) (*Response, error)
//
// The request is a typed struct pointer (JSON body or query-bound), the
// response is a typed struct pointer that is JSON-marshalled, and any error is
// mapped to a stable JSON error body (with params) and HTTP status. Returning
// (nil, err) is the normal failure path; (nil, nil) means 204 No Content.
//
// The package owns serialisation: if a response or error body cannot be
// marshalled, the caller gets a structured 500
// ({"error":"internal server error","code":"internal_error"}) and the marshal
// detail is logged privately, never returned inline.
package httpx

import (
	"encoding/json"
	"errors"

	"github.com/open-runtimes/types-for-go/v4/openruntimes"
)

// Handler is the typed handler shape implemented by every endpoint.
type Handler[Req any, Res any] func(ctx openruntimes.Context, req *Req) (*Res, error)

// Error is a domain error: status + machine code + message + optional params.
//
// Detail and Cause are for operators, not callers: they are never serialised
// into the response body. Detail carries sanitised dependency context that Fail
// logs privately; Cause preserves the wrapped error so callers can still use
// errors.Is/errors.As for transport conditions such as a rejected redirect or a
// cancelled context.
type Error struct {
	Status  int
	Code    string
	Message string
	Params  map[string]any
	Detail  string
	Cause   error
}

// Error implements error and is safe on a nil receiver, so a typed-nil
// *Error can never panic a handler.
func (e *Error) Error() string {
	if e == nil {
		return "<nil>"
	}
	return e.Message
}

// Unwrap exposes the cause for errors.Is/errors.As. Cause is only set for
// non-SDK failures; a mapped Appwrite 4xx is authoritative on its own.
func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

func BadRequest(msg string, params map[string]any) error {
	return &Error{Status: 400, Code: "bad_request", Message: msg, Params: params}
}

func Unauthorized(msg string, params map[string]any) error {
	return &Error{Status: 401, Code: "unauthorized", Message: msg, Params: params}
}

func Forbidden(msg string, params map[string]any) error {
	return &Error{Status: 403, Code: "forbidden", Message: msg, Params: params}
}

func NotFound(msg string, params map[string]any) error {
	return &Error{Status: 404, Code: "not_found", Message: msg, Params: params}
}

func Conflict(msg string, params map[string]any) error {
	return &Error{Status: 409, Code: "conflict", Message: msg, Params: params}
}

// PreconditionFailed reports a stale read/write, for example an optimistic
// concurrency check on a quote decision that another request already applied.
func PreconditionFailed(msg string, params map[string]any) error {
	return &Error{Status: 412, Code: "precondition_failed", Message: msg, Params: params}
}

// Upstream marks a dependency (Appwrite, a provider API) as failing.
func Upstream(msg string, params map[string]any) error {
	return &Error{Status: 502, Code: "upstream_error", Message: msg, Params: params}
}

// Binder lets a request populate itself from query params or the raw request.
type Binder interface {
	Bind(ctx openruntimes.Context) error
}

// Handle adapts a typed handler to Appwrite: bind request, run, marshal result,
// or map the error. This is the only place the request/response plumbing lives.
func Handle[Req any, Res any](ctx openruntimes.Context, h Handler[Req, Res]) openruntimes.Response {
	var req Req

	if b, ok := any(&req).(Binder); ok {
		if err := b.Bind(ctx); err != nil {
			return Fail(ctx, err)
		}
	} else if ctx.Req.Method != "GET" {
		if err := ctx.Req.BodyJson(&req); err != nil {
			return Fail(ctx, BadRequest("invalid request body", map[string]any{"detail": err.Error()}))
		}
	}

	res, err := h(ctx, &req)
	if err != nil {
		return Fail(ctx, err)
	}
	if res == nil {
		return ctx.Res.Empty()
	}
	return writeJSON(ctx, 200, *res)
}

// Fail converts any error into the standard JSON error body.
//
// Domain errors are rendered as-is (their Detail and Cause stay private). Any
// other error is treated as an internal failure: the raw detail is logged
// privately through ctx.Error and only a generic body is returned, so
// dependency messages, SQL, tokens or network details never reach the client.
// A nil error or a typed-nil *Error is an invariant violation, not a panic: it
// is logged and answered with the same structured 500.
func Fail(ctx openruntimes.Context, err error) openruntimes.Response {
	var e *Error
	if errors.As(err, &e) && e != nil {
		if e.Detail != "" {
			ctx.Error("domain error: " + e.Detail)
		}
		status := e.Status
		if status < 400 || status > 599 {
			// A domain error always reaches the client with a failing status;
			// a zero or bogus status is an internal bug.
			ctx.Error("httpx: domain error with invalid status, using 500")
			status = 500
		}
		return writeJSON(ctx, status, errorBody(e))
	}

	if err == nil {
		ctx.Error("httpx: Fail called with a nil error")
	} else {
		ctx.Error("unhandled error: " + err.Error())
	}
	return writeJSON(ctx, 500, internalErrorBody())
}

// errorBody is the public shape of a domain error.
func errorBody(e *Error) map[string]any {
	body := map[string]any{"error": e.Message, "code": e.Code}
	if len(e.Params) > 0 {
		body["params"] = e.Params
	}
	return body
}

func internalErrorBody() map[string]any {
	return map[string]any{"error": "internal server error", "code": "internal_error"}
}

// writeJSON owns response serialisation. ctx.Res.Json falls back to the plain
// text body "Error encoding JSON." when marshalling fails, which is not valid
// JSON and cannot be distinguished by the caller; marshalling here keeps every
// response body decodable and logs the failure privately.
func writeJSON(ctx openruntimes.Context, status int, body any) openruntimes.Response {
	payload, err := json.Marshal(body)
	if err != nil {
		ctx.Error("httpx: marshal response body: " + err.Error())
		// internalErrorBody is a fixed map of strings, so this cannot fail;
		// fall back to a literal to keep the guarantee even if that changes.
		payload = []byte(`{"error":"internal server error","code":"internal_error"}`)
		status = 500
	}
	headers := map[string]string{"content-type": "application/json"}
	return ctx.Res.Binary(payload, ctx.Res.WithStatusCode(status), ctx.Res.WithHeaders(headers))
}

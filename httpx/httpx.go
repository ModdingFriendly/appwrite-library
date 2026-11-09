// Package httpx is the shared typed-handler contract for Appwrite Go Functions.
//
//	func handler(ctx, req *Request) (*Response, error)
//
// The request is a typed struct pointer (JSON body or query-bound), the
// response is a typed struct pointer that is JSON-marshalled, and any error is
// mapped to a stable JSON error body (with params) and HTTP status. Returning
// (nil, err) is the normal failure path; (nil, nil) means 204 No Content.
package httpx

import (
	"errors"

	"github.com/open-runtimes/types-for-go/v4/openruntimes"
)

// Handler is the typed handler shape implemented by every endpoint.
type Handler[Req any, Res any] func(ctx openruntimes.Context, req *Req) (*Res, error)

// Error is a domain error: status + machine code + message + optional params.
type Error struct {
	Status  int
	Code    string
	Message string
	Params  map[string]any
}

func (e *Error) Error() string { return e.Message }

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
	return ctx.Res.Json(*res)
}

// Fail converts any error into the standard JSON error body.
//
// Domain errors are rendered as-is. Any other error is treated as an internal
// failure: the raw detail is logged privately through ctx.Error and only a
// generic body is returned, so dependency messages, SQL, tokens or network
// details never reach the client.
func Fail(ctx openruntimes.Context, err error) openruntimes.Response {
	var e *Error
	if errors.As(err, &e) {
		body := map[string]any{"error": e.Message, "code": e.Code}
		if len(e.Params) > 0 {
			body["params"] = e.Params
		}
		return ctx.Res.Json(body, ctx.Res.WithStatusCode(e.Status))
	}
	ctx.Error("unhandled error: " + err.Error())
	return ctx.Res.Json(
		map[string]any{"error": "internal server error", "code": "internal_error"},
		ctx.Res.WithStatusCode(500),
	)
}

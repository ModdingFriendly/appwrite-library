package httpx_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/open-runtimes/types-for-go/v4/openruntimes"

	"github.com/ModdingFriendly/appwrite-library/httpx"
)

func testContext() openruntimes.Context {
	return openruntimes.NewContext(openruntimes.Logger{})
}

func decode(t *testing.T, res openruntimes.Response) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(res.Body, &body); err != nil {
		t.Fatalf("decode response body %q: %v", string(res.Body), err)
	}
	return body
}

func TestFailDomainError(t *testing.T) {
	ctx := testContext()
	res := httpx.Fail(ctx, httpx.BadRequest("name is required", map[string]any{"field": "name"}))

	if res.StatusCode != 400 {
		t.Fatalf("status = %d, want 400", res.StatusCode)
	}
	body := decode(t, res)
	if body["error"] != "name is required" || body["code"] != "bad_request" {
		t.Fatalf("body = %#v", body)
	}
	params, ok := body["params"].(map[string]any)
	if !ok || params["field"] != "name" {
		t.Fatalf("params = %#v", body["params"])
	}
}

func TestFailDomainErrorThroughWrapper(t *testing.T) {
	ctx := testContext()
	err := fmt.Errorf("wrapped: %w", httpx.Conflict("already decided", nil))
	res := httpx.Fail(ctx, err)

	if res.StatusCode != 409 {
		t.Fatalf("status = %d, want 409", res.StatusCode)
	}
	if body := decode(t, res); body["code"] != "conflict" {
		t.Fatalf("body = %#v", body)
	}
}

func TestFailPreconditionFailed(t *testing.T) {
	ctx := testContext()
	res := httpx.Fail(ctx, httpx.PreconditionFailed("stale quote", map[string]any{"status": "accepted"}))

	if res.StatusCode != 412 {
		t.Fatalf("status = %d, want 412", res.StatusCode)
	}
	if body := decode(t, res); body["code"] != "precondition_failed" {
		t.Fatalf("body = %#v", body)
	}
}

func TestFailUnknownErrorIsSafeAndLogged(t *testing.T) {
	logFile, err := os.CreateTemp(t.TempDir(), "errors-*.log")
	if err != nil {
		t.Fatalf("create log file: %v", err)
	}

	logger := openruntimes.Logger{Enabled: true, StreamErrors: logFile}
	ctx := openruntimes.NewContext(logger)

	secret := "db=postgres://user:super-secret@host/db"
	res := httpx.Fail(ctx, errors.New(secret))

	if res.StatusCode != 500 {
		t.Fatalf("status = %d, want 500", res.StatusCode)
	}
	body := decode(t, res)
	if body["error"] != "internal server error" || body["code"] != "internal_error" {
		t.Fatalf("body = %#v", body)
	}
	if strings.Contains(string(res.Body), "super-secret") {
		t.Fatalf("response leaked raw error: %s", string(res.Body))
	}

	if err := logFile.Close(); err != nil {
		t.Fatalf("close log file: %v", err)
	}
	logged, err := os.ReadFile(logFile.Name())
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}
	if !strings.Contains(string(logged), secret) {
		t.Fatalf("private log %q does not contain raw error %q", string(logged), secret)
	}
}

type greetRequest struct {
	Name string `json:"name"`
}

type greetResponse struct {
	Greeting string `json:"greeting"`
}

func greet(ctx openruntimes.Context, req *greetRequest) (*greetResponse, error) {
	if req.Name == "" {
		return nil, httpx.BadRequest("name is required", map[string]any{"field": "name"})
	}
	return &greetResponse{Greeting: "hello " + req.Name}, nil
}

func postContext(body string) openruntimes.Context {
	ctx := testContext()
	ctx.Req.Method = "POST"
	ctx.Req.SetBodyBinary([]byte(body))
	return ctx
}

func TestHandleBindsAndMarshals(t *testing.T) {
	res := httpx.Handle(postContext(`{"name":"ada"}`), greet)

	if res.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}
	if body := decode(t, res); body["greeting"] != "hello ada" {
		t.Fatalf("body = %#v", body)
	}
}

func TestHandleInvalidBody(t *testing.T) {
	res := httpx.Handle(postContext(`{"name":`), greet)

	if res.StatusCode != 400 {
		t.Fatalf("status = %d, want 400", res.StatusCode)
	}
	if body := decode(t, res); body["code"] != "bad_request" {
		t.Fatalf("body = %#v", body)
	}
}

func TestHandleNilResultIs204(t *testing.T) {
	handler := func(ctx openruntimes.Context, req *greetRequest) (*greetResponse, error) {
		return nil, nil
	}
	res := httpx.Handle(postContext(`{}`), handler)

	if res.StatusCode != 204 {
		t.Fatalf("status = %d, want 204", res.StatusCode)
	}
	if len(res.Body) != 0 {
		t.Fatalf("body = %q, want empty", string(res.Body))
	}
}

func TestHandleUnknownErrorIsSafe(t *testing.T) {
	handler := func(ctx openruntimes.Context, req *greetRequest) (*greetResponse, error) {
		return nil, errors.New("driver: connection string secret")
	}
	res := httpx.Handle(postContext(`{}`), handler)

	if res.StatusCode != 500 {
		t.Fatalf("status = %d, want 500", res.StatusCode)
	}
	if strings.Contains(string(res.Body), "connection string secret") {
		t.Fatalf("response leaked raw error: %s", string(res.Body))
	}
}

// TestFailNilErrorDoesNotPanic covers the defensive path: Fail is only called
// with a failure, so a nil is a caller bug that must not take down the function.
func TestFailNilErrorDoesNotPanic(t *testing.T) {
	res := httpx.Fail(testContext(), nil)

	if res.StatusCode != 500 {
		t.Fatalf("status = %d, want 500", res.StatusCode)
	}
	body := decode(t, res)
	if body["error"] != "internal server error" || body["code"] != "internal_error" {
		t.Fatalf("body = %#v", body)
	}
}

// TestFailTypedNilDomainErrorDoesNotPanic covers a non-nil interface holding a
// nil *httpx.Error: errors.As succeeds and the old code dereferenced nil.
func TestFailTypedNilDomainErrorDoesNotPanic(t *testing.T) {
	var domain *httpx.Error
	var err error = domain // typed nil, interface is non-nil

	res := httpx.Fail(testContext(), err)

	if res.StatusCode != 500 {
		t.Fatalf("status = %d, want 500", res.StatusCode)
	}
	if body := decode(t, res); body["code"] != "internal_error" {
		t.Fatalf("body = %#v", body)
	}
}

// TestNilErrorReceiverIsSafe pins the nil receiver methods.
func TestNilErrorReceiverIsSafe(t *testing.T) {
	var domain *httpx.Error
	if got := domain.Error(); got == "" {
		t.Fatal("nil *httpx.Error.Error() returned an empty string")
	}
	if err := domain.Unwrap(); err != nil {
		t.Fatalf("nil *httpx.Error.Unwrap() = %v", err)
	}
}

// TestDomainErrorInvalidStatusFallsBack covers a hand-built Error with no status.
func TestDomainErrorInvalidStatusFallsBack(t *testing.T) {
	res := httpx.Fail(testContext(), &httpx.Error{Code: "odd", Message: "odd"})

	if res.StatusCode != 500 {
		t.Fatalf("status = %d, want 500", res.StatusCode)
	}
	if body := decode(t, res); body["code"] != "odd" {
		t.Fatalf("body = %#v", body)
	}
}

type unmarshalableResponse struct {
	Broken func() `json:"broken"`
}

// TestHandleMarshalFailureIsStructured500 proves the package owns
// serialisation: ctx.Res.Json would answer "Error encoding JSON." as plain text.
func TestHandleMarshalFailureIsStructured500(t *testing.T) {
	handler := func(ctx openruntimes.Context, req *greetRequest) (*unmarshalableResponse, error) {
		return &unmarshalableResponse{Broken: func() {}}, nil
	}
	res := httpx.Handle(postContext(`{}`), handler)

	if res.StatusCode != 500 {
		t.Fatalf("status = %d, want 500", res.StatusCode)
	}
	if got := res.Headers["content-type"]; got != "application/json" {
		t.Fatalf("content-type = %q, want application/json", got)
	}
	body := decode(t, res)
	if body["error"] != "internal server error" || body["code"] != "internal_error" {
		t.Fatalf("body = %#v", body)
	}
}

// TestFailMarshalFailureIsStructured500 covers an unmarshalable params value on
// a domain error.
func TestFailMarshalFailureIsStructured500(t *testing.T) {
	err := httpx.BadRequest("bad", map[string]any{"field": func() {}})
	res := httpx.Fail(testContext(), err)

	if res.StatusCode != 500 {
		t.Fatalf("status = %d, want 500", res.StatusCode)
	}
	if got := res.Headers["content-type"]; got != "application/json" {
		t.Fatalf("content-type = %q, want application/json", got)
	}
	if body := decode(t, res); body["code"] != "internal_error" {
		t.Fatalf("body = %#v", body)
	}
}

// TestDomainDetailIsLoggedNotReturned keeps upstream detail private.
func TestDomainDetailIsLoggedNotReturned(t *testing.T) {
	logFile, err := os.CreateTemp(t.TempDir(), "errors-*.log")
	if err != nil {
		t.Fatalf("create log file: %v", err)
	}
	logger := openruntimes.Logger{Enabled: true, StreamErrors: logFile}
	ctx := openruntimes.NewContext(logger)

	domain := httpx.NotFound("record not found", map[string]any{"table": "tickets"})
	concrete, ok := domain.(*httpx.Error)
	if !ok {
		t.Fatalf("error = %T", domain)
	}
	concrete.Detail = "appwrite tickets status 404: row 3f9a does not exist"

	res := httpx.Fail(ctx, domain)
	if res.StatusCode != 404 {
		t.Fatalf("status = %d, want 404", res.StatusCode)
	}
	if strings.Contains(string(res.Body), "3f9a") {
		t.Fatalf("response leaked private detail: %s", string(res.Body))
	}
	if err := logFile.Close(); err != nil {
		t.Fatalf("close log: %v", err)
	}
	logged, err := os.ReadFile(logFile.Name())
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	if !strings.Contains(string(logged), "3f9a") {
		t.Fatalf("private log %q does not contain the detail", string(logged))
	}
}

// TestCauseIsPreserved proves callers can still match transport conditions.
func TestCauseIsPreserved(t *testing.T) {
	sentinel := errors.New("dial tcp: connection refused")
	err := &httpx.Error{Status: 502, Code: "upstream_error", Message: "appwrite request failed", Cause: sentinel}

	if !errors.Is(err, sentinel) {
		t.Fatal("errors.Is did not reach the cause")
	}
	var domain *httpx.Error
	if !errors.As(err, &domain) {
		t.Fatal("errors.As did not match the domain error")
	}
}

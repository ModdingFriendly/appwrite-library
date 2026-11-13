package rows

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	sdk "github.com/appwrite/sdk-for-go/client"

	"github.com/ModdingFriendly/appwrite-library/appwrite"
	"github.com/ModdingFriendly/appwrite-library/httpx"
)

// sdkErr produces a genuine *sdk.AppwriteError by calling the pinned SDK
// against a local server that answers with the given status and error type.
func sdkErr(status int, typ string) error {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"message":"secret upstream text","code":` + strconv.Itoa(status) + `,"type":"` + typ + `"}`))
	}))
	defer srv.Close()
	tables, err := appwrite.NewTables(appwrite.Config{Endpoint: srv.URL, ProjectID: "p", DatabaseID: "d", APIKey: "k"})
	if err != nil {
		panic(err)
	}
	_, err = tables.GetRow("d", "tickets", "r1")
	var ae *sdk.AppwriteError
	if !errors.As(err, &ae) {
		panic(fmt.Sprintf("expected an SDK error, got %v", err))
	}
	return err
}

func TestErrorStatusOrder(t *testing.T) {
	if ErrorStatus(nil) != 0 || ErrorStatus(errors.New("x")) != 0 {
		t.Fatal("non-status errors are 0")
	}
	if ErrorStatus(httpx.NotFound("n", nil)) != 404 {
		t.Fatal("httpx status")
	}
	if ErrorStatus(sdkErr(409, "x")) != 409 {
		t.Fatal("sdk status")
	}
	// SDK error wins over an httpx error even when the httpx error is outer.
	outer := &httpx.Error{Status: 502, Code: "upstream_error", Message: "m", Cause: sdkErr(404, "row_not_found")}
	if ErrorStatus(outer) != 404 {
		t.Fatal("sdk error must be extracted before httpx.Error")
	}
	if ErrorStatus(fmt.Errorf("wrap: %w", sdkErr(412, "x"))) != 412 {
		t.Fatal("wrapped sdk")
	}
}

func TestMapErrorPreservesOrderAndShape(t *testing.T) {
	if MapError(nil, "t") != nil {
		t.Fatal("nil -> nil")
	}
	domain := httpx.Conflict("domain conflict", map[string]any{"field": "f"})
	if MapError(domain, "t") != domain {
		t.Fatal("httpx.Error must pass through unchanged, not be re-wrapped as 502")
	}
	got := he(t, MapError(sdkErr(404, "row_not_found"), "tickets"))
	if got.Status != 404 || got.Code != "not_found" || got.Message != appwrite.MessageNotFound ||
		got.Params["table"] != "tickets" || got.Params["reason"] != "row_not_found" {
		t.Fatalf("%+v", got)
	}
	if got.Message == "secret upstream text" || got.Detail == "" {
		t.Fatal("upstream text is private detail only")
	}
	cause := errors.New("dial tcp: refused")
	plain := he(t, MapError(cause, "tickets"))
	if plain.Status != 502 || !errors.Is(plain, cause) {
		t.Fatalf("non-SDK errors become 502 and keep their cause: %+v", plain)
	}
	// An httpx wrapper around an sdk error maps the SDK error first.
	wrapped := &httpx.Error{Status: 502, Message: "m", Cause: sdkErr(403, "x")}
	if he(t, MapError(wrapped, "t")).Status != 403 {
		t.Fatal("sdk error must be mapped before httpx.Error")
	}
}

func TestErrorBodyShapes(t *testing.T) {
	status, body := ErrorBody(httpx.BadRequest("bad", map[string]any{"field": "x"}))
	if status != 400 || body["error"] != "bad" || body["code"] != "bad_request" || body["params"].(map[string]any)["field"] != "x" {
		t.Fatalf("%d %v", status, body)
	}
	_, body = ErrorBody(httpx.NotFound("nf", nil))
	if _, has := body["params"]; has {
		t.Fatal("empty params must be omitted")
	}
	private := &httpx.Error{Status: 502, Code: "upstream_error", Message: "public", Detail: "SECRET", Cause: errors.New("SECRET")}
	_, body = ErrorBody(private)
	for k, v := range body {
		if fmt.Sprint(v) == "SECRET" || k == "detail" || k == "cause" {
			t.Fatalf("private fields leaked: %v", body)
		}
	}
	for _, e := range []error{errors.New("boom"), nil, &httpx.Error{Status: 0, Code: "x", Message: "m"}} {
		status, body := ErrorBody(e)
		if status != 500 {
			t.Fatalf("%v -> %d", e, status)
		}
		if _, isDomain := e.(*httpx.Error); !isDomain && (body["code"] != "internal_error" || body["error"] != "internal server error") {
			t.Fatalf("generic body: %v", body)
		}
	}
}

func TestIsTransactionConflict(t *testing.T) {
	if !IsTransactionConflict(sdkErr(409, "x")) {
		t.Fatal("raw 409")
	}
	if IsTransactionConflict(httpx.Conflict("domain", map[string]any{"field": "f"})) {
		t.Fatal("domain conflict must not match")
	}
	if !IsTransactionConflict(httpx.Conflict("tx", map[string]any{"table": "transaction"})) {
		t.Fatal("transaction conflict")
	}
	if IsTransactionConflict(nil) || IsTransactionConflict(sdkErr(500, "x")) {
		t.Fatal("negatives")
	}
}

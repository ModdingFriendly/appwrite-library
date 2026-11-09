# appwrite-library

Shared Go libraries for Reparix Appwrite Functions. Public, versioned, and
consumed by the builder with a normal `go get` — no copying into functions.

```
go get github.com/ModdingFriendly/appwrite-library@v0.1.0
```

## Packages

### `httpx` — typed handler contract

```go
func handler(ctx openruntimes.Context, req *MyRequest) (*MyResponse, error)
```

- `req` is a typed struct pointer (JSON body, or implements `httpx.Binder` for
  query params).
- `res` is a typed struct pointer, JSON-marshalled automatically. `(nil, nil)`
  → 204 No Content.
- errors are returned, never written inline: `httpx.BadRequest`, `NotFound`,
  `Conflict`, `Upstream`, … become `{ "error", "code", "params" }` with the
  right status.

Router:

```go
case ctx.Req.Path == "/fedex/rates" && ctx.Req.Method == "POST":
    return httpx.Handle(ctx, fedexRates)
```

### `appwrite` — server-side TablesDB access

Wraps the official Appwrite Go SDK (`github.com/appwrite/sdk-for-go`). It builds
a client from the function's short-lived execution key
(`x-appwrite-key`), so no secrets are stored in code.

```go
type Ticket struct {
    ID     string `json:"$id"`
    Device string `json:"device"`
    Status string `json:"status"`
}

page, err := appwrite.List[Ticket](ctx, "tickets",
    appwrite.Equal("organization_id", teamID),
    appwrite.OrderDesc("$createdAt"),
    appwrite.Limit(50),
)
if err != nil {
    return nil, err
}
```

Also: `appwrite.Get`, `appwrite.Create`, `appwrite.Update`, `appwrite.Delete`,
`appwrite.MapError`, and query builders (`Equal`, `OrderAsc`, `OrderDesc`,
`Limit`, `Offset`, `Search`, `Contains`).

## Versioning

Tag releases (`v0.1.0`, `v0.2.0`, …). Functions pin a version in `go.mod`.

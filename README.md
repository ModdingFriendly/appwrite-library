# appwrite-library

Shared Go libraries for Appwrite Functions. Public, versioned, and consumed
with a normal `go get` — no copying into functions.

```
go get github.com/ModdingFriendly/appwrite-library@v0.3.0
```

Requires Go 1.26 (builds with `go 1.26.0`; pinned Appwrite SDK is `v1.0.0`).

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
  `Conflict`, `PreconditionFailed`, `Upstream`, … become `{ "error", "code",
  "params" }` with the right status.
- an unknown error becomes a generic `500 { "error": "internal server error",
  "code": "internal_error" }`; the raw detail is logged privately with
  `ctx.Error` and never returned to the caller.

Router:

```go
case ctx.Req.Path == "/fedex/rates" && ctx.Req.Method == "POST":
    return httpx.Handle(ctx, fedexRates)
```

### `appwrite` — server-side TablesDB access

Wraps the official Appwrite Go SDK (`github.com/appwrite/sdk-for-go`). No
endpoint, project or database identifier is embedded in this module.

#### Explicit configuration (preferred)

```go
cfg := appwrite.Config{
    Endpoint:   os.Getenv("APPWRITE_ENDPOINT"),
    ProjectID:  os.Getenv("APPWRITE_PROJECT_ID"),
    DatabaseID: os.Getenv("APPWRITE_DATABASE_ID"),
    APIKey:     ctx.Req.Headers["x-appwrite-key"], // short-lived execution key
}

type Ticket struct {
    ID     string `json:"$id"`
    Device string `json:"device"`
    Status string `json:"status"`
}

page, err := appwrite.ListWith[Ticket](ctx, cfg, "tickets",
    appwrite.Equal("organization_id", teamID),
    appwrite.OrderDesc("$createdAt"),
    appwrite.Limit(50),
)
if err != nil {
    return nil, err
}
```

`NewClient(cfg)` and `NewTables(cfg)` are available when a handler needs the
raw SDK service (for example transactions).

#### Environment configuration (v0.1.x-compatible calls)

`List`, `Get`, `Create`, `Update` and `Delete` read the same explicit settings
from the environment:

| Variable | Purpose |
|---|---|
| `APPWRITE_ENDPOINT` (or runtime `APPWRITE_FUNCTION_API_ENDPOINT`) | API base URL |
| `APPWRITE_PROJECT_ID` (or runtime `APPWRITE_FUNCTION_PROJECT_ID`) | project ID |
| `APPWRITE_DATABASE_ID` | TablesDB database ID |
| `x-appwrite-key` request header | execution key |

There is **no fallback** to a hard-coded project, endpoint or database. Missing
configuration is an error, not a silent default. Set `APPWRITE_DATABASE_ID` as a
Function Variable when upgrading from v0.1.x.

Also: `ListWith`, `GetWith`, `CreateWith`, `UpdateWith`, `DeleteWith`,
`MapError`, and query builders (`Equal`, `OrderAsc`, `OrderDesc`, `Limit`,
`Offset`, `Search`, `Contains`).

### `money` — exact money, no floats

Canonical storage is the string `"<ISO-4217> <amount>"` (`"GBP 1.00"`,
`"GBP -3.50"`, `"JPY 500"`) in `varchar(32)` columns. Amounts live in integer
minor units plus `math/big.Rat` for fractional quantities, so a ledger value
never passes through `float64`.

```go
price, err := money.ParseMoney("GBP 2.50")          // strict canonical parse
line, err := money.MulMoneyQuantity(price, 3)       // "GBP 7.50"
tax, err := money.MulMoneyRate(line, "20")          // "GBP 1.50"
total, err := money.SumMoney(line, tax)             // "GBP 9.00"
stored := total.String()                            // persist this string

fromCents, err := money.FromMinorUnits("GBP", 900)  // integers, no float
provider, err := money.MoneyFromDecimalString("USD", "12.34")
```

- `ParseMoney`, `MustParseMoney`, `ParseMoneyValue` (rejects JSON numbers),
  `MoneyFromDecimalString`, `FromMinorUnits`, `FormatMoney`.
- `AddMoney`, `SubMoney`, `SumMoney`, `MulMoneyQuantity`, `MulMoneyDecimal`,
  `MulMoneyRate`, `NegMoney`, `AbsMoney`, `CmpMoney`.
- `Money.String()`, `MinorUnits()`, `IsZero()`, `IsNegative()`.
- `ErrInvalidMoney`, `ErrCurrencyMismatch`, `ErrMoneyOverflow`.
- Supported currencies: `GBP`, `EUR`, `USD`, `CHF`, `AUD`, `CAD` (2 dp) and
  `JPY` (0 dp); anything else is rejected.

### `auth` — JWT identity and team membership

Generic caller verification with no product roles or tenant header names baked
in. A function keeps its own role policy and header convention; the library only
returns verified facts.

```go
lookup, err := auth.NewJWTLookupFromEnv() // or auth.NewJWTLookup(cfg)
if err != nil {
    return nil, err
}

identity, err := lookup.CurrentUser(ctx) // Account.Get(), JWT only
if err != nil {
    return nil, err
}

membership, err := lookup.Membership(ctx, teamID, identity.UserID)
if err != nil {
    return nil, err
}
if !membership.Confirmed {
    return nil, httpx.Forbidden("membership is not confirmed", nil)
}
```

- The client sends `X-Appwrite-JWT` and never `X-Appwrite-Key`, so it uses only
  the caller's own permissions.
- `Lookup` is an interface, so applications can stub it in tests.
- Pass `identity.UserID` from `CurrentUser` into `Membership`; never pass an id
  from the request body or a header.
- `Config` has endpoint/project only (no database, no key); `ConfigFromEnv` reads
  `APPWRITE_ENDPOINT`/`APPWRITE_PROJECT_ID` or the runtime `APPWRITE_FUNCTION_*`
  equivalents. There are no embedded defaults.
- `auth.Header(ctx, name)` is a case-insensitive header reader for an
  application's own tenant header.
- Roles are plain strings returned by Appwrite; the package does not interpret
  `admin`, `technician`, `owner` or any other product role.

#### Error mapping

Appwrite client errors keep the server message (`400`, `401`, `403`, `404`,
`409`, `412`). Upstream/5xx and non-SDK errors use a generic public message;
callers log the raw error privately before returning it.

### Transactions

The pinned SDK and Appwrite server already support TablesDB transactions; no SDK
upgrade is needed for billing or quote work. Use the shared helper for the safe
create/stage/commit/rollback flow:

```go
err := appwrite.InTransaction(ctx, func(t *tablesdb.TablesDB, txID string) error {
    _, err := t.CreateRow(cfg.DatabaseID, "quotes", id.Unique(), data,
        t.WithCreateRowTransactionId(txID))
    return err
})
if err != nil {
    return nil, err // nothing is reported as committed
}
```

`InTransaction`:

- creates a transaction with `DefaultTransactionTTL` (60 s),
- runs the callback with the transaction id; the callback must stage every
  write with that id and must not commit, roll back, or issue
  non-transactional writes,
- commits only when the callback succeeds and the acknowledgement status is
  exactly `"committed"`,
- treats an empty, missing, `pending`, `committing` or `failed` commit status as
  failure (fail closed), and
- attempts a rollback on every non-commit path, logging rollback errors and
  ambiguous rollback acknowledgements privately.

`InTransactionWith(ctx, cfg, fn)` is the explicit-configuration variant.

For lower-level control, `NewTables(cfg)` exposes the raw SDK:
`CreateTransaction`, `WithCreateRowTransactionId`,
`WithUpdateRowTransactionId`, `WithDeleteRowTransactionId`,
`WithGetRowTransactionId`, `WithListRowsTransactionId`, `CreateOperations`,
`GetTransaction`, `UpdateTransaction` and `DeleteTransaction`.

Note: a commit that times out or returns an ambiguous acknowledgement may still
have committed on the server. Callers must keep their own idempotency and
conflict handling for billing retries and quote decisions.

## Migrating from v0.1.x

- `appwrite.DatabaseID` is removed. Pass `appwrite.Config{DatabaseID: ...}` to
  the `*With` helpers, or keep the database id as a function-local constant.
  Legacy `List`/`Get`/`Create`/`Update`/`Delete` read `APPWRITE_DATABASE_ID`
  from the environment.
- `appwrite.Client(ctx)` no longer falls back to a built-in endpoint. Set the
  runtime variables (or use `appwrite.NewClient` with explicit configuration).
- Unknown `httpx` errors now return a generic 500 and are logged privately
  instead of exposing the raw error.
- The duplicated JWT/team lookup can move to the new `auth` package; application
  roles, policies and guards stay in the function.

## Versioning

Tag releases (`v0.2.0`, `v0.3.0`, …). Functions pin a version in `go.mod`.

## Changelog

- `v0.3.0` — new `money` package (canonical string money, integer minor units,
  `big.Rat` for fractional quantities; no float conversions).
- `v0.2.0` — explicit `appwrite.Config`, JWT/team membership `auth` lookup,
  `InTransaction` helper.

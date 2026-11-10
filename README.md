# appwrite-library

Shared Go libraries for Appwrite Functions. Public, versioned, and consumed
with a normal `go get` — no copying into functions.

```
go get github.com/ModdingFriendly/appwrite-library@v0.3.2
```

Requires Go 1.26 (builds with `go 1.26.0`; pinned Appwrite SDK is `v1.0.0`).
See [CHANGELOG.md](CHANGELOG.md) for release notes.

## Scope: transport, not tenancy

This module sends requests and maps answers. It knows nothing about
organisations, teams, customers or roles, and it adds **no** tenant filtering,
row ACL or authorization check of its own. Every helper runs with whatever
key/JWT you configure. Tenant enforcement is the application's job:

- filter every read by the caller's team (`organization_id`),
- build row permissions from verified team roles (server-side, never from the
  request body),
- treat server-owned columns (`organization_id`, `customer_user_id`,
  `created_by_user_id`, `$permissions`, …) as derived values.

That policy is Reparix's, not the library's, and it is not implied by any
helper here.

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
- `Fail(ctx, nil)` and a typed-nil `*httpx.Error` are logged and answered with
  that same structured 500 instead of panicking.
- serialisation is owned by the package: if a response body (or an error's
  params) cannot be marshalled, the caller still receives the structured 500,
  never the SDK's plain-text `"Error encoding JSON."`.

`httpx.Error` carries two operator-only fields, neither serialised:

| Field | Purpose |
|---|---|
| `Detail` | sanitised dependency context, logged by `Fail` |
| `Cause` | wrapped error for `errors.Is`/`errors.As` (transport failures only) |

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
    appwrite.Equal("organization_id", teamID), // tenancy is your filter
    appwrite.OrderDesc("$createdAt"),
    appwrite.Limit(50),
)
if err != nil {
    return nil, err
}
```

`NewClient(cfg)` and `NewTables(cfg)` are available when a handler needs the
raw SDK service (for example transactions).

#### Transport policy

The client is hardened, and the policy applies to every request the module
makes:

- **HTTPS only.** `http://` is accepted for loopback hosts (`localhost`,
  `*.localhost`, `127.0.0.0/8`, `::1`) so local development and `httptest` work
  without flags. Any other plain-HTTP host is rejected with
  `appwrite.ErrInsecureEndpoint` unless `Config.AllowInsecureHTTP` is set
  explicitly for a trusted internal/test deployment. TLS 1.2 is the minimum.
- **Redirects are never followed.** The SDK replays headers on every hop, so
  following a `302` would forward `X-Appwrite-Key` / `X-Appwrite-JWT` to the
  redirect target. A redirect becomes a 502 `upstream_error` whose cause wraps
  `appwrite.ErrRedirectRejected`; the target is never contacted.
- A single API call is bounded by `appwrite.DefaultHTTPTimeout` (30 s).

#### Environment configuration (v0.1.x-compatible calls)

`List`, `Get`, `Create`, `Update` and `Delete` read the same explicit settings
from the environment:

| Variable | Purpose |
|---|---|
| `APPWRITE_ENDPOINT` (or runtime `APPWRITE_FUNCTION_API_ENDPOINT`) | API base URL |
| `APPWRITE_PROJECT_ID` (or runtime `APPWRITE_FUNCTION_PROJECT_ID`) | project ID |
| `APPWRITE_DATABASE_ID` | TablesDB database ID |
| `APPWRITE_RESPONSE_FORMAT` | optional response format override |
| `x-appwrite-key` request header | execution key |

There is **no fallback** to a hard-coded project, endpoint or database. Missing
configuration is an error, not a silent default. Set `APPWRITE_DATABASE_ID` as a
Function Variable when upgrading from v0.1.x.

`X-Appwrite-Response-Format` precedence, highest first:

1. `Config.ResponseFormat` (explicit caller value),
2. `APPWRITE_RESPONSE_FORMAT`,
3. `appwrite.DefaultResponseFormat` (`1.8.0`, the version the pinned SDK models
   were generated for).

An empty or whitespace-only value falls through to the next level, so
`APPWRITE_RESPONSE_FORMAT=""` restores the pinned default.

Also: `ListWith`, `GetWith`, `CreateWith`, `UpdateWith`, `DeleteWith`,
`MapError`, and query builders (`Equal`, `OrderAsc`, `OrderDesc`, `Limit`,
`Offset`, `Search`, `Contains`).

#### Error mapping

`MapError` never returns Appwrite's message. Each status maps to a stable
message and code, with `table`, `status` and (when the server supplied a
machine-readable error type) `reason` in `params`:

| Appwrite status | Response | `code` | `message` (constant) |
|---|---|---|---|
| 400 | 400 | `bad_request` | `request rejected` (`MessageBadRequest`) |
| 401 | 401 | `unauthorized` | `authentication required` (`MessageUnauthorized`) |
| 403 | 403 | `forbidden` | `permission denied` (`MessageForbidden`) |
| 404 | 404 | `not_found` | `record not found` (`MessageNotFound`) |
| 409 | 409 | `conflict` | `conflict` (`MessageConflict`) |
| 412 | 412 | `precondition_failed` | `record changed` (`MessageStale`) |
| 5xx / other | 502 | `upstream_error` | `appwrite request failed` (`MessageUpstream`) |

The upstream message is sanitised (control characters removed, capped at 512
characters) into `httpx.Error.Detail`, which `httpx.Fail` logs privately.
Non-SDK failures (dial errors, timeouts, a rejected redirect) keep their cause,
so `errors.Is(err, appwrite.ErrRedirectRejected)` still works.

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
absolute, err := money.AbsMoney(money.MustParseMoney("GBP -3.50"))
```

- `ParseMoney`, `MustParseMoney`, `ParseMoneyValue` (rejects JSON numbers),
  `MoneyFromDecimalString`, `FromMinorUnits`, `FormatMoney`, `ParseDecimal`.
- `AddMoney`, `SubMoney`, `SumMoney`, `MulMoneyQuantity`, `MulMoneyDecimal`,
  `MulMoneyRate`, `NegMoney`, `AbsMoney`, `CmpMoney`.
- `Money.String()`, `MinorUnits()`, `IsZero()`, `IsNegative()`, `Validate()`.
- `ErrInvalidMoney`, `ErrInvalidDecimal` (wraps it), `ErrCurrencyMismatch`,
  `ErrMoneyOverflow`.
- Supported currencies: `GBP`, `EUR`, `USD`, `CHF`, `AUD`, `CAD` (2 dp) and
  `JPY` (0 dp); anything else is rejected.

**Supported range.** The full `int64` minor-unit range is exact, including
`math.MinInt64` and `math.MaxInt64`: `ParseMoney(m.String()) == m` for every
value and every supported currency. The widest stored string is
`"GBP -92233720368547758.08"` (25 characters, well inside `varchar(32)`). Parsing rejects anything outside
the range with `ErrMoneyOverflow`; it never wraps. `NegMoney`/`AbsMoney` report
`ErrMoneyOverflow` for `math.MinInt64` because its positive counterpart is not
representable.

**Fractional inputs are bounded plain decimals.** `MulMoneyDecimal` and
`MulMoneyRate` accept `"0"`, `"12"`, `"-1.25"`, `"+0.5"`, `"0.000000001"`:
optional sign, no leading zeros, at most 15 whole digits and 9 fractional
digits, no surrounding whitespace. Fractions (`"1/3"`), hex (`"0x10"`),
exponents (`"1e3"`) and anything longer are rejected with `ErrInvalidDecimal`.
Results round half-up, ties away from zero.

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
  the caller's own permissions. It inherits the hardened transport above
  (HTTPS, no redirects).
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

Token failures (`401`, `403`, `404`) become `httpx.Unauthorized`/`Forbidden` with
fixed messages. Upstream/5xx and non-SDK errors use a generic public message;
the raw detail is logged privately before returning.

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

## Migrating from v0.3.1

- `money.AbsMoney` now returns `(Money, error)`, matching `NegMoney`. It reports
  `ErrMoneyOverflow` for `math.MinInt64` instead of returning a negative amount.
- `appwrite.MapError` returns stable public messages, not Appwrite's text
  (`appwrite.MessageBadRequest`, `MessageNotFound`, …). Codes and statuses are
  unchanged. If any client matched on the upstream message, move it to the code
  or the `reason` param.
- `appwrite: ` plain-HTTP endpoints outside loopback are rejected. Set
  `Config.AllowInsecureHTTP` only for a trusted internal test deployment.
- `appwrite: ` redirects are rejected. An endpoint that answered `3xx` now
  returns `502 upstream_error`; point the configuration at the final URL.
- `appwrite.ResponseFormat`, `appwrite.Client(ctx)` and `appwrite.Tables(ctx)`
  are deprecated; use `DefaultResponseFormat`, `NewClient(cfg)` and
  `NewTables(cfg)`.

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

Tag releases (`v0.3.2`, `v0.4.0`, …). Functions pin a version in `go.mod`.
Release notes live in [CHANGELOG.md](CHANGELOG.md).

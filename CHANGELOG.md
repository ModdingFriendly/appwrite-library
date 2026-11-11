# Changelog

All notable changes to `github.com/ModdingFriendly/appwrite-library`.
Versions follow semantic versioning; functions pin a version in `go.mod`.

## v0.4.0 — scoped API keys package

Moves the scoped API-key management and machine-key verifier out of a single
Function so more than one Function can share it (the split plan's `core_admin`
and any machine-route consumer).

### Added

- **`apikeys` package** — create/list/rotate/revoke/usage management plus the
  bearer verifier. It is product-agnostic: callers inject an `Authorizer` and an
  `OrganizationLookup`, so tenant/role policy stays in the Function. Behaviour
  is unchanged from the previously internal copy: explicit scope allowlist,
  HMAC-SHA256 pepper (`REPARIX_API_KEY_PEPPER`), constant-time comparison,
  stored-row tenant authority, fail-closed 503 when the pepper is missing,
  per-key rate limits and metadata-only `api_logs` usage rows.

### Compatibility

- No existing package changed. Consumers that did not use the internal copy are
  unaffected.

## v0.3.2 — review fixes

Security and correctness fixes from the 2026-11-10 review. No behaviour change
for a caller that already passes explicit configuration and treats errors
generically; the one API change is `money.AbsMoney` (see **Changed**).

### Security

- **`appwrite`: redirects are rejected instead of followed.** The Appwrite SDK
  replays request headers on every hop, so a `3xx` from the endpoint (or from
  anything in front of it) forwarded `X-Appwrite-Key` and `X-Appwrite-JWT` to
  the redirect target. Requests are no longer replayed at all: a redirect is
  reported as a 502 `upstream_error` whose cause wraps
  `appwrite.ErrRedirectRejected`.
- **`appwrite`: HTTPS is required.** `NewClient`/`NewTables` reject a plain-HTTP
  endpoint with `ErrInvalidEndpoint`/`ErrInsecureEndpoint`. Loopback hosts
  (`localhost`, `*.localhost`, `127.0.0.0/8`, `::1`) are allowed for local
  development and `httptest`; a non-loopback HTTP host needs the explicit
  `Config.AllowInsecureHTTP` opt-in. TLS 1.2 is the minimum version, and the
  client no longer mutates the global default transport.
- **`appwrite`: upstream messages are no longer returned verbatim.** `MapError`
  maps each status to a stable public message and code (`MessageBadRequest`,
  `MessageNotFound`, …). The sanitised Appwrite detail (message plus error
  `type`) is kept on `httpx.Error.Detail`, which `httpx.Fail` logs privately and
  never serialises. The Appwrite error `type`, when it looks like a machine code,
  is exposed as the `reason` param.

### Fixed

- **`money`: full `int64` minor-unit range.** `Money.String` rendered
  `math.MinInt64` as `"GBP --92233720368547758.-8"`; it now uses an unsigned
  magnitude and renders `"GBP -92233720368547758.08"`. `ParseMoney` accepts the
  whole range (19 whole digits plus 9 fractional digits, rounded half-up) and
  rejects only values that genuinely do not fit, with `ErrMoneyOverflow`.
  Round-trips (`ParseMoney(FromMinorUnits(c, v).String()) == v`) now hold for
  every `int64` and every supported currency.
- **`money`: `SubMoney` computes exactly.** `SubMoney(MinInt64, MinInt64)` is
  `0` instead of a false overflow; overflow is only reported when the true
  result is outside `int64`.
- **`money`: `AbsMoney` reports an unrepresentable magnitude.** It now returns
  `(Money, error)` like `NegMoney` and yields `ErrMoneyOverflow` for
  `math.MinInt64` instead of silently staying negative.
- **`money`: bounded plain-decimal inputs.** `MulMoneyDecimal` and `MulMoneyRate`
  no longer use `big.Rat.SetString` (which accepted `"1/3"`, `"0x10"` and
  `"1e3"`). They use the new `ParseDecimal`, a bounded grammar (optional sign,
  up to 15 whole digits, up to 9 fractional digits, no surrounding whitespace)
  that rejects everything else with `ErrInvalidDecimal`, which wraps
  `ErrInvalidMoney`.
- **`httpx`: `Fail` cannot panic.** A nil error and a typed-nil `*httpx.Error`
  are logged and answered with the structured 500 instead of dereferencing nil.
  A domain error with a missing/invalid status falls back to 500.
- **`httpx`: serialisation is owned.** A response (or error params value) that
  cannot be marshalled now returns
  `500 {"error":"internal server error","code":"internal_error"}` with
  `content-type: application/json`, instead of the SDK's plain-text
  `"Error encoding JSON."`.

### Added

- `httpx.Error.Detail` (private diagnostic context, never serialised) and
  `httpx.Error.Cause` + `Unwrap` (so `errors.Is` still reaches transport
  conditions). `Unwrap` is nil-safe, as is `(*Error).Error()`.
- `money.Money.Validate`, `money.ParseDecimal`, `money.ErrInvalidDecimal`,
  `money.MaxDecimalIntegerDigits`, `money.MaxDecimalFractionDigits`,
  `money.MaxDecimalLength`.
- `appwrite.Config.AllowInsecureHTTP`, `appwrite.ErrInvalidEndpoint`,
  `appwrite.ErrInsecureEndpoint`, `appwrite.ErrRedirectRejected`,
  `appwrite.DefaultHTTPTimeout` (30 s, replacing the SDK's 10 s),
  `appwrite.MessageBadRequest` … `appwrite.MessageUpstream`.
- Boundary and property tests for money (all currencies, both `int64` extremes,
  negative rounding, decimal-input rejection) and redirect/credential-forwarding
  tests for the transport.

### Changed

- **Breaking:** `money.AbsMoney(m Money) Money` is now
  `money.AbsMoney(m Money) (Money, error)`, matching `NegMoney`. `math.MinInt64`
  has no positive `int64` counterpart, so the operation cannot be total.
- `appwrite.MapError` messages change from the raw Appwrite text to the stable
  `appwrite.Message*` strings; error codes and statuses are unchanged.
- `appwrite.ResponseFormat`, `appwrite.Client(ctx)` and `appwrite.Tables(ctx)`
  are marked `Deprecated:` in favour of `DefaultResponseFormat`,
  `NewClient(cfg)` and `NewTables(cfg)`.

### Documented

- `APPWRITE_RESPONSE_FORMAT` precedence:
  `Config.ResponseFormat` > `APPWRITE_RESPONSE_FORMAT` > `DefaultResponseFormat`.
- The library is transport, not tenancy: organisation filtering, row ACLs and
  server-owned columns are the consuming application's responsibility.

## v0.3.0

- New `money` package: canonical `"<ISO-4217> <amount>"` strings, integer minor
  units, `math/big.Rat` for fractional quantities, no float conversions.

## v0.2.0

- Explicit `appwrite.Config`, JWT/team membership `auth` lookup, `InTransaction`.
- Removed the built-in endpoint/project fallback from `appwrite.Client`.

## v0.1.0

- Typed handler contract (`httpx`) and Appwrite TablesDB access.

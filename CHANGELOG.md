# Changelog

All notable changes to `github.com/ModdingFriendly/appwrite-library`.
Versions follow semantic versioning; functions pin a version in `go.mod`.

## v0.11.0 — in-memory Appwrite and tenant isolation tests (PAR-1405)

### Added

- **`apptest` package** — an in-memory Appwrite server for unit tests:
  account/JWT, teams and memberships, users, TablesDB rows with queries,
  bulk operations and transactions, storage files, and message sends. Records
  every call and reports endpoints it does not implement.
- **`reparix/isolation` package** — schema-driven two-organisation fixture and
  `Run`, which proves per route that an org A caller can neither read nor
  change org B's data, that lists are filtered to the caller's organisation,
  and that a forged tenant header is refused; a same-tenant control request
  must succeed. `RequireCoverage` ties the cases to the route manifest.

### Compatibility

- Additive, test-only packages. No runtime package changed.

## v0.10.0 — organisation suspension and platform operators (PAR-1301)

### Added

- **`reparix/orgstatus` package** — `Require(store, teamID)` refuses a
  suspended organisation with `403 organization_suspended` and a deleted one
  (status `deleted` or `deleted_at` set) with `403 organization_closed`. Status
  comes from the `organizations` row by `team_id`; empty, unknown or missing
  means active. Each team's status is cached for 30 seconds in the warm runtime
  (`Default`), so a suspension applies within a minute. A failed read reuses the
  last known status, or returns `503 organization_status_unavailable`.
  `AppwriteStore` reads with the server key; `Checker.Forget` drops a cached team
  after a change.
- **`reparix/operator` package** — `Require(ctx, lookup)` verifies the caller's
  JWT and a confirmed membership of the platform operator team
  (`reparix-platform-operators`, or `REPARIX_OPERATOR_TEAM_ID`). Tenant roles,
  including admin and owner, are never operator authority; refusal is
  `403 operator_required`.

### Compatibility

- Additive. Nothing calls the new packages until a service opts in.

## v0.9.1 — caller display names on audit events

### Added

- **`auth.Identity.Name`** — the verified account's display name from
  `Account.Get()`. It is server-derived, never read from a header or body, so a
  caller cannot forge who they are.
- **`firehose.Caller.Name`** and `firehose.Event.ActorName` — the gateway event
  now records `actor_name` alongside `actor_user_id`, and leaves it absent when
  the caller has no name. The audit timeline shows who acted, not just an id.

### Compatibility

- Additive. Existing callers compile unchanged; events gain one optional field.

## Unreleased — bot challenge

### Added

- **`reparix/botcheck` package** — server-side verification of the bot challenge
  a browser solved before a guest write (PAR-1211a): `Config`, `FromEnv`,
  `Verify` and `Require`, for Cloudflare Turnstile and Google reCAPTCHA v3. It
  is switched off until a provider and secret are configured. A missing token is
  `400 bot_challenge_required`, a rejected one `403 bot_challenge_failed`, and an
  unreachable provider `503 bot_challenge_unavailable` (unless fail-open is set).

### Compatibility

- Additive. A service that uses it needs outbound HTTPS to the provider's
  siteverify host.

## v0.8.0 — plan limits

### Added

- **`reparix/plans` package** — server-side plan limits (PAR-1304): `Limits`,
  `Check`, `Enforce`, `MonthStart`, `AppwriteStore`, and the counters
  `TicketsThisMonth`, `SMSThisMonth` and `StoredMB`. A refusal is
  `402 plan_limit_reached` with the metric, usage, limit and plan in its params.
- **`appwrite.GreaterThanEqual`** query builder.

### Compatibility

- Additive. A service that enforces limits needs read access to
  `billing_accounts`, `plans` and the table its counter reads.

## v0.7.0 — scheduled jobs

### Added

- **`reparix/jobs` package** — the scheduled-job pattern for Reparix
  (PAR-1307a): `Runner` decides which jobs are due from the `job_runs` run log,
  bounds the work per organisation and the time per execution, resumes where a cut-short run
  stopped, isolates a failing organisation, and records each run. Also
  `AppwriteStore`, `Purge`, `Due`, `Order` and `Describe`.
- **`appwrite.LessThan`** query builder.

### Compatibility

- Additive. The consuming project needs the `job_runs` table.

## v0.6.0 — sealed secrets package

### Added

- **`reparix/sealed` package** — seals server-only secrets for storage:
  `ParseKey`, `KeyFromEnv`, `Seal`, `Open`, `SealJSON`, `OpenJSON`. It is the
  code Reparix had copied into `service-messaging` and `service-integrations`
  (PAR-1201b), with the same envelope and key mapping. Tests open values sealed
  by both copies, so stored credentials stay readable after the switch.

### Compatibility

- Additive.

## v0.5.1 — committed rows and bounded read retries

### Fixed

- **`reparix/firehose` `Create`/`Update` return the committed row.** Appwrite
  leaves `$sequence`, `$createdAt` and `$updatedAt` empty on a row written
  inside a transaction; they are only assigned at commit. Returning the staged
  row made every gateway mutation hand a client an "incomplete row", so a
  successful write surfaced as a failed request. The helpers now re-read the row
  after the transaction commits. The re-read is best effort: the write has
  already committed, so a failed read is logged and the staged row is returned
  rather than turning a successful mutation into an error.

### Added

- **Bounded retries for safe reads.** The hardened HTTP client retries `GET`
  and `HEAD` up to `DefaultRetryAttempts` (3) with exponential backoff on a
  transport failure (connection reset, EOF, DNS blip) and on the transient
  statuses 429/502/503/504. Mutations are never replayed: Appwrite cannot tell a
  retried create from a second one, so a POST still surfaces its error instead
  of risking duplicate rows.

### Compatibility

- Additive for callers. `Create`/`Update` now return complete rows, which is the
  shape the gateway contract already documented.

## v0.5.0 — firehose publisher package

### Added

- **`reparix/firehose` package** — the shared publisher side of the Reparix
  event firehose. Builds the event envelope, diffs a write into before/after
  `Change`s (text fields keep both values for a word diff; secrets such as
  passcodes, tokens, keys and signatures are recorded as changed without their
  values; values are capped at 20 000 characters), names events
  (`<entity>.created|updated|deleted`, or `.added|updated|removed` for child
  rows), derives entity refs (`customer:ID`, `purchase_order:ID`, ...) so a
  parent's log can include its children, and provides `Create`, `Update` and
  `Delete` helpers that write the business row and its `firehose_events` row in
  one TablesDB transaction. Verified caller identity is passed in; nothing is
  read from a request body.

### Compatibility

- Additive. No existing package changed.

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

// Package money is shared exact-money arithmetic for Appwrite services.
//
// # Storage format
//
// Every monetary value is persisted as the canonical string
//
//	<ISO-4217 code> <amount>
//
// for example "GBP 1.00", "GBP 0.05", "GBP -3.50" (refund or cash variance) or
// "EUR 99.99". The currency code is uppercase, the amount always carries the
// currency's fixed number of decimals, and no thousands separators, currency
// symbols or surrounding whitespace are allowed. ParseMoney accepts that form
// (plus a short form such as "GBP 1.5" when it is unambiguous) and String
// renders the canonical form.
//
// # Why floats are banned
//
// 0.1 + 0.2 != 0.3. Invoice balances, POS change and cash variance must not
// drift, and a float64 loses precision as soon as it is round-tripped through
// JSON, a database or a provider response. Amounts are therefore held in
// integer minor units (pence for GBP) in Money.Minor, and fractional
// quantities or rates use math/big.Rat. There is deliberately no
// float-to-Money conversion in this package: a provider number must be parsed
// from its decimal string with MoneyFromDecimalString.
//
// # Supported range
//
// The full int64 range of minor units is supported, including both boundaries
// (-9223372036854775808 and 9223372036854775807). For GBP that is
// "-92233720368547758.08" .. "92233720368547758.07", at most 25 characters, so
// the varchar(32) storage columns are wide enough for every value. ParseMoney
// and String are exact inverses across that range; a value outside it is
// rejected with ErrMoneyOverflow rather than silently wrapping.
//
// Arithmetic follows the same rule: it computes in big.Int and returns
// ErrMoneyOverflow only when the true result does not fit in int64, so
// SubMoney(math.MinInt64, math.MinInt64) is 0. The one operation that cannot be
// total is sign flipping: NegMoney and AbsMoney report ErrMoneyOverflow for
// math.MinInt64 because +9223372036854775808 has no int64 representation.
//
// # Supported currencies
//
// GBP, EUR, USD, CHF, AUD and CAD have two decimal places; JPY has none. Any
// other code is rejected with ErrInvalidMoney rather than silently assumed to
// have two decimals.
//
// # Storage columns
//
// Appwrite money columns are varchar(32) and hold the canonical string as-is
// (total, amount, unit_price, line_total, subtotal, tax_amount, cost,
// deposit_amount, hourly_rate, opening_float, cash_difference, ...). The size
// is enough for the largest supported amount including the currency prefix, so
// queries, exports and row shapes stay stable across services.
package money

import (
	"errors"
	"fmt"
	"math"
	"math/big"
	"regexp"
	"strconv"
	"strings"
)

// Money is an exact monetary amount held in minor units (pence for GBP).
//
// The zero value is not a valid amount: it has no currency. Prefer the
// constructors (ParseMoney, FromMinorUnits, MoneyFromDecimalString) and use
// Validate when a value arrives from storage or an untyped source.
type Money struct {
	Currency string
	Minor    int64
}

var (
	// ErrInvalidMoney is returned for anything that is not a canonical money
	// string, including an unsupported currency. Handlers translate it into a
	// 400 response.
	ErrInvalidMoney = errors.New("invalid money value")
	// ErrCurrencyMismatch prevents silently adding GBP to USD.
	ErrCurrencyMismatch = errors.New("currency mismatch")
	// ErrMoneyOverflow guards int64 arithmetic and parsing.
	ErrMoneyOverflow = errors.New("money amount overflow")
	// ErrInvalidDecimal rejects the plain-decimal inputs of MulMoneyDecimal and
	// MulMoneyRate (for example "1/3", "0x10" or "1e3"). It wraps
	// ErrInvalidMoney so existing errors.Is checks keep working.
	ErrInvalidDecimal = fmt.Errorf("%w: not a plain decimal", ErrInvalidMoney)
)

// moneyPattern bounds the canonical form. The whole part allows up to 19
// digits (enough for int64) with no leading zeros; the fraction allows up to 9
// digits and is rounded half-up to the currency exponent. Longer inputs are
// rejected before any arithmetic, which keeps parsing allocation-bounded.
var moneyPattern = regexp.MustCompile(`^([A-Z]{3}) (-?(?:0|[1-9][0-9]{0,18}))(?:\.([0-9]{1,9}))?$`)

// currencyExponent is the number of decimal places stored per ISO 4217 code.
var currencyExponent = map[string]int32{
	"GBP": 2,
	"EUR": 2,
	"USD": 2,
	"CHF": 2,
	"AUD": 2,
	"CAD": 2,
	"JPY": 0,
}

func currencyExponentFor(code string) (int32, error) {
	if exponent, ok := currencyExponent[code]; ok {
		return exponent, nil
	}
	return 0, fmt.Errorf("%w: unsupported currency %q", ErrInvalidMoney, code)
}

// Validate reports whether m is a usable amount: it must carry one of the
// supported currency codes. It does not restrict the minor-unit range, which
// covers the whole int64 domain. The zero Money value is invalid because it has
// no currency.
func (m Money) Validate() error {
	if _, err := currencyExponentFor(m.Currency); err != nil {
		return err
	}
	return nil
}

// ParseMoney strictly parses a stored money string. Trailing whitespace is not
// accepted; clients must send the canonical form. The whole int64 range of
// minor units is accepted, so ParseMoney(FromMinorUnits(c, v).String()) == v for
// every v in int64 and every supported currency.
func ParseMoney(raw string) (Money, error) {
	match := moneyPattern.FindStringSubmatch(raw)
	if match == nil {
		return Money{}, fmt.Errorf("%w: %q is not a canonical amount", ErrInvalidMoney, raw)
	}
	code := match[1]
	exponent, err := currencyExponentFor(code)
	if err != nil {
		return Money{}, err
	}
	negative := strings.HasPrefix(match[2], "-")
	magnitude := minorUnitsFromDigits(strings.TrimPrefix(match[2], "-"), match[3], exponent)
	if negative {
		magnitude.Neg(magnitude)
	}
	if !magnitude.IsInt64() {
		return Money{}, fmt.Errorf("%w: %q is outside the supported range", ErrMoneyOverflow, raw)
	}
	return Money{Currency: code, Minor: magnitude.Int64()}, nil
}

// MustParseMoney is for constants in tests and defaults only.
func MustParseMoney(raw string) Money {
	money, err := ParseMoney(raw)
	if err != nil {
		panic(err)
	}
	return money
}

// ParseMoneyValue accepts a decoded JSON string only. JSON numbers are
// rejected so a float can never sneak into the ledger.
func ParseMoneyValue(value any) (Money, error) {
	text, ok := value.(string)
	if !ok {
		return Money{}, fmt.Errorf("%w: expected a string, got %T", ErrInvalidMoney, value)
	}
	return ParseMoney(text)
}

// minorUnitsFromDigits converts whole and fractional digits into an unsigned
// magnitude of minor units, rounding half-up on the first digit beyond the
// currency exponent. The result may exceed int64 (that is checked by the
// caller after the sign is applied) so math.MinInt64 can be parsed.
func minorUnitsFromDigits(whole, fraction string, exponent int32) *big.Int {
	// Pad the fraction so the digit at the exponent boundary exists.
	padded := fraction
	for int32(len(padded)) <= exponent {
		padded += "0"
	}
	kept := padded[:exponent]
	dropped := padded[exponent] - '0'

	digits := whole + kept
	value, ok := new(big.Int).SetString(digits, 10)
	if !ok {
		// Unreachable: the caller's regex has already validated the digits.
		// Returning nil would panic on the caller's Neg/IsInt64, so fall back to
		// a zero that the range check will accept as 0.00.
		return new(big.Int)
	}
	if dropped >= 5 {
		value.Add(value, big.NewInt(1))
	}
	return value
}

// String renders the canonical storage form. It is exact for the full int64
// range, including math.MinInt64, whose magnitude does not fit in int64; the
// magnitude is therefore rendered as a uint64.
func (m Money) String() string {
	code := m.Currency
	exponent, ok := currencyExponent[code]
	if !ok {
		// Legacy behaviour kept for callers that build Money{Minor: ...}
		// without a currency: render the package default rather than a broken
		// string. Validate rejects such a value.
		if code == "" {
			code = "GBP"
		}
		exponent = 2
	}

	scale := uint64(1)
	for index := int32(0); index < exponent; index++ {
		scale *= 10
	}

	magnitude := absUint64(m.Minor)
	whole := magnitude / scale
	sign := ""
	if m.Minor < 0 {
		sign = "-"
	}
	if exponent == 0 {
		return code + " " + sign + strconv.FormatUint(whole, 10)
	}
	fraction := strconv.FormatUint(magnitude%scale, 10)
	if pad := int(exponent) - len(fraction); pad > 0 {
		fraction = strings.Repeat("0", pad) + fraction
	}
	return code + " " + sign + strconv.FormatUint(whole, 10) + "." + fraction
}

// absUint64 returns |value| as a uint64, correct for math.MinInt64.
func absUint64(value int64) uint64 {
	if value < 0 {
		return uint64(-(value + 1)) + 1
	}
	return uint64(value)
}

// IsZero reports whether the amount is exactly zero.
func (m Money) IsZero() bool { return m.Minor == 0 }

// IsNegative reports whether the amount is below zero (refunds, variance).
func (m Money) IsNegative() bool { return m.Minor < 0 }

// MinorUnits returns the amount in the currency's smallest unit: pence for GBP,
// whole yen for JPY, and so on. It exists so callers never re-derive the scale
// themselves and never need a float to compare or persist an amount. The value
// is only meaningful together with Currency, which is why it is not named
// "Amount" or "Value"; pair it with FormatMoney to get a canonical string, or
// use FromMinorUnits for the reverse direction.
func (m Money) MinorUnits() int64 { return m.Minor }

// FromMinorUnits builds a Money from an integer minor-unit amount after
// validating the currency. It is the safe boundary for values that arrive as
// integers (cents-style provider payloads, cash drawer totals, ledger rows);
// amounts that arrive as decimals must use MoneyFromDecimalString instead so
// no float64 is involved. An unsupported currency returns ErrInvalidMoney.
// Every int64 value is accepted, including math.MinInt64.
func FromMinorUnits(currency string, minor int64) (Money, error) {
	if _, err := currencyExponentFor(currency); err != nil {
		return Money{}, err
	}
	return Money{Currency: currency, Minor: minor}, nil
}

// AddMoney adds two amounts of the same currency.
func AddMoney(a, b Money) (Money, error) {
	if a.Currency != b.Currency {
		return Money{}, ErrCurrencyMismatch
	}
	sum, ok := addInt64(a.Minor, b.Minor)
	if !ok {
		return Money{}, ErrMoneyOverflow
	}
	return Money{Currency: a.Currency, Minor: sum}, nil
}

// SubMoney subtracts b from a. The result is computed exactly, so
// SubMoney(x, x) is 0 for every x (including math.MinInt64) and the only error
// is a true out-of-range result.
func SubMoney(a, b Money) (Money, error) {
	if a.Currency != b.Currency {
		return Money{}, ErrCurrencyMismatch
	}
	difference := new(big.Int).Sub(big.NewInt(a.Minor), big.NewInt(b.Minor))
	if !difference.IsInt64() {
		return Money{}, ErrMoneyOverflow
	}
	return Money{Currency: a.Currency, Minor: difference.Int64()}, nil
}

// SumMoney totals a slice; the first currency wins and mismatches error.
func SumMoney(values ...Money) (Money, error) {
	total := Money{Currency: "GBP"}
	for index, value := range values {
		if index == 0 {
			total = Money{Currency: value.Currency}
		}
		next, err := AddMoney(total, value)
		if err != nil {
			return Money{}, err
		}
		total = next
	}
	return total, nil
}

// MulMoneyQuantity multiplies by an integer quantity (stock lines, POS).
func MulMoneyQuantity(m Money, quantity int64) (Money, error) {
	product := new(big.Int).Mul(big.NewInt(m.Minor), big.NewInt(quantity))
	if !product.IsInt64() {
		return Money{}, ErrMoneyOverflow
	}
	return Money{Currency: m.Currency, Minor: product.Int64()}, nil
}

// MulMoneyDecimal multiplies by a fractional quantity (quote lines). The
// quantity must be a bounded plain decimal such as "0.5", "-1.25" or "12"; see
// ParseDecimal for the exact grammar. Fractional exponents ("1e3"), fractions
// ("1/3"), hex ("0x10") and surrounding whitespace are rejected with
// ErrInvalidDecimal. The result is rounded half-up to the currency's minor
// unit, ties away from zero.
func MulMoneyDecimal(m Money, quantity string) (Money, error) {
	ratio, err := ParseDecimal(quantity)
	if err != nil {
		return Money{}, err
	}
	product := new(big.Rat).Mul(new(big.Rat).SetInt64(m.Minor), ratio)
	return roundToMoney(m.Currency, product)
}

// MulMoneyRate multiplies by a rate such as a tax percentage (7.5 => 7.5%).
// The rate follows the same plain-decimal grammar as MulMoneyDecimal.
func MulMoneyRate(m Money, percent string) (Money, error) {
	ratio, err := ParseDecimal(percent)
	if err != nil {
		return Money{}, err
	}
	product := new(big.Rat).Mul(new(big.Rat).SetInt64(m.Minor), ratio)
	product.Quo(product, big.NewRat(100, 1))
	return roundToMoney(m.Currency, product)
}

// roundToMoney rounds a rational minor-unit amount half-up and range-checks it.
func roundToMoney(currency string, value *big.Rat) (Money, error) {
	rounded := roundRatHalfUp(value)
	if !rounded.IsInt64() {
		return Money{}, ErrMoneyOverflow
	}
	return Money{Currency: currency, Minor: rounded.Int64()}, nil
}

// NegMoney flips the sign (used for refunds and cash variance). It reports
// ErrMoneyOverflow for math.MinInt64, whose positive counterpart is not
// representable.
func NegMoney(m Money) (Money, error) {
	if m.Minor == math.MinInt64 {
		return Money{}, ErrMoneyOverflow
	}
	return Money{Currency: m.Currency, Minor: -m.Minor}, nil
}

// AbsMoney returns the absolute amount. It reports ErrMoneyOverflow for
// math.MinInt64 because +9223372036854775808 has no int64 representation;
// callers that only need a magnitude should treat that as an out-of-range
// amount rather than as zero.
func AbsMoney(m Money) (Money, error) {
	if m.Minor >= 0 {
		return m, nil
	}
	if m.Minor == math.MinInt64 {
		return Money{}, ErrMoneyOverflow
	}
	return Money{Currency: m.Currency, Minor: -m.Minor}, nil
}

// CmpMoney returns -1, 0 or 1 comparing a to b; mismatched currencies error.
func CmpMoney(a, b Money) (int, error) {
	if a.Currency != b.Currency {
		return 0, ErrCurrencyMismatch
	}
	switch {
	case a.Minor < b.Minor:
		return -1, nil
	case a.Minor > b.Minor:
		return 1, nil
	default:
		return 0, nil
	}
}

// roundRatHalfUp rounds to the nearest integer, ties away from zero.
func roundRatHalfUp(value *big.Rat) *big.Int {
	numerator := new(big.Int).Set(value.Num())
	denominator := new(big.Int).Set(value.Denom())
	if denominator.Sign() < 0 {
		numerator.Neg(numerator)
		denominator.Neg(denominator)
	}
	negative := numerator.Sign() < 0
	if negative {
		numerator.Neg(numerator)
	}
	quotient := new(big.Int)
	remainder := new(big.Int)
	quotient.QuoRem(numerator, denominator, remainder)
	if new(big.Int).Lsh(remainder, 1).Cmp(denominator) >= 0 {
		quotient.Add(quotient, big.NewInt(1))
	}
	if negative {
		quotient.Neg(quotient)
	}
	return quotient
}

// FormatMoney builds a canonical string from minor units in a currency.
func FormatMoney(currency string, minor int64) (string, error) {
	if _, err := currencyExponentFor(currency); err != nil {
		return "", err
	}
	return Money{Currency: currency, Minor: minor}.String(), nil
}

// MoneyFromDecimalString parses a plain decimal (e.g. a provider amount) and
// scales it to minor units without going through float64. Surrounding
// whitespace is tolerated because provider payloads often carry it; everything
// else follows ParseMoney, so the value must fit the supported range and the
// currency must be supported.
func MoneyFromDecimalString(currency, amount string) (Money, error) {
	amount = strings.TrimSpace(amount)
	if amount == "" {
		return Money{}, fmt.Errorf("%w: amount is empty", ErrInvalidMoney)
	}
	return ParseMoney(currency + " " + amount)
}

func addInt64(a, b int64) (int64, bool) {
	sum := a + b
	if (b > 0 && sum < a) || (b < 0 && sum > a) {
		return 0, false
	}
	return sum, true
}

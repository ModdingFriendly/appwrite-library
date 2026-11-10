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
	"math/big"
	"regexp"
	"strconv"
	"strings"
)

// Money is an exact monetary amount held in minor units (pence for GBP).
type Money struct {
	Currency string
	Minor    int64
}

var (
	// ErrInvalidMoney is returned for anything that is not a canonical money
	// string. Handlers translate it into a 400 response.
	ErrInvalidMoney = errors.New("invalid money value")
	// ErrCurrencyMismatch prevents silently adding GBP to USD.
	ErrCurrencyMismatch = errors.New("currency mismatch")
	// ErrMoneyOverflow guards int64 arithmetic.
	ErrMoneyOverflow = errors.New("money amount overflow")

	moneyPattern = regexp.MustCompile(`^([A-Z]{3}) (-?(?:0|[1-9][0-9]{0,15}))(?:\.([0-9]{1,3}))?$`)
)

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

// ParseMoney strictly parses a stored money string. Trailing whitespace is not
// accepted; clients must send the canonical form.
func ParseMoney(raw string) (Money, error) {
	match := moneyPattern.FindStringSubmatch(raw)
	if match == nil {
		return Money{}, ErrInvalidMoney
	}
	code := match[1]
	exponent, err := currencyExponentFor(code)
	if err != nil {
		return Money{}, err
	}
	negative := strings.HasPrefix(match[2], "-")
	magnitude := strings.TrimPrefix(match[2], "-")
	whole, err := strconv.ParseInt(magnitude, 10, 64)
	if err != nil {
		return Money{}, ErrMoneyOverflow
	}
	minor, ok := scaleToMinor(whole, match[3], exponent)
	if !ok {
		return Money{}, ErrMoneyOverflow
	}
	if negative {
		minor = -minor
	}
	return Money{Currency: code, Minor: minor}, nil
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
		return Money{}, ErrInvalidMoney
	}
	return ParseMoney(text)
}

// scaleToMinor converts whole+fractional digits to minor units with half-up
// rounding. Fractional digits beyond the currency exponent are rounded.
func scaleToMinor(whole int64, fraction string, exponent int32) (int64, bool) {
	sign := int64(1)
	if whole < 0 {
		sign = -1
		whole = -whole
	}
	// Pad or truncate the fraction to the exponent, rounding half-up on the
	// first dropped digit.
	var kept, dropped int64
	for index := int32(0); index < int32(len(fraction)) || index < exponent; index++ {
		digit := int64(0)
		if int(index) < len(fraction) {
			digit = int64(fraction[index] - '0')
		}
		if index < exponent {
			kept = kept*10 + digit
			continue
		}
		if index == exponent {
			dropped = digit
		}
	}
	// Half-up: a dropped digit of 5 or more rounds away from zero.
	if dropped >= 5 {
		kept++
	}
	scale := int64(1)
	for index := int32(0); index < exponent; index++ {
		scale *= 10
	}
	if whole > (int64(^uint64(0)>>1))/scale {
		return 0, false
	}
	return sign * (whole*scale + kept), true
}

// String renders the canonical storage form.
func (m Money) String() string {
	exponent := int32(2)
	if value, ok := currencyExponent[m.Currency]; ok {
		exponent = value
	} else if m.Currency == "" {
		m.Currency = "GBP"
	}
	scale := int64(1)
	for index := int32(0); index < exponent; index++ {
		scale *= 10
	}
	negative := m.Minor < 0
	minor := m.Minor
	if negative {
		minor = -minor
	}
	whole := minor / scale
	sign := ""
	if negative {
		sign = "-"
	}
	if exponent == 0 {
		return fmt.Sprintf("%s %s%d", m.Currency, sign, whole)
	}
	fraction := minor % scale
	return fmt.Sprintf("%s %s%d.%0*d", m.Currency, sign, whole, int(exponent), fraction)
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

// SubMoney subtracts b from a.
func SubMoney(a, b Money) (Money, error) {
	if a.Currency != b.Currency {
		return Money{}, ErrCurrencyMismatch
	}
	if b.Minor == -9223372036854775808 {
		return Money{}, ErrMoneyOverflow
	}
	return AddMoney(a, Money{Currency: b.Currency, Minor: -b.Minor})
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
// quantity arrives as a decimal string; the result is rounded half-up to the
// currency's minor unit.
func MulMoneyDecimal(m Money, quantity string) (Money, error) {
	ratio, ok := new(big.Rat).SetString(quantity)
	if !ok || ratio == nil {
		return Money{}, ErrInvalidMoney
	}
	product := new(big.Rat).Mul(new(big.Rat).SetInt64(m.Minor), ratio)
	rounded := roundRatHalfUp(product)
	if !rounded.IsInt64() {
		return Money{}, ErrMoneyOverflow
	}
	return Money{Currency: m.Currency, Minor: rounded.Int64()}, nil
}

// MulMoneyRate multiplies by a rate such as a tax percentage (7.5 => 7.5%).
func MulMoneyRate(m Money, percent string) (Money, error) {
	ratio, ok := new(big.Rat).SetString(percent)
	if !ok || ratio == nil {
		return Money{}, ErrInvalidMoney
	}
	product := new(big.Rat).Mul(new(big.Rat).SetInt64(m.Minor), ratio)
	product.Quo(product, big.NewRat(100, 1))
	rounded := roundRatHalfUp(product)
	if !rounded.IsInt64() {
		return Money{}, ErrMoneyOverflow
	}
	return Money{Currency: m.Currency, Minor: rounded.Int64()}, nil
}

// NegMoney flips the sign (used for refunds and cash variance).
func NegMoney(m Money) (Money, error) {
	if m.Minor == -9223372036854775808 {
		return Money{}, ErrMoneyOverflow
	}
	return Money{Currency: m.Currency, Minor: -m.Minor}, nil
}

// AbsMoney returns the absolute amount.
func AbsMoney(m Money) Money {
	if m.Minor < 0 {
		return Money{Currency: m.Currency, Minor: -m.Minor}
	}
	return m
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
// scales it to minor units without going through float64.
func MoneyFromDecimalString(currency, amount string) (Money, error) {
	amount = strings.TrimSpace(amount)
	if amount == "" {
		return Money{}, ErrInvalidMoney
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

package money

import (
	"fmt"
	"math/big"
	"regexp"
	"strings"
)

// Bounds for the plain-decimal inputs accepted by MulMoneyDecimal, MulMoneyRate
// and ParseDecimal. They keep parsing bounded and are wide enough for every
// quantity, percentage or rate a repair shop quote uses.
const (
	// MaxDecimalIntegerDigits is the largest number of whole digits (no leading
	// zeros, except for the value 0 itself).
	MaxDecimalIntegerDigits = 15
	// MaxDecimalFractionDigits is the largest number of fractional digits.
	MaxDecimalFractionDigits = 9
	// MaxDecimalLength is the longest accepted string: sign, integer part,
	// decimal point and fraction.
	MaxDecimalLength = 1 + MaxDecimalIntegerDigits + 1 + MaxDecimalFractionDigits
)

// decimalPattern is a bounded plain decimal: an optional sign, a whole part
// without leading zeros, and an optional fraction. big.Rat.SetString would
// otherwise accept fractions ("1/3"), hex ("0x10") and exponents ("1e3"), all
// of which would silently change the meaning of a quote quantity or tax rate.
var decimalPattern = regexp.MustCompile(
	fmt.Sprintf(`^[+-]?(?:0|[1-9][0-9]{0,%d})(?:\.[0-9]{1,%d})?$`,
		MaxDecimalIntegerDigits-1, MaxDecimalFractionDigits))

// ParseDecimal parses a bounded plain decimal into an exact rational.
//
// Accepted: "0", "12", "-1.25", "+0.5", "0.000000001". Rejected (with
// ErrInvalidDecimal, which wraps ErrInvalidMoney): fractions such as "1/3",
// hexadecimal such as "0x10", exponents such as "1e3", leading or trailing
// whitespace, a bare "." or ".5", and anything longer than MaxDecimalLength or
// with more than MaxDecimalFractionDigits fractional digits.
func ParseDecimal(raw string) (*big.Rat, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("%w: empty value", ErrInvalidDecimal)
	}
	if len(raw) > MaxDecimalLength {
		return nil, fmt.Errorf("%w: %q is longer than %d characters", ErrInvalidDecimal, raw, MaxDecimalLength)
	}
	if !decimalPattern.MatchString(raw) {
		return nil, fmt.Errorf("%w: %q", ErrInvalidDecimal, raw)
	}

	digits := raw
	negative := false
	switch digits[0] {
	case '-':
		negative = true
		digits = digits[1:]
	case '+':
		digits = digits[1:]
	}

	whole, fraction := digits, ""
	if point := strings.IndexByte(digits, '.'); point >= 0 {
		whole, fraction = digits[:point], digits[point+1:]
	}

	numerator := new(big.Int)
	// The regex guarantees digits only, so SetString cannot fail.
	numerator.SetString(whole+fraction, 10)
	if negative {
		numerator.Neg(numerator)
	}
	denominator := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(len(fraction))), nil)
	return new(big.Rat).SetFrac(numerator, denominator), nil
}

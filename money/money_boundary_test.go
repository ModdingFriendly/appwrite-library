package money

import (
	"errors"
	"math"
	"math/rand"
	"testing"
)

// currencies is the supported set, used by the boundary and property tests.
var currencies = []string{"GBP", "EUR", "USD", "CHF", "AUD", "CAD", "JPY"}

// TestStringBoundaries pins the extremes of the int64 minor-unit range. The
// MinInt64 case is the one that used to render as "GBP --92233720368547758.-8".
func TestStringBoundaries(t *testing.T) {
	cases := []struct {
		currency string
		minor    int64
		want     string
	}{
		{"GBP", 0, "GBP 0.00"},
		{"GBP", 1, "GBP 0.01"},
		{"GBP", -1, "GBP -0.01"},
		{"GBP", 100, "GBP 1.00"},
		{"GBP", math.MaxInt64, "GBP 92233720368547758.07"},
		{"GBP", math.MinInt64, "GBP -92233720368547758.08"},
		{"JPY", math.MaxInt64, "JPY 9223372036854775807"},
		{"JPY", math.MinInt64, "JPY -9223372036854775808"},
		{"EUR", -5, "EUR -0.05"},
	}
	for _, tc := range cases {
		money, err := FromMinorUnits(tc.currency, tc.minor)
		if err != nil {
			t.Fatalf("FromMinorUnits(%s, %d): %v", tc.currency, tc.minor, err)
		}
		if got := money.String(); got != tc.want {
			t.Errorf("FromMinorUnits(%s, %d).String() = %q, want %q", tc.currency, tc.minor, got, tc.want)
		}
		// Every rendered boundary value must parse back to the same amount.
		round, err := ParseMoney(tc.want)
		if err != nil {
			t.Fatalf("ParseMoney(%q): %v", tc.want, err)
		}
		if round.Minor != tc.minor || round.Currency != tc.currency {
			t.Errorf("ParseMoney(%q) = %+v, want %s %d", tc.want, round, tc.currency, tc.minor)
		}
	}
}

// TestFormatMoneyBoundaries proves FormatMoney and ParseMoney agree at the
// edges, including the largest storable string for each currency.
func TestFormatMoneyBoundaries(t *testing.T) {
	for _, currency := range currencies {
		for _, minor := range []int64{math.MinInt64, math.MinInt64 + 1, -1, 0, 1, math.MaxInt64 - 1, math.MaxInt64} {
			formatted, err := FormatMoney(currency, minor)
			if err != nil {
				t.Fatalf("FormatMoney(%s, %d): %v", currency, minor, err)
			}
			if len(formatted) > 32 {
				t.Errorf("FormatMoney(%s, %d) = %q is longer than the varchar(32) column", currency, minor, formatted)
			}
			parsed, err := ParseMoney(formatted)
			if err != nil {
				t.Fatalf("ParseMoney(%q): %v", formatted, err)
			}
			if parsed.Minor != minor {
				t.Errorf("ParseMoney(FormatMoney(%s, %d)) = %d", currency, minor, parsed.Minor)
			}
		}
	}
}

func TestParseMoneyRangeBoundaries(t *testing.T) {
	accepted := map[string]int64{
		"GBP 92233720368547758.07":  math.MaxInt64,
		"GBP -92233720368547758.08": math.MinInt64,
		"JPY 9223372036854775807":   math.MaxInt64,
		"JPY -9223372036854775808":  math.MinInt64,
	}
	for input, want := range accepted {
		money, err := ParseMoney(input)
		if err != nil {
			t.Fatalf("ParseMoney(%q): %v", input, err)
		}
		if money.Minor != want {
			t.Errorf("ParseMoney(%q).Minor = %d, want %d", input, money.Minor, want)
		}
	}

	rejected := []string{
		"GBP 92233720368547758.08",    // MaxInt64 + 0.01
		"GBP -92233720368547758.09",   // MinInt64 - 0.01
		"JPY 9223372036854775808",     // MaxInt64 + 1
		"JPY -9223372036854775809",    // MinInt64 - 1
		"GBP 9223372036854775807",     // 19 whole digits scaled by 100
		"GBP 999999999999999999999",   // far beyond int64
		"GBP 00000000000000000000000", // leading zeros are not canonical
	}
	for _, input := range rejected {
		if _, err := ParseMoney(input); !errors.Is(err, ErrMoneyOverflow) && !errors.Is(err, ErrInvalidMoney) {
			t.Errorf("ParseMoney(%q) error = %v, want a range or format error", input, err)
		}
	}
}

// TestMoneyRoundTripProperty checks FromMinorUnits -> String -> ParseMoney for a
// wide spread of values in every supported currency.
func TestMoneyRoundTripProperty(t *testing.T) {
	source := rand.New(rand.NewSource(20261110))
	values := []int64{
		math.MinInt64, math.MinInt64 + 1, math.MinInt64 + 3,
		-1001, -1000, -101, -100, -99, -5, -1, 0, 1, 5, 99, 100, 101,
		1000, 1001, math.MaxInt64 - 3, math.MaxInt64 - 1, math.MaxInt64,
	}
	for index := 0; index < 2000; index++ {
		values = append(values, int64(source.Uint64()))
	}
	for _, currency := range currencies {
		for _, minor := range values {
			money, err := FromMinorUnits(currency, minor)
			if err != nil {
				t.Fatalf("FromMinorUnits(%s, %d): %v", currency, minor, err)
			}
			parsed, err := ParseMoney(money.String())
			if err != nil {
				t.Fatalf("ParseMoney(%q): %v", money.String(), err)
			}
			if parsed.Minor != minor || parsed.Currency != currency {
				t.Fatalf("round trip %s %d -> %q -> %+v", currency, minor, money.String(), parsed)
			}
			if again := parsed.String(); again != money.String() {
				t.Fatalf("string round trip %q -> %q", money.String(), again)
			}
		}
	}
}

// TestArithmeticProperty checks that add/subtract are exact inverses whenever the
// true result fits, and that a true overflow is reported instead of wrapping.
func TestArithmeticProperty(t *testing.T) {
	source := rand.New(rand.NewSource(424242))
	for index := 0; index < 1000; index++ {
		a := int64(source.Uint64())
		b := int64(source.Uint64())
		left := Money{Currency: "GBP", Minor: a}
		right := Money{Currency: "GBP", Minor: b}

		sum, err := AddMoney(left, right)
		if err != nil {
			if !errors.Is(err, ErrMoneyOverflow) {
				t.Fatalf("AddMoney(%d, %d): %v", a, b, err)
			}
			continue
		}
		back, err := SubMoney(sum, right)
		if err != nil {
			t.Fatalf("SubMoney(%d, %d): %v", sum.Minor, b, err)
		}
		if back.Minor != a {
			t.Fatalf("%d + %d - %d = %d", a, b, b, back.Minor)
		}
	}
}

func TestSubMoneyBoundaries(t *testing.T) {
	min := Money{Currency: "GBP", Minor: math.MinInt64}
	max := Money{Currency: "GBP", Minor: math.MaxInt64}

	// MinInt64 - MinInt64 is 0, not an overflow. This used to report overflow
	// because the implementation negated MinInt64 to add it.
	zero, err := SubMoney(min, min)
	if err != nil || zero.Minor != 0 {
		t.Fatalf("SubMoney(MinInt64, MinInt64) = %+v, %v", zero, err)
	}

	if _, err := SubMoney(min, Money{Currency: "GBP", Minor: 1}); !errors.Is(err, ErrMoneyOverflow) {
		t.Fatalf("SubMoney(MinInt64, 1) error = %v, want overflow", err)
	}
	if _, err := SubMoney(max, Money{Currency: "GBP", Minor: -1}); !errors.Is(err, ErrMoneyOverflow) {
		t.Fatalf("SubMoney(MaxInt64, -1) error = %v, want overflow", err)
	}
	if _, err := SubMoney(min, max); !errors.Is(err, ErrMoneyOverflow) {
		t.Fatalf("SubMoney(MinInt64, MaxInt64) error = %v, want overflow", err)
	}
	// Zero minus MinInt64 is not representable.
	if _, err := SubMoney(Money{Currency: "GBP"}, min); !errors.Is(err, ErrMoneyOverflow) {
		t.Fatalf("SubMoney(0, MinInt64) error = %v, want overflow", err)
	}
	// MinInt64 minus zero is exact.
	unchanged, err := SubMoney(min, Money{Currency: "GBP"})
	if err != nil || unchanged.Minor != math.MinInt64 {
		t.Fatalf("SubMoney(MinInt64, 0) = %+v, %v", unchanged, err)
	}
	if _, err := SubMoney(min, Money{Currency: "EUR", Minor: 0}); !errors.Is(err, ErrCurrencyMismatch) {
		t.Fatalf("expected currency mismatch, got %v", err)
	}
}

func TestAbsAndNegBoundaries(t *testing.T) {
	if _, err := AbsMoney(Money{Currency: "GBP", Minor: math.MinInt64}); !errors.Is(err, ErrMoneyOverflow) {
		t.Fatalf("AbsMoney(MinInt64) error = %v, want overflow", err)
	}
	if _, err := NegMoney(Money{Currency: "GBP", Minor: math.MinInt64}); !errors.Is(err, ErrMoneyOverflow) {
		t.Fatalf("NegMoney(MinInt64) error = %v, want overflow", err)
	}

	cases := map[int64]int64{math.MaxInt64: math.MaxInt64, -1: 1, 0: 0, 1: 1, math.MinInt64 + 1: math.MaxInt64}
	for input, want := range cases {
		absolute, err := AbsMoney(Money{Currency: "GBP", Minor: input})
		if err != nil || absolute.Minor != want {
			t.Errorf("AbsMoney(%d) = %d, %v; want %d", input, absolute.Minor, err, want)
		}
	}
}

func TestMulMoneyBoundaries(t *testing.T) {
	max := Money{Currency: "GBP", Minor: math.MaxInt64}
	min := Money{Currency: "GBP", Minor: math.MinInt64}

	if got, err := MulMoneyQuantity(max, 1); err != nil || got.Minor != math.MaxInt64 {
		t.Fatalf("MulMoneyQuantity(MaxInt64, 1) = %+v, %v", got, err)
	}
	if got, err := MulMoneyQuantity(min, 1); err != nil || got.Minor != math.MinInt64 {
		t.Fatalf("MulMoneyQuantity(MinInt64, 1) = %+v, %v", got, err)
	}
	if _, err := MulMoneyQuantity(max, 2); !errors.Is(err, ErrMoneyOverflow) {
		t.Fatalf("MulMoneyQuantity(MaxInt64, 2) error = %v, want overflow", err)
	}
	if _, err := MulMoneyQuantity(min, -1); !errors.Is(err, ErrMoneyOverflow) {
		t.Fatalf("MulMoneyQuantity(MinInt64, -1) error = %v, want overflow", err)
	}
	if got, err := MulMoneyQuantity(Money{Currency: "GBP", Minor: 0}, -5); err != nil || got.Minor != 0 {
		t.Fatalf("MulMoneyQuantity(0, -5) = %+v, %v", got, err)
	}
}

// TestMulMoneyNegativeRounding pins ties-away-from-zero for negative amounts.
func TestMulMoneyNegativeRounding(t *testing.T) {
	cases := []struct {
		amount   string
		quantity string
		want     string
	}{
		{"GBP -1.00", "0.005", "GBP -0.01"}, // -0.5 minor units -> -1
		{"GBP -1.00", "-0.005", "GBP 0.01"}, // 0.5 -> 1
		{"GBP -1.00", "0.004", "GBP 0.00"},  // -0.4 -> 0
		{"GBP -1.00", "-0.004", "GBP 0.00"}, // 0.4 -> 0
		{"GBP -3.33", "0.5", "GBP -1.67"},   // -166.5 -> -167
		{"GBP -3.33", "-0.5", "GBP 1.67"},   // 166.5 -> 167
		{"GBP 10.05", "1", "GBP 10.05"},     // exact
		{"GBP -10.05", "1", "GBP -10.05"},   // exact
		{"GBP 0.00", "12.345", "GBP 0.00"},  // zero stays zero
		{"JPY 1000", "0.5", "JPY 500"},      // zero-decimal currency
		{"JPY 1001", "0.5", "JPY 501"},      // 500.5 -> 501
	}
	for _, tc := range cases {
		product, err := MulMoneyDecimal(MustParseMoney(tc.amount), tc.quantity)
		if err != nil {
			t.Fatalf("MulMoneyDecimal(%s, %s): %v", tc.amount, tc.quantity, err)
		}
		if got := product.String(); got != tc.want {
			t.Errorf("MulMoneyDecimal(%s, %s) = %q, want %q", tc.amount, tc.quantity, got, tc.want)
		}
	}

	// Rate: 7.5% of GBP -1.00 is -0.075 -> -0.08 away from zero.
	rate, err := MulMoneyRate(MustParseMoney("GBP -1.00"), "7.5")
	if err != nil || rate.String() != "GBP -0.08" {
		t.Fatalf("MulMoneyRate(GBP -1.00, 7.5) = %v, %v", rate, err)
	}
	if _, err := MulMoneyRate(Money{Currency: "GBP", Minor: math.MaxInt64}, "200"); !errors.Is(err, ErrMoneyOverflow) {
		t.Fatalf("MulMoneyRate overflow error = %v", err)
	}
}

// TestMulMoneyRejectsNonPlainDecimals proves the bounded grammar: big.Rat's own
// parser would accept every one of these.
func TestMulMoneyRejectsNonPlainDecimals(t *testing.T) {
	rejected := []string{
		"1/3", "0x10", "0b101", "1e3", "1E3", "1.5e2",
		"", " ", " 1", "1 ", "\t1", "1\n", "1,000", "1_000",
		".5", "1.", ".", "-", "+", "--1", "++1", "+-1", "1.2.3",
		"NaN", "Inf", "Infinity", "abc", "١٢٣", "0.0000000001",
		"1234567890123456", "01", "00.5", "-01.5",
		"123456789012345.1234567890",
	}
	for _, quantity := range rejected {
		if _, err := MulMoneyDecimal(MustParseMoney("GBP 1.00"), quantity); !errors.Is(err, ErrInvalidDecimal) {
			t.Errorf("MulMoneyDecimal(%q) error = %v, want ErrInvalidDecimal", quantity, err)
		} else if !errors.Is(err, ErrInvalidMoney) {
			t.Errorf("MulMoneyDecimal(%q) error %v does not wrap ErrInvalidMoney", quantity, err)
		}
		if _, err := MulMoneyRate(MustParseMoney("GBP 1.00"), quantity); !errors.Is(err, ErrInvalidDecimal) {
			t.Errorf("MulMoneyRate(%q) error = %v, want ErrInvalidDecimal", quantity, err)
		}
	}

	accepted := map[string]int64{
		"0":               0,
		"1":               100,
		"+1":              100,
		"-1":              -100,
		"0.5":             50,
		"-0.5":            -50,
		"+0.5":            50,
		"0.000000001":     0,
		"123456789012345": 12345678901234500,
	}
	for quantity, want := range accepted {
		product, err := MulMoneyDecimal(MustParseMoney("GBP 1.00"), quantity)
		if err != nil {
			t.Fatalf("MulMoneyDecimal(%q): %v", quantity, err)
		}
		if product.Minor != want {
			t.Errorf("MulMoneyDecimal(%q).Minor = %d, want %d", quantity, product.Minor, want)
		}
	}
}

func TestParseDecimalExact(t *testing.T) {
	cases := map[string]string{
		"0.5":                       "1/2",
		"-1.25":                     "-5/4",
		"+2":                        "2/1",
		"0":                         "0/1",
		"7.5":                       "15/2",
		"0.001":                     "1/1000",
		"123456789012345.123456789": "123456789012345123456789/1000000000",
	}
	for input, want := range cases {
		ratio, err := ParseDecimal(input)
		if err != nil {
			t.Fatalf("ParseDecimal(%q): %v", input, err)
		}
		if got := ratio.String(); got != want {
			t.Errorf("ParseDecimal(%q) = %s, want %s", input, got, want)
		}
	}
}

func TestMoneyValidate(t *testing.T) {
	for _, currency := range currencies {
		if err := (Money{Currency: currency, Minor: math.MinInt64}).Validate(); err != nil {
			t.Errorf("Validate(%s): %v", currency, err)
		}
	}
	for _, money := range []Money{{}, {Currency: "ZZZ", Minor: 1}, {Currency: "gbp", Minor: 1}} {
		if err := money.Validate(); !errors.Is(err, ErrInvalidMoney) {
			t.Errorf("Validate(%+v) error = %v, want ErrInvalidMoney", money, err)
		}
	}
}

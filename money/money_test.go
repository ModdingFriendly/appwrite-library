package money

import (
	"errors"
	"testing"
)

func TestParseMoneyCanonical(t *testing.T) {
	cases := map[string]int64{
		"GBP 0.00":    0,
		"GBP 1.00":    100,
		"GBP 1":       100,
		"GBP 1.5":     150,
		"GBP 1234.50": 123450,
		"GBP -3.50":   -350,
		"GBP -0.05":   -5,
	}
	for input, want := range cases {
		money, err := ParseMoney(input)
		if err != nil {
			t.Fatalf("ParseMoney(%q): %v", input, err)
		}
		if money.Minor != want {
			t.Errorf("ParseMoney(%q).Minor = %d, want %d", input, money.Minor, want)
		}
		if money.Currency != "GBP" {
			t.Errorf("ParseMoney(%q).Currency = %q", input, money.Currency)
		}
	}
}

func TestParseMoneyRoundsHalfUp(t *testing.T) {
	cases := map[string]int64{
		"GBP 1.005":  101,
		"GBP 1.004":  100,
		"GBP -1.005": -101,
	}
	for input, want := range cases {
		money, err := ParseMoney(input)
		if err != nil {
			t.Fatalf("ParseMoney(%q): %v", input, err)
		}
		if money.Minor != want {
			t.Errorf("ParseMoney(%q).Minor = %d, want %d", input, money.Minor, want)
		}
	}
}

func TestParseMoneyRejectsInvalid(t *testing.T) {
	for _, input := range []string{
		"", "abc", "GBP", "GBP1.00", "gbp 1.00", "GBP 1.00 ", "GBP 01.00",
		"GBP .50", "GBP 1,000.00", "XYZ 1.00", "GBP NaN", "GBP Inf",
	} {
		if _, err := ParseMoney(input); err == nil {
			t.Errorf("ParseMoney(%q) accepted an invalid value", input)
		}
	}
}

func TestParseMoneyValueRejectsJSONNumbers(t *testing.T) {
	if _, err := ParseMoneyValue(1.5); err == nil {
		t.Fatal("JSON number accepted as money")
	}
	money, err := ParseMoneyValue("GBP 1.00")
	if err != nil || money.Minor != 100 {
		t.Fatalf("ParseMoneyValue string: %+v %v", money, err)
	}
}

func TestMoneyStringRoundTrip(t *testing.T) {
	cases := []string{"GBP 0.00", "GBP 1.00", "GBP 1234.50", "GBP -3.50", "EUR 9.99", "JPY 500"}
	for _, input := range cases {
		money := MustParseMoney(input)
		if got := money.String(); got != input {
			t.Errorf("round trip %q -> %q", input, got)
		}
	}
}

func TestMoneyArithmetic(t *testing.T) {
	ten := MustParseMoney("GBP 10.00")
	change := MustParseMoney("GBP 0.10")

	added, err := AddMoney(ten, change)
	if err != nil || added.String() != "GBP 10.10" {
		t.Fatalf("AddMoney: %v %v", added, err)
	}
	subtracted, err := SubMoney(ten, MustParseMoney("GBP 2.50"))
	if err != nil || subtracted.String() != "GBP 7.50" {
		t.Fatalf("SubMoney: %v %v", subtracted, err)
	}
	if _, err := AddMoney(ten, MustParseMoney("EUR 1.00")); !errors.Is(err, ErrCurrencyMismatch) {
		t.Fatalf("expected currency mismatch, got %v", err)
	}
	total, err := SumMoney(MustParseMoney("GBP 0.10"), MustParseMoney("GBP 0.20"), MustParseMoney("GBP 0.30"))
	if err != nil || total.String() != "GBP 0.60" {
		t.Fatalf("SumMoney: %v %v", total, err)
	}
}

func TestMoneyMultiplication(t *testing.T) {
	price := MustParseMoney("GBP 2.50")
	line, err := MulMoneyQuantity(price, 3)
	if err != nil || line.String() != "GBP 7.50" {
		t.Fatalf("MulMoneyQuantity: %v %v", line, err)
	}
	fractional, err := MulMoneyDecimal(MustParseMoney("GBP 10.00"), "0.5")
	if err != nil || fractional.String() != "GBP 5.00" {
		t.Fatalf("MulMoneyDecimal: %v %v", fractional, err)
	}
	half, err := MulMoneyDecimal(MustParseMoney("GBP 0.05"), "0.5")
	if err != nil || half.String() != "GBP 0.03" {
		t.Fatalf("MulMoneyDecimal rounding: %v %v", half, err)
	}
	tax, err := MulMoneyRate(MustParseMoney("GBP 20.00"), "20")
	if err != nil || tax.String() != "GBP 4.00" {
		t.Fatalf("MulMoneyRate: %v %v", tax, err)
	}
}

func TestMoneyComparisonAndSigns(t *testing.T) {
	if got, err := CmpMoney(MustParseMoney("GBP 1.99"), MustParseMoney("GBP 2.00")); err != nil || got != -1 {
		t.Fatalf("CmpMoney: %d %v", got, err)
	}
	if !MustParseMoney("GBP 0.00").IsZero() {
		t.Error("zero not detected")
	}
	refund := MustParseMoney("GBP -3.50")
	absolute, err := AbsMoney(refund)
	if err != nil || absolute.String() != "GBP 3.50" {
		t.Errorf("negative handling: %v %v", absolute, err)
	}
	if !refund.IsNegative() {
		t.Errorf("refund not detected as negative: %v", refund)
	}
	negated, err := NegMoney(MustParseMoney("GBP 2.00"))
	if err != nil || negated.String() != "GBP -2.00" {
		t.Fatalf("NegMoney: %v %v", negated, err)
	}
}

func TestMoneyOverflowGuard(t *testing.T) {
	huge := Money{Currency: "GBP", Minor: 9223372036854775807}
	if _, err := AddMoney(huge, MustParseMoney("GBP 0.01")); !errors.Is(err, ErrMoneyOverflow) {
		t.Fatalf("expected overflow, got %v", err)
	}
}

func TestFormatMoneyAndDecimalInput(t *testing.T) {
	if got, err := FormatMoney("GBP", 1250); err != nil || got != "GBP 12.50" {
		t.Fatalf("FormatMoney: %q %v", got, err)
	}
	if _, err := FormatMoney("ZZZ", 1); err == nil {
		t.Fatal("unsupported currency accepted")
	}
	money, err := MoneyFromDecimalString("GBP", "12.34")
	if err != nil || money.String() != "GBP 12.34" {
		t.Fatalf("MoneyFromDecimalString: %v %v", money, err)
	}
}

func TestMinorUnitsRoundTrip(t *testing.T) {
	money, err := FromMinorUnits("GBP", -350)
	if err != nil {
		t.Fatalf("FromMinorUnits: %v", err)
	}
	if got := money.String(); got != "GBP -3.50" {
		t.Fatalf("FromMinorUnits string = %q", got)
	}
	if got := money.MinorUnits(); got != -350 {
		t.Fatalf("MinorUnits = %d, want -350", got)
	}
	parsed := MustParseMoney("JPY 500")
	if got := parsed.MinorUnits(); got != 500 {
		t.Fatalf("JPY MinorUnits = %d, want 500", got)
	}
	if _, err := FromMinorUnits("ZZZ", 1); !errors.Is(err, ErrInvalidMoney) {
		t.Fatalf("expected ErrInvalidMoney for unsupported currency, got %v", err)
	}
	if _, err := FromMinorUnits("", 1); !errors.Is(err, ErrInvalidMoney) {
		t.Fatalf("expected ErrInvalidMoney for empty currency, got %v", err)
	}
	if _, err := FromMinorUnits("gbp", 1); !errors.Is(err, ErrInvalidMoney) {
		t.Fatalf("expected ErrInvalidMoney for lowercase currency, got %v", err)
	}
}

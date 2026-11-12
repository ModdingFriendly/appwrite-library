package rows

import (
	"bytes"
	"encoding/json"
	"math"
	"net/mail"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ModdingFriendly/appwrite-library/httpx"
	"github.com/ModdingFriendly/appwrite-library/money"
)

// FieldType is the wire type of a column.
type FieldType int

const (
	FieldVarchar FieldType = iota + 1
	FieldText
	FieldEmail
	FieldEnum
	FieldDatetime
	FieldInteger
	FieldDouble
	FieldMoney
	FieldBoolean
)

// MoneySign constrains a FieldMoney value.
type MoneySign int

const (
	MoneyAny MoneySign = iota
	MoneyNonNegative
	MoneyPositive
)

// FieldSpec describes one column for ParseField.
type FieldSpec struct {
	Type FieldType
	// MaxLen is a rune cap for string types; 0 = none.
	MaxLen int
	Enum   []string
	// Array makes the column a string array (max MaxArrayItems items).
	Array bool
	Money MoneySign
	// Required makes the field mandatory on create. Updates are patches, so it
	// has no effect there.
	Required bool
	// Min/Max bound integer and double fields when HasMin/HasMax is set, so 0
	// stays a valid explicit bound.
	HasMin bool
	Min    float64
	HasMax bool
	Max    float64
}

// numberPattern ensures json.Number only receives a JSON number literal; a JSON
// string would otherwise decode into json.Number because it has string kind.
var numberPattern = regexp.MustCompile(`^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?$`)

func isNull(raw json.RawMessage) bool { return bytes.Equal(bytes.TrimSpace(raw), []byte("null")) }

func badField(key, expected string) error {
	return httpx.BadRequest("invalid field value", map[string]any{"field": key, "expected": expected})
}

func forbiddenField(field, reason string) error {
	return httpx.Forbidden("field is not client-writable", map[string]any{"field": field, "reason": reason})
}

func missingField(field string) error {
	return httpx.BadRequest("required field is missing", map[string]any{"field": field})
}

func checkBounds(key string, spec FieldSpec, value float64) error {
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return badField(key, "finite number")
	}
	if spec.HasMin && value < spec.Min {
		return httpx.BadRequest("field is below the minimum", map[string]any{
			"field": key, "code": "below_minimum", "value": value, "min": spec.Min})
	}
	if spec.HasMax && value > spec.Max {
		return httpx.BadRequest("field is above the maximum", map[string]any{
			"field": key, "code": "above_maximum", "value": value, "max": spec.Max})
	}
	return nil
}

var datetimeLayouts = []string{
	time.RFC3339Nano,
	time.RFC3339,
	"2006-01-02T15:04:05.999999999",
	"2006-01-02T15:04:05",
	"2006-01-02",
}

// ParseDatetime accepts the gateway's datetime shapes.
func ParseDatetime(value string) (time.Time, bool) {
	for _, layout := range datetimeLayouts {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed, true
		}
	}
	return time.Time{}, false
}

// ParseField validates one raw JSON value against its spec and returns the
// normalised Go value (money is returned in canonical form).
func ParseField(key string, spec FieldSpec, raw json.RawMessage) (any, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return nil, httpx.BadRequest("field value is empty", map[string]any{"field": key})
	}
	if isNull(raw) {
		return nil, httpx.BadRequest("field may not be null", map[string]any{"field": key})
	}

	if spec.Array {
		var items []json.RawMessage
		if err := json.Unmarshal(raw, &items); err != nil {
			return nil, badField(key, "array")
		}
		if len(items) > MaxArrayItems {
			return nil, httpx.BadRequest("too many array items", map[string]any{"field": key, "max": MaxArrayItems})
		}
		scalar := spec
		scalar.Array = false
		out := make([]string, 0, len(items))
		for _, item := range items {
			value, err := ParseField(key, scalar, item)
			if err != nil {
				return nil, err
			}
			text, ok := value.(string)
			if !ok {
				return nil, badField(key, "string array")
			}
			out = append(out, text)
		}
		return out, nil
	}

	switch spec.Type {
	case FieldVarchar, FieldText, FieldEmail, FieldEnum, FieldDatetime:
		var text string
		if err := json.Unmarshal(raw, &text); err != nil {
			return nil, badField(key, "string")
		}
		if spec.MaxLen > 0 && utf8.RuneCountInString(text) > spec.MaxLen {
			return nil, httpx.BadRequest("field is too long", map[string]any{"field": key, "max": spec.MaxLen})
		}
		switch spec.Type {
		case FieldEmail:
			parsed, err := mail.ParseAddress(text)
			if err != nil || parsed.Address != text {
				return nil, badField(key, "email address")
			}
		case FieldEnum:
			ok := false
			for _, candidate := range spec.Enum {
				if text == candidate {
					ok = true
					break
				}
			}
			if !ok {
				return nil, badField(key, "one of "+strings.Join(spec.Enum, ", "))
			}
		case FieldDatetime:
			if _, ok := ParseDatetime(text); !ok {
				return nil, badField(key, "ISO-8601 datetime")
			}
		}
		return text, nil

	case FieldInteger:
		if !numberPattern.Match(raw) {
			return nil, badField(key, "integer")
		}
		var number json.Number
		if err := json.Unmarshal(raw, &number); err != nil {
			return nil, badField(key, "integer")
		}
		value, err := number.Int64()
		if err != nil {
			f, ferr := strconv.ParseFloat(number.String(), 64)
			if ferr != nil || math.IsNaN(f) || math.IsInf(f, 0) || math.Trunc(f) != f ||
				f < float64(-1<<63) || f >= float64(1<<63) {
				return nil, badField(key, "integer")
			}
			value = int64(f)
		}
		if err := checkBounds(key, spec, float64(value)); err != nil {
			return nil, err
		}
		return int(value), nil

	case FieldDouble:
		if !numberPattern.Match(raw) {
			return nil, badField(key, "number")
		}
		var number json.Number
		if err := json.Unmarshal(raw, &number); err != nil {
			return nil, badField(key, "number")
		}
		value, err := number.Float64()
		if err != nil || math.IsNaN(value) || math.IsInf(value, 0) {
			return nil, badField(key, "number")
		}
		if err := checkBounds(key, spec, value); err != nil {
			return nil, err
		}
		return value, nil

	case FieldMoney:
		const shape = `money string such as "GBP 1.00"`
		var text string
		if err := json.Unmarshal(raw, &text); err != nil {
			return nil, badField(key, shape)
		}
		parsed, err := money.ParseMoney(text)
		if err != nil || parsed.String() != text {
			return nil, badField(key, shape)
		}
		switch spec.Money {
		case MoneyNonNegative:
			if parsed.IsNegative() {
				return nil, badField(key, "money amount zero or greater")
			}
		case MoneyPositive:
			if parsed.IsNegative() || parsed.IsZero() {
				return nil, badField(key, "money amount greater than zero")
			}
		}
		return parsed.String(), nil

	case FieldBoolean:
		var value bool
		if err := json.Unmarshal(raw, &value); err != nil {
			return nil, badField(key, "boolean")
		}
		return value, nil
	}
	return nil, badField(key, "known type")
}

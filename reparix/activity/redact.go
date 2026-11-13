package activity

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

// emailPattern redacts anything that looks like a customer email. A stored
// value must never carry contact details, even when staff type one into a
// display field.
var emailPattern = regexp.MustCompile(`(?i)[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}`)

// controlPattern matches C0/C1 controls, NUL and DEL. A stored value is a
// single line, so line breaks are stripped too.
var controlPattern = regexp.MustCompile(`[\x00-\x1f\x7f-\x9f]`)

// SanitizeText strips control characters, redacts email addresses, collapses
// whitespace and caps the result at the summary column length.
func SanitizeText(value string) string {
	return SanitizeTextLimit(value, MaxSummaryRunes)
}

// SanitizeTextLimit is SanitizeText with an explicit rune cap. The cap is
// counted in runes, so a multi-byte character is never split.
func SanitizeTextLimit(value string, max int) string {
	if !utf8.ValidString(value) {
		value = strings.ToValidUTF8(value, "")
	}
	value = controlPattern.ReplaceAllString(value, " ")
	value = emailPattern.ReplaceAllString(value, "[redacted]")
	value = strings.Join(strings.Fields(value), " ")
	return Truncate(value, max)
}

// SanitizeToken keeps only characters that are safe in an id-like column
// (event name, table id, row id, actor id, source) and enforces the column
// length. Everything else is dropped rather than stored.
func SanitizeToken(value string) string {
	return SanitizeTokenLimit(value, MaxTokenRunes)
}

// SanitizeTokenLimit is SanitizeToken with an explicit rune cap.
func SanitizeTokenLimit(value string, max int) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	var out strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '.', r == '_', r == '-', r == ':':
			out.WriteRune(r)
		default:
			// Drop anything else rather than storing it in a token column.
		}
	}
	return Truncate(out.String(), max)
}

// Truncate caps a value at max runes without splitting a multi-byte
// character. A non-positive max leaves the value untouched.
func Truncate(value string, max int) string {
	if max <= 0 || utf8.RuneCountInString(value) <= max {
		return value
	}
	runes := []rune(value)
	return strings.TrimRight(string(runes[:max]), " ")
}

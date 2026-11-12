// Package spam is the shared spam heuristic used by the public contact
// endpoints.
//
// It is a pure function of the submitted text: no I/O, no clock, no
// configuration and no dependency on the Appwrite Function runtime, so the
// same answer is produced by every Function and by every test.
//
// The heuristics are deliberately small and explainable (a port of the legacy
// classes/SpamDetector.php rules):
//
//   - vowel ratio: text whose share of vowels is below VowelRatioMin or above
//     VowelRatioMax scores VowelRatioWeight;
//   - repeated characters: three identical characters in a row scores
//     RepeatedCharacterWeight;
//   - few words: fewer than FewWordsLimit whitespace-separated words in more
//     than LongTextBytes bytes scores FewWordsWeight.
//
// A text is spam when the total score reaches SpamThreshold. An empty text is
// never spam.
package spam

import "strings"

const (
	// VowelRatioMin is the lowest acceptable share of vowels.
	VowelRatioMin = 0.2
	// VowelRatioMax is the highest acceptable share of vowels.
	VowelRatioMax = 0.6

	// VowelRatioWeight is the score of the vowel-ratio rule.
	VowelRatioWeight = 0.3
	// RepeatedCharacterWeight is the score of the repeated-character rule.
	RepeatedCharacterWeight = 0.4
	// FewWordsWeight is the score of the few-words rule.
	FewWordsWeight = 0.3

	// SpamThreshold is the score at which a text is reported as spam.
	SpamThreshold = 0.6

	// FewWordsLimit is the number of words below which a long text is
	// suspicious.
	FewWordsLimit = 3
	// LongTextBytes is the length, in bytes, above which a text with few words
	// is suspicious.
	LongTextBytes = 40
)

// Result is the outcome of one heuristic analysis.
type Result struct {
	// IsSpam reports whether the text reached the spam threshold.
	IsSpam bool `json:"is_spam"`
	// Score is the accumulated heuristic score.
	Score float64 `json:"score"`
}

// Analyze scores the text with the shared spam heuristics.
//
// The text is trimmed and lower-cased first, and the rules are measured in
// bytes, so the result does not depend on the encoding of the submission.
func Analyze(text string) Result {
	t := strings.ToLower(strings.TrimSpace(text))
	if t == "" {
		return Result{}
	}

	score := 0.0

	vowels := strings.Count(t, "a") + strings.Count(t, "e") + strings.Count(t, "i") +
		strings.Count(t, "o") + strings.Count(t, "u")
	if ratio := float64(vowels) / float64(len(t)); ratio < VowelRatioMin || ratio > VowelRatioMax {
		score += VowelRatioWeight
	}

	for i := 0; i+2 < len(t); i++ {
		if t[i] == t[i+1] && t[i] == t[i+2] {
			score += RepeatedCharacterWeight
			break
		}
	}

	if len(strings.Fields(t)) < FewWordsLimit && len(t) > LongTextBytes {
		score += FewWordsWeight
	}

	return Result{IsSpam: score >= SpamThreshold, Score: score}
}

// IsSpam reports whether the text reaches the spam threshold.
func IsSpam(text string) bool {
	return Analyze(text).IsSpam
}

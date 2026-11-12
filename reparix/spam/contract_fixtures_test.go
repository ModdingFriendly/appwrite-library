package spam_test

// Contract fixtures for the shared spam heuristic. The fixtures pin the
// reference core-go/SpamDetector behaviour:
//
//   - empty and whitespace-only text scores zero and is not spam;
//   - the vowel ratio is measured in bytes over the trimmed lower-case text;
//   - any three identical consecutive bytes add the repeated-character score;
//   - fewer than three words is only a signal when the byte length is > 40;
//   - a score of exactly 0.6 or more is spam.
//
// The HTTP 400 for blank text belongs to the calling route; the pure package
// deliberately reports a zero score instead.

import (
	"encoding/json"
	"math"
	"os"
	"strings"
	"testing"

	"github.com/ModdingFriendly/appwrite-library/reparix/spam"
)

type spamFixture struct {
	Name       string  `json:"name"`
	Text       string  `json:"text"`
	Repeat     string  `json:"repeat"`
	Count      int     `json:"count"`
	WantIsSpam bool    `json:"want_is_spam"`
	WantScore  float64 `json:"want_score"`
}

func loadSpamFixtures(t *testing.T) []spamFixture {
	t.Helper()
	raw, err := os.ReadFile("testdata/spam_cases.json")
	if err != nil {
		t.Fatalf("read spam fixture: %v", err)
	}
	var fixtures []spamFixture
	if err := json.Unmarshal(raw, &fixtures); err != nil {
		t.Fatalf("decode spam fixture: %v", err)
	}
	if len(fixtures) == 0 {
		t.Fatal("spam fixture is empty")
	}
	return fixtures
}

func fixtureText(tc spamFixture) string {
	if tc.Repeat != "" {
		return strings.Repeat(tc.Repeat, tc.Count)
	}
	return tc.Text
}

func TestSpamFixtures(t *testing.T) {
	for _, tc := range loadSpamFixtures(t) {
		t.Run(tc.Name, func(t *testing.T) {
			text := fixtureText(tc)
			got := spam.Analyze(text)
			if got.IsSpam != tc.WantIsSpam {
				t.Fatalf("is_spam = %v, want %v (score %v)", got.IsSpam, tc.WantIsSpam, got.Score)
			}
			if math.Abs(got.Score-tc.WantScore) > 1e-9 {
				t.Fatalf("score = %v, want %v", got.Score, tc.WantScore)
			}
			if got.Score < 0 || got.Score > 1 {
				t.Fatalf("score outside [0,1]: %v", got.Score)
			}
			if spam.IsSpam(text) != got.IsSpam {
				t.Fatalf("IsSpam disagrees with Analyze for %q", text)
			}
		})
	}
}

func TestSpamConstantsMatchReference(t *testing.T) {
	cases := map[string]struct {
		got  float64
		want float64
	}{
		"vowel ratio min":      {spam.VowelRatioMin, 0.2},
		"vowel ratio max":      {spam.VowelRatioMax, 0.6},
		"vowel ratio weight":   {spam.VowelRatioWeight, 0.3},
		"repeated char weight": {spam.RepeatedCharacterWeight, 0.4},
		"few words weight":     {spam.FewWordsWeight, 0.3},
		"spam threshold":       {spam.SpamThreshold, 0.6},
	}
	for name, c := range cases {
		if c.got != c.want {
			t.Fatalf("%s = %v, want %v", name, c.got, c.want)
		}
	}
	if spam.FewWordsLimit != 3 {
		t.Fatalf("few words limit = %d, want 3", spam.FewWordsLimit)
	}
	if spam.LongTextBytes != 40 {
		t.Fatalf("long text bytes = %d, want 40", spam.LongTextBytes)
	}
}

func TestAnalyzeIsDeterministic(t *testing.T) {
	texts := []string{
		"",
		"  ",
		"My phone screen is cracked and needs replacing.",
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"ckckckckckckckckckckckckckckckckckckckckckckck",
	}
	for _, text := range texts {
		first := spam.Analyze(text)
		for i := 0; i < 5; i++ {
			next := spam.Analyze(text)
			if next != first {
				t.Fatalf("Analyze(%q) is not deterministic: %+v != %+v", text, next, first)
			}
		}
	}
}

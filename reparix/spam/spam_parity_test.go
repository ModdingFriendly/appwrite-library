package spam

import (
	"math/rand"
	"strings"
	"testing"
)

// referenceIsSpam is a verbatim copy of the heuristic still served by
// functions/core-go/spam.go (isSpam). It is pinned here so the shared port is
// proven to match the reference implementation, including its byte-based
// measurements and the exact 0.6 threshold.
func referenceIsSpam(text string) (bool, float64) {
	t := strings.ToLower(strings.TrimSpace(text))
	if t == "" {
		return false, 0
	}

	score := 0.0

	vowels := strings.Count(t, "a") + strings.Count(t, "e") + strings.Count(t, "i") +
		strings.Count(t, "o") + strings.Count(t, "u")
	if ratio := float64(vowels) / float64(len(t)); ratio < 0.2 || ratio > 0.6 {
		score += 0.3
	}

	for i := 0; i+2 < len(t); i++ {
		if t[i] == t[i+1] && t[i] == t[i+2] {
			score += 0.4
			break
		}
	}

	if len(strings.Fields(t)) < 3 && len(t) > 40 {
		score += 0.3
	}

	return score >= 0.6, score
}

func TestParityWithCoreGoReference(t *testing.T) {
	corpus := []string{
		"",
		"   ",
		"hello",
		"My phone screen is cracked and needs replacing.",
		"aaaa",
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"CHEAP WATCHES BUY NOW CLICK HERE NOW",
		"Ünïcödé text with accents and more words to be here",
		"ééé",
		"a b c",
		"Great repair service, quick turnaround and friendly staff.",
	}
	alphabet := []rune("aeiouxyz 0123ABCé£")
	rng := rand.New(rand.NewSource(7))
	for i := 0; i < 20000; i++ {
		n := rng.Intn(60)
		var b strings.Builder
		for j := 0; j < n; j++ {
			b.WriteRune(alphabet[rng.Intn(len(alphabet))])
		}
		corpus = append(corpus, b.String())
	}

	for _, text := range corpus {
		wantSpam, wantScore := referenceIsSpam(text)
		got := Analyze(text)
		if got.IsSpam != wantSpam || got.Score != wantScore {
			t.Fatalf("parity mismatch for %q: got %+v, want (%v, %v)", text, got, wantSpam, wantScore)
		}
	}
}

package agent

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// ReferenceAnswer answers an Agent Captcha question.
//
// This exists so that CI can run the entire flow unattended, and so that a
// developer can exercise registration without a model in the loop. In
// production the agent's own model reads the question; that is the point of
// making the challenge natural language in the first place.
//
// Shipping a solver does not weaken the system. The question is a liveness and
// instruction-following check, the proof of work is the actual cost function,
// and neither one authorizes anything: a registered identity with no grant
// secret can do nothing at all.
func ReferenceAnswer(question string) (string, error) {
	q := strings.TrimSpace(question)

	if m := arithmeticRe.FindStringSubmatch(q); m != nil {
		a, b, c := atoi(m[1]), atoi(m[2]), atoi(m[3])
		return strconv.Itoa(a + b - c), nil
	}

	if m := sortRe.FindStringSubmatch(q); m != nil {
		words := splitList(m[1])
		if len(words) < 3 {
			return "", fmt.Errorf("agent: sort question listed only %d words", len(words))
		}
		sorted := append([]string(nil), words...)
		sort.Strings(sorted)
		return sorted[2], nil
	}

	if m := letterCountRe.FindStringSubmatch(q); m != nil {
		letter, word := m[1], m[2]
		return strconv.Itoa(strings.Count(word, letter)), nil
	}

	if m := nthWordRe.FindStringSubmatch(q); m != nil {
		words := splitList(m[1])
		n := atoi(m[2])
		if n < 1 || n > len(words) {
			return "", fmt.Errorf("agent: nth-word question asked for word %d of %d", n, len(words))
		}
		return words[n-1], nil
	}

	return "", fmt.Errorf("agent: unrecognized challenge question: %q", q)
}

var (
	arithmeticRe  = regexp.MustCompile(`^Compute:\s*(\d+)\s*\+\s*(\d+)\s*-\s*(\d+)\.`)
	sortRe        = regexp.MustCompile(`^Sort these words alphabetically:\s*(.+?)\.\s*Reply with only the third word\.$`)
	letterCountRe = regexp.MustCompile(`^Reply with only the number of times the letter "(.)" appears in "([a-z]+)"\.$`)
	nthWordRe     = regexp.MustCompile(`^Given the list:\s*(.+?)\.\s*Reply with only word number (\d+), counting from 1\.$`)
)

func splitList(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func atoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

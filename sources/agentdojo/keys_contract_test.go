package agentdojo_test

import (
	"os"
	"strings"
	"testing"

	"github.com/0x71pp17/agent-defense-eval/defenses"
	"github.com/0x71pp17/agent-defense-eval/sources/agentdojo"
)

// The classifier scorer (Python) and the Classifier defense (Go) must agree on
// the exact set of texts. CI writes the scorer's keys to SCORER_KEYS_FILE; the
// test is skipped when it is unset.
func TestScorerKeysMatchDefense(t *testing.T) {
	path := os.Getenv("SCORER_KEYS_FILE")
	if path == "" {
		t.Skip("SCORER_KEYS_FILE not set")
	}
	b, err := os.ReadFile(path) // #nosec G304 -- test input path from CI
	if err != nil {
		t.Fatal(err)
	}
	scorer := strings.Fields(string(b))
	p, err := agentdojo.LoadPairs()
	if err != nil {
		t.Fatal(err)
	}
	empty := defenses.NewClassifier(defenses.ScoreTable{Scores: map[string]float64{}}, 0.5, defenses.ScopeBoth)
	needed := empty.Missing(p.Load())
	if strings.Join(scorer, "\n") != strings.Join(needed, "\n") {
		t.Fatalf("scorer produces %d keys, defense needs %d; the sets differ", len(scorer), len(needed))
	}
}

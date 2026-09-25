package agentdojo

import (
	"os"
	"strings"

	"github.com/0x71pp17/agent-defense-eval/defenses"
)

func osGetenv(k string) string            { return os.Getenv(k) }
func osReadFile(p string) ([]byte, error) { return os.ReadFile(p) } // #nosec G304 -- test input path from CI
func fields(s string) []string            { return strings.Fields(s) }
func joinLines(x []string) string         { return strings.Join(x, "\n") }
func newEmptyClassifier() defenses.Classifier {
	return defenses.NewClassifier(defenses.ScoreTable{Scores: map[string]float64{}}, 0.5, defenses.ScopeBoth)
}

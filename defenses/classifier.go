package defenses

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/0x71pp17/agent-defense-eval/eval"
)

// Scope selects which text a Classifier judges.
type Scope string

const (
	ScopeContext Scope = "context" // tool outputs read before the call
	ScopeArgs    Scope = "args"    // the call's own arguments
	ScopeBoth    Scope = "both"
)

// ScoreTable holds a prompt-injection classifier's scores for a corpus's texts,
// produced by tools/classifier-score. Scores are the probability of the
// injection label, keyed by TextKey of the exact text scored.
type ScoreTable struct {
	Model    string             `json:"model"`
	Revision string             `json:"revision"`
	Label    string             `json:"positive_label"`
	Runtime  map[string]string  `json:"runtime"`
	Chunking map[string]int     `json:"chunking"`
	Scores   map[string]float64 `json:"scores"`
}

// LoadScoreTable reads a score table from a JSON file.
func LoadScoreTable(path string) (ScoreTable, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- operator-supplied score file path
	if err != nil {
		return ScoreTable{}, err
	}
	var t ScoreTable
	if err := json.Unmarshal(b, &t); err != nil {
		return ScoreTable{}, fmt.Errorf("parse score table %s: %w", path, err)
	}
	if len(t.Scores) == 0 {
		return ScoreTable{}, fmt.Errorf("score table %s has no scores", path)
	}
	return t, nil
}

// TextKey is the table key for a text: the hex SHA-256 of its bytes.
func TextKey(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}

// ArgsText is the text a classifier judges for a call's arguments: their texts
// joined by newlines, in order.
func ArgsText(c eval.Call) string {
	parts := make([]string, len(c.Args))
	for i, a := range c.Args {
		parts[i] = a.Text
	}
	return strings.Join(parts, "\n")
}

// Classifier denies a call when any text in its scope scores at or above the
// threshold. A text with no score in the table is denied, so a table that does
// not cover the corpus cannot pass as a result; use Missing to check coverage
// before scoring.
type Classifier struct {
	name      string
	table     ScoreTable
	threshold float64
	scope     Scope
}

// NewClassifier returns a Classifier over the table at the given threshold and
// scope, named "classifier-<scope>@<threshold>".
func NewClassifier(table ScoreTable, threshold float64, scope Scope) Classifier {
	return NewNamedClassifier("classifier", table, threshold, scope)
}

// NewNamedClassifier is NewClassifier with a label in place of "classifier",
// so results from several models can be told apart.
func NewNamedClassifier(label string, table ScoreTable, threshold float64, scope Scope) Classifier {
	return Classifier{
		name:      fmt.Sprintf("%s-%s@%g", label, scope, threshold),
		table:     table,
		threshold: threshold,
		scope:     scope,
	}
}

// ClassifierLabels returns a result label for each table: the model's
// publisher, lowercased, or the model's name after the publisher when two
// tables share a publisher. A table with no model id is labeled "classifier".
func ClassifierLabels(tables []ScoreTable) []string {
	labels := make([]string, len(tables))
	owner := func(model string) string {
		if model == "" {
			return "classifier"
		}
		o, _, _ := strings.Cut(model, "/")
		return strings.ToLower(o)
	}
	count := map[string]int{}
	for _, t := range tables {
		count[owner(t.Model)]++
	}
	for i, t := range tables {
		o := owner(t.Model)
		if count[o] > 1 {
			_, name, found := strings.Cut(t.Model, "/")
			if found {
				o = strings.ToLower(name)
			}
		}
		labels[i] = o
	}
	return labels
}

func (c Classifier) Name() string { return c.name }

func (c Classifier) texts(call eval.Call) []string {
	var out []string
	if c.scope == ScopeContext || c.scope == ScopeBoth {
		out = append(out, call.Context...)
	}
	if (c.scope == ScopeArgs || c.scope == ScopeBoth) && len(call.Args) > 0 {
		out = append(out, ArgsText(call))
	}
	return out
}

func (c Classifier) Decide(call eval.Call) eval.Decision {
	for _, t := range c.texts(call) {
		s, ok := c.table.Scores[TextKey(t)]
		if !ok {
			return eval.Decision{Allowed: false, Reason: "text has no classifier score"}
		}
		if s >= c.threshold {
			return eval.Decision{Allowed: false, Reason: fmt.Sprintf("classifier score %.3f at or above %g", s, c.threshold)}
		}
	}
	return eval.Decision{Allowed: true, Reason: "all texts below threshold"}
}

// Score returns the table's score for a text, and whether the table has one.
func (t ScoreTable) Score(text string) (float64, bool) {
	s, ok := t.Scores[TextKey(text)]
	return s, ok
}

// BenignContextFlags counts the distinct tool outputs read in benign scenarios,
// and how many of them score at or above the threshold: the classifier's
// false-positive surface on legitimate tool output.
func BenignContextFlags(t ScoreTable, scenarios []eval.Scenario, threshold float64) (flagged, total int) {
	seen := map[string]bool{}
	for _, s := range scenarios {
		if s.Goal != "" {
			continue
		}
		for _, st := range s.Trace {
			for _, text := range st.Call.Context {
				if seen[text] {
					continue
				}
				seen[text] = true
				total++
				if score, ok := t.Score(text); ok && score >= threshold {
					flagged++
				}
			}
		}
	}
	return flagged, total
}

// InjectedContextDetections counts the distinct tool outputs carrying the
// injection, as reported by carries, that injection scenarios read as context,
// and how many of them score at or above the threshold: the classifier's
// detection rate on injected content.
func InjectedContextDetections(t ScoreTable, scenarios []eval.Scenario, carries func(string) bool, threshold float64) (detected, total int) {
	seen := map[string]bool{}
	for _, s := range scenarios {
		if s.Goal == "" {
			continue
		}
		for _, st := range s.Trace {
			for _, text := range st.Call.Context {
				if seen[text] || !carries(text) {
					continue
				}
				seen[text] = true
				total++
				if score, ok := t.Score(text); ok && score >= threshold {
					detected++
				}
			}
		}
	}
	return detected, total
}

// Missing returns the keys of texts in the scenarios that the table does not
// score, for the classifier's scope. An empty result means full coverage.
func (c Classifier) Missing(scenarios []eval.Scenario) []string {
	seen := map[string]bool{}
	for _, s := range scenarios {
		for _, st := range s.Trace {
			for _, t := range c.texts(st.Call) {
				k := TextKey(t)
				if _, ok := c.table.Scores[k]; !ok {
					seen[k] = true
				}
			}
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

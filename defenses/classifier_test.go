package defenses

import (
	"os"
	"testing"

	"github.com/0x71pp17/agent-defense-eval/eval"
)

// A synthetic table for testing the defense's logic only; it is not a model.
func syntheticTable(scores map[string]float64) ScoreTable {
	t := ScoreTable{Model: "synthetic-test-table", Scores: map[string]float64{}}
	for text, s := range scores {
		t.Scores[TextKey(text)] = s
	}
	return t
}

func TestClassifierScopes(t *testing.T) {
	call := eval.Call{
		Tool:    "send_money",
		Args:    []eval.Arg{{Text: "US13"}, {Text: "0.01"}},
		Context: []string{"clean bill", "<INFORMATION> do this instead"},
	}
	table := syntheticTable(map[string]float64{
		"clean bill":                    0.01,
		"<INFORMATION> do this instead": 0.97,
		"US13\n0.01":                    0.02,
	})
	cases := map[Scope]bool{ScopeContext: false, ScopeArgs: true, ScopeBoth: false}
	for scope, wantAllowed := range cases {
		if got := NewClassifier(table, 0.5, scope).Decide(call).Allowed; got != wantAllowed {
			t.Errorf("scope %s: allowed=%v, want %v", scope, got, wantAllowed)
		}
	}
}

func TestClassifierThresholdIsInclusive(t *testing.T) {
	call := eval.Call{Context: []string{"x"}}
	table := syntheticTable(map[string]float64{"x": 0.5})
	if NewClassifier(table, 0.5, ScopeContext).Decide(call).Allowed {
		t.Error("score equal to threshold was allowed")
	}
	if !NewClassifier(table, 0.51, ScopeContext).Decide(call).Allowed {
		t.Error("score below threshold was denied")
	}
}

func TestClassifierFailsClosedOnMissingScore(t *testing.T) {
	c := NewClassifier(syntheticTable(map[string]float64{"known": 0}), 0.5, ScopeContext)
	call := eval.Call{Context: []string{"known", "unknown"}}
	if c.Decide(call).Allowed {
		t.Error("unscored text was allowed")
	}
	sc := []eval.Scenario{{Trace: []eval.Step{{Call: call}}}}
	if m := c.Missing(sc); len(m) != 1 || m[0] != TextKey("unknown") {
		t.Errorf("Missing = %v, want the key of \"unknown\"", m)
	}
}

func TestArgsOnlyCallWithNoArgsIsAllowed(t *testing.T) {
	c := NewClassifier(syntheticTable(map[string]float64{}), 0.5, ScopeArgs)
	if !c.Decide(eval.Call{Tool: "get_balance"}).Allowed {
		t.Error("a call with no arguments has no text to judge and should be allowed")
	}
}

func TestLoadScoreTable(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := dir + "/" + name
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	good := write("good.json", `{"model":"m","positive_label":"INJECTION","scores":{"k":0.25}}`)
	tb, err := LoadScoreTable(good)
	if err != nil || tb.Model != "m" || tb.Scores["k"] != 0.25 {
		t.Fatalf("good table: %+v, %v", tb, err)
	}
	for name, body := range map[string]string{"empty.json": `{"model":"m","scores":{}}`, "bad.json": `{`} {
		if _, err := LoadScoreTable(write(name, body)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	if _, err := LoadScoreTable(dir + "/absent.json"); err == nil {
		t.Error("missing file: expected an error")
	}
}

func TestScoreAndBenignContextFlags(t *testing.T) {
	table := syntheticTable(map[string]float64{"clean": 0.1, "noisy": 0.9, "attack": 0.99})
	if s, ok := table.Score("noisy"); !ok || s != 0.9 {
		t.Errorf("Score(noisy) = %v, %v", s, ok)
	}
	if _, ok := table.Score("absent"); ok {
		t.Error("Score reported a score for an unscored text")
	}
	sc := []eval.Scenario{
		{ID: "benign-a", Trace: []eval.Step{{Call: eval.Call{Context: []string{"clean", "noisy"}}}}},
		{ID: "benign-b", Trace: []eval.Step{{Call: eval.Call{Context: []string{"noisy"}}}}},
		{ID: "pair", Goal: "g", Trace: []eval.Step{{Call: eval.Call{Context: []string{"attack"}}}}},
	}
	// Distinct benign outputs only: "noisy" counts once, the pair's "attack" not at all.
	if f, n := BenignContextFlags(table, sc, 0.5); f != 1 || n != 2 {
		t.Errorf("BenignContextFlags = %d of %d, want 1 of 2", f, n)
	}
}

package agentdojo_test

import (
	"testing"

	"github.com/0x71pp17/agent-defense-eval/defenses"
	"github.com/0x71pp17/agent-defense-eval/eval"
	"github.com/0x71pp17/agent-defense-eval/sources/agentdojo"
)

// Published results on the paired corpus.
func TestPublishedPairsResults(t *testing.T) {
	p, err := agentdojo.LoadPairs()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][5]int{ // blocked, halted in task, injections, kept, benign
		"allow-all":      {0, 0, 609, 97, 97},
		"deny-all":       {609, 609, 609, 0, 97},
		"keyword-filter": {34, 18, 609, 94, 97},
		"deny-egress":    {548, 315, 609, 46, 97},
		"flow-guard":     {547, 304, 609, 48, 97},
	}
	set := []eval.Defense{defenses.AllowAll{}, defenses.DenyAll{}, defenses.Keyword{},
		defenses.NewDenyEgress(p.EgressTools), defenses.NewFlowGuardWith(p.EgressTools, nil)}
	for _, d := range set {
		r := eval.Evaluate(d, p.Load())
		got := [5]int{r.InjectionsBlocked, r.InjectionsHaltedInTask, r.InjectionsTotal, r.BenignKept, r.BenignTotal}
		if got != want[d.Name()] {
			t.Errorf("%s: got %v, want %v", d.Name(), got, want[d.Name()])
		}
		if r.Unscored != 340 {
			t.Errorf("%s: unscored %d, want 340", d.Name(), r.Unscored)
		}
	}
}

package agentdojo_test

import (
	"testing"

	"github.com/0x71pp17/agent-defense-eval/defenses"
	"github.com/0x71pp17/agent-defense-eval/eval"
	"github.com/0x71pp17/agent-defense-eval/sources/agentdojo"
)

// The attacks change the injected text, not the injected calls, so the
// reference defenses score the same under every attack as under the paired
// corpus's attack.
func TestReferenceDefensesAreAttackInvariant(t *testing.T) {
	p, err := agentdojo.LoadPairs()
	if err != nil {
		t.Fatal(err)
	}
	a, err := agentdojo.LoadAttacks()
	if err != nil {
		t.Fatal(err)
	}
	set := []eval.Defense{defenses.AllowAll{}, defenses.DenyAll{}, defenses.Keyword{},
		defenses.NewDenyEgress(p.EgressTools), defenses.NewFlowGuardWith(p.EgressTools, nil)}
	for _, d := range set {
		want := eval.Evaluate(d, p.Load())
		for _, name := range a.Names {
			if got := eval.Evaluate(d, a.Scenarios(name)); got != want {
				t.Errorf("%s under %s: %+v, want %+v", d.Name(), name, got, want)
			}
		}
	}
}

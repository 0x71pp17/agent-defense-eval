package eval

import (
	"math"
	"math/rand/v2"
	"reflect"
	"testing"
)

// near compares means averaged over trials with rates computed directly.
func near(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

// provenanceGate denies any call carrying a non-trusted argument, so it is
// sensitive to every label the perturbation changes.
type provenanceGate struct{}

func (provenanceGate) Name() string { return "provenance-gate" }
func (provenanceGate) Decide(c Call) Decision {
	for _, a := range c.Args {
		if a.Provenance != Trusted {
			return Decision{Allowed: false}
		}
	}
	return Decision{Allowed: true}
}

func TestRelabelAtZeroIsIdentity(t *testing.T) {
	sc := Bundled{}.Load()
	got := Relabel(sc, 0, 0, rand.New(rand.NewPCG(1, 1)))
	if !reflect.DeepEqual(got, sc) {
		t.Error("relabel at rate 0 changed the scenarios")
	}
}

func TestRelabelDoesNotMutateInput(t *testing.T) {
	sc := Bundled{}.Load()
	before := Bundled{}.Load()
	_ = Relabel(sc, 1, 1, rand.New(rand.NewPCG(1, 1)))
	_ = StripProvenance(sc)
	if !reflect.DeepEqual(sc, before) {
		t.Error("perturbation mutated its input")
	}
}

func TestSweepIsDeterministic(t *testing.T) {
	sc := Bundled{}.Load()
	a := Sweep(provenanceGate{}, sc, OverTaint, []float64{0.2}, 20, 7)
	b := Sweep(provenanceGate{}, sc, OverTaint, []float64{0.2}, 20, 7)
	if !reflect.DeepEqual(a, b) {
		t.Error("same seed produced different results")
	}
}

func TestSweepAtZeroMatchesEvaluate(t *testing.T) {
	sc := Bundled{}.Load()
	r := Evaluate(provenanceGate{}, sc)
	p := Sweep(provenanceGate{}, sc, MissedTaint, []float64{0}, 5, 1)[0]
	if !near(p.BlockMean, r.BlockRate()) || !near(p.UtilityMean, r.UtilityRate()) {
		t.Errorf("rate 0 sweep %+v differs from evaluate %+v", p, r)
	}
}

// A defense that never reads provenance must score identically under any
// relabeling; otherwise the perturbation is leaking into something else.
func TestProvenanceBlindDefenseIsInvariant(t *testing.T) {
	sc := Bundled{}.Load()
	base := Evaluate(allowEverything{}, sc)
	for _, axis := range []Axis{MissedTaint, OverTaint} {
		for _, p := range Sweep(allowEverything{}, sc, axis, []float64{0.3, 1}, 10, 3) {
			if !near(p.BlockMean, base.BlockRate()) || !near(p.UtilityMean, base.UtilityRate()) {
				t.Errorf("provenance-blind defense moved under relabeling: %+v", p)
			}
		}
	}
	stripped := Evaluate(allowEverything{}, StripProvenance(sc))
	if stripped != base {
		t.Errorf("provenance-blind defense moved under stripping: %+v vs %+v", stripped, base)
	}
}

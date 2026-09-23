package agentdojo_test

import (
	"math"
	"testing"

	"github.com/0x71pp17/agent-defense-eval/defenses"
	"github.com/0x71pp17/agent-defense-eval/eval"
	"github.com/0x71pp17/agent-defense-eval/sources/agentdojo"
)

func near(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

// Endpoints follow from flow-guard's logic and pin the sweep to it.
func TestSweepEndpoints(t *testing.T) {
	c, err := agentdojo.Load()
	if err != nil {
		t.Fatal(err)
	}
	fg := defenses.NewFlowGuardWith(c.EgressTools, nil)
	sc := c.Corrected()
	base := eval.Evaluate(fg, sc)

	// Every label trusted: with no destination allowlist, flow-guard denies nothing.
	miss := eval.Sweep(fg, sc, eval.MissedTaint, []float64{1}, 3, 1)[0]
	if !near(miss.BlockMean, 0) || !near(miss.UtilityMean, 1) {
		t.Errorf("all-trusted: block %.3f utility %.3f, want 0 and 1", miss.BlockMean, miss.UtilityMean)
	}

	// Over-taint cannot raise blocking beyond what untrusted labels already give,
	// since injection arguments start untrusted.
	over := eval.Sweep(fg, sc, eval.OverTaint, []float64{1}, 3, 1)[0]
	if !near(over.BlockMean, base.BlockRate()) {
		t.Errorf("over-taint changed blocking: %.3f vs %.3f", over.BlockMean, base.BlockRate())
	}

	// Stripped labels: every egress call is denied, the same as full over-taint.
	stripped := eval.Evaluate(fg, eval.StripProvenance(sc))
	if !near(stripped.UtilityRate(), over.UtilityMean) || !near(stripped.BlockRate(), over.BlockMean) {
		t.Errorf("stripped %+v differs from full over-taint %+v", stripped, over)
	}
}

// The published sweep points. Trials are seeded, so the means are exact up to
// floating-point accumulation.
func TestPublishedSweepPoints(t *testing.T) {
	c, err := agentdojo.Load()
	if err != nil {
		t.Fatal(err)
	}
	fg := defenses.NewFlowGuardWith(c.EgressTools, nil)
	rates := []float64{0.2, 0.5}
	const trials, seed = 100, 20260922
	want := map[eval.Axis][2][2]float64{ // per rate: block mean, utility mean
		eval.MissedTaint: {{0.8296153846153834, 0.6105154639175256}, {0.7288461538461536, 0.7192783505154634}},
		eval.OverTaint:   {{0.8461538461538448, 0.5117525773195876}, {0.8461538461538448, 0.48556701030927796}},
	}
	for axis, w := range want {
		for i, p := range eval.Sweep(fg, c.Corrected(), axis, rates, trials, seed) {
			if !near(p.BlockMean, w[i][0]) || !near(p.UtilityMean, w[i][1]) {
				t.Errorf("axis %d rate %.1f: block %.6f utility %.6f, want %.6f %.6f",
					axis, p.Rate, p.BlockMean, p.UtilityMean, w[i][0], w[i][1])
			}
		}
	}
}

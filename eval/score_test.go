package eval

import "testing"

// A tiny defense used to test the scoring engine independently of the real
// defenses: it denies exactly the tools named.
type denyTools struct{ tools map[string]bool }

func (denyTools) Name() string { return "deny-tools" }
func (d denyTools) Decide(c Call) Decision {
	if d.tools[c.Tool] {
		return Decision{Allowed: false, Reason: "blocked tool"}
	}
	return Decision{Allowed: true}
}

func TestEvaluate_CountsInjectionsAndBenign(t *testing.T) {
	sc := Bundled{}.Load()
	// Sanity on the corpus shape the whole harness depends on.
	inj, ben := 0, 0
	for _, s := range sc {
		if len(s.injectedCalls()) > 0 {
			inj++
		} else {
			ben++
		}
	}
	if inj != 6 || ben != 4 {
		t.Fatalf("corpus shape changed: %d injections, %d benign (want 6, 4)", inj, ben)
	}
}

func TestEvaluate_BlockAndUtilityMath(t *testing.T) {
	sc := Bundled{}.Load()
	// A defense that denies every send/post blocks all egress injections and
	// over-blocks the benign forward, so utility is not full.
	d := denyTools{tools: map[string]bool{"email.send": true, "payment.send": true, "booking.share": true, "webhook.post": true}}
	r := Evaluate(d, sc)
	if r.InjectionsBlocked == 0 || r.InjectionsBlocked > r.InjectionsTotal {
		t.Errorf("block count out of range: %+v", r)
	}
	if r.BenignKept >= r.BenignTotal {
		t.Errorf("expected the benign forward to be over-blocked, got %d/%d", r.BenignKept, r.BenignTotal)
	}
}

func TestCompare_SortsByFrontier(t *testing.T) {
	sc := Bundled{}.Load()
	all := allowEverything{}
	none := denyEverything{}
	c := Compare([]Defense{all, none}, sc)
	// deny-all has the higher block rate, so it sorts first.
	if c.Results[0].Defense != "all-deny" {
		t.Errorf("expected highest block rate first, got %s", c.Results[0].Defense)
	}
}

type allowEverything struct{}

func (allowEverything) Name() string         { return "all-allow" }
func (allowEverything) Decide(Call) Decision { return Decision{Allowed: true} }

type denyEverything struct{}

func (denyEverything) Name() string         { return "all-deny" }
func (denyEverything) Decide(Call) Decision { return Decision{Allowed: false} }

// An injection scenario with no tool call must not be counted as benign.
func TestInjectionWithoutCallsIsUnscored(t *testing.T) {
	sc := []Scenario{{ID: "text-only", Goal: "make the agent say something"}}
	r := Evaluate(allowEverything{}, sc)
	if r.Unscored != 1 || r.BenignTotal != 0 || r.InjectionsTotal != 0 {
		t.Errorf("text-only injection mis-scored: %+v", r)
	}
}

// A defense that denies a user-task call before the injected call is recorded
// as halting in the task, not as a clean block.
func TestHaltedInTaskIsSeparated(t *testing.T) {
	sc := []Scenario{{
		ID: "pair", Goal: "g",
		Trace: []Step{
			{Call: Call{Tool: "user.step"}},
			{Call: Call{Tool: "attacker.step"}, Injected: true},
		},
	}}
	early := Evaluate(denyTools{tools: map[string]bool{"user.step": true}}, sc)
	if early.InjectionsBlocked != 1 || early.InjectionsHaltedInTask != 1 || early.CleanBlockRate() != 0 {
		t.Errorf("early denial mis-scored: %+v", early)
	}
	late := Evaluate(denyTools{tools: map[string]bool{"attacker.step": true}}, sc)
	if late.InjectionsBlocked != 1 || late.InjectionsHaltedInTask != 0 || late.CleanBlockRate() != 1 {
		t.Errorf("injected-call denial mis-scored: %+v", late)
	}
}

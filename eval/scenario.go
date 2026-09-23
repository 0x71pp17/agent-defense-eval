package eval

// Suite names the environment a scenario is drawn from, following AgentDojo's
// grouping (arXiv:2406.13352).
type Suite string

const (
	SuiteWorkspace Suite = "workspace"
	SuiteBanking   Suite = "banking"
	SuiteTravel    Suite = "travel"
	SuiteSlack     Suite = "slack"
)

// Step is one call in a scenario's trace. Injected marks the call that exists
// only because of an injection: the call a defense must deny.
type Step struct {
	Call     Call
	Injected bool
}

// Scenario is a user task and its trace. An injection scenario contains one or
// more injected steps; a benign scenario contains none.
type Scenario struct {
	ID    string
	Suite Suite
	Task  string
	Goal  string
	Trace []Step
	// Baseline is the same user task's calls in an environment with no
	// injection, when the corpus records it. It lets the scorer tell whether a
	// denial was caused by the injection.
	Baseline []Call
}

func (s Scenario) injectedCalls() []Call {
	var out []Call
	for _, st := range s.Trace {
		if st.Injected {
			out = append(out, st.Call)
		}
	}
	return out
}

// Source supplies scenarios. Bundled returns the built-in corpus; implement
// Source to score defenses against exported AgentDojo traces or another suite.
type Source interface {
	Load() []Scenario
}

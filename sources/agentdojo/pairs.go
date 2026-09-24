package agentdojo

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/0x71pp17/agent-defense-eval/eval"
)

//go:embed agentdojo-v1.2-pairs.json
var pairsJSON []byte

// PairStats reports how the paired export went.
type PairStats struct {
	Pairs                    int `json:"pairs"`
	ScorablePairs            int `json:"scorable_pairs"`
	ScorableNotBeforeACall   int `json:"scorable_pairs_injection_not_before_a_call"`
	UnscorablePairs          int `json:"unscorable_pairs"`
	UnscorableNotBeforeACall int `json:"unscorable_pairs_injection_not_before_a_call"`
}

type rawScenario struct {
	ID     string `json:"id"`
	Suite  string `json:"suite"`
	Kind   string `json:"kind"`
	Task   string `json:"task"`
	Attack string `json:"attack"`
	Trace  []struct {
		Tool     string   `json:"tool"`
		Dest     string   `json:"dest"`
		Injected bool     `json:"injected"`
		Context  []string `json:"context"`
		Args     []struct {
			Provenance string `json:"provenance"`
			Text       string `json:"text"`
		} `json:"args"`
	} `json:"trace"`
}

type pairsDocument struct {
	Source      string            `json:"source"`
	Attack      string            `json:"attack"`
	EgressTools []string          `json:"egress_tools"`
	Stats       PairStats         `json:"stats"`
	Outputs     map[string]string `json:"outputs"`
	Carrying    []string          `json:"outputs_carrying_injection"`
	Scenarios   []rawScenario     `json:"scenarios"`
}

// decode resolves a raw scenario's context hashes against the output table.
func (s rawScenario) decode(outputs map[string]string) (eval.Scenario, error) {
	sc := eval.Scenario{ID: s.ID, Suite: eval.Suite(s.Suite), Task: s.Task}
	if s.Kind == "injection" {
		sc.Goal = s.Task
	}
	for _, st := range s.Trace {
		call := eval.Call{Tool: st.Tool, Dest: st.Dest}
		for _, h := range st.Context {
			text, ok := outputs[h]
			if !ok {
				return eval.Scenario{}, fmt.Errorf("scenario %s references missing output %s", s.ID, h)
			}
			call.Context = append(call.Context, text)
		}
		for _, a := range st.Args {
			call.Args = append(call.Args, eval.Arg{Provenance: eval.Provenance(a.Provenance), Text: a.Text})
		}
		sc.Trace = append(sc.Trace, eval.Step{Call: call, Injected: st.Injected})
	}
	return sc, nil
}

// carryingSet resolves the exporter's list of injection-carrying output hashes
// to their texts.
func carryingSet(hashes []string, outputs map[string]string) (map[string]bool, error) {
	set := make(map[string]bool, len(hashes))
	for _, h := range hashes {
		text, ok := outputs[h]
		if !ok {
			return nil, fmt.Errorf("carrying list references missing output %s", h)
		}
		set[text] = true
	}
	return set, nil
}

// twinID is the benign twin's id for a pair id: the pair id without its
// attack prefix and injection-task suffix.
func twinID(pairID string) (string, bool) {
	if _, rest, found := strings.Cut(pairID, ":"); found {
		pairID = rest
	}
	cut := strings.LastIndex(pairID, "-")
	if cut < 0 {
		return "", false
	}
	return pairID[:cut], true
}

// Pairs is the paired corpus: each AgentDojo user task replayed in the default
// environment (benign) and in an environment carrying each injection task's
// attack (injection), with the tool outputs read before every call.
type Pairs struct {
	Source      string
	Attack      string
	EgressTools []string
	Stats       PairStats
	scenarios   []eval.Scenario
	carrying    map[string]bool
	twins       map[string][]eval.Call
}

// CarriesInjection reports whether a tool output text carries the injection:
// the exporter found it differs from the clean environment's output at the
// same step, and no clean environment produces it.
func (p Pairs) CarriesInjection(text string) bool { return p.carrying[text] }

// LoadPairs parses the embedded paired corpus.
func LoadPairs() (Pairs, error) {
	var d pairsDocument
	if err := json.Unmarshal(pairsJSON, &d); err != nil {
		return Pairs{}, fmt.Errorf("parse agentdojo pairs: %w", err)
	}
	carrying, err := carryingSet(d.Carrying, d.Outputs)
	if err != nil {
		return Pairs{}, err
	}
	p := Pairs{Source: d.Source, Attack: d.Attack, EgressTools: d.EgressTools, Stats: d.Stats,
		carrying: carrying, twins: map[string][]eval.Call{}}
	for _, raw := range d.Scenarios {
		sc, err := raw.decode(d.Outputs)
		if err != nil {
			return Pairs{}, err
		}
		p.scenarios = append(p.scenarios, sc)
	}
	// Each pair links to its benign twin: the same user task in the default
	// environment.
	for _, sc := range p.scenarios {
		if sc.Goal == "" {
			calls := make([]eval.Call, len(sc.Trace))
			for i, st := range sc.Trace {
				calls[i] = st.Call
			}
			p.twins[sc.ID] = calls
		}
	}
	for i, sc := range p.scenarios {
		if sc.Goal == "" {
			continue
		}
		if p.scenarios[i].Baseline, err = p.twin(sc.ID); err != nil {
			return Pairs{}, err
		}
	}
	return p, nil
}

func (p Pairs) twin(pairID string) ([]eval.Call, error) {
	id, ok := twinID(pairID)
	base, found := p.twins[id]
	if !ok || !found {
		return nil, fmt.Errorf("pair %s has no benign twin", pairID)
	}
	return base, nil
}

// Load returns the scenarios, satisfying eval.Source.
func (p Pairs) Load() []eval.Scenario { return p.scenarios }

// Benign returns the corpus's benign scenarios.
func (p Pairs) Benign() []eval.Scenario {
	var out []eval.Scenario
	for _, sc := range p.scenarios {
		if sc.Goal == "" {
			out = append(out, sc)
		}
	}
	return out
}

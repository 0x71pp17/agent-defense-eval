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

type pairsDocument struct {
	Source      string            `json:"source"`
	Attack      string            `json:"attack"`
	EgressTools []string          `json:"egress_tools"`
	Stats       PairStats         `json:"stats"`
	Outputs     map[string]string `json:"outputs"`
	Carrying    []string          `json:"outputs_carrying_injection"`
	Scenarios   []struct {
		ID    string `json:"id"`
		Suite string `json:"suite"`
		Kind  string `json:"kind"`
		Task  string `json:"task"`
		Trace []struct {
			Tool     string   `json:"tool"`
			Dest     string   `json:"dest"`
			Injected bool     `json:"injected"`
			Context  []string `json:"context"`
			Args     []struct {
				Provenance string `json:"provenance"`
				Text       string `json:"text"`
			} `json:"args"`
		} `json:"trace"`
	} `json:"scenarios"`
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
	p := Pairs{Source: d.Source, Attack: d.Attack, EgressTools: d.EgressTools, Stats: d.Stats,
		carrying: map[string]bool{}}
	for _, h := range d.Carrying {
		text, ok := d.Outputs[h]
		if !ok {
			return Pairs{}, fmt.Errorf("carrying list references missing output %s", h)
		}
		p.carrying[text] = true
	}
	for _, s := range d.Scenarios {
		sc := eval.Scenario{ID: s.ID, Suite: eval.Suite(s.Suite), Task: s.Task}
		injection := s.Kind == "injection"
		if injection {
			sc.Goal = s.Task
		}
		for _, st := range s.Trace {
			call := eval.Call{Tool: st.Tool, Dest: st.Dest}
			for _, h := range st.Context {
				text, ok := d.Outputs[h]
				if !ok {
					return Pairs{}, fmt.Errorf("scenario %s references missing output %s", s.ID, h)
				}
				call.Context = append(call.Context, text)
			}
			for _, a := range st.Args {
				call.Args = append(call.Args, eval.Arg{Provenance: eval.Provenance(a.Provenance), Text: a.Text})
			}
			sc.Trace = append(sc.Trace, eval.Step{Call: call, Injected: st.Injected})
		}
		p.scenarios = append(p.scenarios, sc)
	}
	// Link each pair to its benign twin: the same user task in the default
	// environment. Pair ids extend the twin's id with the injection task.
	twins := map[string][]eval.Call{}
	for _, sc := range p.scenarios {
		if sc.Goal == "" {
			calls := make([]eval.Call, len(sc.Trace))
			for i, st := range sc.Trace {
				calls[i] = st.Call
			}
			twins[sc.ID] = calls
		}
	}
	for i, sc := range p.scenarios {
		if sc.Goal == "" {
			continue
		}
		cut := strings.LastIndex(sc.ID, "-")
		base, ok := twins[sc.ID[:max(cut, 0)]]
		if cut < 0 || !ok {
			return Pairs{}, fmt.Errorf("pair %s has no benign twin", sc.ID)
		}
		p.scenarios[i].Baseline = base
	}
	return p, nil
}

// Load returns the scenarios, satisfying eval.Source.
func (p Pairs) Load() []eval.Scenario { return p.scenarios }

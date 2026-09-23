// Package agentdojo loads a corpus exported from AgentDojo task ground truth
// (arXiv:2406.13352) by tools/agentdojo-export. User tasks are benign
// scenarios; injection tasks are injection scenarios whose every call is
// injected. The corpus is embedded, so it loads with no files or network.
package agentdojo

import (
	_ "embed"
	"encoding/json"
	"fmt"

	"github.com/0x71pp17/agent-defense-eval/eval"
)

//go:embed agentdojo-v1.2.json
var corpusJSON []byte

// Diagnostics reports how the exporter's provenance rule labeled arguments on
// benign calls, and how many of its untrusted labels the environment data
// supports.
type Diagnostics struct {
	BenignUntrustedArgs    int `json:"benign_untrusted_args"`
	UntrustedInEnvironment int `json:"untrusted_in_environment"`
	UntrustedInNeither     int `json:"untrusted_in_neither"`
	TasksSkipped           int `json:"tasks_skipped"`
}

type document struct {
	Source      string      `json:"source"`
	EgressTools []string    `json:"egress_tools"`
	Diagnostics Diagnostics `json:"diagnostics"`
	Scenarios   []struct {
		ID    string `json:"id"`
		Suite string `json:"suite"`
		Kind  string `json:"kind"`
		Task  string `json:"task"`
		Trace []struct {
			Tool string `json:"tool"`
			Dest string `json:"dest"`
			Args []struct {
				Name       string `json:"name"`
				Provenance string `json:"provenance"`
				Origin     string `json:"origin"`
				Text       string `json:"text"`
			} `json:"args"`
		} `json:"trace"`
	} `json:"scenarios"`
}

// Corpus is the loaded AgentDojo corpus.
type Corpus struct {
	Source      string
	EgressTools []string
	Diagnostics Diagnostics
	// Unscorable lists injection tasks whose AgentDojo ground truth contains no
	// tool call. AgentDojo judges them from environment state after a live run,
	// so they cannot be scored offline; eval.Evaluate counts them as unscored.
	Unscorable []string
	scenarios  []eval.Scenario
	corrected  []eval.Scenario
}

// Load parses the embedded corpus.
func Load() (Corpus, error) {
	var d document
	if err := json.Unmarshal(corpusJSON, &d); err != nil {
		return Corpus{}, fmt.Errorf("parse agentdojo corpus: %w", err)
	}
	c := Corpus{Source: d.Source, EgressTools: d.EgressTools, Diagnostics: d.Diagnostics}
	for _, s := range d.Scenarios {
		sc := eval.Scenario{ID: s.ID, Suite: eval.Suite(s.Suite), Task: s.Task}
		injected := s.Kind == "injection"
		if injected && len(s.Trace) == 0 {
			// Kept in the scenario list so the scorer reports it as unscored.
			c.Unscorable = append(c.Unscorable, s.ID)
		}
		if injected {
			sc.Goal = s.Task
		}
		fixed := sc
		for _, st := range s.Trace {
			call := eval.Call{Tool: st.Tool, Dest: st.Dest}
			fixedCall := eval.Call{Tool: st.Tool, Dest: st.Dest}
			for _, a := range st.Args {
				call.Args = append(call.Args, eval.Arg{Provenance: eval.Provenance(a.Provenance), Text: a.Text})
				p := eval.Provenance(a.Provenance)
				if !injected && a.Origin == "neither" {
					p = eval.Trusted
				}
				fixedCall.Args = append(fixedCall.Args, eval.Arg{Provenance: p, Text: a.Text})
			}
			sc.Trace = append(sc.Trace, eval.Step{Call: call, Injected: injected})
			fixed.Trace = append(fixed.Trace, eval.Step{Call: fixedCall, Injected: injected})
		}
		c.scenarios = append(c.scenarios, sc)
		c.corrected = append(c.corrected, fixed)
	}
	return c, nil
}

// Load returns the scenarios, satisfying eval.Source.
func (c Corpus) Load() []eval.Scenario { return c.scenarios }

// Corrected returns the scenarios with one labeling error removed: on benign
// tasks, a value found in neither the prompt nor the environment data was most
// likely produced by the agent, and is relabeled trusted. Injection tasks are
// unchanged; their values originate from injected content.
func (c Corpus) Corrected() []eval.Scenario { return c.corrected }

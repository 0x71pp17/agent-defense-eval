package agentdojo

import (
	_ "embed"
	"encoding/json"
	"fmt"

	"github.com/0x71pp17/agent-defense-eval/eval"
)

//go:embed agentdojo-v1.2-attacks.json
var attacksJSON []byte

type attacksDocument struct {
	Source      string               `json:"source"`
	Attacks     []string             `json:"attacks"`
	EgressTools []string             `json:"egress_tools"`
	Stats       map[string]PairStats `json:"stats"`
	Outputs     map[string]string    `json:"outputs"`
	Carrying    []string             `json:"outputs_carrying_injection"`
	Scenarios   []rawScenario        `json:"scenarios"`
}

// Attacks is the attack-coverage corpus: the paired corpus's user and
// injection task pairs replayed under additional AgentDojo attacks. It holds
// injection pairs only; each attack's scenarios reuse the paired corpus's
// benign tasks, which do not depend on the attack, and each pair links to its
// benign twin there.
type Attacks struct {
	Source      string
	Names       []string
	EgressTools []string
	Stats       map[string]PairStats
	byAttack    map[string][]eval.Scenario
	benign      []eval.Scenario
	carrying    map[string]bool
}

// CarriesInjection reports whether a tool output text carries an injection,
// by the same rule as Pairs.CarriesInjection.
func (a Attacks) CarriesInjection(text string) bool { return a.carrying[text] }

// LoadAttacks parses the embedded attack-coverage corpus and links it to the
// paired corpus's benign tasks.
func LoadAttacks() (Attacks, error) {
	var d attacksDocument
	if err := json.Unmarshal(attacksJSON, &d); err != nil {
		return Attacks{}, fmt.Errorf("parse agentdojo attacks: %w", err)
	}
	pairs, err := LoadPairs()
	if err != nil {
		return Attacks{}, err
	}
	carrying, err := carryingSet(d.Carrying, d.Outputs)
	if err != nil {
		return Attacks{}, err
	}
	a := Attacks{Source: d.Source, Names: d.Attacks, EgressTools: d.EgressTools, Stats: d.Stats,
		byAttack: map[string][]eval.Scenario{}, benign: pairs.Benign(), carrying: carrying}
	known := map[string]bool{}
	for _, n := range d.Attacks {
		known[n] = true
	}
	for _, raw := range d.Scenarios {
		if !known[raw.Attack] {
			return Attacks{}, fmt.Errorf("scenario %s names unlisted attack %q", raw.ID, raw.Attack)
		}
		sc, err := raw.decode(d.Outputs)
		if err != nil {
			return Attacks{}, err
		}
		if sc.Baseline, err = pairs.twin(sc.ID); err != nil {
			return Attacks{}, err
		}
		a.byAttack[raw.Attack] = append(a.byAttack[raw.Attack], sc)
	}
	return a, nil
}

// Scenarios returns an attack's injection pairs followed by the benign tasks.
func (a Attacks) Scenarios(attack string) []eval.Scenario {
	out := append([]eval.Scenario(nil), a.byAttack[attack]...)
	return append(out, a.benign...)
}

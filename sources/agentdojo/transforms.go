package agentdojo

import (
	"embed"
	"encoding/json"
	"fmt"

	"github.com/0x71pp17/agent-defense-eval/eval"
)

// transformFiles embeds every transformed attack corpus present at build time.
// A transform is available only when its corpus file is committed, so the set
// grows as corpora are added without touching this code.
//
//go:embed all:transformed
var transformFiles embed.FS

// transformOrder is the stable presentation order; only transforms whose corpus
// is embedded are returned by Transforms.
var transformOrder = []string{"framing", "field_split", "leet"}

func transformCorpus(name string) ([]byte, bool) {
	b, err := transformFiles.ReadFile("transformed/agentdojo-v1.2-attacks-" + name + ".json")
	if err != nil {
		return nil, false
	}
	return b, true
}

// Transforms lists the readable evasion transforms whose corpus is committed,
// in a stable order.
func Transforms() []string {
	var out []string
	for _, name := range transformOrder {
		if _, ok := transformCorpus(name); ok {
			out = append(out, name)
		}
	}
	return out
}

// InjectedPair is one injected tool output and its baseline counterpart: the
// output the same injected call produced before the transform was applied. The
// texts differ; a classifier's scores on them are compared to measure the drop.
type InjectedPair struct {
	Scenario  string
	Baseline  string // untransformed injected tool output
	Transform string // transformed injected tool output
}

// TransformCorpus is a transformed attack corpus paired to the baseline attack
// corpus by scenario and injected step.
type TransformCorpus struct {
	Name  string
	Pairs []InjectedPair
}

// LoadTransform loads a transform's corpus and pairs each injection-carrying
// output to its baseline counterpart at the same scenario and step.
func LoadTransform(name string) (TransformCorpus, error) {
	raw, ok := transformCorpus(name)
	if !ok {
		return TransformCorpus{}, fmt.Errorf("unknown or uncommitted transform %q", name)
	}
	base, err := loadAttacksDoc(attacksJSON)
	if err != nil {
		return TransformCorpus{}, fmt.Errorf("baseline: %w", err)
	}
	tf, err := loadAttacksDoc(raw)
	if err != nil {
		return TransformCorpus{}, fmt.Errorf("transform %s: %w", name, err)
	}
	if tf.transform != name {
		return TransformCorpus{}, fmt.Errorf("corpus for %q records transform %q", name, tf.transform)
	}
	tc := TransformCorpus{Name: name}
	for id, bs := range base.byID {
		ts, ok := tf.byID[id]
		if !ok {
			return TransformCorpus{}, fmt.Errorf("transform %s missing scenario %s", name, id)
		}
		if len(bs.Trace) != len(ts.Trace) {
			return TransformCorpus{}, fmt.Errorf("scenario %s trace length differs under %s", id, name)
		}
		for i := range bs.Trace {
			bStep, tStep := bs.Trace[i], ts.Trace[i]
			if bStep.Injected != tStep.Injected {
				return TransformCorpus{}, fmt.Errorf("scenario %s step %d injected flag differs under %s", id, i, name)
			}
			if !tStep.Injected {
				continue
			}
			for j := range tStep.Context {
				bText, tText := base.outputs[bStep.Context[j]], tf.outputs[tStep.Context[j]]
				if !tf.carrying[tStep.Context[j]] {
					continue
				}
				tc.Pairs = append(tc.Pairs, InjectedPair{Scenario: id, Baseline: bText, Transform: tText})
			}
		}
	}
	return tc, nil
}

// ScoreDrop reports, for the injection-carrying outputs a transform changed, the
// classifier's score on the baseline output minus its score on the transformed
// output. Unchanged outputs (a transform that did not alter a given output) are
// excluded, so the distribution describes the transform's effect where it acts.
type ScoreDrop struct {
	Transform string
	N         int     // injected outputs the transform changed
	Mean      float64 // mean of baseline score minus transformed score
	Max       float64
	Min       float64
	Evaded    int // outputs at or above threshold on the baseline, below it after
}

// DropVsThreshold measures the score drop for one transform under one table.
func DropVsThreshold(tc TransformCorpus, score func(string) (float64, bool), threshold float64) (ScoreDrop, error) {
	d := ScoreDrop{Transform: tc.Name, Min: 1, Max: -1}
	seen := map[string]bool{}
	var sum float64
	for _, p := range tc.Pairs {
		if p.Baseline == p.Transform || seen[p.Transform] {
			continue
		}
		seen[p.Transform] = true
		bs, ok1 := score(p.Baseline)
		ts, ok2 := score(p.Transform)
		if !ok1 || !ok2 {
			return ScoreDrop{}, fmt.Errorf("transform %s: a paired output has no score", tc.Name)
		}
		drop := bs - ts
		sum += drop
		d.N++
		if drop > d.Max {
			d.Max = drop
		}
		if drop < d.Min {
			d.Min = drop
		}
		if bs >= threshold && ts < threshold {
			d.Evaded++
		}
	}
	if d.N > 0 {
		d.Mean = sum / float64(d.N)
	} else {
		d.Min, d.Max = 0, 0
	}
	return d, nil
}

// attacksDoc is the parsed corpus with lookups the transform join needs.
type attacksDoc struct {
	transform string
	outputs   map[string]string
	carrying  map[string]bool
	byID      map[string]rawScenario
}

func loadAttacksDoc(raw []byte) (attacksDoc, error) {
	var d struct {
		Transform string            `json:"transform"`
		Outputs   map[string]string `json:"outputs"`
		Carrying  []string          `json:"outputs_carrying_injection"`
		Scenarios []rawScenario     `json:"scenarios"`
	}
	if err := json.Unmarshal(raw, &d); err != nil {
		return attacksDoc{}, err
	}
	out := attacksDoc{transform: d.Transform, outputs: d.Outputs,
		carrying: make(map[string]bool, len(d.Carrying)), byID: make(map[string]rawScenario, len(d.Scenarios))}
	if out.transform == "" {
		out.transform = "identity"
	}
	for _, h := range d.Carrying {
		out.carrying[h] = true
	}
	for _, s := range d.Scenarios {
		out.byID[s.ID] = s
	}
	return out, nil
}

// Scenarios returns the transform's injection scenarios plus the paired corpus's
// benign tasks, the set a classifier is scored over for this corpus.
func (tc TransformCorpus) Scenarios() ([]eval.Scenario, error) {
	raw, ok := transformCorpus(tc.Name)
	if !ok {
		return nil, fmt.Errorf("unknown or uncommitted transform %q", tc.Name)
	}
	var d attacksDocument
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, err
	}
	pairs, err := LoadPairs()
	if err != nil {
		return nil, err
	}
	var out []eval.Scenario
	for _, s := range d.Scenarios {
		sc, err := s.decode(d.Outputs)
		if err != nil {
			return nil, err
		}
		out = append(out, sc)
	}
	return append(out, pairs.Benign()...), nil
}

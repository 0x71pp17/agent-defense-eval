package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/0x71pp17/agent-defense-eval/defenses"
	"github.com/0x71pp17/agent-defense-eval/eval"
	"github.com/0x71pp17/agent-defense-eval/sources/agentdojo"
)

type detection struct {
	Detected int `json:"detected"`
	Total    int `json:"total"`
}

type attackReport struct {
	Comparison eval.Comparison      `json:"comparison"`
	Injected   map[string]detection `json:"injected_tool_outputs_detected,omitempty"`
}

type attacksReport struct {
	Corpus      string                  `json:"corpus"`
	Threshold   float64                 `json:"threshold"`
	Classifiers []string                `json:"classifiers,omitempty"`
	BenignFlags map[string]detection    `json:"benign_tool_outputs_flagged,omitempty"`
	Attacks     map[string]attackReport `json:"attacks"`
	Order       []string                `json:"attack_order"`
}

// runAttacks scores the reference defenses, and any classifier tables, under
// each attack in the attack-coverage corpus.
func runAttacks(scoresPath string, threshold float64, format string) {
	a, err := agentdojo.LoadAttacks()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	var tables []defenses.ScoreTable
	var paths []string
	if scoresPath != "" {
		paths = strings.Split(scoresPath, ",")
		for _, path := range paths {
			table, err := defenses.LoadScoreTable(strings.TrimSpace(path))
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(2)
			}
			tables = append(tables, table)
		}
	}
	labels := defenses.ClassifierLabels(tables)

	var all []eval.Scenario
	for _, name := range a.Names {
		all = append(all, a.Scenarios(name)...)
	}
	rep := attacksReport{Corpus: "attacks", Threshold: threshold, Classifiers: labels,
		Attacks: map[string]attackReport{}, Order: a.Names}
	if len(tables) > 0 {
		rep.BenignFlags = map[string]detection{}
	}
	for i, table := range tables {
		if missing := defenses.NewClassifier(table, threshold, defenses.ScopeBoth).Missing(all); len(missing) > 0 {
			fmt.Fprintf(os.Stderr, "score table %s does not cover this corpus: %d texts unscored\n", paths[i], len(missing))
			os.Exit(2)
		}
		f, n := defenses.BenignContextFlags(table, a.Scenarios(a.Names[0]), threshold)
		rep.BenignFlags[labels[i]] = detection{f, n}
	}

	for _, name := range a.Names {
		scenarios := a.Scenarios(name)
		set := []eval.Defense{defenses.AllowAll{}, defenses.DenyAll{}, defenses.Keyword{},
			defenses.NewDenyEgress(a.EgressTools), defenses.NewFlowGuardWith(a.EgressTools, nil)}
		ar := attackReport{}
		if len(tables) > 0 {
			ar.Injected = map[string]detection{}
		}
		for i, table := range tables {
			for _, scope := range []defenses.Scope{defenses.ScopeContext, defenses.ScopeArgs, defenses.ScopeBoth} {
				set = append(set, defenses.NewNamedClassifier(labels[i], table, threshold, scope))
			}
			d, n := defenses.InjectedContextDetections(table, scenarios, a.CarriesInjection, threshold)
			ar.Injected[labels[i]] = detection{d, n}
		}
		ar.Comparison = eval.Compare(set, scenarios)
		rep.Attacks[name] = ar
	}

	if format == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rep); err != nil {
			fmt.Fprintln(os.Stderr, "encode:", err)
			os.Exit(2)
		}
		return
	}
	fmt.Printf("corpus: attacks (%s)\n", a.Source)
	for _, label := range labels {
		b := rep.BenignFlags[label]
		fmt.Printf("%s: distinct tool outputs read in benign tasks scoring at or above %g: %d of %d\n", label, threshold, b.Detected, b.Total)
	}
	for _, name := range a.Names {
		ar := rep.Attacks[name]
		fmt.Printf("\nattack: %s\n", name)
		for _, label := range labels {
			d := ar.Injected[label]
			fmt.Printf("%s: distinct injected tool outputs scoring at or above %g: %d of %d\n", label, threshold, d.Detected, d.Total)
		}
		printTable(ar.Comparison.Results)
	}
}

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/0x71pp17/agent-defense-eval/defenses"
	"github.com/0x71pp17/agent-defense-eval/sources/agentdojo"
)

// runDrop measures each classifier's score drop under one evasion transform,
// comparing a baseline attack-corpus score table to a transformed-corpus table
// for the same model. It needs both tables per model: -scores lists the
// transformed tables, -baseline-scores the matching baseline tables, in the
// same order.
func runDrop(transform, scoresPath, baselinePath string, threshold float64, format string) {
	if scoresPath == "" || baselinePath == "" {
		fmt.Fprintln(os.Stderr, "-corpus attacks-<transform> needs -scores and -baseline-scores, one table per model each")
		os.Exit(2)
	}
	tc, err := agentdojo.LoadTransform(transform)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	tfPaths := strings.Split(scoresPath, ",")
	basePaths := strings.Split(baselinePath, ",")
	if len(tfPaths) != len(basePaths) {
		fmt.Fprintln(os.Stderr, "-scores and -baseline-scores must list the same number of tables")
		os.Exit(2)
	}

	type row struct {
		Model string              `json:"model"`
		Drop  agentdojo.ScoreDrop `json:"drop"`
	}
	var rows []row
	for i := range tfPaths {
		base, err := defenses.LoadScoreTable(strings.TrimSpace(basePaths[i]))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		tf, err := defenses.LoadScoreTable(strings.TrimSpace(tfPaths[i]))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		if base.Model != tf.Model {
			fmt.Fprintf(os.Stderr, "table pair %d is for different models: %s vs %s\n", i, base.Model, tf.Model)
			os.Exit(2)
		}
		score := func(text string) (float64, bool) {
			if s, ok := tf.Score(text); ok {
				return s, true
			}
			return base.Score(text)
		}
		d, err := agentdojo.DropVsThreshold(tc, score, threshold)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		rows = append(rows, row{Model: base.Model, Drop: d})
	}

	if format == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(map[string]any{"transform": transform, "threshold": threshold, "models": rows}); err != nil {
			fmt.Fprintln(os.Stderr, "encode:", err)
			os.Exit(2)
		}
		return
	}
	fmt.Printf("transform: %s (readable), threshold %g\n\n", transform, threshold)
	fmt.Printf("%-46s %-8s %-24s %s\n", "model", "changed", "score drop mean [min,max]", "evaded")
	for _, r := range rows {
		d := r.Drop
		fmt.Printf("%-46s %-8d %-24s %d\n", r.Model, d.N,
			fmt.Sprintf("%.3f [%.3f, %.3f]", d.Mean, d.Min, d.Max), d.Evaded)
	}
}

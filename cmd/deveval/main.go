// Command deveval scores a set of agent-authorization defenses against a
// scenario corpus and prints the comparison on two axes: injection block rate
// and utility retention. It evaluates decision layers offline against scenario
// definitions; it does not run a live agent.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"

	"github.com/0x71pp17/agent-defense-eval/defenses"
	"github.com/0x71pp17/agent-defense-eval/eval"
	"github.com/0x71pp17/agent-defense-eval/sources/agentdojo"
)

type report struct {
	Corpus      string                   `json:"corpus"`
	Comparison  eval.Comparison          `json:"comparison"`
	BySuite     map[string][]eval.Result `json:"by_suite,omitempty"`
	Diagnostics *agentdojo.Diagnostics   `json:"provenance_diagnostics,omitempty"`
	Unscorable  []string                 `json:"unscorable,omitempty"`
	Corrected   *eval.Result             `json:"flow_guard_corrected_labels,omitempty"`
	Sweep       *sweepReport             `json:"flow_guard_label_sweep,omitempty"`
	Classifier  *classifierReport        `json:"classifier,omitempty"`
}

type classifierReport struct {
	Model      string            `json:"model"`
	Revision   string            `json:"revision"`
	Label      string            `json:"positive_label"`
	Runtime    map[string]string `json:"runtime"`
	Chunking   map[string]int    `json:"chunking"`
	Thresholds []eval.Result     `json:"threshold_sweep"`
}

var classifierThresholds = []float64{0.5, 0.8, 0.9, 0.95, 0.99}

// thresholdSweep scores the context-and-arguments classifier at each threshold.
func thresholdSweep(table defenses.ScoreTable, scenarios []eval.Scenario) []eval.Result {
	out := make([]eval.Result, 0, len(classifierThresholds))
	for _, t := range classifierThresholds {
		out = append(out, eval.Evaluate(defenses.NewClassifier(table, t, defenses.ScopeBoth), scenarios))
	}
	return out
}

type sweepReport struct {
	Base        string            `json:"base_labels"`
	Trials      int               `json:"trials"`
	Seed        uint64            `json:"seed"`
	Stripped    eval.Result       `json:"labels_stripped"`
	MissedTaint []eval.SweepPoint `json:"missed_taint"`
	OverTaint   []eval.SweepPoint `json:"over_taint"`
}

var sweepRates = []float64{0, 0.05, 0.1, 0.2, 0.3, 0.5, 0.75, 1}

const (
	sweepTrials        = 100
	sweepSeed   uint64 = 20260922
)

func main() {
	corpus := flag.String("corpus", "bundled", "scenario corpus: bundled, agentdojo, or pairs")
	scoresPath := flag.String("scores", "", "pairs only: classifier score table from tools/classifier-score")
	threshold := flag.Float64("threshold", 0.5, "classifier decision threshold")
	format := flag.String("format", "text", "output format: text or json")
	sweep := flag.Bool("sweep", false, "agentdojo only: sweep flow-guard over provenance label errors")
	flag.Parse()

	var scenarios []eval.Scenario
	var set []eval.Defense
	rep := report{Corpus: *corpus}

	switch *corpus {
	case "bundled":
		scenarios = eval.Bundled{}.Load()
		set = []eval.Defense{defenses.AllowAll{}, defenses.DenyAll{}, defenses.Keyword{}, defenses.NewFlowGuard()}
	case "agentdojo":
		c, err := agentdojo.Load()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		scenarios = c.Load()
		// Provenance is the only egress control here: the corpus names no
		// destination allowlist, so the destination check is disabled.
		set = []eval.Defense{defenses.AllowAll{}, defenses.DenyAll{}, defenses.Keyword{},
			defenses.NewDenyEgress(c.EgressTools), defenses.NewFlowGuardWith(c.EgressTools, nil)}
		d := c.Diagnostics
		rep.Diagnostics = &d
		rep.Unscorable = c.Unscorable
		rep.BySuite = bySuite(set, scenarios)
		fg := eval.Evaluate(defenses.NewFlowGuardWith(c.EgressTools, nil), c.Corrected())
		rep.Corrected = &fg
		if *sweep {
			guard := defenses.NewFlowGuardWith(c.EgressTools, nil)
			base := c.Corrected()
			rep.Sweep = &sweepReport{
				Base: "corrected", Trials: sweepTrials, Seed: sweepSeed,
				Stripped:    eval.Evaluate(guard, eval.StripProvenance(base)),
				MissedTaint: eval.Sweep(guard, base, eval.MissedTaint, sweepRates, sweepTrials, sweepSeed),
				OverTaint:   eval.Sweep(guard, base, eval.OverTaint, sweepRates, sweepTrials, sweepSeed),
			}
		}
	case "pairs":
		p, err := agentdojo.LoadPairs()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		scenarios = p.Load()
		set = []eval.Defense{defenses.AllowAll{}, defenses.DenyAll{}, defenses.Keyword{},
			defenses.NewDenyEgress(p.EgressTools), defenses.NewFlowGuardWith(p.EgressTools, nil)}
		if *scoresPath != "" {
			table, err := defenses.LoadScoreTable(*scoresPath)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(2)
			}
			both := defenses.NewClassifier(table, *threshold, defenses.ScopeBoth)
			if missing := both.Missing(scenarios); len(missing) > 0 {
				fmt.Fprintf(os.Stderr, "score table %s does not cover this corpus: %d texts unscored\n", *scoresPath, len(missing))
				os.Exit(2)
			}
			set = append(set,
				defenses.NewClassifier(table, *threshold, defenses.ScopeContext),
				defenses.NewClassifier(table, *threshold, defenses.ScopeArgs),
				both)
			rep.Classifier = &classifierReport{Model: table.Model, Revision: table.Revision,
				Label: table.Label, Runtime: table.Runtime, Chunking: table.Chunking,
				Thresholds: thresholdSweep(table, scenarios)}
		}
		rep.BySuite = bySuite(set, scenarios)
	default:
		fmt.Fprintln(os.Stderr, "unknown corpus:", *corpus)
		os.Exit(2)
	}
	if *scoresPath != "" && *corpus != "pairs" {
		fmt.Fprintln(os.Stderr, "-scores applies only to -corpus pairs")
		os.Exit(2)
	}
	rep.Comparison = eval.Compare(set, scenarios)

	if *format == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rep); err != nil {
			fmt.Fprintln(os.Stderr, "encode:", err)
			os.Exit(2)
		}
		return
	}

	fmt.Printf("corpus: %s\n\n", rep.Corpus)
	printTable(rep.Comparison.Results)
	if len(rep.BySuite) > 0 {
		suites := make([]string, 0, len(rep.BySuite))
		for s := range rep.BySuite {
			suites = append(suites, s)
		}
		sort.Strings(suites)
		for _, s := range suites {
			fmt.Printf("\nsuite: %s\n", s)
			printTable(rep.BySuite[s])
		}
	}
	if rep.Diagnostics != nil {
		d := rep.Diagnostics
		fmt.Printf("\nprovenance labels on benign calls: %d untrusted; %d found in environment data, %d in neither prompt nor environment\n",
			d.BenignUntrustedArgs, d.UntrustedInEnvironment, d.UntrustedInNeither)
	}
	if rep.Corrected != nil {
		r := rep.Corrected
		fmt.Printf("flow-guard with agent-generated values relabeled trusted: block %d/%d (%.0f%%), utility %d/%d (%.0f%%)\n",
			r.InjectionsBlocked, r.InjectionsTotal, r.BlockRate()*100, r.BenignKept, r.BenignTotal, r.UtilityRate()*100)
	}
	if rep.Sweep != nil {
		sw := rep.Sweep
		fmt.Printf("\nflow-guard label sweep: base = %s labels, %d trials per rate, seed %d\n", sw.Base, sw.Trials, sw.Seed)
		printSweep("missed taint (untrusted labeled trusted)", sw.MissedTaint)
		printSweep("over-taint (trusted labeled untrusted)", sw.OverTaint)
		fmt.Printf("\nlabels stripped (no provenance tracking): block %d/%d (%.0f%%), utility %d/%d (%.0f%%)\n",
			sw.Stripped.InjectionsBlocked, sw.Stripped.InjectionsTotal, sw.Stripped.BlockRate()*100,
			sw.Stripped.BenignKept, sw.Stripped.BenignTotal, sw.Stripped.UtilityRate()*100)
	}
	if rep.Classifier != nil {
		c := rep.Classifier
		fmt.Printf("\nclassifier: %s (revision %s, positive label %s)\n", c.Model, c.Revision, c.Label)
		fmt.Printf("threshold sweep, scope both:\n")
		printTable(c.Thresholds)
	}
	if len(rep.Unscorable) > 0 {
		fmt.Printf("unscorable injection tasks (no tool call in ground truth): %d\n", len(rep.Unscorable))
	}
}

func bySuite(set []eval.Defense, scenarios []eval.Scenario) map[string][]eval.Result {
	groups := map[string][]eval.Scenario{}
	for _, s := range scenarios {
		groups[string(s.Suite)] = append(groups[string(s.Suite)], s)
	}
	out := map[string][]eval.Result{}
	for suite, sc := range groups {
		out[suite] = eval.Compare(set, sc).Results
	}
	return out
}

func printTable(results []eval.Result) {
	fmt.Printf("%-24s %-18s %-18s %-18s %s\n", "defense", "injection block", "clean block", "utility", "unscored")
	for _, r := range results {
		fmt.Printf("%-24s %-18s %-18s %-18s %d\n", r.Defense,
			fmt.Sprintf("%d/%d (%3.0f%%)", r.InjectionsBlocked, r.InjectionsTotal, r.BlockRate()*100),
			fmt.Sprintf("%d (%3.0f%%)", r.InjectionsBlocked-r.InjectionsHaltedInTask, r.CleanBlockRate()*100),
			fmt.Sprintf("%d/%d (%3.0f%%)", r.BenignKept, r.BenignTotal, r.UtilityRate()*100),
			r.Unscored)
	}
}

func printSweep(title string, pts []eval.SweepPoint) {
	fmt.Printf("\n%s\n", title)
	fmt.Printf("%-6s %-24s %-24s\n", "rate", "block mean [min-max]", "utility mean [min-max]")
	for _, p := range pts {
		fmt.Printf("%-6.2f %-24s %-24s\n", p.Rate,
			fmt.Sprintf("%3.0f%% [%3.0f-%3.0f]", p.BlockMean*100, p.BlockMin*100, p.BlockMax*100),
			fmt.Sprintf("%3.0f%% [%3.0f-%3.0f]", p.UtilityMean*100, p.UtilityMin*100, p.UtilityMax*100))
	}
}

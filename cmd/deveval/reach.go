package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/0x71pp17/agent-defense-eval/sources/agentdojo"
)

// runEgressReach reports how AgentDojo's injection-task goals relate to the
// egress policy a flow-and-destination defense mediates.
func runEgressReach(format string) {
	a, err := agentdojo.LoadAttacks()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	gr := a.EgressReach(a.EgressTools)
	if format == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(gr); err != nil {
			fmt.Fprintln(os.Stderr, "encode:", err)
			os.Exit(2)
		}
		return
	}
	fmt.Printf("egress reach over %d injection-task goals\n\n", len(gr.Tasks))
	fmt.Printf("  reachable only through egress tools (mediated): %d\n", gr.OnEgress)
	fmt.Printf("  mixes egress and non-egress tools:              %d\n", gr.Mixed)
	fmt.Printf("  reachable with no egress tool (never mediated): %d\n\n", gr.OffEgress)
	fmt.Println("goals a flow-and-destination defense never inspects:")
	for _, tr := range gr.Tasks {
		if tr.OffEgress() {
			fmt.Printf("  %s/%s: %v\n", tr.Suite, tr.Task, tr.Tools)
		}
	}
}

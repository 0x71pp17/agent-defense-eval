package agentdojo_test

import (
	"testing"

	"github.com/0x71pp17/agent-defense-eval/sources/agentdojo"
)

// The egress reach across AgentDojo's injection tasks: how many attacker goals
// a flow-and-destination defense keyed on the egress policy can never inspect.
func TestPublishedEgressReach(t *testing.T) {
	a, err := agentdojo.LoadAttacks()
	if err != nil {
		t.Fatal(err)
	}
	gr := a.EgressReach(a.EgressTools)
	if got := len(gr.Tasks); got != 26 {
		t.Fatalf("classified %d injection tasks, want 26", got)
	}
	if gr.OnEgress != 13 || gr.OffEgress != 4 || gr.Mixed != 9 {
		t.Errorf("reach = on %d, off %d, mixed %d; want 13, 4, 9", gr.OnEgress, gr.OffEgress, gr.Mixed)
	}
	offGoals := map[string]bool{}
	for _, tr := range gr.Tasks {
		if tr.OffEgress() {
			offGoals[tr.Suite+"/"+tr.Task] = true
		}
	}
	want := []string{"banking/injection_task_7", "travel/injection_task_0", "travel/injection_task_4", "workspace/injection_task_1"}
	for _, g := range want {
		if !offGoals[g] {
			t.Errorf("expected off-egress goal %s not found", g)
		}
	}
	if len(offGoals) != len(want) {
		t.Errorf("off-egress goals = %v, want %v", offGoals, want)
	}
}

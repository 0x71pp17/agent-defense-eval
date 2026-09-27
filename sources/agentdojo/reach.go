package agentdojo

import (
	"sort"
	"strings"
)

// TaskReach classifies one injection task by how its goal's tool calls relate to
// the egress policy a flow-and-destination defense mediates.
type TaskReach struct {
	Suite       string
	Task        string
	Tools       []string
	EgressTools int // of Tools, how many are egress
	Total       int // len(Tools)
}

// OffEgress reports whether the goal completes without any egress tool, so a
// flow-and-destination defense keyed on egress never inspects the goal call.
func (r TaskReach) OffEgress() bool { return r.EgressTools == 0 }

// Mixed reports whether the goal uses both egress and non-egress tools.
func (r TaskReach) Mixed() bool { return r.EgressTools > 0 && r.EgressTools < r.Total }

// GoalReach summarizes the egress reach across a corpus's injection tasks.
type GoalReach struct {
	Tasks     []TaskReach
	OnEgress  int // goal reachable only through egress tools
	OffEgress int // goal reachable with no egress tool
	Mixed     int // goal uses both
}

// EgressReach classifies every injection task in the attack coverage corpus by
// its egress reach. The injected tool calls are attack-invariant, so one
// classification covers all attacks. egress is the set the defense mediates.
func (a Attacks) EgressReach(egress []string) GoalReach {
	set := make(map[string]bool, len(egress))
	for _, t := range egress {
		set[t] = true
	}
	seen := map[string]TaskReach{}
	order := []string{}
	for _, name := range a.Names {
		for _, s := range a.byAttack[name] {
			task, ok := injectionTaskID(s.ID)
			if !ok {
				continue
			}
			var tools []string
			for _, st := range s.Trace {
				if st.Injected {
					tools = append(tools, st.Call.Tool)
				}
			}
			if len(tools) == 0 {
				continue
			}
			key := string(s.Suite) + "/" + task
			if _, dup := seen[key]; dup {
				continue
			}
			tr := TaskReach{Suite: string(s.Suite), Task: task, Tools: tools, Total: len(tools)}
			for _, t := range tools {
				if set[t] {
					tr.EgressTools++
				}
			}
			seen[key] = tr
			order = append(order, key)
		}
	}
	sort.Strings(order)
	var gr GoalReach
	for _, k := range order {
		tr := seen[k]
		gr.Tasks = append(gr.Tasks, tr)
		switch {
		case tr.OffEgress():
			gr.OffEgress++
		case tr.Mixed():
			gr.Mixed++
		default:
			gr.OnEgress++
		}
	}
	return gr
}

// injectionTaskID extracts the injection-task id from a pair id like
// "direct:workspace-user_task_0-injection_task_1".
func injectionTaskID(id string) (string, bool) {
	if _, rest, found := strings.Cut(id, ":"); found {
		id = rest
	}
	j := strings.LastIndex(id, "-injection_task_")
	if j < 0 {
		return "", false
	}
	return id[j+1:], true
}

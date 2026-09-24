package agentdojo

import "testing"

func TestAttacksShape(t *testing.T) {
	a, err := LoadAttacks()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"direct", "ignore_previous", "injecagent", "system_message", "tool_knowledge"}
	if len(a.Names) != len(want) {
		t.Fatalf("attacks = %v, want %v", a.Names, want)
	}
	for i, name := range want {
		if a.Names[i] != name {
			t.Fatalf("attack %d = %q, want %q", i, a.Names[i], name)
		}
		st := a.Stats[name]
		if st.Pairs != 949 || st.ScorablePairs != 609 || st.ScorableNotBeforeACall != 0 {
			t.Errorf("%s stats: %+v", name, st)
		}
		benign, scorable, unscorable := 0, 0, 0
		for _, s := range a.Scenarios(name) {
			switch {
			case s.Goal == "":
				benign++
			case len(s.Baseline) == 0:
				t.Fatalf("%s: pair %s has no baseline", name, s.ID)
			default:
				hasInjected := false
				for _, st := range s.Trace {
					hasInjected = hasInjected || st.Injected
				}
				if hasInjected {
					scorable++
				} else {
					unscorable++
				}
			}
		}
		if benign != 97 || scorable != 609 || unscorable != 340 {
			t.Errorf("%s: %d benign, %d scorable, %d unscorable; want 97, 609, 340", name, benign, scorable, unscorable)
		}
	}
}

// Under every attack, each injected call has injection-carrying output in its
// context, and no benign call does.
func TestAttacksInjectionReachesContext(t *testing.T) {
	a, err := LoadAttacks()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range a.Names {
		for _, s := range a.Scenarios(name) {
			for _, st := range s.Trace {
				carried := false
				for _, c := range st.Call.Context {
					carried = carried || a.CarriesInjection(c)
				}
				if st.Injected && !carried {
					t.Fatalf("%s %s: injected call %s sees no injection", name, s.ID, st.Call.Tool)
				}
				if s.Goal == "" && carried {
					t.Fatalf("%s: benign %s call %s sees injection-carrying output", name, s.ID, st.Call.Tool)
				}
			}
		}
	}
}

func TestTwinID(t *testing.T) {
	cases := map[string]string{
		"banking-user_task_0-injection_task_3":        "banking-user_task_0",
		"direct:banking-user_task_0-injection_task_3": "banking-user_task_0",
	}
	for in, want := range cases {
		if got, ok := twinID(in); !ok || got != want {
			t.Errorf("twinID(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
	if _, ok := twinID("nodash"); ok {
		t.Error("an id with no injection-task suffix produced a twin id")
	}
}

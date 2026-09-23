package agentdojo

import (
	"strings"
	"testing"
)

func TestPairsShape(t *testing.T) {
	p, err := LoadPairs()
	if err != nil {
		t.Fatal(err)
	}
	benign, withCalls, withoutCalls := 0, 0, 0
	for _, s := range p.Load() {
		if s.Goal == "" {
			benign++
			for _, st := range s.Trace {
				if st.Injected {
					t.Fatalf("benign scenario %s has an injected step", s.ID)
				}
			}
			continue
		}
		injectedSeen := false
		for _, st := range s.Trace {
			if st.Injected {
				injectedSeen = true
			} else if injectedSeen {
				t.Fatalf("%s: a user-task step follows an injected step", s.ID)
			}
		}
		if injectedSeen {
			withCalls++
		} else {
			withoutCalls++
		}
	}
	if benign != 97 || withCalls != 609 || withoutCalls != 340 {
		t.Fatalf("got %d benign, %d scorable, %d unscorable; want 97, 609, 340", benign, withCalls, withoutCalls)
	}
	if p.Stats.ScorableNotBeforeACall != 0 {
		t.Errorf("%d scorable pairs never expose the injection", p.Stats.ScorableNotBeforeACall)
	}
}

// Every injected call in a scorable pair sees the attack in its context, and no
// benign scenario ever does.
func TestInjectionReachesContext(t *testing.T) {
	p, err := LoadPairs()
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range p.Load() {
		for _, st := range s.Trace {
			hit := false
			for _, c := range st.Call.Context {
				if strings.Contains(c, "<INFORMATION>") {
					hit = true
				}
			}
			if st.Injected && !hit {
				t.Fatalf("%s: injected call %s does not see the injection", s.ID, st.Call.Tool)
			}
			if s.Goal == "" && hit {
				t.Fatalf("benign %s: call %s sees attack text", s.ID, st.Call.Tool)
			}
		}
	}
}

package agentdojo

import "testing"

func TestCorpusShape(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	benign, injection := 0, 0
	for _, s := range c.Load() {
		if len(s.Trace) == 0 && s.Goal == "" {
			t.Errorf("benign scenario %s has an empty trace", s.ID)
		}
		if s.Goal != "" {
			injection++
		} else {
			benign++
		}
	}
	if benign != 97 || injection != 35 {
		t.Fatalf("got %d benign, %d injection; want 97, 35", benign, injection)
	}
	if len(c.Unscorable) != 9 {
		t.Errorf("got %d unscorable injection tasks, want 9: %v", len(c.Unscorable), c.Unscorable)
	}
	if len(c.EgressTools) == 0 {
		t.Error("corpus carries no egress tool policy")
	}
	d := c.Diagnostics
	if d.UntrustedInEnvironment+d.UntrustedInNeither != d.BenignUntrustedArgs {
		t.Errorf("diagnostics do not add up: %+v", d)
	}
}

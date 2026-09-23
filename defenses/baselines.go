// Package defenses provides reference implementations of the eval.Defense
// interface: three baselines that mark the corners and floor of the tradeoff,
// and FlowGuard, a provenance-and-destination defense representative of the
// information-flow class.
package defenses

import (
	"strings"

	"github.com/0x71pp17/agent-defense-eval/eval"
)

// AllowAll permits every call. It marks the utility ceiling and the security
// floor.
type AllowAll struct{}

func (AllowAll) Name() string { return "allow-all" }
func (AllowAll) Decide(eval.Call) eval.Decision {
	return eval.Decision{Allowed: true, Reason: "no policy"}
}

// DenyAll refuses every call. It marks the security ceiling and the utility
// floor, and shows that a high block rate alone is worthless.
type DenyAll struct{}

func (DenyAll) Name() string { return "deny-all" }
func (DenyAll) Decide(eval.Call) eval.Decision {
	return eval.Decision{Allowed: false, Reason: "everything refused"}
}

// Keyword denies a call when any argument's text contains a suspicious phrase.
// It is the strawman most reach for first: it catches obvious in-band injection
// strings, misses paraphrases, cannot see a malicious destination, and
// over-blocks legitimate text that happens to use a flagged word.
type Keyword struct{}

var keywordBlocklist = []string{
	"ignore previous", "forward", "wire", "send to", "exfiltrate", "attacker", "password",
}

func (Keyword) Name() string { return "keyword-filter" }
func (Keyword) Decide(c eval.Call) eval.Decision {
	for _, a := range c.Args {
		low := strings.ToLower(a.Text)
		for _, kw := range keywordBlocklist {
			if strings.Contains(low, kw) {
				return eval.Decision{Allowed: false, Reason: "matched blocked phrase: " + kw}
			}
		}
	}
	return eval.Decision{Allowed: true, Reason: "no blocked phrase"}
}

// DenyEgress refuses every call to an egress tool and allows everything else.
// It is FlowGuard without provenance: the ablation that isolates what the egress
// policy contributes from what provenance labels contribute.
type DenyEgress struct{ egress map[string]bool }

// NewDenyEgress returns a DenyEgress for the given egress tools.
func NewDenyEgress(egress []string) DenyEgress {
	d := DenyEgress{egress: map[string]bool{}}
	for _, t := range egress {
		d.egress[t] = true
	}
	return d
}

func (DenyEgress) Name() string { return "deny-egress" }
func (d DenyEgress) Decide(c eval.Call) eval.Decision {
	if d.egress[c.Tool] {
		return eval.Decision{Allowed: false, Reason: "egress tool refused"}
	}
	return eval.Decision{Allowed: true, Reason: "not an egress tool"}
}

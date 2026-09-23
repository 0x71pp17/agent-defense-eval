package defenses

import "github.com/0x71pp17/agent-defense-eval/eval"

// FlowGuard is a provenance-and-destination defense representative of the
// information-flow class (a reference monitor with control/data separation, as
// in CaMeL, arXiv:2503.18813). It refuses untrusted or tenant-private data into
// an egress sink and refuses egress to a destination off its allowlist. It does
// not read call content, so an injection that rides a permitted flow passes.
type FlowGuard struct {
	egressTools  map[string]bool
	allowedDests map[string]bool
}

// NewFlowGuard returns a FlowGuard configured for the bundled corpus: its four
// send and post tools are egress, and one internal destination is allowed.
func NewFlowGuard() FlowGuard {
	return NewFlowGuardWith(
		[]string{"email.send", "payment.send", "booking.share", "webhook.post"},
		[]string{"api.internal.example"},
	)
}

// NewFlowGuardWith returns a FlowGuard for the given egress tools and
// destination allowlist. An empty allowlist disables the destination check,
// leaving provenance as the only control on egress.
func NewFlowGuardWith(egress, allowedDests []string) FlowGuard {
	f := FlowGuard{egressTools: map[string]bool{}, allowedDests: map[string]bool{}}
	for _, t := range egress {
		f.egressTools[t] = true
	}
	for _, d := range allowedDests {
		f.allowedDests[d] = true
	}
	return f
}

func (FlowGuard) Name() string { return "flow-guard" }

func (f FlowGuard) Decide(c eval.Call) eval.Decision {
	if !f.egressTools[c.Tool] {
		return eval.Decision{Allowed: true, Reason: "local sink, no egress"}
	}
	for _, a := range c.Args {
		if a.Provenance != eval.Trusted {
			return eval.Decision{Allowed: false, Reason: string(a.Provenance) + " data may not reach an egress sink"}
		}
	}
	if len(f.allowedDests) > 0 && c.Dest != "" && !f.allowedDests[c.Dest] {
		return eval.Decision{Allowed: false, Reason: "destination " + c.Dest + " is not on the egress allowlist"}
	}
	return eval.Decision{Allowed: true, Reason: "trusted data to an allowed destination"}
}

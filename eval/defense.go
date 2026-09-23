// Package eval scores agent-authorization defenses on two axes: how many
// injection-driven tool calls a defense denies, and how many legitimate calls
// it still allows. It measures a defense class, not one implementation: any
// approach that can rule on a proposed tool call implements Defense and is
// scored against the same corpus, so results are comparable across defenses.
package eval

// Provenance is where an argument's value came from. A defense that reasons
// about information flow uses this; a content-only defense ignores it.
type Provenance string

const (
	Trusted       Provenance = "trusted"        // operator or system origin
	UntrustedWeb  Provenance = "untrusted.web"  // fetched content, open-web tool output
	TenantPrivate Provenance = "tenant.private" // another principal's private data
	Unknown       Provenance = "unknown"        // provenance not established
)

// Arg is one argument to a call: its provenance and its content. Provenance
// serves flow-based defenses; Text serves content-based ones.
type Arg struct {
	Provenance Provenance
	Text       string
}

// Call is a proposed agent tool call presented to a defense for a decision.
type Call struct {
	Tool string
	Args []Arg
	Dest string // egress destination for a call that leaves the machine; empty otherwise
	// Context holds the tool outputs the agent read before proposing this call,
	// in order. Corpora without recorded outputs leave it empty.
	Context []string
}

// Decision is a defense's ruling on a call.
type Decision struct {
	Allowed bool
	Reason  string
}

// Defense decides whether a proposed agent action may proceed. Any guardrail or
// authorization approach implements this to be scored by the harness. Decide
// must be a pure function of the call and the defense's own configuration.
type Defense interface {
	Name() string
	Decide(Call) Decision
}

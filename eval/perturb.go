package eval

import "math/rand/v2"

// Relabel returns a deep copy of the scenarios with provenance labels perturbed
// independently per argument. missRate is the probability that a non-trusted
// label becomes trusted (a tracker missing taint); overRate is the probability
// that a trusted label becomes untrusted (a tracker over-tainting). Argument
// text, tools, and destinations are unchanged.
func Relabel(scenarios []Scenario, missRate, overRate float64, rng *rand.Rand) []Scenario {
	return mapArgs(scenarios, func(a Arg) Arg {
		switch {
		case a.Provenance == Trusted && rng.Float64() < overRate:
			a.Provenance = UntrustedWeb
		case a.Provenance != Trusted && rng.Float64() < missRate:
			a.Provenance = Trusted
		}
		return a
	})
}

// StripProvenance returns a deep copy with every label set to Unknown: the input
// a provenance-based defense receives when no tracking exists.
func StripProvenance(scenarios []Scenario) []Scenario {
	return mapArgs(scenarios, func(a Arg) Arg {
		a.Provenance = Unknown
		return a
	})
}

func mapArgs(scenarios []Scenario, f func(Arg) Arg) []Scenario {
	out := make([]Scenario, len(scenarios))
	for i, s := range scenarios {
		s.Trace = append([]Step(nil), s.Trace...)
		for j, st := range s.Trace {
			args := make([]Arg, len(st.Call.Args))
			for k, a := range st.Call.Args {
				args[k] = f(a)
			}
			s.Trace[j].Call.Args = args
		}
		out[i] = s
	}
	return out
}

// SweepPoint is a defense's mean score over trials at one perturbation rate,
// with the range observed across trials.
type SweepPoint struct {
	Rate        float64 `json:"rate"`
	BlockMean   float64 `json:"block_mean"`
	BlockMin    float64 `json:"block_min"`
	BlockMax    float64 `json:"block_max"`
	UtilityMean float64 `json:"utility_mean"`
	UtilityMin  float64 `json:"utility_min"`
	UtilityMax  float64 `json:"utility_max"`
}

// Axis selects which label error a sweep varies.
type Axis int

const (
	MissedTaint Axis = iota // non-trusted labeled trusted
	OverTaint               // trusted labeled untrusted
)

// Sweep scores a defense at each rate on one axis, over the given number of
// trials. Trials use a PCG generator seeded from seed and the trial index, so
// results are reproducible.
func Sweep(d Defense, scenarios []Scenario, axis Axis, rates []float64, trials int, seed uint64) []SweepPoint {
	out := make([]SweepPoint, 0, len(rates))
	for _, rate := range rates {
		p := SweepPoint{Rate: rate, BlockMin: 1, UtilityMin: 1}
		for t := 0; t < trials; t++ {
			rng := rand.New(rand.NewPCG(seed, uint64(t))) // #nosec G404 -- reproducible experiment sampling, not a security decision
			miss, over := rate, 0.0
			if axis == OverTaint {
				miss, over = 0, rate
			}
			r := Evaluate(d, Relabel(scenarios, miss, over, rng))
			b, u := r.BlockRate(), r.UtilityRate()
			p.BlockMean += b
			p.UtilityMean += u
			p.BlockMin, p.BlockMax = min(p.BlockMin, b), max(p.BlockMax, b)
			p.UtilityMin, p.UtilityMax = min(p.UtilityMin, u), max(p.UtilityMax, u)
		}
		p.BlockMean /= float64(trials)
		p.UtilityMean /= float64(trials)
		out = append(out, p)
	}
	return out
}

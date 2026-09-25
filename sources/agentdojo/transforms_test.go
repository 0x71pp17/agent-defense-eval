package agentdojo

import "testing"

func TestLoadTransformPairsToBaseline(t *testing.T) {
	for _, name := range Transforms() {
		tc, err := LoadTransform(name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(tc.Pairs) == 0 {
			t.Fatalf("%s: no injected pairs", name)
		}
		changed := 0
		for _, p := range tc.Pairs {
			if p.Baseline == "" || p.Transform == "" {
				t.Fatalf("%s: empty output in a pair for %s", name, p.Scenario)
			}
			if p.Baseline != p.Transform {
				changed++
			}
		}
		if changed == 0 {
			t.Errorf("%s: no injected output changed", name)
		}
		t.Logf("%s: %d injected pairs, %d changed by the transform", name, len(tc.Pairs), changed)
	}
}

// The drop measurement, exercised with a synthetic scorer that returns a high
// score for the baseline and a low one for the transformed text, so a full
// evasion is measured deterministically.
func TestDropVsThreshold(t *testing.T) {
	names := Transforms()
	if len(names) == 0 {
		t.Skip("no transformed corpus committed")
	}
	tc, err := LoadTransform(names[0])
	if err != nil {
		t.Fatal(err)
	}
	baselines := map[string]bool{}
	for _, p := range tc.Pairs {
		baselines[p.Baseline] = true
	}
	score := func(text string) (float64, bool) {
		if baselines[text] {
			return 0.9, true
		}
		return 0.1, true
	}
	d, err := DropVsThreshold(tc, score, 0.5)
	if err != nil {
		t.Fatal(err)
	}
	if d.N == 0 || d.Evaded != d.N {
		t.Errorf("expected every changed output evaded: %+v", d)
	}
	if d.Mean < 0.79 || d.Mean > 0.81 {
		t.Errorf("mean drop = %.3f, want ~0.8", d.Mean)
	}
}

// A missing score is an error, not a silent zero.
func TestDropFailsOnMissingScore(t *testing.T) {
	names := Transforms()
	if len(names) == 0 {
		t.Skip("no transformed corpus committed")
	}
	tc, err := LoadTransform(names[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DropVsThreshold(tc, func(string) (float64, bool) { return 0, false }, 0.5); err == nil {
		t.Error("expected an error when a paired output has no score")
	}
}

// The scorer and the classifier defense must agree on the texts for each
// transformed corpus. CI writes the scorer's keys per transform to
// SCORER_TRANSFORM_KEYS_DIR/<name>.txt; the test is skipped when unset.
func TestScorerKeysMatchDefenseForTransforms(t *testing.T) {
	dir := osGetenv("SCORER_TRANSFORM_KEYS_DIR")
	if dir == "" {
		t.Skip("SCORER_TRANSFORM_KEYS_DIR not set")
	}
	for _, name := range Transforms() {
		b, err := osReadFile(dir + "/" + name + ".txt")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		tc, err := LoadTransform(name)
		if err != nil {
			t.Fatal(err)
		}
		scenarios, err := tc.Scenarios()
		if err != nil {
			t.Fatal(err)
		}
		empty := newEmptyClassifier()
		needed := empty.Missing(scenarios)
		if joinLines(fields(string(b))) != joinLines(needed) {
			t.Fatalf("%s: scorer keys and defense keys differ", name)
		}
	}
}

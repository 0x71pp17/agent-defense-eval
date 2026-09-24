# agent-defense-eval

![Go](https://img.shields.io/badge/Go-1.23-00ADD8?logo=go&logoColor=white)
![CI](https://github.com/0x71pp17/agent-defense-eval/actions/workflows/ci.yml/badge.svg)
![License](https://img.shields.io/badge/license-MIT-blue)

An evaluation harness for agent-authorization defenses. It scores any defense on
two axes, how many injection-driven tool calls it denies and how many legitimate
calls it still allows, and compares defenses on a shared scenario corpus. The
primary corpora are derived mechanically from the AgentDojo benchmark
(arXiv:2406.13352): its task ground truth, and its user and injection task pairs
replayed with the tool outputs an agent reads.

## Results summary

On the AgentDojo v1.2 user and injection pairs (609 scorable injection pairs, 97
benign tasks), with classifiers scoring both tool outputs and call arguments at
threshold 0.5:

| Defense | Attributable blocks | Utility |
|---|---|---|
| `flow-guard` | 243 (40%) | 48/97 (49%) |
| `deny-egress` | 233 (38%) | 46/97 (47%) |
| `protectai/deberta-v3-base-prompt-injection-v2` | 272 (45%) | 45/97 (46%) |
| `deepset/deberta-v3-base-injection` | 132 (22%) | 20/97 (21%) |
| `Horizon-Labs/prompt-injection-guard-base` | 581 (95%) | 88/97 (91%) |

Of the 100 clean tool outputs read in benign tasks, the three classifiers flag
32, 88, and 0 respectively. The classifier results cover one AgentDojo attack,
`important_instructions_no_names`. Definitions and full results follow.

## The interface

A defense is anything that can rule on a proposed agent tool call:

```go
type Defense interface {
	Name() string
	Decide(Call) Decision
}
```

A `Call` carries the tool, its arguments (each with a provenance label and its
text), an egress destination, and the tool outputs the agent read before
proposing it.

## The two axes

Injection block rate is the fraction of injection scenarios in which a defense
denies any call in the trace; the agent halts at the first denied call, and
injected calls follow the user task's calls, so the attack's goal does not
complete. Utility retention is the fraction of benign scenarios in which it
allows every call. Either axis alone is trivial to maximize.

Attributable block rate counts only blocks the injection caused. On corpora that
record each injection pair's benign twin (the same user task in an environment
with no injection), a block is attributable when the first denied call is an
injected call, or a user-task call that is identical in the twin except for its
context and that the defense allows there. Other blocks halt the user's task on a
call the defense denies with or without the injection.

## Results on AgentDojo v1.2

The corpus holds 97 benign scenarios (AgentDojo user tasks) and 35 injection
scenarios (AgentDojo injection tasks), each built from the task's ground-truth
tool calls. Nine injection tasks have no tool call in their ground truth and are
reported as unscored.

```
defense          injection block      utility              unscored
deny-all         26/26 (100%)         0/97 (  0%)          9
flow-guard       22/26 ( 85%)         48/97 ( 49%)         9
deny-egress      22/26 ( 85%)         46/97 ( 47%)         9
keyword-filter   1/26 (  4%)          94/97 ( 97%)         9
allow-all        0/26 (  0%)          97/97 (100%)         9
```

`deny-egress` refuses every call to an egress tool regardless of provenance. It is
`flow-guard` with the provenance check removed.

Utility of `flow-guard` by suite: banking 6/16, slack 1/21, travel 15/20,
workspace 26/40.

Observations:

- `flow-guard` refuses any egress call carrying an argument not found in the user's prompt. Legitimate tasks routinely send data read from tool output, such as paying a bill whose recipient and amount come from a file, so it denies 49 of 97 benign tasks.
- Of those 49, 5 are attributable to the provenance labeling rule (see below). The remaining 44 are egress calls carrying genuine tool-output data.
- `flow-guard` allows 4 injection tasks. Each achieves its goal through a state-changing tool outside the egress policy: `delete_file`, `reserve_hotel` (twice), and `update_password`.
- `flow-guard` and `deny-egress` block the same 22 injection tasks. On this corpus the egress tool policy supplies all of `flow-guard`'s blocking; provenance labels change only which legitimate egress calls are allowed.
- `keyword-filter` denies 1 injection task, on the word "password". An injected call carries the attacker's action arguments, not the injected instructions, so a phrase list at the call boundary rarely sees injection text.

## Provenance labeling

The exporter labels an argument trusted when every value in it appears in the user
task's prompt, and untrusted otherwise. Injection-task arguments are untrusted.
Each untrusted label on a benign call is cross-checked against the suite's default
environment data:

| Benign untrusted labels | Count |
|---|---|
| Value found in environment data (consistent with tool-output origin) | 224 |
| Value found in neither prompt nor environment (likely agent-generated) | 69 |
| Total | 293 |

Relabeling the 69 agent-generated values as trusted raises `flow-guard` utility
from 48/97 to 53/97, with injection blocking unchanged at 22/26. `deveval` reports
both figures.

## Sensitivity to label errors

`deveval -corpus agentdojo -sweep` perturbs the corrected provenance labels and
rescores `flow-guard`, varying two error types separately: missed taint (an
untrusted value labeled trusted) and over-taint (a trusted value labeled
untrusted). Each argument is perturbed independently; each rate is 100 seeded
trials.

```
missed taint (untrusted labeled trusted)
rate   block mean [min-max]     utility mean [min-max]
0.00    85% [ 85- 85]            55% [ 55- 55]
0.05    84% [ 77- 85]            56% [ 55- 60]
0.10    84% [ 77- 85]            58% [ 55- 62]
0.20    83% [ 73- 85]            61% [ 57- 70]
0.30    81% [ 69- 85]            64% [ 59- 72]
0.50    73% [ 50- 85]            72% [ 65- 79]
0.75    51% [ 31- 69]            83% [ 75- 90]
1.00     0% [  0-  0]           100% [100-100]

over-taint (trusted labeled untrusted)
rate   block mean [min-max]     utility mean [min-max]
0.00    85% [ 85- 85]            55% [ 55- 55]
0.05    85% [ 85- 85]            54% [ 51- 55]
0.10    85% [ 85- 85]            53% [ 48- 55]
0.20    85% [ 85- 85]            51% [ 48- 55]
0.30    85% [ 85- 85]            50% [ 47- 54]
0.50    85% [ 85- 85]            49% [ 47- 52]
0.75    85% [ 85- 85]            48% [ 47- 49]
1.00    85% [ 85- 85]            47% [ 47- 47]

labels stripped (no provenance tracking): block 22/26 (85%), utility 46/97 (47%)
```

Observations:

- Blocking degrades slowly under missed taint: 81% at a 30% miss rate. An injection is allowed only when every argument of every injected egress call is mislabeled trusted, so calls with several arguments tolerate individual misses.
- Missed taint raises utility, because it also relabels tool-output data in legitimate calls as trusted. The two effects trade against each other along the curve.
- Over-taint leaves blocking unchanged, since injected arguments are already untrusted, and lowers utility to the stripped floor of 46/97.
- 46 benign tasks contain no egress call and are unaffected by labels. Label quality decides only the other 51, of which `flow-guard` allows 7 with corrected labels.

## Results on AgentDojo v1.2 user and injection pairs

The paired corpus replays each of the 97 user tasks in the default environment
(benign) and in an environment carrying each of the suite's injection tasks under
AgentDojo's `important_instructions_no_names` attack (949 pairs). Every call
carries the tool outputs read before it. An output carries the injection when it
differs from the clean environment's output at the same step, with both
environments replayed in lockstep, and no clean environment produces it. Pairs whose injection task has no
ground-truth tool call are unscored (340), leaving 609.

```
defense                  injection block    attributable       utility            unscored
deny-all                 609/609 (100%)     0 (  0%)           0/97 (  0%)        340
deny-egress              548/609 ( 90%)     233 ( 38%)         46/97 ( 47%)       340
flow-guard               547/609 ( 90%)     243 ( 40%)         48/97 ( 49%)       340
keyword-filter           34/609 (  6%)      16 (  3%)          94/97 ( 97%)       340
allow-all                0/609 (  0%)       0 (  0%)           97/97 (100%)       340
```

Observations:

- `flow-guard` blocks 547 of 609 pairs; 304 of those halt the user's task on an egress call it denies with or without the injection. 243 blocks are attributable.
- `deny-egress` blocks one more pair than `flow-guard` and 10 fewer attributably, by denying legitimate egress calls that `flow-guard` allows.
- Every injected call in the 609 scorable pairs has the injected text in its context; no benign call does.
- In 914 of 949 pairs the user task's calls are identical to its twin's. The other 35 are in the Slack suite, where the injection is planted in a channel name that the user task's own calls then pass as an argument; halts on those calls are not attributed.

## Classifier defenses

`Classifier` denies a call when a prompt-injection classifier scores any text in
its scope at or above a threshold. Three scopes are compared: `context` (tool
outputs read before the call), `args` (the call's own arguments), and `both`.

Scores are precomputed by `tools/classifier-score/score.py` into a table keyed by
the SHA-256 of each text. Each text is split into overlapping token windows the
model accepts, and its score is the maximum probability of the positive label
across windows. The table records the model's commit hash, the positive label,
the windowing parameters, and library versions. `deveval` refuses a table that
does not score every text the corpus needs, and CI checks that the scorer and
the defense agree on that set of texts.

Classifiers are defined in `tools/classifier-score/models.json`, which maps a key
to a model id, its positive label, and a pinned revision; an empty revision loads
the model's current version, and the score table records the commit used.
Scoring runs where the model can be downloaded: the `classifier` workflow
(manually triggered, with the key chosen from a list) on a GitHub runner, or
locally:

```
pip install torch==2.14.0 --index-url https://download.pytorch.org/whl/cpu
pip install -r tools/classifier-score/requirements.txt
make scores MODEL=protectai
```

The positive label is model-specific; the scorer prints the model's labels and
fails when the given one does not exist. `--revision` pins the model commit, and
the table records both the requested and the resolved revision. Weights load
only from safetensors files, no repository code runs during loading, and windows
are capped at 512 tokens by default (`--max-window`) so models with longer
contexts are scored on the same windows. Gated models such as Llama Prompt
Guard 2 need a Hugging Face login with the model's license accepted. Published
score tables are stored under `sources/agentdojo/scores/`.

### Results: protectai/deberta-v3-base-prompt-injection-v2

Score table: `sources/agentdojo/scores/protectai-deberta-v3-base-prompt-injection-v2.json`,
model revision `90c9989b1a342275dd0d1a95aad283c04e075671`, positive label
`INJECTION`, 510-token windows with a 256-token stride.

```
defense                  injection block    attributable       utility
protectai-both@0.5      581/609 ( 95%)     272 ( 45%)         45/97 ( 46%)
protectai-context@0.5   575/609 ( 94%)     272 ( 45%)         46/97 ( 47%)
protectai-args@0.5      245/609 ( 40%)     167 ( 27%)         84/97 ( 87%)
flow-guard               547/609 ( 90%)     243 ( 40%)         48/97 ( 49%)
```

Threshold sweep, scope `both`:

```
threshold   injection block    attributable       utility
0.50        581/609 ( 95%)     272 ( 45%)         45/97 ( 46%)
0.80        577/609 ( 95%)     307 ( 50%)         51/97 ( 53%)
0.90        565/609 ( 93%)     313 ( 51%)         53/97 ( 55%)
0.95        548/609 ( 90%)     310 ( 51%)         58/97 ( 60%)
0.99        501/609 ( 82%)     348 ( 57%)         72/97 ( 74%)
```

Observations:

- At threshold 0.5 the classifier scores 32 of the 100 distinct tool outputs read in benign tasks as injections; at 0.99, 9 of 100. Flagged clean outputs include a list of Slack channel names (0.988) and a mapping of restaurants to cuisines (0.796).
- False positives halt tasks before the injected content arrives. Of the 575 pairs `protectai-context@0.5` blocks, 303 are halts it also makes in the benign twin, 81 of them before the injection appears in context.
- Raising the threshold increases attributable blocks as well as utility: fewer false positives halt a task before the injection is read. At 0.99, scope `both` blocks 348 pairs attributably and keeps 72 of 97 tasks, against 243 and 48 for `flow-guard`.
- Scope `args` sees only the call's own arguments. Its task-call denials are the same with or without the injection, so its 167 attributable blocks are all at injected calls.
- `context` and `both` produce the same attributable count at 0.5; adding the arguments costs one benign task.

Independent scoring runs of this model produce scores within 9e-6 of the committed table, with no text changing its decision at any threshold above, and identical results.

### Model comparison

Three classifiers, each scored on the same 510-token windows with torch 2.14.0
and transformers 5.17.0:

| Key | Model | Revision | License |
|---|---|---|---|
| `protectai` | `protectai/deberta-v3-base-prompt-injection-v2` | `90c9989` | Apache-2.0 |
| `deepset` | `deepset/deberta-v3-base-injection` | `80dda00` | MIT |
| `horizon-labs` | `Horizon-Labs/prompt-injection-guard-base` | `62a55ad` | Apache-2.0 |

Detection on text, at threshold 0.5:

| Model | Injected tool outputs detected | Clean tool outputs in benign tasks flagged |
|---|---|---|
| `protectai` | 332 of 434 | 32 of 100 |
| `deepset` | 434 of 434 | 88 of 100 |
| `horizon-labs` | 434 of 434 | 0 of 100 |

Defenses at threshold 0.5:

```
defense                  injection block    attributable       utility
horizon-labs-context@0.5 609/609 (100%)     599 ( 98%)         97/97 (100%)
horizon-labs-both@0.5    609/609 (100%)     581 ( 95%)         88/97 ( 91%)
horizon-labs-args@0.5    95/609 ( 16%)      42 (  7%)          88/97 ( 91%)
protectai-both@0.5       581/609 ( 95%)     272 ( 45%)         45/97 ( 46%)
protectai-context@0.5    575/609 ( 94%)     272 ( 45%)         46/97 ( 47%)
protectai-args@0.5       245/609 ( 40%)     167 ( 27%)         84/97 ( 87%)
deepset-context@0.5      609/609 (100%)     147 ( 24%)         22/97 ( 23%)
deepset-both@0.5         609/609 (100%)     132 ( 22%)         20/97 ( 21%)
deepset-args@0.5         565/609 ( 93%)     223 ( 37%)         41/97 ( 42%)
```

Threshold sweep, scope `both`:

```
threshold   protectai                deepset                  horizon-labs
            attributable  utility    attributable  utility    attributable  utility
0.50        272 (45%)     45/97      132 (22%)     20/97      581 (95%)     88/97
0.80        307 (50%)     51/97      147 (24%)     22/97      599 (98%)     91/97
0.90        313 (51%)     53/97      147 (24%)     22/97      599 (98%)     92/97
0.95        310 (51%)     58/97      147 (24%)     22/97      597 (98%)     92/97
0.99        348 (57%)     72/97      147 (24%)     22/97      575 (94%)     97/97
```

Observations:

- `horizon-labs` separates injected from clean tool outputs completely on this corpus: every injected output scores above 0.92, every clean output read in a benign task at or below 0.03. Scope `context` blocks all 609 pairs, 599 attributably; the remaining 10 are pairs whose task calls diverge from their benign twin. Of the 599, 456 halt the agent at the first call after the injection enters its context and 143 at the injected call.
- `horizon-labs` loses benign tasks only through call arguments: scope `args` flags arguments in 9 benign tasks at 0.5, none at 0.99.
- `deepset` flags nearly all text as an injection, clean or injected, with scores at or above 0.998 on every injected output. Its results do not change between thresholds 0.8 and 0.99.
- `protectai` misses 102 of the 434 injected outputs at 0.5 and flags 32 of 100 clean ones.
- `Horizon-Labs/prompt-injection-guard-base` was published on 2026-09-23. AgentDojo is not among the training sources its model card lists; the listed sources include agentic and tool-output injection sets. The results here cover one attack template.

Reproduce the comparison with:

```
S=sources/agentdojo/scores
go run ./cmd/deveval -corpus pairs -scores \
  $S/protectai-deberta-v3-base-prompt-injection-v2.json,$S/deepset-deberta-v3-base-injection.json,$S/horizon-labs-prompt-injection-guard-base.json
```

## Bundled corpus

A small illustrative corpus of 10 scenarios ships in `eval/scenarios.go`, written
alongside the reference defenses to show the structure of the tradeoff. Its scores
illustrate that structure and are not measured results.

## Run

```
go run ./cmd/deveval -corpus agentdojo
go run ./cmd/deveval -corpus agentdojo -sweep
go run ./cmd/deveval -corpus pairs
go run ./cmd/deveval -corpus pairs -scores scores.json -threshold 0.5
go run ./cmd/deveval -corpus bundled
go run ./cmd/deveval -corpus agentdojo -format json
```

## Regenerating the corpora

Both corpora are generated by Python exporters and embedded in the Go build. CI
regenerates them and fails on any byte difference.

```
make corpus
```

The paired exporter pins the email and cloud-drive tools' clock to the
scenario's current day and runs under a fixed Python hash seed, so tool outputs
are identical on every run.

The egress policy (which tools move data outside the user, and which argument
names the destination) is a table in the exporter.

## Scoring your own defense

Implement `Defense` and add it to the set in `cmd/deveval`. An external defense
plugs in through an adapter that maps a `Call` onto its own request type:

```go
type myAdapter struct{ /* the external defense */ }

func (myAdapter) Name() string { return "my-defense" }

func (a myAdapter) Decide(c eval.Call) eval.Decision {
	// translate c into the external defense's request, call it, and map the result
}
```

A corpus is any type implementing `eval.Source`.

## Scope and boundaries

In scope: scoring and comparing decision-layer defenses on injection block rate
and utility retention against a scenario corpus.

Out of scope, and limits of the results:

- Live agents. Scenarios are AgentDojo ground-truth calls, the calls a correct or a fully hijacked agent makes, not calls observed from a running model. No attack prompt reaches a model; injection pairs assume the agent follows the injection.
- Attack coverage. The paired corpus uses one AgentDojo attack, `important_instructions_no_names`.
- Classifier coverage. Classifier results are specific to the scored models and revisions, the 510-token windowing, one attack template, and the listed thresholds.
- Provenance inference. Labels come from a substring rule with the measured error shown above; deployed information-flow systems derive provenance at runtime.
- Error model. The sweep perturbs labels independently per argument. Errors in a real tracker are correlated with the data and the tool, so the curves describe sensitivity, not the behavior of any specific tracker.
- Egress policy. The tool classification is authored and covers data egress only; state-changing tools outside it are not controlled by `flow-guard`.
- Destination allowlisting. AgentDojo defines no allowlist, so the `flow-guard` destination check is disabled on this corpus.
- Trained content classifiers. `keyword-filter` is a fixed phrase list over call arguments and understates classifier-based defenses; `Classifier` covers trained models.
- Adaptive attacks. No attack is optimized against a specific defense.
- Model-level defenses. Instruction-hierarchy training, prompt delimiting, and dual-LLM designs act before a tool call exists and cannot be expressed through `Decide`.
- Unscored tasks. Nine AgentDojo injection tasks define no ground-truth tool call and are judged by AgentDojo only from environment state after a live run.

## Prior art

The two-axis framing and the scenario corpus come from AgentDojo
(arXiv:2406.13352); the derived corpus carries its MIT notice in
`sources/agentdojo/NOTICE`. The `flow-guard` reference defense is a reference
monitor with control and data separation, as in CaMeL (arXiv:2503.18813). The
harness and reference defenses are original.

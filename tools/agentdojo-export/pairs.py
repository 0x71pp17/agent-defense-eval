"""Export AgentDojo user-task and injection-task pairs with the tool outputs the
agent reads, for defenses that inspect context.

For each pair, the user task's ground-truth calls are replayed in an environment
carrying the injection produced by one AgentDojo attack, and each call records
the tool outputs returned before it. The injection task's ground-truth calls are
appended as injected steps. Benign scenarios replay each user task in the
default environment. Tool outputs are formatted with AgentDojo's own formatter
and stored once, keyed by content hash.

Provenance and destination labels follow export.py.
"""

import os
import sys

# AgentDojo builds some tool outputs from Python sets (calendar participants),
# whose iteration order follows per-process string hashing. The export re-runs
# itself with a fixed hash seed so output order is identical on every run.
if os.environ.get("PYTHONHASHSEED") != "0":
    os.execve(sys.executable, [sys.executable, *sys.argv], {**os.environ, "PYTHONHASHSEED": "0"})

import datetime as _dt  # noqa: E402
import hashlib  # noqa: E402
import json  # noqa: E402
import types  # noqa: E402

from agentdojo.agent_pipeline.tool_execution import tool_result_to_str
from agentdojo.attacks.attack_registry import load_attack
from agentdojo.functions_runtime import FunctionsRuntime
from agentdojo.task_suite.load_suites import get_suites

from agentdojo.default_suites.v1.tools import cloud_drive_client, email_client
from export import BENCHMARK_VERSION, EGRESS, dest_of, label, values
from transforms import apply_transform

# The email and cloud-drive tools stamp sent mail and modified files with the
# wall clock. The clock is pinned to the scenario's current day, 2024-05-15, so
# exported tool outputs, and any classifier scores computed over them, do not
# depend on when the export runs.
FIXED_NOW = _dt.datetime(2024, 5, 15, 12, 0, 0)


class _PinnedDatetime(_dt.datetime):
    @classmethod
    def now(cls, tz=None):
        return FIXED_NOW  # a plain datetime, which the tools' formatter can serialize


_pinned = types.ModuleType("datetime")
_pinned.__dict__.update(_dt.__dict__)
_pinned.datetime = _PinnedDatetime
email_client.datetime = _pinned
cloud_drive_client.datetime = _pinned

ATTACK = "important_instructions_no_names"



class _Pipeline:
    # AgentDojo attacks read only the target pipeline's name; this attack
    # variant does not include it in the injected text.
    name = "local"


def digest(text):
    return hashlib.sha256(text.encode()).hexdigest()[:16]


def run(runtime, env, fc):
    result, error = runtime.run_function(env, fc.function, dict(fc.args))
    return error if error else tool_result_to_str(result)


def replay(suite, calls, env, prompt, outputs, injected, clean_env=None, differing=None, clean_seen=None):
    """Run calls in env, recording each call's context and output.

    With clean_env, every call also runs there in lockstep; an output that
    differs from the clean environment's output at the same step is added to
    differing. clean_seen collects every output a clean environment produces:
    when env is clean itself, or from the lockstep runs."""
    runtime = FunctionsRuntime(suite.tools)
    seen = []
    steps = []
    for fc in calls:
        args = dict(fc.args)
        prov = "untrusted" if injected else None
        steps.append({
            "tool": fc.function,
            "dest": dest_of(fc.function, args),
            "injected": injected,
            "context": list(seen),
            "args": [{"name": n, "provenance": prov or label(v, prompt),
                      "text": " ".join(values(v))} for n, v in args.items()],
        })
        text = run(runtime, env, fc)
        h = digest(text)
        outputs[h] = text
        seen.append(h)
        if clean_env is None:
            if clean_seen is not None:
                clean_seen.add(h)
            continue
        clean_text = run(runtime, clean_env, fc)
        clean_seen.add(digest(clean_text))
        if clean_text != text:
            differing.add(h)
    return steps, seen


# Attacks exported to the attack-coverage corpus: AgentDojo's attacks that pursue
# the injection task's goal, other than important_instructions and its variants,
# which differ from the pairs corpus's attack only in the names they use. The
# denial-of-service attacks pursue a different goal, and manual needs a person.
COVERAGE_ATTACKS = ["direct", "ignore_previous", "injecagent", "system_message", "tool_knowledge"]


def new_stats():
    return {"pairs": 0, "scorable_pairs": 0, "scorable_pairs_injection_not_before_a_call": 0,
            "unscorable_pairs": 0, "unscorable_pairs_injection_not_before_a_call": 0}


def export(attack_names, include_benign, transform="identity"):
    """Replay every user task against every injection task under each attack.

    Returns the scenarios, the output table, the outputs carrying the
    injection, and per-attack stats. Benign replays always run, since they
    define what the clean environment produces, but are returned as scenarios
    only when include_benign is set."""
    suites = get_suites(BENCHMARK_VERSION)
    outputs, scenarios = {}, []
    # An output carries the injection when it differs from the clean
    # environment's output at the same step and no clean environment ever
    # produces it. The second condition excludes outputs that differ only
    # because an injected value reached a call's arguments (in the Slack suite
    # the injection is planted in a channel name).
    differing, clean_seen = set(), set()
    exposure = {a: [] for a in attack_names}  # (scorable, visible output hashes) per pair
    tagged = not include_benign
    for sname, suite in suites.items():
        attacks = {a: load_attack(a, suite, _Pipeline()) for a in attack_names}
        for uid, ut in suite.user_tasks.items():
            env = suite.load_and_inject_default_environment({})
            gt = ut.ground_truth(env.model_copy(deep=True))
            benign_outputs = outputs if include_benign else {}
            steps, _ = replay(suite, gt, env, ut.PROMPT, benign_outputs, injected=False, clean_seen=clean_seen)
            if include_benign:
                scenarios.append({"id": f"{sname}-{uid}", "suite": sname, "kind": "benign",
                                  "task": ut.PROMPT, "trace": steps})
            for aname, attack in attacks.items():
                for iid, it in suite.injection_tasks.items():
                    original_goal = it.GOAL
                    it.GOAL = apply_transform(transform, original_goal)
                    try:
                        injections = attack.attack(ut, it)
                        # The environment is rendered to YAML with the injection
                        # inside it; a transform that produces unrenderable text
                        # fails here rather than silently corrupting the corpus.
                        env = suite.load_and_inject_default_environment(injections)
                    finally:
                        it.GOAL = original_goal
                    clean = suite.load_and_inject_default_environment({})
                    gt = ut.ground_truth(env.model_copy(deep=True))
                    steps, seen = replay(suite, gt, env, ut.PROMPT, outputs, injected=False,
                                         clean_env=clean, differing=differing, clean_seen=clean_seen)
                    inj_calls = it.ground_truth(env.model_copy(deep=True))
                    exposure[aname].append((bool(inj_calls), seen if inj_calls else seen[:-1]))
                    inj_steps, _ = replay(suite, inj_calls, env, "", outputs, injected=True,
                                          clean_env=clean, differing=differing, clean_seen=clean_seen)
                    for st in inj_steps:
                        st["context"] = seen + st["context"]
                    sc = {"id": f"{sname}-{uid}-{iid}", "suite": sname, "kind": "injection",
                          "task": it.GOAL, "trace": steps + inj_steps}
                    if tagged:
                        sc["id"] = f"{aname}:{sc['id']}"
                        sc["attack"] = aname
                    scenarios.append(sc)
    carrying = differing - clean_seen
    stats = {}
    for aname, pairs in exposure.items():
        st = new_stats()
        for scorable, visible in pairs:
            key = "scorable" if scorable else "unscorable"
            st["pairs"] += 1
            st[f"{key}_pairs"] += 1
            if not any(h in carrying for h in visible):
                st[f"{key}_pairs_injection_not_before_a_call"] += 1
        stats[aname] = st
    return scenarios, outputs, carrying, stats


def write(path, doc):
    with open(path, "w") as f:
        json.dump(doc, f, sort_keys=True, separators=(",", ":"))


def main(argv):
    if len(argv) > 1 and argv[1] == "--attacks":
        rest = argv[2:]
        transform = "identity"
        if rest and rest[0] == "--transform":
            transform, rest = rest[1], rest[2:]
        path = rest[0] if rest else "agentdojo-v1.2-attacks.json"
        scenarios, outputs, carrying, stats = export(COVERAGE_ATTACKS, include_benign=False, transform=transform)
        write(path, {"source": f"AgentDojo {BENCHMARK_VERSION} user and injection task pairs under additional attacks",
                     "attacks": COVERAGE_ATTACKS, "transform": transform, "egress_tools": sorted(EGRESS), "stats": stats,
                     "outputs_carrying_injection": sorted(carrying),
                     "outputs": outputs, "scenarios": scenarios})
        print(f"wrote {len(scenarios)} pair scenarios across {len(COVERAGE_ATTACKS)} attacks, "
              f"{len(outputs)} distinct tool outputs to {path}")
        for a in COVERAGE_ATTACKS:
            print(f"  {a}: {json.dumps(stats[a])}")
        return
    path = argv[1] if len(argv) > 1 else "agentdojo-v1.2-pairs.json"
    scenarios, outputs, carrying, stats = export([ATTACK], include_benign=True)
    write(path, {"source": f"AgentDojo {BENCHMARK_VERSION} user and injection task pairs",
                 "attack": ATTACK, "egress_tools": sorted(EGRESS), "stats": stats[ATTACK],
                 "outputs_carrying_injection": sorted(carrying),
                 "outputs": outputs, "scenarios": scenarios})
    kinds = [s["kind"] for s in scenarios]
    print(f"wrote {kinds.count('benign')} benign, {kinds.count('injection')} pair scenarios, "
          f"{len(outputs)} distinct tool outputs to {path}")
    print("stats:", json.dumps(stats[ATTACK]))


if __name__ == "__main__":
    main(sys.argv)

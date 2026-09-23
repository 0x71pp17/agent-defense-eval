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
# Every injection this attack produces opens with this tag. Environment
# rendering rewrites whitespace and quoting inside the injected text, so exposure
# is detected by the tag rather than by matching the full string.
ATTACK_MARKER = "<INFORMATION>"


class _Pipeline:
    # AgentDojo attacks read only the target pipeline's name; this attack
    # variant does not include it in the injected text.
    name = "local"


def digest(text):
    return hashlib.sha256(text.encode()).hexdigest()[:16]


def replay(suite, calls, env, prompt, outputs, injected):
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
        result, error = runtime.run_function(env, fc.function, args)
        text = error if error else tool_result_to_str(result)
        h = digest(text)
        outputs[h] = text
        seen.append(h)
    return steps, seen


def main(path):
    suites = get_suites(BENCHMARK_VERSION)
    outputs = {}
    scenarios = []
    stats = {"pairs": 0, "scorable_pairs": 0, "scorable_pairs_injection_not_before_a_call": 0,
             "unscorable_pairs": 0, "unscorable_pairs_injection_not_before_a_call": 0}
    for sname, suite in suites.items():
        attack = load_attack(ATTACK, suite, _Pipeline())
        for uid, ut in suite.user_tasks.items():
            env = suite.load_and_inject_default_environment({})
            gt = ut.ground_truth(env.model_copy(deep=True))
            steps, _ = replay(suite, gt, env, ut.PROMPT, outputs, injected=False)
            scenarios.append({"id": f"{sname}-{uid}", "suite": sname, "kind": "benign",
                              "task": ut.PROMPT, "trace": steps})
            for iid, it in suite.injection_tasks.items():
                injections = attack.attack(ut, it)
                env = suite.load_and_inject_default_environment(injections)
                gt = ut.ground_truth(env.model_copy(deep=True))
                steps, seen = replay(suite, gt, env, ut.PROMPT, outputs, injected=False)
                inj_calls = it.ground_truth(env.model_copy(deep=True))
                visible = seen if inj_calls else seen[:-1]
                exposed = any(ATTACK_MARKER in outputs[h] for h in visible)
                key = "scorable" if inj_calls else "unscorable"
                stats[f"{key}_pairs"] += 1
                if not exposed:
                    stats[f"{key}_pairs_injection_not_before_a_call"] += 1
                inj_steps, _ = replay(suite, inj_calls, env, "", outputs, injected=True)
                for st in inj_steps:
                    st["context"] = seen + st["context"]
                scenarios.append({"id": f"{sname}-{uid}-{iid}", "suite": sname, "kind": "injection",
                                  "task": it.GOAL, "trace": steps + inj_steps})
                stats["pairs"] += 1
    doc = {"source": f"AgentDojo {BENCHMARK_VERSION} user and injection task pairs",
           "attack": ATTACK, "attack_marker": ATTACK_MARKER, "egress_tools": sorted(EGRESS), "stats": stats,
           "outputs": outputs, "scenarios": scenarios}
    with open(path, "w") as f:
        json.dump(doc, f, sort_keys=True, separators=(",", ":"))
    kinds = [s["kind"] for s in scenarios]
    print(f"wrote {kinds.count('benign')} benign, {kinds.count('injection')} pair scenarios, "
          f"{len(outputs)} distinct tool outputs to {path}")
    print("stats:", json.dumps(stats))


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "agentdojo-v1.2-pairs.json")

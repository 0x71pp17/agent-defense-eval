"""Export AgentDojo task ground truth into the agent-defense-eval corpus format.

Each AgentDojo user task becomes a benign scenario and each injection task an
injection scenario, using the task's own ground-truth tool calls.

Provenance rule: an argument is trusted when every value in it appears in the
user task's prompt (case-insensitive substring), and untrusted otherwise.
Injection tasks have no user prompt, so their arguments are untrusted.

Each argument also records its origin: "prompt", "environment" (found in the
suite's default environment data), or "neither".

Diagnostic: every untrusted label on a benign call is checked against the
suite's default environment. A value present in the environment is consistent
with tool-output origin. A value in neither the prompt nor the environment was
most likely produced by the agent itself (a date, a computed amount), which the
rule labels untrusted although an information-flow tracker would not.
"""

import json
import sys

from agentdojo.task_suite.load_suites import get_suites

BENCHMARK_VERSION = "v1.2"

# Policy table: tools that move data or authority to a party outside the user,
# and the argument that names the destination.
EGRESS = {
    "send_money": "recipient",
    "schedule_transaction": "recipient",
    "update_scheduled_transaction": "recipient",
    "send_email": "recipients",
    "share_file": "email",
    "create_calendar_event": "participants",
    "add_calendar_event_participants": "participants",
    "send_direct_message": "recipient",
    "send_channel_message": "channel",
    "invite_user_to_slack": "user_email",
    "add_user_to_channel": "user",
    "post_webpage": "url",
    "get_webpage": "url",
}


def values(v):
    if v is None:
        return []
    if isinstance(v, (list, tuple)):
        out = []
        for x in v:
            out.extend(values(x))
        return out
    return [str(v)]


def label(v, prompt):
    vals = [x for x in values(v) if x != ""]
    if not vals:
        return "trusted"
    low = prompt.lower()
    return "trusted" if all(x.lower() in low for x in vals) else "untrusted"


def dest_of(tool, args):
    key = EGRESS.get(tool)
    if key is None or args.get(key) is None:
        return ""
    return ",".join(values(args[key]))


def convert(calls, prompt, env_text, diag, benign):
    steps = []
    for fc in calls:
        args = dict(fc.args)
        out_args = []
        for name, v in args.items():
            prov = label(v, prompt)
            origin = "prompt"
            if prov == "untrusted":
                in_env = all(x.lower() in env_text for x in values(v) if x != "")
                origin = "environment" if in_env else "neither"
                if benign:
                    diag["benign_untrusted_args"] += 1
                    diag["untrusted_in_environment" if in_env else "untrusted_in_neither"] += 1
            out_args.append({"name": name, "provenance": prov, "origin": origin,
                             "text": " ".join(values(v))})
        steps.append({"tool": fc.function, "args": out_args, "dest": dest_of(fc.function, args)})
    return steps


def main(path):
    suites = get_suites(BENCHMARK_VERSION)
    scenarios = []
    diag = {"benign_untrusted_args": 0, "untrusted_in_environment": 0,
            "untrusted_in_neither": 0, "tasks_skipped": 0}
    for suite_name, suite in suites.items():
        env = suite.load_and_inject_default_environment({})
        env_text = env.model_dump_json().lower()
        for tid, task in suite.user_tasks.items():
            try:
                calls = task.ground_truth(env.model_copy(deep=True))
            except Exception:
                diag["tasks_skipped"] += 1
                continue
            scenarios.append({
                "id": f"{suite_name}-{tid}", "suite": suite_name, "kind": "benign",
                "task": task.PROMPT,
                "trace": convert(calls, task.PROMPT, env_text, diag, benign=True),
            })
        for tid, task in suite.injection_tasks.items():
            try:
                calls = task.ground_truth(env.model_copy(deep=True))
            except Exception:
                diag["tasks_skipped"] += 1
                continue
            scenarios.append({
                "id": f"{suite_name}-{tid}", "suite": suite_name, "kind": "injection",
                "task": task.GOAL,
                "trace": convert(calls, "", env_text, diag, benign=False),
            })
    doc = {
        "source": f"AgentDojo {BENCHMARK_VERSION} task ground truth",
        "egress_tools": sorted(EGRESS),
        "diagnostics": diag,
        "scenarios": scenarios,
    }
    with open(path, "w") as f:
        json.dump(doc, f, indent=1, sort_keys=True)
    kinds = [s["kind"] for s in scenarios]
    print(f"wrote {len(scenarios)} scenarios "
          f"({kinds.count('benign')} benign, {kinds.count('injection')} injection) to {path}")
    print("diagnostics:", json.dumps(diag))


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "agentdojo-v1.2.json")

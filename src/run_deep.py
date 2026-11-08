"""Run the Deep hardened detection loop and write deterministic results.

Run: python src/run_deep.py
Reads the Build synthetic sample logs, experiments/config.json,
the Learn after snapshot (the hardened baseline), and
experiments/snapshot_current.json. Runs the hardened loop, walks
the incident through its full lifecycle using recorded review
timestamps (not the wall clock), and writes
results/results_deep.json. No wall clock, no randomness, so
two runs produce an identical file.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
EXP = os.path.join(ROOT, "experiments")
RES = os.path.join(ROOT, "results")
sys.path.insert(0, HERE)
import run_build  # noqa: E402
from detection_hardened import run_deep, transition  # noqa: E402

# Recorded review times for the lifecycle walkthrough. These are
# fixed synthetic review timestamps for this teaching run, stated
# here so the results file stays deterministic.
REVIEW_STEPS = [
    ("triaged", "2026-11-05T11:00:00Z", "lab-reviewer",
     "Alerts A001 and A002 confirmed against the synthetic log lines."),
    ("contained", "2026-11-05T11:30:00Z", "lab-reviewer",
     "Affected synthetic accounts and the drifted controls noted for "
     "correction in the runbook."),
    ("closed", "2026-11-05T12:00:00Z", "lab-reviewer",
     "Closure checklist complete; incident closed."),
]
CLOSURE_DONE = {"accounts_reviewed": True, "ports_checked": True,
                "updates_confirmed": True,
                "closure_note_recorded": True}


def load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def main():
    with open(os.path.join(EXP, "config.json"), encoding="utf-8") as f:
        config = json.load(f)
    baseline = load_json(os.path.join(
        EXP, "snapshot_after.json"))
    current = load_json(os.path.join(EXP, "snapshot_current.json"))
    result = run_deep(run_build.load_sources(), config, baseline, current)
    incident = result["incident"]
    for to_state, at_ts, actor, note in REVIEW_STEPS:
        checklist = CLOSURE_DONE if to_state == "closed" else None
        transition(incident, to_state, at_ts, actor, note,
                   checklist=checklist)
    s = result["sources"]["total"]
    print(f"Lines {s['lines']}, parsed {s['parsed']}, "
          f"quarantined {s['quarantined']}")
    for rule in ("R1", "R2", "R3", "R4", "R5"):
        r = result["per_rule"][rule]
        print(f"{rule}: firings {r['firings_before_dedup']}, "
              f"alerts {r['alerts_after_dedup']}")
    drift = result["baseline_drift"]
    print(f"Drift: {drift['drift_count']} controls "
          f"({', '.join(drift['drifted_controls'])})")
    print(f"Alerts total {result['alerts_total_after_dedup']}, "
          f"incident {incident['incident_id']} "
          f"lifecycle {incident['lifecycle']}")
    path = os.path.join(RES, "results_deep.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, sort_keys=True)
        f.write("\n")
    print("Wrote", path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

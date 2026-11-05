"""Run the Deep hardened detection loop and write deterministic results.

Run: python level-3-deep/run_deep.py
Reads the Build synthetic sample logs, level-3-deep/config.json,
the Learn after snapshot (the hardened baseline), and
level-3-deep/snapshot_current.json. Runs the hardened loop, walks
the incident through its full lifecycle using recorded review
timestamps (not the wall clock), and writes
level-3-deep/results_deep.json. No wall clock, no randomness, so
two runs produce an identical file.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
from detection_hardened import run_deep, transition  # noqa: E402

BUILD_DIR = os.path.join(ROOT, "level-2-build")
sys.path.insert(0, BUILD_DIR)
import run_build  # noqa: E402

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
    with open(os.path.join(HERE, "config.json"), encoding="utf-8") as f:
        config = json.load(f)
    baseline = load_json(os.path.join(
        ROOT, "level-1-learn", "snapshot_after.json"))
    current = load_json(os.path.join(HERE, "snapshot_current.json"))
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
    path = os.path.join(HERE, "results_deep.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, sort_keys=True)
        f.write("\n")
    print("Wrote", path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

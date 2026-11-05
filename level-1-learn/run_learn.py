"""Run the Learn hardening check and write deterministic results.

Run: python level-1-learn/run_learn.py
Reads snapshot_before.json and snapshot_after.json (both synthetic
teaching data in this folder), evaluates both against the 10-control
checklist, and writes level-1-learn/results_learn.json. No timestamps,
no randomness, so two runs produce an identical file.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from hardening import compare_snapshots  # noqa: E402


def load(name):
    with open(os.path.join(HERE, name), encoding="utf-8") as f:
        return json.load(f)


def main():
    result = compare_snapshots(load("snapshot_before.json"),
                               load("snapshot_after.json"))
    for phase in ("before", "after"):
        r = result[phase]
        print(f"{phase}: {r['passed']} of {r['total']} controls passed "
              f"({r['score_percent']} percent)")
        for c in r["controls"]:
            state = "PASS" if c["passed"] else "FAIL"
            print(f"  {c['control_id']} {c['control']}: {state}")
    s = result["summary"]
    print(f"Summary: before {s['before_passed']} of {s['controls_total']}, "
          f"after {s['after_passed']} of {s['controls_total']}, "
          f"improvement +{s['improvement']}")
    out = {"scenario": "hardening baseline on one synthetic lab VM snapshot, "
                       "10 controls, defensive scope only",
           "before": result["before"], "after": result["after"],
           "summary": s}
    path = os.path.join(HERE, "results_learn.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, sort_keys=True)
        f.write("\n")
    print("Wrote", path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

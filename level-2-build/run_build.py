"""Run the Build detection loop and write deterministic results.

Run: python level-2-build/run_build.py
Reads the four synthetic sample log files in level-2-build/sample_logs/,
runs the defensive detection loop, and writes
level-2-build/results_build.json. Central aggregation is held in the
results structure (records list plus per-source totals); no
central_log.jsonl file is generated, so no generated log churn is
committed. No timestamps from the wall clock, no randomness, so two
runs produce an identical file.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from detection import run_detection  # noqa: E402

SOURCE_FILES = {"auth": "auth.log", "sudo": "sudo.log",
                "service": "service.log", "firewall": "firewall.log"}


def load_sources():
    sources = {}
    log_dir = os.path.join(HERE, "sample_logs")
    for source, name in SOURCE_FILES.items():
        with open(os.path.join(log_dir, name), encoding="utf-8") as f:
            sources[source] = f.read().splitlines()
    return sources


def main():
    result = run_detection(load_sources())
    s = result["sources"]["total"]
    print(f"Lines {s['lines']}, parsed {s['parsed']}, "
          f"quarantined {s['quarantined']}")
    for rule in ("R1", "R2", "R3", "R4"):
        r = result["per_rule"][rule]
        print(f"{rule}: firings {r['firings_before_dedup']}, "
              f"alerts {r['alerts_after_dedup']}")
    print(f"Alerts total {result['alerts_total_after_dedup']}, "
          f"incident {result['incident']['incident_id']} "
          f"opened {result['incident']['opened_at']}")
    path = os.path.join(HERE, "results_build.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, sort_keys=True)
        f.write("\n")
    print("Wrote", path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

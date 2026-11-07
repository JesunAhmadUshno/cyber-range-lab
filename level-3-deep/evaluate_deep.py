"""Threshold sweep and authored-intent sanity check for the Deep loop.

Run: python level-3-deep/evaluate_deep.py
Writes level-3-deep/results_eval.json. Two parts, both deterministic:

1. Sweep: R1 firings, R1 alerts and total alerts (R1 to R5) for
   failed_login_threshold 1 to 10 and failed_login_window_seconds
   60, 300, 600, 900, 1800, all other config values at their defaults.
2. Authored intent: precision and episode recall per rule against
   authored_intent.json. These labels were written by the same hand
   as the logs and rules, so this is a circular sanity check, never
   an evaluation of detection quality on real logs.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, "level-2-build"))
import run_build  # noqa: E402
from detection_hardened import (  # noqa: E402
    baseline_drift,
    build_detection,
    deduplicate_configured,
    ingest,
    run_rules_configured,
)

THRESHOLDS = list(range(1, 11))
WINDOWS = [60, 300, 600, 900, 1800]
RULE_SOURCE = {"R1": "auth", "R2": "sudo", "R3": "service", "R4": "service"}


def load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def line_episodes(sources, labels):
    """Map (source, ts) to the authored episode id of that line."""
    out = {}
    for source, lines in sources.items():
        tags = labels["lines"][source]
        for line, tag in zip([x for x in lines if x.strip()], tags):
            rec = build_detection.parse_line(source, line)
            if rec is not None and tag is not None:
                out[(source, rec["ts"])] = tag
    return out


def intent_scores(firings, episodes_of, labels):
    """Precision and episode recall for R1 to R4 against authored intent."""
    eps = labels["episodes"]
    out = {}
    for rule, source in RULE_SOURCE.items():
        fired = [episodes_of[(source, f["ts"])] for f in firings if f["rule"] == rule]
        hits = [e for e in fired if eps[e]["intent"] == "suspicious"]
        expected = sorted(e for e, v in eps.items() if v["expected_rule"] == rule)
        found = sorted({e for e in fired if e in expected})
        out[rule] = {
            "firings": len(fired),
            "firings_on_suspicious_lines": len(hits),
            "precision": round(len(hits) / len(fired), 4) if fired else None,
            "episodes_expected": expected,
            "episodes_found": found,
            "episode_recall": round(len(found) / len(expected), 4) if expected else None,
            "benign_episodes_fired": sorted({e for e in fired if eps[e]["intent"] == "benign"}),
        }
    return out


def evaluate(config, labels, baseline, current, sources):
    """Full deterministic evaluation dict (the content of results_eval.json)."""
    records, _ = ingest(sources)
    drift, _ = baseline_drift(baseline, current, max(r["ts"] for r in records))
    episodes_of = line_episodes(sources, labels)
    sweep = []
    for window in WINDOWS:
        for threshold in THRESHOLDS:
            cfg = dict(config, failed_login_threshold=threshold, failed_login_window_seconds=window)
            firings = run_rules_configured(records, cfg)
            alerts = deduplicate_configured(firings + drift, cfg)
            r1 = intent_scores(firings, episodes_of, labels)["R1"]
            sweep.append({
                "failed_login_window_seconds": window,
                "failed_login_threshold": threshold,
                "r1_firings": r1["firings"],
                "r1_alerts": sum(1 for a in alerts if a["rule"] == "R1"),
                "alerts_total": len(alerts),
                "r1_precision": r1["precision"],
                "r1_episode_recall": r1["episode_recall"],
            })
    return {
        "synthetic": True,
        "scenario": "R1 threshold and window sweep plus an authored-intent sanity check "
                    "on the synthetic logs, defensive scope only",
        "default_config": config,
        "thresholds": THRESHOLDS,
        "windows_seconds": WINDOWS,
        "sweep": sweep,
        "authored_intent_caveat": labels["caveat"],
        "authored_intent_default_config": intent_scores(
            run_rules_configured(records, config), episodes_of, labels),
    }


def main():
    result = evaluate(
        load_json(os.path.join(HERE, "config.json")),
        load_json(os.path.join(HERE, "authored_intent.json")),
        load_json(os.path.join(ROOT, "level-1-learn", "snapshot_after.json")),
        load_json(os.path.join(HERE, "snapshot_current.json")),
        run_build.load_sources())
    for row in result["sweep"]:
        if row["failed_login_window_seconds"] == 600:
            print(f"threshold {row['failed_login_threshold']}: R1 firings {row['r1_firings']}, "
                  f"alerts {row['alerts_total']}, precision {row['r1_precision']}, "
                  f"recall {row['r1_episode_recall']}")
    path = os.path.join(HERE, "results_eval.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, sort_keys=True)
        f.write("\n")
    print("Wrote", path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

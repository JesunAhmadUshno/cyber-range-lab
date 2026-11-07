"""Tests for the Deep threshold sweep and the authored-intent sanity check."""
import json
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEEP = os.path.join(ROOT, "level-3-deep")
sys.path.insert(0, DEEP)
sys.path.insert(0, os.path.join(ROOT, "level-2-build"))
import evaluate_deep  # noqa: E402
import run_build  # noqa: E402


def load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def fresh():
    return evaluate_deep.evaluate(
        load_json(os.path.join(DEEP, "config.json")),
        load_json(os.path.join(DEEP, "authored_intent.json")),
        load_json(os.path.join(ROOT, "level-1-learn", "snapshot_after.json")),
        load_json(os.path.join(DEEP, "snapshot_current.json")),
        run_build.load_sources())


def row(result, threshold, window=600):
    return next(r for r in result["sweep"] if r["failed_login_threshold"] == threshold
                and r["failed_login_window_seconds"] == window)


class TestEval(unittest.TestCase):
    def test_committed_file_matches_a_fresh_run(self):
        self.assertEqual(load_json(os.path.join(DEEP, "results_eval.json")), fresh())

    def test_sweep_anchors_match_recorded_deep_results(self):
        result, deep = fresh(), load_json(os.path.join(DEEP, "results_deep.json"))
        self.assertEqual(row(result, 5)["r1_firings"], deep["per_rule"]["R1"]["firings_before_dedup"])
        self.assertEqual(row(result, 5)["alerts_total"], deep["alerts_total_after_dedup"])
        self.assertEqual(row(result, 3)["r1_firings"], deep["threshold_check_threshold_3"]["r1_firings"])

    def test_threshold_four_fires_on_the_benign_near_miss(self):
        r = row(fresh(), 4)
        self.assertEqual(r["r1_firings"], 4)
        self.assertEqual(r["r1_precision"], 0.75)

    def test_threshold_seven_misses_the_burst(self):
        r = row(fresh(), 7)
        self.assertEqual(r["r1_firings"], 0)
        self.assertEqual(r["r1_episode_recall"], 0.0)

    def test_labels_cover_every_non_blank_line(self):
        labels = load_json(os.path.join(DEEP, "authored_intent.json"))
        for source, lines in run_build.load_sources().items():
            self.assertEqual(len(labels["lines"][source]), len([x for x in lines if x.strip()]), source)


if __name__ == "__main__":
    unittest.main()

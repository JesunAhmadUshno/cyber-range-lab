"""Unit tests for Level 3 Deep hardened detection. Hand-computed.

Regression expectations come from the Build results on the same
synthetic sample logs: 26 lines, 24 parsed, 2 quarantined; R1 2,
R2 2, R3 1, R4 2 firings under the default config. Deep adds R5:
the current snapshot drifts on C01 and C07 against the Learn
after snapshot, so R5 fires 2 times and dedups to 1 alert.
Totals: 9 firings, 5 alerts.
"""
import copy
import json
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEEP = os.path.join(ROOT, "level-3-deep")
BUILD = os.path.join(ROOT, "level-2-build")
LEARN = os.path.join(ROOT, "level-1-learn")
sys.path.insert(0, DEEP)
sys.path.insert(0, BUILD)
from detection_hardened import (  # noqa: E402
    DEFAULT_CONFIG, DetectionConfigError, IncidentError,
    baseline_drift, new_incident, run_rules_configured,
    transition, validate_config,
)
import run_build  # noqa: E402
import run_deep as run_deep_module  # noqa: E402
from detection_hardened import run_deep as run_deep_fn  # noqa: E402


def load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


BASELINE = load_json(os.path.join(LEARN, "snapshot_after.json"))
CURRENT = load_json(os.path.join(DEEP, "snapshot_current.json"))
CONFIG = load_json(os.path.join(DEEP, "config.json"))


def deep_result():
    return run_deep_fn(run_build.load_sources(), CONFIG, BASELINE, CURRENT)


class TestConfig(unittest.TestCase):
    def test_config_file_equals_build_defaults(self):
        self.assertEqual(validate_config(CONFIG), validate_config(
            DEFAULT_CONFIG))

    def test_missing_field_rejected(self):
        bad = dict(CONFIG)
        del bad["admin_users"]
        with self.assertRaises(DetectionConfigError):
            validate_config(bad)

    def test_bad_threshold_rejected(self):
        for value in (0, -1, "5", True, 2.5):
            bad = copy.deepcopy(CONFIG)
            bad["failed_login_threshold"] = value
            with self.assertRaises(DetectionConfigError):
                validate_config(bad)

    def test_bad_ports_rejected(self):
        for value in ([], [22, 22], [0], [70000], ["22"]):
            bad = copy.deepcopy(CONFIG)
            bad["baseline_ports"] = value
            with self.assertRaises(DetectionConfigError):
                validate_config(bad)

    def test_duplicate_admin_users_rejected(self):
        bad = copy.deepcopy(CONFIG)
        bad["admin_users"] = ["labadmin", "labadmin"]
        with self.assertRaises(DetectionConfigError):
            validate_config(bad)


class TestRegression(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = deep_result()

    def test_source_totals_preserved(self):
        self.assertEqual(self.result["sources"]["total"],
                         {"lines": 26, "parsed": 24, "quarantined": 2})

    def test_build_rules_preserved(self):
        per = self.result["per_rule"]
        self.assertEqual(per["R1"], {"firings_before_dedup": 2,
                                     "alerts_after_dedup": 1})
        self.assertEqual(per["R2"], {"firings_before_dedup": 2,
                                     "alerts_after_dedup": 1})
        self.assertEqual(per["R3"], {"firings_before_dedup": 1,
                                     "alerts_after_dedup": 1})
        self.assertEqual(per["R4"], {"firings_before_dedup": 2,
                                     "alerts_after_dedup": 1})

    def test_deep_totals(self):
        self.assertEqual(self.result["firings_total_before_dedup"], 9)
        self.assertEqual(self.result["alerts_total_after_dedup"], 5)

    def test_incident_identity_preserved(self):
        inc = self.result["incident"]
        self.assertEqual(inc["incident_id"], "INC-001")
        self.assertEqual(inc["opened_at"], "2026-11-05T10:08:00Z")
        self.assertEqual(inc["alert_ids"], ["A001", "A002"])
        self.assertEqual(inc["affected_users"], ["alice", "guest"])
        self.assertEqual(inc["lifecycle"], "open")

    def test_threshold_change_changes_r1(self):
        records, _ = __import__("detection_hardened").ingest(
            run_build.load_sources())
        cfg = copy.deepcopy(CONFIG)
        cfg["failed_login_threshold"] = 3
        firings = run_rules_configured(records, cfg)
        self.assertEqual(
            sum(1 for f in firings if f["rule"] == "R1"), 6)
        self.assertEqual(self.result["threshold_check_threshold_3"]
                         ["r1_firings"], 6)

    def test_admin_list_from_config(self):
        records, _ = __import__("detection_hardened").ingest(
            run_build.load_sources())
        cfg = copy.deepcopy(CONFIG)
        cfg["admin_users"] = ["labadmin", "laboperator", "guest"]
        firings = run_rules_configured(records, cfg)
        self.assertEqual(
            sum(1 for f in firings if f["rule"] == "R2"), 0)

    def test_baseline_ports_from_config(self):
        records, _ = __import__("detection_hardened").ingest(
            run_build.load_sources())
        cfg = copy.deepcopy(CONFIG)
        cfg["baseline_ports"] = [22, 9090, 8080]
        firings = run_rules_configured(records, cfg)
        self.assertEqual(
            sum(1 for f in firings if f["rule"] == "R3"), 0)


class TestDrift(unittest.TestCase):
    def test_current_snapshot_drifts_on_two_controls(self):
        firings, summary = baseline_drift(
            BASELINE, CURRENT, "2026-11-05T10:52:00Z")
        self.assertEqual(summary["drifted_controls"], ["C01", "C07"])
        self.assertEqual(summary["drift_count"], 2)
        self.assertEqual(summary["baseline_passed"], 10)
        self.assertEqual(summary["current_passed"], 8)
        self.assertEqual(len(firings), 2)
        self.assertTrue(all(f["rule"] == "R5" for f in firings))

    def test_identical_snapshot_has_no_drift(self):
        firings, summary = baseline_drift(
            BASELINE, BASELINE, "2026-11-05T10:52:00Z")
        self.assertEqual(summary["drift_count"], 0)
        self.assertEqual(firings, [])

    def test_before_snapshot_drifts_on_all_controls(self):
        before = load_json(os.path.join(LEARN, "snapshot_before.json"))
        _, summary = baseline_drift(
            BASELINE, before, "2026-11-05T10:52:00Z")
        self.assertEqual(summary["drift_count"], 10)
        self.assertEqual(summary["current_passed"], 0)


def fresh_incident():
    result = deep_result()
    return result["incident"]


class TestLifecycle(unittest.TestCase):
    def test_full_lifecycle_and_log(self):
        inc = fresh_incident()
        transition(inc, "triaged", "2026-11-05T11:00:00Z",
                   "lab-reviewer", "Confirmed.")
        transition(inc, "contained", "2026-11-05T11:30:00Z",
                   "lab-reviewer", "Contained.")
        transition(inc, "closed", "2026-11-05T12:00:00Z",
                   "lab-reviewer", "Closed.",
                   checklist={k: True for k in (
                       "accounts_reviewed", "ports_checked",
                       "updates_confirmed", "closure_note_recorded")})
        self.assertEqual(inc["lifecycle"], "closed")
        self.assertEqual(inc["status"], "closed")
        self.assertEqual(
            [(t["from"], t["to"]) for t in inc["transitions"]],
            [(None, "open"), ("open", "triaged"),
             ("triaged", "contained"), ("contained", "closed")])

    def test_skip_is_rejected(self):
        inc = fresh_incident()
        with self.assertRaises(IncidentError):
            transition(inc, "contained", "2026-11-05T11:00:00Z",
                       "lab-reviewer", "Skip triage.")

    def test_backward_is_rejected(self):
        inc = fresh_incident()
        transition(inc, "triaged", "2026-11-05T11:00:00Z",
                   "lab-reviewer", "Confirmed.")
        with self.assertRaises(IncidentError):
            transition(inc, "open", "2026-11-05T11:05:00Z",
                       "lab-reviewer", "Backwards.")

    def test_close_with_incomplete_checklist_is_rejected(self):
        inc = fresh_incident()
        transition(inc, "triaged", "2026-11-05T11:00:00Z",
                   "lab-reviewer", "Confirmed.")
        transition(inc, "contained", "2026-11-05T11:30:00Z",
                   "lab-reviewer", "Contained.")
        with self.assertRaises(IncidentError):
            transition(inc, "closed", "2026-11-05T12:00:00Z",
                       "lab-reviewer", "Close early.",
                       checklist={"accounts_reviewed": True})
        self.assertEqual(inc["lifecycle"], "contained")

    def test_closed_incident_cannot_move(self):
        inc = fresh_incident()
        for state, ts in (("triaged", "2026-11-05T11:00:00Z"),
                          ("contained", "2026-11-05T11:30:00Z")):
            transition(inc, state, ts, "lab-reviewer", "Step.")
        transition(inc, "closed", "2026-11-05T12:00:00Z",
                   "lab-reviewer", "Closed.",
                   checklist={k: True for k in (
                       "accounts_reviewed", "ports_checked",
                       "updates_confirmed", "closure_note_recorded")})
        with self.assertRaises(IncidentError):
            transition(inc, "open", "2026-11-05T12:05:00Z",
                       "lab-reviewer", "Reopen.")

    def test_none_incident_rejected(self):
        self.assertIsNone(new_incident([]))
        with self.assertRaises(IncidentError):
            transition(None, "triaged", "2026-11-05T11:00:00Z",
                       "lab-reviewer", "No incident.")


class TestDeterminism(unittest.TestCase):
    def test_run_deep_is_deterministic(self):
        first = json.dumps(deep_result(), sort_keys=True)
        second = json.dumps(deep_result(), sort_keys=True)
        self.assertEqual(first, second)

    def test_runner_module_has_review_steps(self):
        self.assertEqual([s[0] for s in run_deep_module.REVIEW_STEPS],
                         ["triaged", "contained", "closed"])


if __name__ == "__main__":
    unittest.main()

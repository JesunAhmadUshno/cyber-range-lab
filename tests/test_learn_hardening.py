"""Unit tests for Level 1 Learn hardening checker. Hand-computed expectations.

The after snapshot passes all 10 controls and the before snapshot
passes 0 of 10, by construction of the two synthetic snapshots in
level-1-learn/. Every expected count below is computed from those
files by hand, not copied from the code output.
"""
import copy
import json
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LEVEL = os.path.join(ROOT, "level-1-learn")
sys.path.insert(0, LEVEL)
from hardening import (  # noqa: E402
    CONTROLS,
    HardeningError,
    compare_snapshots,
    evaluate_snapshot,
)


def load(name):
    with open(os.path.join(LEVEL, name), encoding="utf-8") as f:
        return json.load(f)


BEFORE = load("snapshot_before.json")
AFTER = load("snapshot_after.json")


def by_id(result):
    return {c["control"]: c for c in result["controls"]}


class TestScores(unittest.TestCase):
    def test_before_score_zero_of_ten(self):
        r = evaluate_snapshot(BEFORE)
        self.assertEqual(r["passed"], 0)
        self.assertEqual(r["total"], 10)
        self.assertEqual(r["score_percent"], 0)

    def test_after_score_ten_of_ten(self):
        r = evaluate_snapshot(AFTER)
        self.assertEqual(r["passed"], 10)
        self.assertEqual(r["total"], 10)
        self.assertEqual(r["score_percent"], 100)

    def test_compare_summary(self):
        s = compare_snapshots(BEFORE, AFTER)["summary"]
        self.assertEqual(s, {"controls_total": 10, "before_passed": 0,
                             "after_passed": 10, "improvement": 10,
                             "before_score_percent": 0,
                             "after_score_percent": 100})

    def test_snapshots_labelled_synthetic(self):
        self.assertTrue(BEFORE["synthetic"])
        self.assertTrue(AFTER["synthetic"])

    def test_remediation_text_on_before_failures(self):
        for c in evaluate_snapshot(BEFORE)["controls"]:
            self.assertFalse(c["passed"])
            self.assertTrue(len(c["remediation"]) > 10)
        for c in evaluate_snapshot(AFTER)["controls"]:
            self.assertTrue(c["passed"])
            self.assertEqual(c["remediation"], "")


class TestControlsExact(unittest.TestCase):
    def test_control_order_and_names(self):
        names = [name for _, name, _, _ in CONTROLS]
        self.assertEqual(names, [
            "automatic_updates_on", "password_ssh_off", "key_only_access",
            "root_login_disabled", "sudo_list_bounded",
            "logging_and_audit_on", "firewall_default_deny",
            "labnet_isolated", "unused_services_off",
            "backup_snapshot_present"])
        ids = [cid for cid, _, _, _ in CONTROLS]
        self.assertEqual(ids, ["C%02d" % i for i in range(1, 11)])

    def test_after_each_control_passes(self):
        result = by_id(evaluate_snapshot(AFTER))
        for name in result:
            self.assertTrue(result[name]["passed"], name)

    def test_before_each_control_fails(self):
        result = by_id(evaluate_snapshot(BEFORE))
        for name in result:
            self.assertFalse(result[name]["passed"], name)


class TestMutations(unittest.TestCase):
    """Flipping one after-control back must fail that named check."""

    def check_mutation(self, mutate, control):
        cfg = copy.deepcopy(AFTER)
        mutate(cfg)
        result = by_id(evaluate_snapshot(cfg))
        self.assertFalse(result[control]["passed"], control)

    def test_mutation_c01_updates_off(self):
        self.check_mutation(lambda c: c.update(automatic_updates=False),
                            "automatic_updates_on")

    def test_mutation_c02_password_on(self):
        self.check_mutation(
            lambda c: c["ssh"].update(password_authentication=True),
            "password_ssh_off")

    def test_mutation_c03_publickey_off(self):
        self.check_mutation(
            lambda c: c["ssh"].update(publickey_authentication=False),
            "key_only_access")

    def test_mutation_c04_root_login_yes(self):
        self.check_mutation(
            lambda c: c["ssh"].update(permit_root_login="yes"),
            "root_login_disabled")

    def test_mutation_c05_sudo_guest_added(self):
        self.check_mutation(lambda c: c.update(sudo_users=["labadmin", "guest"]),
                            "sudo_list_bounded")

    def test_mutation_c06_audit_off(self):
        self.check_mutation(lambda c: c["logging"].update(audit_enabled=False),
                            "logging_and_audit_on")

    def test_mutation_c07_firewall_allow(self):
        self.check_mutation(lambda c: c["firewall"].update(default_inbound="allow"),
                            "firewall_default_deny")

    def test_mutation_c08_route_home_on(self):
        self.check_mutation(lambda c: c["network"].update(routes_to_home_lan=True),
                            "labnet_isolated")

    def test_mutation_c09_telnet_on(self):
        self.check_mutation(
            lambda c: c["services"].update(enabled=["ssh", "telnet"]),
            "unused_services_off")

    def test_mutation_c10_snapshot_missing(self):
        self.check_mutation(lambda c: c["backup"].update(snapshot_present=False),
                            "backup_snapshot_present")


class TestValidation(unittest.TestCase):
    def test_missing_field_rejected(self):
        cfg = copy.deepcopy(AFTER)
        del cfg["firewall"]
        with self.assertRaises(HardeningError):
            evaluate_snapshot(cfg)

    def test_non_synthetic_rejected(self):
        cfg = copy.deepcopy(AFTER)
        cfg["synthetic"] = False
        with self.assertRaises(HardeningError):
            evaluate_snapshot(cfg)

    def test_missing_ssh_field_rejected(self):
        cfg = copy.deepcopy(AFTER)
        del cfg["ssh"]["permit_root_login"]
        with self.assertRaises(HardeningError):
            evaluate_snapshot(cfg)


class TestDeterminism(unittest.TestCase):
    def test_evaluate_twice_identical(self):
        self.assertEqual(compare_snapshots(BEFORE, AFTER),
                         compare_snapshots(BEFORE, AFTER))


if __name__ == "__main__":
    unittest.main()

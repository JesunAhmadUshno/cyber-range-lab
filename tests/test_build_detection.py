"""Unit tests for Level 2 Build defensive detection. Hand-computed.

Fixture expectations are computed from the synthetic sample logs in
experiments/sample_logs/ by hand: 26 lines, 24 parsed, 2 quarantined;
firings R1 2, R2 2, R3 1, R4 2 (7 total); 4 alerts after dedup; one
incident INC-001 opened at the first high severity firing time.
"""
import json
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "src")
EXP = os.path.join(ROOT, "experiments")
RES = os.path.join(ROOT, "results")
LEVEL = SRC
sys.path.insert(0, LEVEL)
from detection import (  # noqa: E402
    BASELINE_PORTS,
    build_incident,
    deduplicate,
    ingest,
    parse_line,
    run_detection,
    run_rules,
)

sys.path.insert(0, LEVEL)
import run_build  # noqa: E402


def failed_lines(user, times):
    return ["2026-11-05T%s lab-vm-01 sshd[1]: Failed password for %s "
            "from 10.99.0.10 port 22" % (t, user) for t in times]


CLEAN = {
    "auth": ["2026-11-05T09:00:00Z lab-vm-01 sshd[1]: Accepted password "
             "for labadmin from 10.99.0.12 port 22"],
    "sudo": ["2026-11-05T09:05:00Z lab-vm-01 sudo: labadmin : TTY=pts/1 ; "
             "USER=root ; COMMAND=/bin/systemctl status"],
    "service": ["2026-11-05T09:10:00Z lab-vm-01 service-monitor: "
                "listening port=22 protocol=tcp",
                "2026-11-05T09:11:00Z lab-vm-01 systemd[1]: "
                "automatic_updates status=enabled"],
    "firewall": ["2026-11-05T09:12:00Z lab-vm-01 firewall: "
                 "action=allow port=22 src=10.99.0.5"],
}


class TestParser(unittest.TestCase):
    def test_parse_auth_failed(self):
        r = parse_line("auth", failed_lines("alice", ["10:00:00Z"])[0])
        self.assertEqual((r["event"], r["user"], r["host"]),
                         ("failed_login", "alice", "lab-vm-01"))

    def test_parse_auth_accepted(self):
        r = parse_line("auth", CLEAN["auth"][0])
        self.assertEqual(r["event"], "successful_login")

    def test_parse_sudo(self):
        r = parse_line("sudo", CLEAN["sudo"][0])
        self.assertEqual((r["event"], r["user"]), ("sudo_to_root", "labadmin"))

    def test_parse_service_port(self):
        r = parse_line("service", CLEAN["service"][0])
        self.assertEqual((r["event"], r["detail"]),
                         ("listening_port", "port=22 protocol=tcp"))

    def test_parse_service_updates(self):
        r = parse_line("service",
                       "2026-11-05T09:11:00Z lab-vm-01 systemd[1]: "
                       "automatic_updates status=disabled")
        self.assertEqual(r["detail"], "status=disabled")

    def test_parse_firewall(self):
        r = parse_line("firewall", CLEAN["firewall"][0])
        self.assertEqual(r["event"], "firewall_allow")

    def test_malformed_returns_none_each_source(self):
        for source in ("auth", "sudo", "service", "firewall"):
            self.assertIsNone(parse_line(source, "not a log line at all"))

    def test_bad_timestamp_quarantined(self):
        self.assertIsNone(parse_line(
            "auth", "not-a-time lab-vm-01 sshd[1]: Failed password for "
                    "alice from 10.99.0.10 port 22"))


class TestSampleLogs(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = run_detection(run_build.load_sources())

    def test_totals(self):
        self.assertEqual(self.result["sources"]["total"],
                         {"lines": 26, "parsed": 24, "quarantined": 2})

    def test_per_source_counts(self):
        s = self.result["sources"]
        self.assertEqual(s["auth"], {"lines": 12, "parsed": 11, "quarantined": 1})
        self.assertEqual(s["sudo"], {"lines": 5, "parsed": 4, "quarantined": 1})
        self.assertEqual(s["service"], {"lines": 6, "parsed": 6, "quarantined": 0})
        self.assertEqual(s["firewall"], {"lines": 3, "parsed": 3, "quarantined": 0})

    def test_per_rule_firings_and_alerts(self):
        self.assertEqual(self.result["per_rule"], {
            "R1": {"firings_before_dedup": 2, "alerts_after_dedup": 1},
            "R2": {"firings_before_dedup": 2, "alerts_after_dedup": 1},
            "R3": {"firings_before_dedup": 1, "alerts_after_dedup": 1},
            "R4": {"firings_before_dedup": 2, "alerts_after_dedup": 1}})
        self.assertEqual(self.result["firings_total_before_dedup"], 7)
        self.assertEqual(self.result["alerts_total_after_dedup"], 4)

    def test_incident_fields(self):
        inc = self.result["incident"]
        self.assertEqual(inc["incident_id"], "INC-001")
        self.assertEqual(inc["opened_at"], "2026-11-05T10:08:00Z")
        self.assertEqual(inc["status"], "open")
        self.assertEqual(inc["severity"], "high")
        self.assertEqual(inc["alert_ids"], ["A001", "A002"])
        self.assertEqual(inc["affected_hosts"], ["lab-vm-01"])
        self.assertEqual(inc["affected_users"], ["alice", "guest"])
        self.assertTrue(len(inc["recommended_response"]) >= 3)

    def test_determinism(self):
        again = run_detection(run_build.load_sources())
        self.assertEqual(json.dumps(self.result, sort_keys=True),
                         json.dumps(again, sort_keys=True))

    def test_results_file_matches_runner(self):
        with open(os.path.join(RES, "results_build.json"),
                  encoding="utf-8") as f:
            on_disk = json.load(f)
        self.assertEqual(on_disk["firings_total_before_dedup"], 7)
        self.assertEqual(on_disk["incident"]["incident_id"], "INC-001")


class TestRules(unittest.TestCase):
    def test_r1_boundary_four_fails_no_alert(self):
        src = {"auth": failed_lines("eve", ["10:00:00Z", "10:02:00Z",
                                            "10:04:00Z", "10:06:00Z"])}
        records, _ = ingest(src)
        self.assertEqual([f for f in run_rules(records)
                          if f["rule"] == "R1"], [])

    def test_r1_boundary_five_fails_alert(self):
        src = {"auth": failed_lines("eve", ["10:00:00Z", "10:02:00Z",
                                            "10:04:00Z", "10:06:00Z",
                                            "10:08:00Z"])}
        records, _ = ingest(src)
        firings = [f for f in run_rules(records) if f["rule"] == "R1"]
        self.assertEqual(len(firings), 1)
        self.assertEqual(firings[0]["ts"], "2026-11-05T10:08:00Z")

    def test_r1_outside_window_no_alert(self):
        src = {"auth": failed_lines("eve", ["10:00:00Z", "10:20:00Z",
                                            "10:40:00Z", "11:00:00Z",
                                            "11:20:00Z"])}
        records, _ = ingest(src)
        self.assertEqual([f for f in run_rules(records)
                          if f["rule"] == "R1"], [])

    def test_r2_non_admin_fires_admin_does_not(self):
        records, _ = ingest({"sudo": CLEAN["sudo"] + [
            "2026-11-05T09:06:00Z lab-vm-01 sudo: guest : TTY=pts/0 ; "
            "USER=root ; COMMAND=/bin/id"]})
        firings = [f for f in run_rules(records) if f["rule"] == "R2"]
        self.assertEqual(len(firings), 1)
        self.assertEqual(firings[0]["user"], "guest")

    def test_r3_baseline_ports_exact(self):
        self.assertEqual(BASELINE_PORTS, (22, 9090))
        records, _ = ingest({"service": CLEAN["service"]})
        self.assertEqual([f for f in run_rules(records)
                          if f["rule"] == "R3"], [])

    def test_r3_new_port_fires(self):
        records, _ = ingest({"service": [
            "2026-11-05T09:10:00Z lab-vm-01 service-monitor: "
            "listening port=8080 protocol=tcp"]})
        firings = [f for f in run_rules(records) if f["rule"] == "R3"]
        self.assertEqual(len(firings), 1)

    def test_r4_disabled_fires_enabled_does_not(self):
        records, _ = ingest({"service": [
            "2026-11-05T09:11:00Z lab-vm-01 systemd[1]: "
            "automatic_updates status=enabled"]})
        self.assertEqual([f for f in run_rules(records)
                          if f["rule"] == "R4"], [])
        records, _ = ingest({"service": [
            "2026-11-05T09:11:00Z lab-vm-01 systemd[1]: "
            "automatic_updates status=disabled"]})
        self.assertEqual(len([f for f in run_rules(records)
                              if f["rule"] == "R4"]), 1)

    def test_clean_fixture_no_firings_no_incident(self):
        result = run_detection(CLEAN)
        self.assertEqual(result["firings_total_before_dedup"], 0)
        self.assertEqual(result["alerts"], [])
        self.assertIsNone(result["incident"])

    def test_dedup_collapses_within_window(self):
        records, _ = ingest({"service": [
            "2026-11-05T09:11:00Z lab-vm-01 systemd[1]: "
            "automatic_updates status=disabled",
            "2026-11-05T09:13:00Z lab-vm-01 systemd[1]: "
            "automatic_updates status=disabled"]})
        alerts = deduplicate(run_rules(records))
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["count"], 2)

    def test_dedup_separates_outside_window(self):
        records, _ = ingest({"service": [
            "2026-11-05T09:11:00Z lab-vm-01 systemd[1]: "
            "automatic_updates status=disabled",
            "2026-11-05T09:40:00Z lab-vm-01 systemd[1]: "
            "automatic_updates status=disabled"]})
        alerts = deduplicate(run_rules(records))
        self.assertEqual(len(alerts), 2)

    def test_incident_none_without_alerts(self):
        self.assertIsNone(build_incident([]))

    def test_malformed_never_crashes_ingest(self):
        records, stats = ingest({"auth": ["", "junk", "more junk"]})
        self.assertEqual(records, [])
        self.assertEqual(stats["auth"]["quarantined"], 2)


if __name__ == "__main__":
    unittest.main()

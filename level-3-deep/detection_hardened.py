"""Hardened defensive detection loop, Level 3 Deep, synthetic data only.

This module extends the Level 2 Build detection loop in three ways:

1. Policy is configurable. Thresholds, the admin user list, and the
   baseline port list are read from a validated config dict instead
   of code constants. The default config equals the Build constants
   exactly, so the Build numbers are preserved as a regression.
2. One new defensive rule, R5 baseline_drift, compares a new
   synthetic snapshot against the Learn hardened baseline by
   reusing the Learn hardening checker (imported, not copied) and
   fires once per control that passed in the baseline and fails in
   the new snapshot. Detection and hardening only.
3. The incident gains a lifecycle: open, triaged, contained,
   closed, in that order only, with every transition logged and a
   four item closure checklist required before closing.

Ingestion and line parsing are reused from the Build module by
import. Detection only. It contains no offensive content, never
connects to, changes, or scans any system, and uses timestamps
only from the log lines and recorded review times supplied by the
caller, never from the wall clock. Only the Python standard
library is used.
"""
import importlib.util
import os
from datetime import timedelta

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def _load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


build_detection = _load_module(
    "p24_build_detection",
    os.path.join(ROOT, "level-2-build", "detection.py"))
learn_hardening = _load_module(
    "p24_learn_hardening",
    os.path.join(ROOT, "level-1-learn", "hardening.py"))

parse_ts = build_detection.parse_ts
ingest = build_detection.ingest
SEVERITY_RANK = build_detection.SEVERITY_RANK


class DetectionConfigError(Exception):
    """Named error for an invalid detection config."""


class IncidentError(Exception):
    """Named error for an invalid incident lifecycle move."""


DEFAULT_CONFIG = {
    "failed_login_threshold": 5,
    "failed_login_window_seconds": 600,
    "dedup_window_seconds": 600,
    "admin_users": ["labadmin", "laboperator"],
    "baseline_ports": [22, 9090],
}


def validate_config(config):
    """Validate a config dict. Returns a normalised copy."""
    if not isinstance(config, dict):
        raise DetectionConfigError("config must be an object")
    for key in DEFAULT_CONFIG:
        if key not in config:
            raise DetectionConfigError("config missing field: '" + key + "'")
    out = {}
    for key in ("failed_login_threshold", "failed_login_window_seconds",
                "dedup_window_seconds"):
        value = config[key]
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            raise DetectionConfigError(key + " must be a positive integer")
        out[key] = value
    users = config["admin_users"]
    if (not isinstance(users, list) or not users
            or not all(isinstance(u, str) and u for u in users)
            or len(set(users)) != len(users)):
        raise DetectionConfigError(
            "admin_users must be a non-empty list of unique strings")
    out["admin_users"] = list(users)
    ports = config["baseline_ports"]
    if (not isinstance(ports, list) or not ports
            or not all(isinstance(p, int) and not isinstance(p, bool)
                       and 1 <= p <= 65535 for p in ports)
            or len(set(ports)) != len(ports)):
        raise DetectionConfigError(
            "baseline_ports must be a non-empty list of unique ports")
    out["baseline_ports"] = list(ports)
    return out


def _window_text(seconds):
    """Human text for the R1 window: whole minutes when it divides evenly."""
    if seconds % 60 == 0:
        return str(seconds // 60) + (" minute" if seconds == 60 else " minutes")
    return str(seconds) + " seconds"


def _firing(rule, name, severity, ts, host, user, detail):
    return {"rule": rule, "rule_name": name, "severity": severity,
            "ts": ts, "host": host, "user": user, "detail": detail}


def run_rules_configured(records, config):
    """Run R1 to R4 with the supplied config. Returns firings."""
    cfg = validate_config(config)
    firings = []
    ordered = sorted(records,
                     key=lambda r: (r["ts"], r["source"], r["user"]))
    failed = [r for r in ordered if r["event"] == "failed_login"]
    by_key = {}
    for rec in failed:
        by_key.setdefault((rec["host"], rec["user"]), []).append(rec)
    for key in sorted(by_key):
        events = by_key[key]
        times = [parse_ts(r["ts"]) for r in events]
        window = cfg["failed_login_window_seconds"]
        for i, rec in enumerate(events):
            start = times[i] - timedelta(seconds=window)
            count = sum(1 for t in times[:i + 1] if start <= t <= times[i])
            if count >= cfg["failed_login_threshold"]:
                firings.append(_firing(
                    "R1", "repeated_failed_logins", "high", rec["ts"],
                    rec["host"], rec["user"],
                    str(count) + " failed logins in " + _window_text(window)))
    for rec in ordered:
        if (rec["event"] == "sudo_to_root"
                and rec["user"] not in cfg["admin_users"]):
            firings.append(_firing(
                "R2", "sudo_by_non_admin_user", "high", rec["ts"],
                rec["host"], rec["user"],
                "sudo to root by non-admin user " + rec["user"]))
    for rec in ordered:
        if rec["event"] == "listening_port":
            port = int(rec["detail"].split()[0].split("=")[1])
            if port not in cfg["baseline_ports"]:
                firings.append(_firing(
                    "R3", "new_listening_port_not_in_baseline", "medium",
                    rec["ts"], rec["host"], rec["user"],
                    "listening port " + str(port) + " not in baseline"))
    for rec in ordered:
        if (rec["event"] == "automatic_updates_status"
                and rec["detail"] == "status=disabled"):
            firings.append(_firing(
                "R4", "automatic_updates_disabled", "medium", rec["ts"],
                rec["host"], rec["user"],
                "automatic_updates status=disabled"))
    firings.sort(key=lambda f: (f["ts"], f["rule"], f["host"], f["user"]))
    return firings


def baseline_drift(baseline_snapshot, current_snapshot, at_ts,
                   host="lab-vm-01"):
    """R5: controls that passed in the baseline and fail now.

    Both snapshots are evaluated with the Learn hardening checker.
    Returns (firings, drift_summary). Detection only: this reads
    synthetic configuration fields and changes nothing.
    """
    baseline = learn_hardening.evaluate_snapshot(baseline_snapshot)
    current = learn_hardening.evaluate_snapshot(current_snapshot)
    base_pass = {c["control_id"]: c["passed"] for c in baseline["controls"]}
    firings = []
    drifted = []
    for control in current["controls"]:
        cid = control["control_id"]
        if base_pass.get(cid) and not control["passed"]:
            drifted.append(cid)
            firing = _firing(
                "R5", "baseline_drift", "medium", at_ts, host, "system",
                "control " + cid + " " + control["control"]
                + " passed in baseline and fails in current snapshot")
            # Carried so dedup keeps one alert per drifted control.
            firing["control_id"] = cid
            firings.append(firing)
    summary = {
        "baseline_passed": baseline["passed"],
        "baseline_total": baseline["total"],
        "current_passed": current["passed"],
        "current_total": current["total"],
        "drifted_controls": drifted,
        "drift_count": len(drifted),
    }
    return firings, summary


def deduplicate_configured(firings, config):
    """Collapse repeated firings inside the configured dedup window.

    The key is (rule, host, user, control id). Only R5 firings carry a
    control id; without it, two controls drifting at the same time
    merged into one alert that named only the first control (the
    v1.0 behaviour, fixed after v1.0).
    """
    cfg = validate_config(config)
    window = cfg["dedup_window_seconds"]
    alerts = []
    groups = {}
    for firing in firings:
        key = (firing["rule"], firing["host"], firing["user"],
               firing.get("control_id", ""))
        groups.setdefault(key, []).append(firing)
    for key in sorted(groups):
        group = sorted(groups[key], key=lambda f: f["ts"])
        current = None
        for firing in group:
            if current is not None and (
                    parse_ts(firing["ts"]) - parse_ts(current["first_seen"])
                    <= timedelta(seconds=window)):
                current["count"] += 1
                current["last_seen"] = firing["ts"]
            else:
                current = {"rule": firing["rule"],
                           "rule_name": firing["rule_name"],
                           "severity": firing["severity"],
                           "host": firing["host"], "user": firing["user"],
                           "first_seen": firing["ts"],
                           "last_seen": firing["ts"], "count": 1,
                           "detail": firing["detail"]}
                alerts.append(current)
    alerts.sort(key=lambda a: (a["first_seen"], a["rule"], a["host"],
                               a["user"]))
    for i, alert in enumerate(alerts, start=1):
        alert["alert_id"] = "A%03d" % i
    return [{"alert_id": a["alert_id"], "rule": a["rule"],
             "rule_name": a["rule_name"], "severity": a["severity"],
             "host": a["host"], "user": a["user"],
             "first_seen": a["first_seen"], "last_seen": a["last_seen"],
             "count": a["count"], "detail": a["detail"]} for a in alerts]


LIFECYCLE = ("open", "triaged", "contained", "closed")
CLOSURE_CHECKLIST = ("accounts_reviewed", "ports_checked",
                     "updates_confirmed", "closure_note_recorded")


def new_incident(alerts):
    """Create the incident record (status open) for the top severity set."""
    base = build_detection.build_incident(alerts)
    if base is None:
        return None
    # Lower severity alerts are linked, not escalated, so the response
    # steps about ports and updates point at alerts the incident holds.
    base["related_alert_ids"] = [a["alert_id"] for a in alerts
                                 if a["alert_id"] not in base["alert_ids"]
                                 and a["host"] in base["affected_hosts"]]
    base["lifecycle"] = "open"
    base["transitions"] = [{
        "from": None, "to": "open", "at": base["opened_at"],
        "actor": "detection-loop",
        "note": "Incident opened from the highest severity alerts."}]
    base["closure_checklist"] = {item: False for item in CLOSURE_CHECKLIST}
    return base


def transition(incident, to_state, at_ts, actor, note,
               checklist=None):
    """Move an incident one lifecycle step. Returns the incident.

    Only the exact next state in LIFECYCLE is allowed. Closing
    requires a complete closure checklist, supplied here or already
    recorded on the incident.
    """
    if incident is None:
        raise IncidentError("no incident to transition")
    current = incident["lifecycle"]
    if current not in LIFECYCLE:
        raise IncidentError("unknown lifecycle state: " + str(current))
    index = LIFECYCLE.index(current)
    if index + 1 >= len(LIFECYCLE) or LIFECYCLE[index + 1] != to_state:
        raise IncidentError(
            "invalid transition " + current + " to " + str(to_state)
            + ": only " + (LIFECYCLE[index + 1]
                           if index + 1 < len(LIFECYCLE) else "none")
            + " is allowed")
    if checklist is not None:
        if not isinstance(checklist, dict):
            raise IncidentError("checklist must be an object")
        for item in CLOSURE_CHECKLIST:
            if item in checklist:
                if not isinstance(checklist[item], bool):
                    raise IncidentError(
                        "checklist item " + item + " must be a boolean")
                incident["closure_checklist"][item] = checklist[item]
    if to_state == "closed":
        missing = [i for i in CLOSURE_CHECKLIST
                   if incident["closure_checklist"].get(i) is not True]
        if missing:
            raise IncidentError(
                "cannot close: checklist incomplete: "
                + ", ".join(missing))
    incident["transitions"].append({
        "from": current, "to": to_state, "at": at_ts,
        "actor": actor, "note": note})
    incident["lifecycle"] = to_state
    incident["status"] = to_state
    return incident


def run_deep(sources, config, baseline_snapshot, current_snapshot):
    """Full hardened loop. Deterministic dict, no wall clock."""
    cfg = validate_config(config)
    records, stats = ingest(sources)
    firings = run_rules_configured(records, cfg)
    last_ts = max(r["ts"] for r in records) if records else None
    drift_firings, drift = baseline_drift(
        baseline_snapshot, current_snapshot, last_ts)
    all_firings = sorted(firings + drift_firings,
                         key=lambda f: (f["ts"], f["rule"], f["host"],
                                        f["user"]))
    alerts = deduplicate_configured(all_firings, cfg)
    per_rule = {}
    for rule in ("R1", "R2", "R3", "R4", "R5"):
        per_rule[rule] = {
            "firings_before_dedup": sum(
                1 for f in all_firings if f["rule"] == rule),
            "alerts_after_dedup": sum(
                1 for a in alerts if a["rule"] == rule),
        }
    alt_cfg = dict(cfg)
    alt_cfg["failed_login_threshold"] = 3
    alt_firings = run_rules_configured(records, alt_cfg)
    incident = new_incident(alerts)
    return {
        "scenario": "hardened defensive detection loop on synthetic "
                    "log data and synthetic snapshots, 4 sources, "
                    "5 rules, defensive scope only",
        "synthetic": True,
        "config": cfg,
        "sources": stats,
        "per_rule": per_rule,
        "firings_total_before_dedup": len(all_firings),
        "alerts_total_after_dedup": len(alerts),
        "alerts": alerts,
        "baseline_drift": drift,
        "threshold_check_threshold_3": {
            "r1_firings": sum(1 for f in alt_firings
                              if f["rule"] == "R1"),
            "note": "Same records rerun with failed_login_threshold 3 "
                    "to prove the threshold comes from config.",
        },
        "incident": incident,
    }

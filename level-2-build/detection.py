"""Defensive detection loop, Level 2 Build, synthetic logs only.

This module ingests synthetic log text from four sources (auth, sudo,
service, firewall), parses each line into one normalised record, runs
four named defensive detection rules, deduplicates the firings into
alerts, and builds one incident record for the highest severity set.

Detection only. It contains no offensive content, no instructions
for performing any attack, and it never connects to, changes, or
scans any system. The log lines are synthetic telemetry examples
authored for this folder. Only the Python standard library is used.
All results are deterministic: timestamps come from the log lines,
never from the wall clock, and there is no randomness.
"""
import re
from datetime import datetime, timedelta, timezone

# Policy constants from the Learn hardening baseline.
ADMIN_USERS = ("labadmin", "laboperator")
BASELINE_PORTS = (22, 9090)
# Rule thresholds, in code, exact.
FAILED_LOGIN_THRESHOLD = 5
FAILED_LOGIN_WINDOW_SECONDS = 600
DEDUP_WINDOW_SECONDS = 600
SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3}

TS_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def parse_ts(text):
    return datetime.strptime(text, TS_FORMAT).replace(tzinfo=timezone.utc)


def fmt_ts(value):
    return value.strftime(TS_FORMAT)


_AUTH_FAIL = re.compile(
    r"^(\S+) (\S+) sshd\[\d+\]: Failed password for (\S+) from \S+ port \d+$")
_AUTH_OK = re.compile(
    r"^(\S+) (\S+) sshd\[\d+\]: Accepted password for (\S+) from \S+ port \d+$")
_SUDO = re.compile(
    r"^(\S+) (\S+) sudo: (\S+) : .*USER=(\S+) ; COMMAND=(.+)$")
_SVC_UPDATES = re.compile(
    r"^(\S+) (\S+) systemd\[\d+\]: automatic_updates status=(\S+)$")
_SVC_PORT = re.compile(
    r"^(\S+) (\S+) service-monitor: listening port=(\d+) protocol=(\S+)$")
_SVC_START = re.compile(
    r"^(\S+) (\S+) systemd\[\d+\]: Started (\S+)$")
_FW = re.compile(
    r"^(\S+) (\S+) firewall: action=(\S+) port=(\d+) src=\S+$")


def _record(ts, source, host, user, event, detail):
    return {"ts": ts, "source": source, "host": host, "user": user,
            "event": event, "detail": detail}


def parse_line(source, line):
    """Parse one line from the named source. Returns a record or None.

    None means the line is malformed for its source and the caller
    quarantines it (counts it, never crashes on it).
    """
    line = line.strip()
    if not line:
        return None
    try:
        if source == "auth":
            m = _AUTH_FAIL.match(line)
            if m:
                parse_ts(m.group(1))
                return _record(m.group(1), source, m.group(2), m.group(3),
                               "failed_login", "ssh password login failed")
            m = _AUTH_OK.match(line)
            if m:
                parse_ts(m.group(1))
                return _record(m.group(1), source, m.group(2), m.group(3),
                               "successful_login", "ssh password login accepted")
            return None
        if source == "sudo":
            m = _SUDO.match(line)
            if not m:
                return None
            parse_ts(m.group(1))
            target = m.group(4)
            event = "sudo_to_root" if target == "root" else "sudo"
            return _record(m.group(1), source, m.group(2), m.group(3),
                           event, "sudo target=" + target)
        if source == "service":
            m = _SVC_UPDATES.match(line)
            if m:
                parse_ts(m.group(1))
                return _record(m.group(1), source, m.group(2), "system",
                               "automatic_updates_status",
                               "status=" + m.group(3))
            m = _SVC_PORT.match(line)
            if m:
                parse_ts(m.group(1))
                return _record(m.group(1), source, m.group(2), "system",
                               "listening_port",
                               "port=" + m.group(3) + " protocol=" + m.group(4))
            m = _SVC_START.match(line)
            if m:
                parse_ts(m.group(1))
                return _record(m.group(1), source, m.group(2), "system",
                               "service_started", "service=" + m.group(3))
            return None
        if source == "firewall":
            m = _FW.match(line)
            if not m:
                return None
            parse_ts(m.group(1))
            return _record(m.group(1), source, m.group(2), "system",
                           "firewall_" + m.group(3),
                           "port=" + m.group(4))
    except ValueError:
        return None
    return None


def ingest(sources):
    """Ingest {source_name: [lines]} into one central record list.

    Central aggregation lives in this returned list and in the
    results structure the runner writes. No central_log.jsonl file
    is generated, so no generated log churn is committed.
    Returns (records, stats) where stats counts lines, parsed, and
    quarantined per source and in total.
    """
    records = []
    stats = {}
    total = {"lines": 0, "parsed": 0, "quarantined": 0}
    for source in sorted(sources):
        lines = sources[source]
        parsed = 0
        quarantined = 0
        for line in lines:
            if not line.strip():
                continue
            rec = parse_line(source, line)
            if rec is None:
                quarantined += 1
            else:
                parsed += 1
                records.append(rec)
        stats[source] = {"lines": parsed + quarantined,
                         "parsed": parsed, "quarantined": quarantined}
        total["lines"] += parsed + quarantined
        total["parsed"] += parsed
        total["quarantined"] += quarantined
    records.sort(key=lambda r: (r["ts"], r["source"], r["event"], r["user"]))
    stats["total"] = total
    return records, stats


def _firing(rule, name, severity, rec, detail):
    return {"rule": rule, "rule_name": name, "severity": severity,
            "ts": rec["ts"], "host": rec["host"], "user": rec["user"],
            "detail": detail}


def run_rules(records):
    """Run the four named defensive detection rules. Returns firings."""
    firings = []
    ordered = sorted(records, key=lambda r: (r["ts"], r["source"], r["user"]))
    # R1 repeated_failed_logins: 5 or more failed logins for one user
    # on one host inside any 10 minute window. One firing per event
    # that brings the in-window count to the threshold or above.
    failed = [r for r in ordered if r["event"] == "failed_login"]
    by_key = {}
    for rec in failed:
        by_key.setdefault((rec["host"], rec["user"]), []).append(rec)
    for key in sorted(by_key):
        events = by_key[key]
        times = [parse_ts(r["ts"]) for r in events]
        for i, rec in enumerate(events):
            start = times[i] - timedelta(seconds=FAILED_LOGIN_WINDOW_SECONDS)
            count = sum(1 for t in times[:i + 1] if start <= t <= times[i])
            if count >= FAILED_LOGIN_THRESHOLD:
                firings.append(_firing(
                    "R1", "repeated_failed_logins", "high", rec,
                    str(count) + " failed logins in 10 minutes"))
    # R2 sudo by a non-admin user to root. Defensive detection of a
    # privilege signal outside the approved admin list from Learn.
    for rec in ordered:
        if rec["event"] == "sudo_to_root" and rec["user"] not in ADMIN_USERS:
            firings.append(_firing(
                "R2", "sudo_by_non_admin_user", "high", rec,
                "sudo to root by non-admin user " + rec["user"]))
    # R3 new listening port not in the Learn baseline (22, 9090).
    for rec in ordered:
        if rec["event"] == "listening_port":
            port = int(rec["detail"].split()[0].split("=")[1])
            if port not in BASELINE_PORTS:
                firings.append(_firing(
                    "R3", "new_listening_port_not_in_baseline", "medium", rec,
                    "listening port " + str(port) + " not in baseline"))
    # R4 automatic updates disabled signal in service logs.
    for rec in ordered:
        if (rec["event"] == "automatic_updates_status"
                and rec["detail"] == "status=disabled"):
            firings.append(_firing(
                "R4", "automatic_updates_disabled", "medium", rec,
                "automatic_updates status=disabled"))
    firings.sort(key=lambda f: (f["ts"], f["rule"], f["host"], f["user"]))
    return firings


def deduplicate(firings):
    """Collapse repeated firings of the same rule, host, and user
    inside the dedup window into one alert with a count."""
    alerts = []
    groups = {}
    for firing in firings:
        key = (firing["rule"], firing["host"], firing["user"])
        groups.setdefault(key, []).append(firing)
    for key in sorted(groups):
        group = sorted(groups[key], key=lambda f: f["ts"])
        current = None
        for firing in group:
            if current is not None and (
                    parse_ts(firing["ts"]) - parse_ts(current["first_seen"])
                    <= timedelta(seconds=DEDUP_WINDOW_SECONDS)):
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
    alerts.sort(key=lambda a: (a["first_seen"], a["rule"], a["host"], a["user"]))
    for i, alert in enumerate(alerts, start=1):
        alert["alert_id"] = "A%03d" % i
    ordered = [{"alert_id": a["alert_id"], "rule": a["rule"],
                "rule_name": a["rule_name"], "severity": a["severity"],
                "host": a["host"], "user": a["user"],
                "first_seen": a["first_seen"], "last_seen": a["last_seen"],
                "count": a["count"], "detail": a["detail"]} for a in alerts]
    return ordered


RESPONSE_STEPS = [
    "Review the affected accounts and confirm each login and sudo use with the account owner.",
    "Check the host listening ports against the baseline ports 22 and 9090 and remove "
    "any service that is not approved.",
    "Re-enable automatic updates and confirm the update service reports status enabled.",
    "Keep the incident open until a reviewer confirms the signals are explained, then record the closure note.",
]


def build_incident(alerts):
    """Create ONE incident record for the highest severity alert set."""
    if not alerts:
        return None
    top = max(SEVERITY_RANK[a["severity"]] for a in alerts)
    selected = [a for a in alerts if SEVERITY_RANK[a["severity"]] == top]
    return {
        "incident_id": "INC-001",
        "opened_at": min(a["first_seen"] for a in selected),
        "severity": selected[0]["severity"],
        "status": "open",
        "alert_ids": [a["alert_id"] for a in selected],
        "affected_hosts": sorted({a["host"] for a in selected}),
        "affected_users": sorted({a["user"] for a in selected}),
        "recommended_response": list(RESPONSE_STEPS),
    }


def run_detection(sources):
    """Full loop: ingest, rules, dedup, incident. Deterministic dict."""
    records, stats = ingest(sources)
    firings = run_rules(records)
    alerts = deduplicate(firings)
    per_rule = {}
    for rule in ("R1", "R2", "R3", "R4"):
        per_rule[rule] = {
            "firings_before_dedup": sum(1 for f in firings if f["rule"] == rule),
            "alerts_after_dedup": sum(1 for a in alerts if a["rule"] == rule),
        }
    return {
        "scenario": "defensive detection loop on synthetic log data, "
                    "4 sources, 4 rules, defensive scope only",
        "synthetic": True,
        "sources": stats,
        "records": records,
        "per_rule": per_rule,
        "firings_total_before_dedup": len(firings),
        "alerts_total_after_dedup": len(alerts),
        "alerts": alerts,
        "incident": build_incident(alerts),
    }

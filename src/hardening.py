"""Hardening baseline checker, Level 1 Learn, defensive scope only.

This module evaluates a synthetic lab VM configuration snapshot
(labelled synthetic, stored as JSON in this folder) against a
10-control hardening checklist: automatic updates, key-only SSH,
root login disabled, bounded sudo, logging and audit on, firewall
default deny, lab network isolation, unused services off, and a
backup snapshot present.

It reads configuration fields only. It does not connect to any
machine, does not change any system, does not scan any network,
and contains no offensive content of any kind. Remediation text
is defensive configuration guidance only.

Only the Python standard library is used.
"""


class HardeningError(Exception):
    """Named error for invalid snapshot configuration."""


ALLOWED_SUDO_USERS = ("labadmin", "laboperator")
MAX_SUDO_USERS = 2
ALLOWED_LAB_PORTS = (22,)
LABNET_CIDR = "10.99.0.0/24"
UNUSED_SERVICES = ("ftp", "rsh", "telnet")


def _is_bool(value):
    return isinstance(value, bool)


def validate_snapshot(config):
    """Check the snapshot has the required sections and field types."""
    if not isinstance(config, dict):
        raise HardeningError("snapshot must be an object")
    if config.get("synthetic") is not True:
        raise HardeningError("snapshot must be labelled synthetic: true")
    for key in ("label", "automatic_updates", "ssh", "sudo_users",
                "logging", "firewall", "network", "services", "backup"):
        if key not in config:
            raise HardeningError("snapshot missing field: '" + key + "'")
    if not _is_bool(config["automatic_updates"]):
        raise HardeningError("automatic_updates must be a boolean")
    ssh = config["ssh"]
    if not isinstance(ssh, dict):
        raise HardeningError("ssh must be an object")
    for key in ("password_authentication", "publickey_authentication",
                "permit_root_login", "authorized_key_users"):
        if key not in ssh:
            raise HardeningError("ssh missing field: '" + key + "'")
    if not isinstance(config["sudo_users"], list) or not all(
            isinstance(u, str) for u in config["sudo_users"]):
        raise HardeningError("sudo_users must be a list of strings")
    for section in ("logging", "firewall", "network", "services", "backup"):
        if not isinstance(config[section], dict):
            raise HardeningError(section + " must be an object")
    return True


def _check_automatic_updates(c):
    return c["automatic_updates"] is True


def _check_password_ssh_off(c):
    return c["ssh"]["password_authentication"] is False


def _check_key_only_access(c):
    ssh = c["ssh"]
    return (ssh["publickey_authentication"] is True
            and isinstance(ssh["authorized_key_users"], list)
            and len(ssh["authorized_key_users"]) >= 1
            and ssh["password_authentication"] is False)


def _check_root_login_disabled(c):
    return c["ssh"]["permit_root_login"] == "no"


def _check_sudo_bounded(c):
    users = c["sudo_users"]
    return (1 <= len(users) <= MAX_SUDO_USERS
            and all(u in ALLOWED_SUDO_USERS for u in users)
            and len(set(users)) == len(users))


def _check_logging_and_audit_on(c):
    log = c["logging"]
    return (log.get("system_log_enabled") is True
            and log.get("audit_enabled") is True)


def _check_firewall_default_deny(c):
    fw = c["firewall"]
    ports = fw.get("allowed_inbound_ports")
    return (fw.get("default_inbound") == "deny"
            and isinstance(ports, list)
            and len(ports) >= 1
            and all(p in ALLOWED_LAB_PORTS for p in ports))


def _check_labnet_isolated(c):
    net = c["network"]
    return (net.get("labnet_cidr") == LABNET_CIDR
            and net.get("routes_to_home_lan") is False
            and net.get("routes_to_management") is False)


def _check_unused_services_off(c):
    enabled = c["services"].get("enabled")
    if not isinstance(enabled, list):
        return False
    return not any(s in UNUSED_SERVICES for s in enabled)


def _check_backup_present(c):
    backup = c["backup"]
    snap = backup.get("snapshot_id")
    return (backup.get("snapshot_present") is True
            and isinstance(snap, str) and len(snap) > 0)


CONTROLS = [
    ("C01", "automatic_updates_on", _check_automatic_updates,
     "Enable automatic security updates for the lab VM."),
    ("C02", "password_ssh_off", _check_password_ssh_off,
     "Set SSH password authentication to off in the lab VM configuration."),
    ("C03", "key_only_access", _check_key_only_access,
     "Enable public key authentication, add an authorized key for each named lab user, "
     "and keep password authentication off."),
    ("C04", "root_login_disabled", _check_root_login_disabled,
     "Set SSH permit root login to no; use a named account with sudo instead."),
    ("C05", "sudo_list_bounded", _check_sudo_bounded,
     "Trim the sudo list to at most 2 named allowed lab users and remove every other entry."),
    ("C06", "logging_and_audit_on", _check_logging_and_audit_on,
     "Turn on the system log and the audit service for the lab VM."),
    ("C07", "firewall_default_deny", _check_firewall_default_deny,
     "Set the inbound firewall default to deny and allow only the named lab ports (22)."),
    ("C08", "labnet_isolated", _check_labnet_isolated,
     "Keep the lab VM on labnet 10.99.0.0/24 with no route to the home LAN and no route "
     "to management interfaces, as configuration fields."),
    ("C09", "unused_services_off", _check_unused_services_off,
     "Disable unused services (ftp, rsh, telnet) on the lab VM."),
    ("C10", "backup_snapshot_present", _check_backup_present,
     "Take a named snapshot of the hardened lab VM and record its id."),
]


def evaluate_snapshot(config):
    """Evaluate one snapshot. Returns a deterministic result dict."""
    validate_snapshot(config)
    results = []
    for cid, name, fn, remediation in CONTROLS:
        passed = bool(fn(config))
        results.append({
            "control_id": cid,
            "control": name,
            "passed": passed,
            "remediation": "" if passed else remediation,
        })
    passed_count = sum(1 for r in results if r["passed"])
    return {
        "label": config["label"],
        "synthetic": True,
        "controls": results,
        "passed": passed_count,
        "total": len(results),
        "score_percent": round(100 * passed_count / len(results)),
    }


def compare_snapshots(before, after):
    """Evaluate the before and after snapshots and summarise the change."""
    b = evaluate_snapshot(before)
    a = evaluate_snapshot(after)
    return {
        "before": b,
        "after": a,
        "summary": {
            "controls_total": a["total"],
            "before_passed": b["passed"],
            "after_passed": a["passed"],
            "improvement": a["passed"] - b["passed"],
            "before_score_percent": b["score_percent"],
            "after_score_percent": a["score_percent"],
        },
    }

# Level 2, Build: cyber-range-lab

Status: DONE (2026-11-05). A defensive detection loop end to end on
synthetic log data, built with the Python standard library only:
logs to one place, named signals to alerts, and one incident record.
Defensive scope only.

## Main claim

Build ran the defensive detection loop end to end on 26 synthetic log lines from 4 sources (auth 12, sudo 5, service 6, firewall 3), parsed 24 records and quarantined 2 malformed lines, produced 7 rule firings before deduplication (R1 repeated_failed_logins 2, R2 sudo_by_non_admin_user 2, R3 new_listening_port_not_in_baseline 1, R4 automatic_updates_disabled 2), collapsed them to 4 alerts after deduplication, and created 1 incident record INC-001 opened at 2026-11-05T10:08:00Z for the high severity alerts A001 and A002 affecting host lab-vm-01 and users alice and guest, with 26 new Build unit tests passing as part of 48 total tests.

## Honest scope line

Synthetic logs only, authored as defensive telemetry examples in
level-2-build/sample_logs/. This is not a live Dell R610 capture, no
live machine was read, and no system was connected to, changed, or
scanned. Defensive scope only: no offensive scenario, no attack
instructions, no exploit content, and nothing that targets any real
system. The signals are counts and configuration facts in log lines
(failed login counts, sudo use by a non-admin user, a listening port
outside the baseline, an updates-disabled status).

## BUILD-SPEC

1. Ingestion. Four synthetic sources (auth, sudo, service, firewall
   log text files in sample_logs/) are read into ONE central record
   list by detection.ingest. Central aggregation choice: the central
   store lives in memory and in the records list and per-source
   totals of results_build.json. No central_log.jsonl file is
   generated, so no generated log churn is committed.
2. Parser. Each source has its own line format. Every parsed line is
   normalised to {ts, source, host, user, event, detail}. A line
   that does not match its source format, or whose timestamp does
   not parse, is counted as quarantined and never crashes the run.
3. Detection rules, thresholds in code, defensive detection only.
   R1 repeated_failed_logins (high): 5 or more failed logins for one
   user on one host inside any 10 minute window; one firing per
   event that brings the in-window count to 5 or above.
   R2 sudo_by_non_admin_user (high): a sudo to root event whose user
   is not in the Learn admin list (labadmin, laboperator).
   R3 new_listening_port_not_in_baseline (medium): a listening port
   that is not in the Learn baseline ports (22, 9090).
   R4 automatic_updates_disabled (medium): a service log line that
   reports automatic_updates status=disabled.
4. Alerts. Firings are deduplicated by rule, host, and user: repeat
   firings inside a 10 minute dedup window collapse into one alert
   with a count, a first_seen time, and a last_seen time. Alert ids
   are assigned in first_seen order (A001, A002, and so on).
5. Incident record. For the highest severity alert set (high here),
   ONE incident record is created: id INC-001, opened_at taken from
   the log timestamps (never the wall clock), the high alert ids
   attached, affected hosts and users, defensive recommended
   response steps, and status open.
6. Runner. run_build.py loads the four sample log files, runs the
   loop, prints the totals, and writes results_build.json
   deterministically (sorted keys, log timestamps only).

## Run it

    python level-2-build/run_build.py
    python -m unittest tests.test_build_detection -v
    python -m unittest discover -s tests
    python tests/test_smoke.py

The runner writes level-2-build/results_build.json deterministically:
run it twice and the file is identical (verified 2026-11-05:
sha256 cab1ad075a6e122bd8fd35fb757a656965cf88b38a5423340679823da53028a1
on both runs).

## Results (measured 2026-11-05, Muse VM, Python 3.12)

Per source:

| Source | Lines | Parsed | Quarantined |
| --- | --- | --- | --- |
| auth | 12 | 11 | 1 |
| sudo | 5 | 4 | 1 |
| service | 6 | 6 | 0 |
| firewall | 3 | 3 | 0 |
| Total | 26 | 24 | 2 |

Per rule:

| Rule | Name | Firings before dedup | Alerts after dedup |
| --- | --- | --- | --- |
| R1 | repeated_failed_logins | 2 | 1 |
| R2 | sudo_by_non_admin_user | 2 | 1 |
| R3 | new_listening_port_not_in_baseline | 1 | 1 |
| R4 | automatic_updates_disabled | 2 | 1 |
| Total |  | 7 | 4 |

Alerts:

| Alert | Rule | Severity | Host | User | First seen | Count |
| --- | --- | --- | --- | --- | --- | --- |
| A001 | R1 | high | lab-vm-01 | alice | 2026-11-05T10:08:00Z | 2 |
| A002 | R2 | high | lab-vm-01 | guest | 2026-11-05T10:15:00Z | 2 |
| A003 | R4 | medium | lab-vm-01 | system | 2026-11-05T10:30:00Z | 2 |
| A004 | R3 | medium | lab-vm-01 | system | 2026-11-05T10:35:00Z | 1 |

Incident: INC-001, opened 2026-11-05T10:08:00Z, severity high,
status open, alerts A001 and A002, affected host lab-vm-01,
affected users alice and guest, with 4 defensive recommended
response steps recorded in results_build.json.

Hand checks: lines 12 + 5 + 6 + 3 = 26. Parsed 11 + 4 + 6 + 3 = 24.
Quarantined 1 + 1 + 0 + 0 = 2, and 24 + 2 = 26. Alice has 6 failed
logins inside 9 minutes, so R1 fires at the 5th and the 6th event:
2 firings, 1 alert with count 2. Bob has 4 failed logins, below the
threshold of 5, so R1 does not fire for bob (the exact boundary is
unit tested: 4 fails give no firing, 5 fails give one). Guest has
2 sudo to root events as a non-admin, so R2 fires twice and dedups
to 1 alert; the labadmin and laboperator sudo events are admin use
and do not fire. Port 8080 is outside the baseline (22, 9090), so
R3 fires once; ports 22 and 9090 do not fire. Two updates-disabled
lines give R4 2 firings and 1 alert. Firings 2 + 2 + 1 + 2 = 7;
alerts 1 + 1 + 1 + 1 = 4.

## Failure modes and limits

- Synthetic logs, not a live capture: the numbers describe four
  hand-authored log text files, not the logs of any real machine.
  No R610 capture is claimed.
- Thresholds are teaching constants: 5 failed logins in 10 minutes,
  the admin list, the baseline ports, and the 10 minute dedup window
  are hand chosen in code, not a reviewed site policy.
- Parser covers only the authored formats: a real log line in a
  different format is quarantined, not parsed. Quarantine is safe
  (counted, never a crash) but it is also silent signal loss.
- One host, four rules, batch only: no streaming, no live log
  shipping, no fleet, and no rule types beyond counts, membership,
  and status checks on the normalised fields.
- Dedup is window based only: two bursts for the same rule, host,
  and user more than 10 minutes apart become two alerts, and the
  loop does not correlate different rules into one alert.
- The incident is a record, not a workflow: no notification, no
  assignment, and no closure tracking beyond the status field.
- This level was run on the Muse VM (CPU), not on its fleet node
  Dell R610. That costs a grade deduction, named in the grade.

## Grade

Grade: 8,300 of 10,000 for this Build level.

Deductions (they sum to 1,700):
- Synthetic logs, not a live machine capture: minus 600.
- Rule thresholds, admin list, and baseline are hand chosen teaching
  constants, not a reviewed site policy: minus 300.
- Single host, four rules, batch only, with no live log shipping or
  streaming: minus 300.
- Run on the Muse VM, not the assigned Dell R610 fleet node:
  minus 200.
- Parser covers only the authored line formats; other real formats
  are quarantined rather than parsed: minus 200.
- Incident is a single record with no notification or closure
  workflow: minus 100.

## What Deep adds next

Deep stays gated. Any scenario content needs Jesun's batched
sign-off first, per the standing P24 rule, and no scenario content
is drafted here. The defensive extension that Deep can add without
scenario content is a range runbook for this detection loop:
operating the loop on the lab host, reviewing alerts, closing
incidents, and tuning thresholds against recorded synthetic cases.
See the root README level map and SPEC.md.

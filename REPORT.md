# Report: cyber-range-lab (P24)

Defensive scope only. Every log line and snapshot in this repo is
synthetic teaching data written for it; no real machine was read,
changed or scanned. Scenario work stays held for the Owner's
sign-off per scenario, none is drafted, and no verdict here depends
on running a scenario (docs/decisions/0002).

## Current state (2026-11-08)

- Verdict: Draft, not pre-registered (README.md). The loop runs end to
  end on its authored inputs, but it has never read a real lab VM, so
  the system under study has not yet run (METHOD section 8).
- What exists: a 10-control hardening checker, a four-source detection
  loop with five rules, deduplicated alerts and an incident lifecycle,
  a threshold sweep, a runbook, 80 unit tests plus the layout test,
  and a browser port that must reproduce every results file before the
  dashboard builds.
- What is missing for Functional: one read-only defensive capture of a
  real lab VM's configuration and logs, run through the loop, with the
  capture committed to experiments/ (open gap 5 below). No scenario is
  needed for it.
- What is missing for Evaluated: a locked PROPOSAL.md (the draft is in
  Part 1 there) and the reliability profile: stated targets, timed
  drills, monitoring that would catch each drill's fault, and a
  postmortem per incident.

## Questions scored

No hypothesis was written before a result, so nothing below is a
confirmatory test. The original acceptance criteria (PROPOSAL.md,
Part 2) are scored as written.

| Criterion (source) | Result | Evidence |
| --- | --- | --- |
| Learn closes when the code runs, its write-up teaches the idea, and a fresh reader can follow it (SPEC) | Met | src/run_learn.py, results/results_learn.json, Baseline section below |
| Build closes when the system runs end to end, tests pass, and a result table with method exists (SPEC) | Met on synthetic logs only | src/run_build.py, results/results_build.json, 26 tests |
| Deep closes when the Deep scope in the section text is done (SPEC: "further sign-off scenarios, each with a blue team report, plus the range runbook") | Missed: only the runbook part. The scenario part is held by rule, so the Deep scope is compressed (docs/decisions/0003) | docs/RUNBOOK.md |
| Hardened loop reproduces the detection-loop numbers on the default config (Deep spec) | Met | tests/test_deep_hardened.py, results/results_deep.json |
| results_deep.json identical across two runs (Deep spec) | Met | hash below; CI fails if any results file changes |
| Every result on a live R610 capture (implied by SPEC subject: a range on the isolated lab network) | Missed | every snapshot and log is synthetic |

## Reproduce

```text
python3 src/run_learn.py
python3 src/run_build.py
python3 src/run_deep.py
python3 src/evaluate_deep.py
git diff --exit-code results/
python3 -m unittest discover -s tests -p "test_*.py" -v
cd site && npm ci && npm run build
```

Determinism: results_deep.json sha256 e0e633f7e049c5ccd806abdc931e8011b597c2f2e895695ad9964c21068424bb
(recorded 2026-11-07, unchanged after the 2026-11-08 move to src/).

Where each headline number comes from:

| Number | Field | Printed by |
| --- | --- | --- |
| 26 lines, 24 parsed, 2 quarantined | results/results_deep.json `sources.total` | `python3 src/run_deep.py` |
| 9 firings, 6 alerts | `firings_total_before_dedup`, `alerts_total_after_dedup` | `python3 src/run_deep.py` |
| drift on 2 of 10 controls (C01, C07) | `baseline_drift` | `python3 src/run_deep.py` |
| incident INC-001 closed | `incident.lifecycle` | `python3 src/run_deep.py` |
| only thresholds 5 and 6 separate the burst from the near miss at 600 s | results/results_eval.json `sweep` rows with precision 1.0 and episode recall 1.0 at window 600 | `python3 src/evaluate_deep.py` |

## Compute, data and versions

- Runs: Muse VM (CPU), Python 3.12, 2026-11-05 and 2026-11-07; CI on
  Python 3.11 and 3.12 on every pull request since. Runtime under one
  second; no GPU, network or paid service.
- Data: experiments/ holds every input. snapshot_before.json,
  snapshot_after.json (2026-11-05), snapshot_current.json, config.json
  (2026-11-05), sample_logs/ (four logs, 2026-11-05) and
  authored_intent.json (2026-11-07). All are hand-written and labelled
  synthetic in the files themselves.
- Code: Python standard library only (docs/decisions/0001). The
  dashboard uses React 18.3.1 and Vite 6.4.5.

## Threat model and scope

The range models one isolated lab VM (lab-vm-01 on labnet 10.99.0.0/24) whose owner wants to know two things: is the VM configured to a hardened baseline, and do its logs show signals that need a human to look. The defender sees configuration snapshots and four log sources (auth, sudo, service, firewall). The signals in scope are repeated failed SSH logins, sudo to root outside the admin list, a listening port outside the baseline, automatic updates switched off, and a hardening control regressing from the baseline. Out of scope: anything off the VM, network traffic, malware, log tampering, and any adversary who avoids these five signals. Every log line and snapshot is synthetic teaching data written for this repo.

## Candidate ATT&CK mapping

Detection-side labels only, marked candidate: not reviewed against the ATT&CK data sources and not validated on any real activity.

| Rule | Candidate technique | Note |
| --- | --- | --- |
| R1 repeated_failed_logins | T1110 Brute Force | Count over a window, no source or password-spray logic |
| R2 sudo_by_non_admin_user | T1548.003 Sudo and Sudo Caching | Flags use outside the admin list, not abuse of sudo caching itself |
| R4 automatic_updates_disabled | T1562.001 Disable or Modify Tools | Closest fit; updates are not a security tool in the strict sense |
| R3 new_listening_port_not_in_baseline | unmapped | Configuration hygiene, not an attack technique |
| R5 baseline_drift | unmapped | Configuration drift, not an attack technique |

## Baseline: the hardening checker (recorded 2026-11-05)

Former level-1-learn (Learn). The checker is the baseline instrument:
it states what a hardened lab VM looks like, control by control.

### Scope

Defensive work only: no offensive scenarios, no attack instructions,
no exploit content, and nothing that targets any real system. The two
snapshots are synthetic teaching data stored as JSON in experiments/
(snapshot_before.json and snapshot_after.json), labelled synthetic in
the files themselves. They are not a live capture from the Dell R610
or from any other machine, no live server is claimed, and the checker
never connects to, changes, or scans anything. It evaluates
configuration fields only. The Build level detection loop is gated
and is not in this level.

### Method

1. Snapshot. One synthetic lab VM is described by plain configuration
   fields: automatic updates, SSH settings, the sudo user list,
   logging, firewall, network, enabled services, and backup.
2. Validation. The checker requires the synthetic label, every named
   section, and the SSH sub-fields. A missing field or a snapshot
   that is not labelled synthetic raises a named HardeningError.
3. Controls. Ten named controls (C01 to C10) are evaluated in a fixed
   order. Each control returns pass or fail only, and a failed control
   carries defensive remediation text (what to set, never how to
   attack anything).
4. Controls in detail. C01 automatic updates on. C02 SSH password
   authentication off. C03 key-only access (public key on, an
   authorized key user present, password off). C04 root login
   disabled. C05 sudo list bounded (1 to 2 users, all from the allowed
   list labadmin and laboperator, no duplicates). C06 system log and
   audit both on. C07 firewall default inbound deny with only the
   named lab port 22 allowed. C08 isolation as configuration fields:
   labnet_cidr is 10.99.0.0/24 and both routes_to_home_lan and
   routes_to_management are false. C09 none of the unused services
   (ftp, rsh, telnet) is enabled. C10 a backup snapshot is present
   with a non-empty snapshot id.
5. Score. The score is the count of passed controls out of 10, with
   a percent. The runner evaluates the before snapshot and the after
   snapshot and reports the improvement.

### Run it

    python src/run_learn.py
    python -m unittest tests.test_learn_hardening -v
    python tests/test_layout.py

The runner writes results/results_learn.json deterministically:
run it twice and the file is identical (verified 2026-11-05:
sha256 d043ea07644aab6518d7bc2981ee4bc0edf3287b73adf4e9c0696ec945da2af2
on both runs).

### Results (measured 2026-11-05, Muse VM, Python 3.12)

| Control | Name | Before | After | Remediation when failing (defensive only) |
| --- | --- | --- | --- | --- |
| C01 | automatic_updates_on | FAIL | PASS | Enable automatic security updates. |
| C02 | password_ssh_off | FAIL | PASS | Set SSH password authentication to off. |
| C03 | key_only_access | FAIL | PASS | Enable public key auth and add an authorized key user. |
| C04 | root_login_disabled | FAIL | PASS | Set permit root login to no; use a named sudo account. |
| C05 | sudo_list_bounded | FAIL | PASS | Trim sudo to at most 2 named allowed lab users. |
| C06 | logging_and_audit_on | FAIL | PASS | Turn on the system log and the audit service. |
| C07 | firewall_default_deny | FAIL | PASS | Default inbound deny; allow only lab port 22. |
| C08 | labnet_isolated | FAIL | PASS | Labnet 10.99.0.0/24; no route to home LAN or management. |
| C09 | unused_services_off | FAIL | PASS | Disable unused services (ftp, rsh, telnet). |
| C10 | backup_snapshot_present | FAIL | PASS | Take a named snapshot and record its id. |

Summary: Learn ran a deterministic 10-control hardening checklist
on two synthetic lab VM snapshots on the Muse VM: the before
snapshot passed 0 of 10 controls (0 percent) and the after snapshot
passed 10 of 10 controls (100 percent), an improvement of 10
controls, with 22 unit tests passing plus the scaffold smoke test.

Hand checks: before passes are 0, counted control by control in the
table (every before field was set to its unhardened value). After
passes are 10, one per control. Improvement is 10 minus 0 = 10.
Percents are 0 divided by 10 = 0 percent and 10 divided by 10 =
100 percent. The before sudo list has 4 users (labadmin, temp,
guest, backupsvc), which fails both the bound of 2 and the allowed
list. The before firewall allows 5 ports (22, 80, 443, 3389, 5900)
with default allow, which fails C07 on both parts.

### Limits (baseline checker)

- Synthetic snapshot, not a live VM: the numbers describe two
  hand-written JSON files, not the state of any real machine. No
  R610 capture is claimed.
- Config fields, not enforced state: a field that says a control is
  on is taken at face value. The checker cannot know whether a real
  machine enforces it, and it never inspects a real machine.
- One VM, ten controls: no fleet, no continuous monitoring, no drift
  detection, and no detection or alerting loop (that is Build,
  gated).
- Fixed policy constants: the allowed sudo users, the bound of 2,
  the single allowed lab port 22, and the unused service list are
  teaching constants in the code, not a reviewed site policy.
- Validation is structural only: it checks presence, the synthetic
  label, and a few types. A plausible but wrong value inside a field
  is caught only where a control compares it to its expected value.
- This level was run on the Muse VM (CPU), not on its fleet node Dell R610.

## Method and results: the detection loop (recorded 2026-11-05)

Former level-2-build (Build). The build spec is in PROPOSAL.md, Part 2.

### Main claim (as recorded at v0.5)

Build ran the defensive detection loop end to end on 26 synthetic log lines from 4 sources (auth 12, sudo 5, service 6, firewall 3), parsed 24 records and quarantined 2 malformed lines, produced 7 rule firings before deduplication (R1 repeated_failed_logins 2, R2 sudo_by_non_admin_user 2, R3 new_listening_port_not_in_baseline 1, R4 automatic_updates_disabled 2), collapsed them to 4 alerts after deduplication, and created 1 incident record INC-001 opened at 2026-11-05T10:08:00Z for the high severity alerts A001 and A002 affecting host lab-vm-01 and users alice and guest, with 26 new Build unit tests passing as part of 48 total tests.

### Scope

Synthetic logs only, authored as defensive telemetry examples in
experiments/sample_logs/. This is not a live Dell R610 capture, no
live machine was read, and no system was connected to, changed, or
scanned. Defensive scope only: no offensive scenario, no attack
instructions, no exploit content, and nothing that targets any real
system. The signals are counts and configuration facts in log lines
(failed login counts, sudo use by a non-admin user, a listening port
outside the baseline, an updates-disabled status).

### Run it

    python src/run_build.py
    python -m unittest tests.test_build_detection -v
    python -m unittest discover -s tests
    python tests/test_layout.py

The runner writes results/results_build.json deterministically:
run it twice and the file is identical (verified 2026-11-05:
sha256 cab1ad075a6e122bd8fd35fb757a656965cf88b38a5423340679823da53028a1
on both runs).

### Results (measured 2026-11-05, Muse VM, Python 3.12)

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

### Limits (detection loop)

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
- This level was run on the Muse VM (CPU), not on its fleet node Dell R610.

## Method and results: the hardened loop (recorded 2026-11-05, updated 2026-11-07)

Former level-3-deep (compressed Deep). The Deep spec is in
PROPOSAL.md, Part 2; the runbook is docs/RUNBOOK.md.

### Main claim (as recorded, updated 2026-11-07)

Deep ran the hardened defensive detection loop on 26 synthetic log lines from 4 sources, parsed 24 records and quarantined 2 malformed lines, produced 9 rule firings before deduplication (R1 2, R2 2, R3 1, R4 2, R5 2), collapsed them to 6 alerts after deduplication (5 at v1.0, before the R5 dedup fix below), found baseline drift on 2 of 10 hardening controls (C01 and C07, current snapshot 8 of 10 against the baseline 10 of 10), and closed incident INC-001 through its full lifecycle (open, triaged, contained, closed, 4 logged transitions, 4 of 4 closure checklist items), with 32 Deep unit tests passing as part of 80 total tests (23 and 71 at v1.0).

### Update after v1.0 (2026-11-07)

Three defects found in review were fixed, with regression tests:

- R5 dedup collapse. Dedup keyed on (rule, host, user), so the two
  drift firings (C01 and C07, same timestamp) merged into one alert
  A005 whose text named only C01; C07 firewall_default_deny dropped
  out of the alert. Dedup now also keys on the control id, so each
  drifted control keeps its own alert: A005 (C01) and A006 (C07).
  Alerts go from 5 to 6. Firings are unchanged at 9.
- R1 detail text said "in 10 minutes" whatever the configured
  window. It now states the configured window ("in 15 minutes" for
  900 seconds, "in 90 seconds" for 90). The default text is
  unchanged, so A001 still reads "5 failed logins in 10 minutes".
- The incident held only the high severity alerts, while its
  response steps asked the reader to act on ports and updates. It
  now also lists related_alert_ids (A003 to A006, same host), linked
  but not escalated.

Two measurements were added, both deterministic and written by
src/evaluate_deep.py to results/results_eval.json:

- Sensitivity sweep. R1 firings, R1 alerts and total alerts for
  failed_login_threshold 1 to 10 against windows of 60, 300, 600,
  900 and 1800 seconds. At the 600 second window, thresholds 1 to 4
  also fire on bob's 4-failure near miss, and thresholds 7 and up
  miss alice's 6-failure burst. Only 5 and 6 separate the two, so
  the default of 5 is one of two values that work on these lines.
  The anchors equal the recorded results: threshold 5 gives 2 R1
  firings, threshold 3 gives 6.
- Authored-intent sanity check. authored_intent.json labels each
  line with the episode it was written for (from the hand checks
  in REPORT.md (Build)). At the default config every rule
  scores precision 1.0 and episode recall 1.0. This is circular:
  the same hand wrote the lines, the rules and the labels. It
  shows the rules do what the author meant on the author's lines,
  nothing about real logs.

The fan-out set in docs/fanout/ is dated v1.0 and keeps the v1.0 numbers.

### Scope

Synthetic logs and synthetic snapshots only. This is not a live
Dell R610 capture, no live machine was read, and no system was
connected to, changed, or scanned. Defensive scope only: no
offensive scenario content is drafted here or in docs/RUNBOOK.md.
Scenario work stays held for Jesun's batched sign-off, per the
standing P24 rule.

### What the hardened loop adds over the detection loop

1. Configurable policy. experiments/config.json holds the failed
   login threshold (5) and window (600 seconds), the dedup window
   (600 seconds), the admin users (labadmin, laboperator), and
   the baseline ports (22, 9090). The loader validates the config
   and raises DetectionConfigError on a missing field, a bad
   threshold, a duplicate entry, or an invalid port. Default
   values equal the Build constants, so Build is the regression.
2. Config proof. The same records rerun with
   failed_login_threshold set to 3 give 6 R1 firings instead of
   2 (alice fires 4 times, bob fires 2 times). Setting guest as
   an admin user gives 0 R2 firings, and adding port 8080 to the
   baseline gives 0 R3 firings. Each effect is unit tested.
3. R5 baseline_drift, the one new rule, defensive only. The new
   snapshot snapshot_current.json is compared against the Learn
   after snapshot by importing and reusing the Learn hardening
   checker. One firing per control that passed in the baseline
   and fails now.
4. Incident lifecycle. open, triaged, contained, closed, in that
   order only. Every transition is logged with a timestamp, an
   actor, and a note. Closing requires all four closure checklist
   items: accounts_reviewed, ports_checked, updates_confirmed,
   closure_note_recorded. A skip, a backward move, or a close
   with an incomplete checklist raises IncidentError.
5. Runbook. docs/RUNBOOK.md covers isolation on labnet
   10.99.0.0/24 with no route out, snapshot and reset, baseline
   check, detection run, incident handling, evidence checklist,
   and teardown. No scenario content.

### Run it

    python src/run_deep.py
    python -m unittest tests.test_deep_hardened -v
    python -m unittest discover -s tests
    python tests/test_layout.py

The runner writes results/results_deep.json
deterministically: run it twice and the file is identical
(verified 2026-11-07 after the fixes above: sha256
e0e633f7e049c5ccd806abdc931e8011b597c2f2e895695ad9964c21068424bb
on both runs; the v1.0 file hashed
6440fca7eeb3433973f9f85c29a086fb548d48412407f8a9f22b64684d61ce02). Timestamps come from the log lines and the fixed
recorded review times in run_deep.py, never the wall clock.

### Results (measured 2026-11-05, re-run 2026-11-07, Muse VM, Python 3.12)

| Test | Result |
| --- | --- |
| Log lines, 4 sources | 26 lines |
| Parsed records | 24 |
| Quarantined malformed lines | 2 |
| Rule firings before dedup (R1 2, R2 2, R3 1, R4 2, R5 2) | 9 |
| Alerts after dedup | 6 (5 at v1.0, before the R5 dedup fix) |
| Baseline controls passed | 10 of 10 |
| Current snapshot controls passed | 8 of 10 |
| Drifted controls | 2 (C01 automatic_updates_on, C07 firewall_default_deny) |
| Threshold check, threshold 3 in config | R1 firings 6 (against 2 at threshold 5) |
| Incident | INC-001, opened 2026-11-05T10:08:00Z, lifecycle closed |
| Lifecycle transitions logged | 4 (open, triaged, contained, closed) |
| Closure checklist | 4 of 4 items true at close |
| Unit tests | 80 passed in total (22 Learn, 26 Build, 32 Deep), plus the scaffold smoke test |
| Determinism | results_deep.json identical across two runs (hash above) |

Alerts:

| Alert | Rule | Severity | Host | User | First seen | Count |
| --- | --- | --- | --- | --- | --- | --- |
| A001 | R1 | high | lab-vm-01 | alice | 2026-11-05T10:08:00Z | 2 |
| A002 | R2 | high | lab-vm-01 | guest | 2026-11-05T10:15:00Z | 2 |
| A003 | R4 | medium | lab-vm-01 | system | 2026-11-05T10:30:00Z | 2 |
| A004 | R3 | medium | lab-vm-01 | system | 2026-11-05T10:35:00Z | 1 |
| A005 | R5 | medium | lab-vm-01 | system | 2026-11-05T10:52:00Z | 1 |
| A006 | R5 | medium | lab-vm-01 | system | 2026-11-05T10:52:00Z | 1 |

Hand checks: R1 to R4 match Build exactly on the same logs
(2 + 2 + 1 + 2 = 7). The current snapshot sets automatic updates
off, which fails C01, and sets the firewall default to allow
with ports 22 and 3389, which fails C07. Every other control
matches the baseline, so drift is 2 and the current score is
10 minus 2 = 8 of 10. Firings 7 + 2 = 9. R1 to R4 each dedup to
one alert and R5 keeps one alert per drifted control, so alerts
are 4 + 2 = 6. At threshold 3, alice has 6 failed
logins and fires at the 3rd, 4th, 5th, and 6th (4 firings) and
bob has 4 and fires at the 3rd and 4th (2 firings), total 6.

## Failure modes and limits

- Synthetic data, not a live capture: the numbers describe the
  authored log files and JSON snapshots, not any real machine.
  No R610 capture is claimed.
- Config defaults are still teaching values: the config file
  makes policy changeable and validated, but the values in it
  are the Build teaching constants, not a reviewed site policy.
- Drift reads configuration fields only: a field that says a
  control is on is taken at face value, exactly as in Learn.
  Drift also reports only controls that regressed from the
  baseline; a control failing in both snapshots is invisible
  to R5 by design and is caught by the Learn checker itself.
- One new rule only: compressed Deep adds R5 and no other rule
  type. Correlation across rules, streaming, and live log
  shipping are v1.1 backlog in REPORT.md (Future work).
- Lifecycle is a record, not a service: transitions are held in
  the incident dict and written in results_deep.json. There is
  no persistence across runs, no notification, and no assignment
  queue. The closed lifecycle in the results is a walkthrough
  with fixed recorded review timestamps, not a real incident
  handled on a live host.
- Parser limits carry over from Build: line formats outside the
  authored formats are quarantined, counted, and never parsed.
- This level was run on the Muse VM (CPU), not on its fleet node Dell R610.

## Review findings (2026-11-07)

A self-review by the project against a research rubric. It is not the
independent review that METHOD stage 7 asks for: no second reader has
re-derived the numbers yet.

| Criterion | Evidence and reasoning |
| --- | --- |
| Research question | The repo asks an engineering question (can one hardening checker and one rule loop cover baseline, detection, drift and response on one VM?), not a research one. There is no question about detection quality that the data could answer. |
| Hypotheses | Nothing is predicted before measurement. The hand checks in REPORT.md (Build) and REPORT.md (hardened loop) state expected counts, and the code reproduces them, but those are specifications, not hypotheses. |
| Method | Standard-library Python, deterministic runners, results written with sorted keys, hash-checked across two runs, CI on Python 3.11 and 3.12. Rules, thresholds and the dedup policy are fully specified in code and config. |
| Baselines | No comparison with any existing tool (fail2ban, Wazuh, OSSEC, Sigma rules) on the same lines. See open gap 3. |
| Statistics and uncertainty | Every output is a deterministic count on a fixed 26-line corpus: there is no sampling, so there is no sampling uncertainty to report. The real uncertainty is external validity, which no interval on this corpus can express. The new sensitivity sweep is the honest substitute: it shows how the counts move with the two R1 parameters. |
| Reproducibility | `python3 src/run_deep.py` and `python3 src/evaluate_deep.py` regenerate the committed results byte for byte; CI now fails if any committed results file differs from a fresh run. The dashboard's in-browser port is held to the same files by site/src/engine.check.mjs. |
| Threats to validity | Failure modes are written per level. This review adds the main one plainly: the corpus is circular (see below). |
| Related work | The novelty draft (PROPOSAL.md) is a placeholder ("NO MEASUREMENT YET") and the dossier (PROPOSAL.md) defers prior art. A short related-work note is added below; a measured comparison is open gap 3. |
| Limitations | Written for every stage in this report and quoted on the dashboard. |

### The central threat: a circular corpus

The 26 log lines were written by the same hand that wrote the rules, so every rule fires on lines written so that it would fire. The counts (9 firings, 6 alerts) show the rules behave as designed. They say nothing about detection on real logs: there is no benign background volume, one host, 52 minutes of activity, and no adversary who tries to avoid the five signals.

### Fixed in that review

1. **R5 dedup collapse (correctness).** Dedup keyed on (rule, host, user), so the two drift firings for C01 and C07, which share a timestamp, merged into one alert whose text named only C01. Dedup now also keys on the control id. Alerts go from 5 to 6 (A005 C01, A006 C07); firings stay at 9. Regression test: `test_each_drifted_control_gets_its_own_alert`.
2. **R1 detail text.** It said "in 10 minutes" whatever the configured window. It now states the configured window; the default text is unchanged. Test: `test_r1_detail_uses_configured_window`.
3. **Medium alerts outside the incident.** The incident took only the top-severity alerts, while its response steps asked the reader to act on ports and updates. It now lists `related_alert_ids` (A003 to A006), linked but not escalated. Test: `test_incident_links_lower_severity_alerts`.
4. **Unargued thresholds.** src/evaluate_deep.py sweeps failed_login_threshold 1 to 10 against windows of 60, 300, 600, 900 and 1800 seconds and writes results/results_eval.json. At the 600 second window only thresholds 5 and 6 fire on alice's burst without firing on bob's near miss, so the default is one of two working values on these lines, not an arbitrary constant. The recorded anchors match: threshold 5 gives 2 R1 firings, threshold 3 gives 6.
5. **No detection metrics at all.** experiments/authored_intent.json labels each line with the episode it was written for, from the README hand checks, and evaluate_deep.py reports precision and episode recall per rule. At the default config every rule scores 1.0 on both. This is labelled everywhere as a circular sanity check, not an evaluation.
6. **No threat model or framework mapping.** REPORT.md (formerly README.md) has a threat model statement and a candidate ATT&CK table (R1 T1110, R2 T1548.003, R4 T1562.001; R3 and R5 left unmapped as hygiene and drift), marked candidate.
7. **No independent check of the published numbers.** The dashboard runs a JavaScript port of all three levels, and its build fails unless the port reproduces every committed results file, including alert ids, order and text.

### Related work (short note, not a measured comparison)

- fail2ban's shipped defaults (`maxretry = 5`, `findtime = 10m` in jail.conf) match R1's threshold of 5 and window of 600 seconds. fail2ban bans the source address; R1 raises an alert per user and host. Not run on these logs.
- Host intrusion detection systems such as OSSEC and Wazuh ship rule sets for SSH authentication failures and sudo use; SigmaHQ publishes vendor-neutral rules for Linux auth logs. None was run on this corpus, so no claim of difference is made.
- Configuration drift detection against a hardening baseline is the core of benchmark scanners such as CIS-Benchmark tooling and OpenSCAP. R5 is a ten-control teaching version of that idea, reading configuration fields, not the system.

### Open gaps and exactly what each needs

1. **Ground truth and real detection metrics.** Needs a labelled log corpus that the rule author did not write: for example a public honeypot or lab SSH auth.log set with labels, or a capture from the Dell R610 lab VM under the runbook with an independent labeller. Compute: seconds on a CPU.
2. **False positive rate under benign volume.** Needs benign background logs at realistic volume (days of auth, sudo and service logs from a lab host with normal admin activity). The parser quarantines any format it was not written for, so the parsers would also need extending to real syslog prefixes.
3. **Baseline comparison.** Needs fail2ban (and optionally Wazuh) installed on a lab VM: `apt install fail2ban` then `fail2ban-regex experiments/sample_logs/auth.log /etc/fail2ban/filter.d/sshd.conf`. Not done here because the repo is standard-library only and this machine has no fail2ban package; it is a few minutes of free work on the R610 lab VM.
4. **Novelty.** Needs the prior-art reading that the dossier defers, then a measured row in the novelty table (both in PROPOSAL.md). No compute, a reading task with dated sources.
5. **Fleet run.** Needs the Dell R610 node inside labnet; every run so far was on a VM.
6. **External review.** This review was done by the project itself. Needs a reviewer outside the project who re-derives every number from experiments/.
7. **Streaming, clock skew, time zones, log rotation.** Engineering scope for v1.1 (REPORT.md (Future work)). Needs a log shipper on the lab VM and a long-running process; not a research gap the current batch data can answer.
8. **A real incident.** The lifecycle timestamps are fixed recorded review times from run_deep.py. Needs an actual handled event on the lab range, which also needs the scenario sign-off the repo keeps on hold.

## Threats to validity

- Construct: the rules count what they were written to count. On an
  authored corpus, precision and recall of 1.0 measure agreement
  between the author's lines and the author's rules, not detection.
- Internal: none of the expected counts was written down before the
  code that produces it; the hand checks and the code came in the
  same commits.
- External: one simulated host, 52 minutes of activity, no benign
  background volume, no real log format. Nothing here transfers to a
  real machine until open gaps 1, 2 and 5 are closed.
- Location: every run so far was on the Muse VM, not on the Dell R610
  fleet node the project is assigned to.

## Future work

The v1.1 backlog (the rest of the v2 Deep scope), as recorded on
2026-11-05:

- Live operation on the Dell R610 fleet node inside labnet,
  replacing the synthetic snapshots and logs with a real lab
  capture taken under the runbook.
- Streaming or scheduled log shipping into the loop, replacing
  the batch-only runner.
- Cross-rule alert correlation, so related alerts from
  different rules can be grouped into one incident.
- Persistent incident store across runs, with assignment and
  notification, replacing the in-memory lifecycle record.
- A reviewed site policy for thresholds, admin users, and
  baseline ports, replacing the teaching defaults in
  config.json.
- Additional defensive detection rule types beyond counts,
  membership, status, and drift checks, each with its own
  measured synthetic case set.
- Parser coverage for real log formats beyond the authored
  synthetic formats, with quarantine rates measured per format.

Held, not backlog:

- Scenario work: HELD for Jesun's batched sign-off. It is not
  drafted, not listed in detail, and not part of v1.1 planning
  until that sign-off is given. This line is the full record.

## Conclusion

On its own hand-written inputs the loop does what its specification
says, deterministically, and a browser port reproduces every number.
That shows the code is correct against its specification. It does not
show the loop detects anything on a real machine, and no claim of that
kind is made. The next step that changes the verdict is a read-only
capture from a real lab VM, which needs no scenario content.

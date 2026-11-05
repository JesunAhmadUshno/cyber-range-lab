# Level 1, Learn: cyber-range-lab

Status: DONE (2026-11-05). A hardening checklist engine that scores a
before and an after configuration snapshot for one lab VM, built with
the Python standard library only. Defensive scope only.

## Honest scope line

Defensive work only: no offensive scenarios, no attack instructions,
no exploit content, and nothing that targets any real system. The two
snapshots are synthetic teaching data stored as JSON in this folder
(snapshot_before.json and snapshot_after.json), labelled synthetic in
the files themselves. They are not a live capture from the Dell R610
or from any other machine, no live server is claimed, and the checker
never connects to, changes, or scans anything. It evaluates
configuration fields only. The Build level detection loop is gated
and is not in this level.

## Method

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

## Run it

    python level-1-learn/run_learn.py
    python -m unittest tests.test_learn_hardening -v
    python tests/test_smoke.py

The runner writes level-1-learn/results_learn.json deterministically:
run it twice and the file is identical (verified 2026-11-05:
sha256 d043ea07644aab6518d7bc2981ee4bc0edf3287b73adf4e9c0696ec945da2af2
on both runs).

## Results (measured 2026-11-05, Muse VM, Python 3.12)

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

## Failure modes and limits

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
- This level was run on the Muse VM (CPU), not on its fleet node
  Dell R610. That costs a grade deduction, named in the grade.

## Grade

Grade: 8,500 of 10,000 for this Learn level.

Deductions (they sum to 1,500):
- Synthetic snapshot, not a live VM capture: minus 600.
- Checklist evaluates configuration fields only, not enforced or
  live state on a real machine: minus 400.
- Run on the Muse VM, not the assigned Dell R610 fleet node:
  minus 200.
- Single VM and 10 controls only, with no detection, monitoring, or
  drift checking at this level: minus 200.
- Sudo, port, and unused service policy are fixed teaching constants,
  not a reviewed site policy: minus 100.

## What Build adds next

Build (later, gated): the detection loop end to end on one scenario:
logs to one place, one alert on a named signal, one incident record.
That scope stays gated and no scenario content is in this level.
See the root README level map and SPEC.md.

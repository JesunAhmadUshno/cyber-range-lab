# Tutorial: P24 cyber-range-lab, course module

Module: P24-cyber-range-lab
By Jesun Ahmad Ushno
Date: 2026-11-05
License for this tutorial: CC BY 4.0. Code in the repo: Apache-2.0.

## What you will do

You will clone the cyber-range-lab repo, run all three levels,
run the test suite for each level, and read your own results
against the recorded v1.0 numbers. Every command below exists in
the repo as shipped at v1.0 and was run by the author of this
module on 2026-11-05 to verify it. The project needs Python 3.11
or 3.12 and uses the standard library only. No credential is
needed. All data is synthetic teaching data: no live machine is
read, and nothing connects to, changes, or scans any system.
This module is defensive work only: hardening, detection,
baseline drift review, and incident closure.

Note on commands: the level READMEs write the runner commands
with `python`. On systems where only `python3` is present, use
the `python3` forms below, which run the same files.

## Step 0: Clone and enter the repo

```text
git clone https://github.com/JesunAhmadUshno/cyber-range-lab.git
cd cyber-range-lab
```

## Step 1: Level 1, Learn, hardening checklist

Read level-1-learn/README.md first. It explains the 10 controls
(C01 to C10), the synthetic before and after snapshots, and why
a failed control returns defensive remediation text only.

Run the Learn runner:

```text
python3 level-1-learn/run_learn.py
```

Run the Learn tests:

```text
python3 -m unittest tests.test_learn_hardening -v
```

Run the scaffold smoke test:

```text
python3 tests/test_smoke.py
```

Read your results:

- Expected summary: before 0 of 10, after 10 of 10, improvement
  plus 10. The runner writes level-1-learn/results_learn.json.
- Expected tests: 22 tests, all passing.
- Expected smoke test line: scaffold smoke test PASS.

## Step 2: Level 2, Build, defensive detection loop

Read level-2-build/README.md. The loop reads 4 synthetic sources
(auth, sudo, service, firewall) into one central record list,
normalises each line, quarantines malformed lines, applies 4
rules (R1 repeated_failed_logins, R2 sudo_by_non_admin_user,
R3 new_listening_port_not_in_baseline, R4
automatic_updates_disabled), deduplicates firings into alerts,
and creates one incident record.

Run the Build runner:

```text
python3 level-2-build/run_build.py
```

Run the Build tests:

```text
python3 -m unittest tests.test_build_detection -v
```

Read your results:

- Expected totals: 26 lines, 24 parsed, 2 quarantined, 7
  firings before dedup, 4 alerts after dedup, incident INC-001
  opened 2026-11-05T10:08:00Z at high severity.
- Per rule: R1 2 firings, R2 2 firings, R3 1 firing, R4 2
  firings, each deduplicating to 1 alert.
- The runner writes level-2-build/results_build.json,
  identical across two runs.
- Expected tests: 26 Build tests, all passing, 48 in total.

## Step 3: Level 3, Deep, hardened loop, drift, lifecycle

Read level-3-deep/README.md, level-3-deep/DEEP-SPEC.md, and
level-3-deep/RUNBOOK.md. Deep moves policy into
level-3-deep/config.json with validation, adds rule R5
baseline_drift by reusing the Learn checker, adds an incident
lifecycle (open, triaged, contained, closed) with a 4-item
closure checklist, and documents defensive operations in the
runbook.

Run the Deep runner:

```text
python3 level-3-deep/run_deep.py
```

Run the Deep tests:

```text
python3 -m unittest tests.test_deep_hardened -v
```

Read your results:

- Expected totals: 26 lines, 24 parsed, 2 quarantined, 9
  firings before dedup (R1 2, R2 2, R3 1, R4 2, R5 2), 5 alerts
  after dedup.
- Expected drift: baseline 10 of 10, current snapshot 8 of 10,
  drifted controls C01 and C07.
- Expected incident: INC-001, lifecycle closed, 4 logged
  transitions, closure checklist 4 of 4.
- The runner writes level-3-deep/results_deep.json, identical
  across two runs.
- Expected tests: 23 Deep tests, all passing, 71 in total.

## Step 4: Run the full test suite

```text
python3 -m unittest discover -s tests -v
```

Expected: 71 tests in total (22 Learn, 26 Build, 23 Deep), all
passing, plus the scaffold smoke test.

## Step 5: Check your understanding

1. Why does the before snapshot score 0 of 10? (Answer: every
   control field was set to its unhardened value in the
   synthetic before snapshot, so each of C01 to C10 fails. The
   after snapshot sets each field to its hardened value, so all
   10 pass. The hand checks are spelled out in the Learn
   README.)
2. A user has 4 failed logins in the window. Why does R1 not
   fire? (Answer: the threshold is 5 or more failed logins for
   one user on one host inside any 10 minute window. Four is
   below the threshold. The boundary is unit tested: 4 gives no
   firing, 5 gives one.)
3. The Deep loop reports drift on C01 and C07. What does drift
   mean here, and what does it not mean? (Answer: R5 compares
   the current synthetic snapshot against the hardened baseline
   by reusing the Learn checker. C01 and C07 passed in the
   baseline and fail now, so the current score is 8 of 10. It
   reads configuration fields only, so it does not prove the
   enforced state of any real machine.)

## Limits to keep with the numbers

- Synthetic snapshots and logs only. No live capture is claimed.
- Thresholds and policy values are teaching values, not a
  reviewed site policy, even where Deep makes them configurable.
- One host, batch only, with no streaming or live log shipping.
- Drift and hardening read configuration fields at face value.

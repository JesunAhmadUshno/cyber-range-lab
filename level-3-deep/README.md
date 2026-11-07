# Level 3, Deep: cyber-range-lab

Status: DONE (2026-11-05, compressed Deep). The range runbook plus
the detection loop hardened, built with the Python standard
library only. Defensive scope only. See DEEP-SPEC.md for the
level spec and RUNBOOK.md for operations.

## Main claim

Deep ran the hardened defensive detection loop on 26 synthetic log lines from 4 sources, parsed 24 records and quarantined 2 malformed lines, produced 9 rule firings before deduplication (R1 2, R2 2, R3 1, R4 2, R5 2), collapsed them to 6 alerts after deduplication (5 at v1.0, before the R5 dedup fix below), found baseline drift on 2 of 10 hardening controls (C01 and C07, current snapshot 8 of 10 against the baseline 10 of 10), and closed incident INC-001 through its full lifecycle (open, triaged, contained, closed, 4 logged transitions, 4 of 4 closure checklist items), with 32 Deep unit tests passing as part of 80 total tests (23 and 71 at v1.0).

## Update after v1.0 (2026-11-07)

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
level-3-deep/evaluate_deep.py to level-3-deep/results_eval.json:

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
  in level-2-build/README.md). At the default config every rule
  scores precision 1.0 and episode recall 1.0. This is circular:
  the same hand wrote the lines, the rules and the labels. It
  shows the rules do what the author meant on the author's lines,
  nothing about real logs.

The fan-out set in fanout/ is dated v1.0 and keeps the v1.0 numbers.

## Honest scope line

Synthetic logs and synthetic snapshots only. This is not a live
Dell R610 capture, no live machine was read, and no system was
connected to, changed, or scanned. Defensive scope only: no
offensive scenario content is drafted here or in RUNBOOK.md.
Scenario work stays held for Jesun's batched sign-off, per the
standing P24 rule.

## What Deep adds over Build

1. Configurable policy. level-3-deep/config.json holds the failed
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
5. Runbook. RUNBOOK.md covers isolation on labnet
   10.99.0.0/24 with no route out, snapshot and reset, baseline
   check, detection run, incident handling, evidence checklist,
   and teardown. No scenario content.

## Run it

    python level-3-deep/run_deep.py
    python -m unittest tests.test_deep_hardened -v
    python -m unittest discover -s tests
    python tests/test_smoke.py

The runner writes level-3-deep/results_deep.json
deterministically: run it twice and the file is identical
(verified 2026-11-07 after the fixes above: sha256
e0e633f7e049c5ccd806abdc931e8011b597c2f2e895695ad9964c21068424bb
on both runs; the v1.0 file hashed
6440fca7eeb3433973f9f85c29a086fb548d48412407f8a9f22b64684d61ce02). Timestamps come from the log lines and the fixed
recorded review times in run_deep.py, never the wall clock.

## Results (measured 2026-11-05, Muse VM, Python 3.12)

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
  shipping are v1.1 backlog in the root ROADMAP.md.
- Lifecycle is a record, not a service: transitions are held in
  the incident dict and written in results_deep.json. There is
  no persistence across runs, no notification, and no assignment
  queue. The closed lifecycle in the results is a walkthrough
  with fixed recorded review timestamps, not a real incident
  handled on a live host.
- Parser limits carry over from Build: line formats outside the
  authored formats are quarantined, counted, and never parsed.
- This level was run on the Muse VM (CPU), not on its fleet
  node Dell R610. That costs a grade deduction, named below.

## Grade

Grade: 8,400 of 10,000 for this Deep level.

Deductions (they sum to 1,600):
- Synthetic logs and snapshots, not a live machine capture:
  minus 600.
- Single host, batch only, with no live log shipping or
  streaming: minus 300.
- Run on the Muse VM, not the assigned Dell R610 fleet node:
  minus 200.
- Config values are validated teaching defaults, not a
  reviewed site policy: minus 200.
- Drift compares configuration fields only and Deep adds one
  new rule type only: minus 200.
- Lifecycle is an in-memory record with no persistence or
  notification: minus 100.

## What stays held and what is next

Scenario content stays held for Jesun's batched sign-off and is
not drafted. The rest of the v2 Deep scope is the v1.1 backlog
in the root ROADMAP.md.

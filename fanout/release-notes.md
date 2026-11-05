# Release notes draft: cyber-range-lab

Status: DRAFT notes for releases that already exist. Dated 2026-11-05.
These notes summarise the existing GitHub releases. No new release is
created by this file.

Releases verified with gh release list on 2026-11-05:
v0.1, v0.5, and v1.0, at the URLs below.

## v0.1, Learn: defensive hardening checklist

URL: https://github.com/JesunAhmadUshno/cyber-range-lab/releases/tag/v0.1

- A 10-control hardening checklist engine over synthetic before
  and after lab VM snapshots, built with the Python standard
  library only. Defensive scope only. The snapshots are
  synthetic teaching data, not a live machine capture.
- Measured run: 10 controls (C01 to C10); before snapshot 0 of
  10 passed (0 percent); after snapshot 10 of 10 passed (100
  percent); improvement plus 10 controls.
- Tests: 22 unit tests in tests/test_learn_hardening.py, plus
  the scaffold smoke test.
- Grade: 8,500 of 10,000, deductions itemized in the Learn
  README.
- Limits carried in the release: synthetic snapshots only,
  configuration fields only, one VM and 10 controls, teaching
  policy constants, no detection or drift checking at this
  level.

## v0.5, Build: defensive detection loop

URL: https://github.com/JesunAhmadUshno/cyber-range-lab/releases/tag/v0.5

- A defensive detection loop end to end on synthetic logs: 4
  sources (auth, sudo, service, firewall) to one central record
  list, 4 named rules, deduplicated alerts, and one incident
  record. No live machine was read.
- Measured run: 26 log lines, 24 parsed records, 2 quarantined
  malformed lines, 7 rule firings before deduplication (R1 2,
  R2 2, R3 1, R4 2), 4 alerts after deduplication, incident
  INC-001 opened 2026-11-05T10:08:00Z at high severity with
  status open.
- Tests: 26 Build unit tests, 48 in total with Learn.
- Grade: 8,300 of 10,000, deductions itemized in the Build
  README.
- Limits carried in the release: synthetic logs only, teaching
  thresholds, single host and batch only, parser covers only
  the authored formats, incident is a record with no closure
  workflow at this level.

## v1.0, Deep: hardened detection loop, baseline drift, runbook

URL: https://github.com/JesunAhmadUshno/cyber-range-lab/releases/tag/v1.0

- Compressed Deep under the December Compression Protocol: the
  range runbook plus the detection loop hardened, with
  configurable thresholds validated from config, rule R5
  baseline drift reusing the Learn checker, and an incident
  lifecycle with a closure checklist. Defensive scope only.
- Measured run: 26 log lines, 24 parsed, 2 quarantined, 9 rule
  firings before deduplication (R1 2, R2 2, R3 1, R4 2, R5 2),
  5 alerts after deduplication, baseline drift on 2 controls
  (C01 and C07, baseline 10 of 10 against current snapshot 8 of
  10), incident INC-001 closed through its full lifecycle with
  4 logged transitions and 4 of 4 closure checklist items.
- Tests: 23 Deep unit tests, 71 in total with Learn and Build.
- Grade: 8,400 of 10,000, deductions itemized in the Deep
  README (total deductions 1,600).
- The rest of the v2 Deep scope is the v1.1 backlog in
  ROADMAP.md. It is not part of v1.0 and is not claimed by
  these notes. Scenario work stays held for Jesun's batched
  sign-off and is not part of any release.

# DEEP-SPEC: Level 3 Deep, cyber-range-lab (P24), compressed Deep

Status: written before build, 2026-11-05, ROADMAP-V3-BATCH December
Compression Protocol. Defensive scope only.

## Compressed Deep definition for this project

Per the batch ledger: the range runbook plus the detection loop
hardened. That is the single hardest capability in the SPEC Deep
scope that can be built without held content. The rest of the v2
Deep scope is named in the repo root ROADMAP.md as the v1.1
backlog.

Held, not drafted: any offensive scenario content. Scenario work
stays held for Jesun's batched sign-off and no scenario, exploit,
or target content is drafted, listed, or implied in this level.

## What is built

1. Configurable thresholds. All detection policy moves out of code
   constants into level-3-deep/config.json: failed login threshold
   and window, dedup window, admin users, baseline ports. The
   loader validates types and ranges and raises a named
   DetectionConfigError on a bad config. Default config values
   equal the Build constants exactly, so the Build results are a
   regression test.
2. Regression preservation. With the default config, rules R1 to
   R4 on the Build synthetic sample logs must reproduce the Build
   numbers exactly: 26 lines, 24 parsed, 2 quarantined, firings
   R1 2, R2 2, R3 1, R4 2 (7 total), 4 alerts after dedup, and
   incident INC-001 opened 2026-11-05T10:08:00Z.
3. One new defensive rule only. R5 baseline_drift (medium): a new
   synthetic snapshot is compared against the Learn after snapshot
   (the hardened baseline) by reusing the Learn hardening checker
   (evaluate_snapshot, imported, not copied). One firing per
   control that passed in the baseline and fails in the new
   snapshot. No other new rule types.
4. Incident lifecycle. An incident moves open, triaged, contained,
   closed, in that order only. Every transition is logged with a
   supplied timestamp, actor, and note. Closing requires a closure
   checklist with all four items true: accounts_reviewed,
   ports_checked, updates_confirmed, closure_note_recorded. An
   out-of-order move, a skip, a backward move, or a close with an
   incomplete checklist raises a named IncidentError.
5. Runbook. level-3-deep/RUNBOOK.md covers isolation, snapshot
   and reset, baseline check, detection run, incident handling,
   evidence checklist, and teardown. Operational steps only, no
   scenario content.
6. Determinism. run_deep.py writes results_deep.json with sorted
   keys, timestamps taken only from log lines and recorded review
   times, no wall clock and no randomness. Two runs must produce
   an identical file, hash verified.

## Acceptance criteria

- Full test suite passes, including new tests/test_deep_*.py.
- Runner run twice, results_deep.json identical across runs.
- Measured results table in level-3-deep/README.md matches
  results_deep.json exactly.
- Failure modes section written in the Deep README.
- Root README, DOSSIER.md, and root ROADMAP.md updated to ship
  state, with the rest of v2 Deep scope in ROADMAP.md as v1.1.
- No em dash character in any file. Standard library only.

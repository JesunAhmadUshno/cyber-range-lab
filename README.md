# cyber-range-lab

A working cyber range on an isolated lab network. Defense first: hardening, logging, detection, response. Offensive scenarios run only inside the isolation and only on Jesun's sign-off. This scaffold holds the defensive Learn scope and the isolation rules only.

Status: Build DONE (2026-11-05, ROADMAP-V3-BATCH). Learn and Build are built, tested, and measured below. Defensive scope only; all data is synthetic teaching data, not a live R610 capture. Deep is not started and stays gated; any scenario content needs Jesun's sign-off.
Project: P24. Fleet node: Dell R610. Wave: Wave 5 (after P13).

## Start here

1. Read SPEC.md for scope and acceptance criteria.
2. Read DOSSIER.md for the past, present, and future of this problem (v1).
3. Read NOVELTY.md for the proposed novelty (DRAFT, pending the Jev claim_check gate).
4. Start at level-1-learn/README.md, then level-2-build, then level-3-deep.

## Level map

- Level 1, Learn: DONE. A 10-control hardening baseline checker over synthetic before and after lab VM snapshots.
- Level 2, Build: DONE. A defensive detection loop end to end on synthetic logs: 4 sources to one central record list, 4 named rules, deduplicated alerts, and one incident record.
- Level 3, Deep: not started, gated. Further work needs Jesun's sign-off for any scenario content; the defensive runbook extension is the named next scope.

## Benchmarks

Measured 2026-11-05 with level-1-learn/run_learn.py on the Muse VM, Python 3.12. The snapshots are synthetic teaching data, not a live machine.

| Test | Result |
| --- | --- |
| Hardening controls | 10 controls (C01 to C10) |
| Before snapshot | 0 of 10 controls passed (0 percent) |
| After snapshot | 10 of 10 controls passed (100 percent) |
| Improvement | Plus 10 controls, before to after |
| Unit tests | 22 passed, plus the scaffold smoke test |
| Determinism | results_learn.json identical across two runs (hash verified) |

Measured 2026-11-05 with level-2-build/run_build.py on the Muse VM, Python 3.12. The logs are synthetic teaching data, not a live machine.

| Test | Result |
| --- | --- |
| Log lines, 4 sources (auth, sudo, service, firewall) | 26 lines |
| Parsed records | 24 |
| Quarantined malformed lines | 2 |
| Rule firings before dedup (R1 2, R2 2, R3 1, R4 2) | 7 |
| Alerts after dedup | 4 |
| Incident records | 1 (INC-001, opened 2026-11-05T10:08:00Z, high severity) |
| Unit tests | 48 passed in total (22 Learn, 26 Build), plus the scaffold smoke test |
| Determinism | results_build.json identical across two runs (hash verified) |

## Novelty

PROPOSED. See NOVELTY.md. The novelty text is a draft until the Jev claim_check gate passes on it.

## License

Code: Apache-2.0 (see LICENSE). Tutorials: CC BY 4.0. Ruled in D-V3-11, 2026-11-04.

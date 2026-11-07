# cyber-range-lab

A working cyber range on an isolated lab network. Defense first: hardening, logging, detection, response. Offensive scenarios run only inside the isolation and only on Jesun's sign-off. It holds the defensive Learn, Build, and compressed Deep scope and the isolation rules.

Status: v1.0 SHIPPED (2026-11-05, ROADMAP-V3-BATCH). Learn, Build, and compressed Deep are built, tested, and measured below. Defensive scope only; all data is synthetic teaching data, not a live R610 capture. Any scenario content stays held and needs Jesun's sign-off; none is drafted.
Project: P24. Fleet node: Dell R610. Wave: Wave 5 (after P13).

## Start here

1. Read SPEC.md for scope and acceptance criteria.
2. Read DOSSIER.md for the past, present, and future of this problem (v1).
3. Read NOVELTY.md for the proposed novelty (DRAFT, pending the Jev claim_check gate).
4. Start at level-1-learn/README.md, then level-2-build, then level-3-deep.

## Level map

- Level 1, Learn: DONE. A 10-control hardening baseline checker over synthetic before and after lab VM snapshots.
- Level 2, Build: DONE. A defensive detection loop end to end on synthetic logs: 4 sources to one central record list, 4 named rules, deduplicated alerts, and one incident record.
- Level 3, Deep: DONE (compressed Deep). The range runbook plus the detection loop hardened: configurable thresholds, baseline drift rule R5 reusing the Learn checker, and an incident lifecycle with a closure checklist.

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

Measured 2026-11-05 with level-3-deep/run_deep.py on the Muse VM, Python 3.12. The logs and snapshots are synthetic teaching data, not a live machine.

| Test | Result |
| --- | --- |
| Log lines, 4 sources | 26 lines |
| Parsed records, quarantined | 24 parsed, 2 quarantined |
| Rule firings before dedup (R1 2, R2 2, R3 1, R4 2, R5 2) | 9 |
| Alerts after dedup | 6 (5 at v1.0; R5 dedup fix, see level-3-deep/README.md) |
| Baseline drift | 2 controls (C01, C07); current snapshot 8 of 10 against baseline 10 of 10 |
| Incident | INC-001, lifecycle closed, 4 logged transitions, closure checklist 4 of 4 |
| Unit tests | 75 passed in total (22 Learn, 26 Build, 27 Deep), plus the scaffold smoke test |
| Determinism | results_deep.json identical across two runs (hash verified) |
| Deep grade | 8,400 of 10,000 (deductions in level-3-deep/README.md) |

## Novelty

PROPOSED. See NOVELTY.md. The novelty text is a draft until the Jev claim_check gate passes on it.

## Fan-out

Written fan-out set for v1.0, dated 2026-11-05, in fanout/ (it keeps the v1.0 numbers, including 5 Deep alerts
before the R5 dedup fix):

- fanout/blog-post.md: "Hardening First, Detection Second", the
  full story with the main results claim gated by Jev
  claim_check (model jev-1.13.0, noul 0.87, route CLEAR, no
  block).
- fanout/tutorial.md: course module P24-cyber-range-lab. Every
  command in it was executed and passed on 2026-11-05 (all three
  runners, all per-level tests, full suite at 71 tests).
- fanout/website-page.md: project page copy only, not published.
- fanout/linkedin-post.md: DRAFT NOT POSTED, link as the
  first-comment line per the LinkedIn rule.
- fanout/paper-candidate.md: the detection loop and baseline
  drift note at CANDIDATE. Submission is Jesun's tap, nothing
  submitted.
- fanout/release-notes.md: draft notes for the live releases
  v0.1, v0.5, and v1.0.

Publicity grades and the channel log are in PUBLICITY.md.
Overall fan-out grade: 9,543 of 10,000. The loop never posts to
social: all social channels are held with named reasons in
PUBLICITY.md. Defensive scope only throughout this set.

## License

Code: Apache-2.0 (see LICENSE). Tutorials: CC BY 4.0. Ruled in D-V3-11, 2026-11-04.

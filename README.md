# cyber-range-lab

A working cyber range on an isolated lab network. Defense first: hardening, logging, detection, response. Offensive scenarios run only inside the isolation and only on Jesun's sign-off. This scaffold holds the defensive Learn scope and the isolation rules only.

Status: Learn DONE (2026-11-05, ROADMAP-V3-BATCH). Level 1 is built, tested, and measured below. Defensive scope only; the snapshot is synthetic teaching data, not a live R610 capture. Build and Deep are not started and stay gated.
Project: P24. Fleet node: Dell R610. Wave: Wave 5 (after P13).

## Start here

1. Read SPEC.md for scope and acceptance criteria.
2. Read DOSSIER.md for the past, present, and future of this problem (v1).
3. Read NOVELTY.md for the proposed novelty (DRAFT, pending the Jev claim_check gate).
4. Start at level-1-learn/README.md, then level-2-build, then level-3-deep.

## Level map

- Level 1, Learn: the core idea, built small and clean, with a teaching path.
- Level 2, Build: a real working system other people can run.
- Level 3, Deep: benchmarks, optimization, evaluation, hard cases.

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

## Novelty

PROPOSED. See NOVELTY.md. The novelty text is a draft until the Jev claim_check gate passes on it.

## License

Code: Apache-2.0 (see LICENSE). Tutorials: CC BY 4.0. Ruled in D-V3-11, 2026-11-04.

# Changelog

All notable changes to this project. Format: Keep a Changelog 1.1.
Versions follow Semantic Versioning. The tags v0.1, v0.5 and v1.0 were
released under the earlier Learn / Build / Deep ladder; under the
portfolio standard v2 the verdict is Draft (README.md), and the next
release waits until a level is earned.

## [Unreleased]

### Changed
- 2026-11-08: Adopted the portfolio standard v2. README.md is the
  abstract (question, headline, field, job family, verdict: Draft, not
  pre-registered), with Reproduce, Lifecycle and Layout. PROPOSAL.md
  (not locked) folds in SPEC.md, NOVELTY.md, DOSSIER.md, the Build
  spec and DEEP-SPEC.md, and drafts a confirmatory cycle. REPORT.md
  folds in the three level READMEs, the threat model, the candidate
  ATT&CK mapping, docs/research-review.md and the ROADMAP.md backlog.
  Code moves to src/, inputs to experiments/, results to results/
  (byte for byte unchanged), the runbook to docs/RUNBOOK.md and the
  fan-out to docs/fanout/. docs/index.md is retired; its summary is in
  README.md and REPORT.md. Grades leave every public file.
- 2026-11-08: The dashboard reads the verdict and lifecycle from
  README.md and the failure modes from REPORT.md; it no longer shows a
  grade.

### Added
- 2026-11-08: CHANGELOG.md, CITATION.cff, SECURITY.md, four decision
  records in docs/decisions/, tests/test_layout.py (required files,
  README abstract, no public grade). CI runs with read-only
  permissions; CodeQL covers JavaScript as well as Python; Dependabot
  watches the site's npm packages.
- 2026-11-07: Threshold and window sweep and the authored-intent
  sanity check (src/evaluate_deep.py, results/results_eval.json).
  Threat model and candidate ATT&CK mapping. Self-review against a
  research rubric. Live dashboard in site/ with a browser port that
  must reproduce every results file before it builds; Pages workflow.

### Fixed
- 2026-11-07: R5 drift alerts no longer merge across controls (alerts
  5 to 6, docs/decisions/0004). R1's alert text states the configured
  window. The incident lists related lower-severity alerts.

### Removed
- 2026-11-08: tests/test_smoke.py (replaced by tests/test_layout.py).

## [1.0] - 2026-11-05

### Added
- Compressed Deep: range runbook plus hardened detection loop:
  configurable thresholds, R5 baseline drift, incident lifecycle with
  closure checklist (docs/decisions/0003). 9 firings, 5 alerts at
  this release.
- Written fan-out set (now docs/fanout/), defensive only.
- GitHub Actions polish pack: CI matrix with ruff, CodeQL, Dependabot,
  release artifacts, labeler, greetings, stale (comment only).

## [0.5] - 2026-11-05

### Added
- Build: defensive detection loop on synthetic logs, four rules, one
  incident record (26 lines, 24 parsed, 7 firings, 4 alerts).

## [0.1] - 2026-11-05

### Added
- Learn: 10-control hardening checker on synthetic snapshots (before 0
  of 10, after 10 of 10).
- 2026-11-04: Wave 0 scaffold (spec, dossier, novelty draft).

[Unreleased]: https://github.com/JesunAhmadUshno/cyber-range-lab/compare/v1.0...HEAD
[1.0]: https://github.com/JesunAhmadUshno/cyber-range-lab/releases/tag/v1.0
[0.5]: https://github.com/JesunAhmadUshno/cyber-range-lab/releases/tag/v0.5
[0.1]: https://github.com/JesunAhmadUshno/cyber-range-lab/releases/tag/v0.1

# DOSSIER: cyber-range-lab (P24), ship state v1.0, 2026-11-05

Written under the documentation and publishing standard (past, present, future). Updated at ship time.

## Past

Prior art for this project is named in NOVELTY.md (public cyber range guides and SIEM tutorials). The history of the problem, the key papers and systems, and what was tried before are recorded in the Roadmap v2 section text in SPEC.md and will be expanded with dated sources at the project's wave, before Build opens.

## Present

Current demand evidence: hiring value scored in the fleet pass (new candidates P23 to P29: see the decision pack Sections 4 and 5) [confirmed, fleet and scoring pass 2026-11-04; for P23 to P29, the decision pack 2026-11-04]. The Round 3 research (2026-11-04) found the market centre at post-training, evals, environments, and inference depth [confirmed as the research finding; the report is at ~/workspace/research_notes/roadmap-v3-revaluation-research-20261104-0949/report.md]. Tools and versions are pinned at Build time, not in this v1.

## Present state at v1.0 (2026-11-05)

Learn DONE: a 10-control hardening checker over synthetic before
and after snapshots (0 of 10 to 10 of 10), grade 8,500 of 10,000.
Build DONE: a defensive detection loop on 26 synthetic log lines
(24 parsed, 2 quarantined, 7 firings, 4 alerts, incident INC-001),
grade 8,300 of 10,000. Compressed Deep DONE: the range runbook
plus the hardened loop (configurable thresholds validated from
config.json, R5 baseline drift reusing the Learn checker, an
incident lifecycle with logged transitions and a closure
checklist), measured at 9 firings, 5 alerts at v1.0 (6 after the R5 dedup fix), drift on 2 controls,
incident closed, 71 total tests, grade 8,400 of 10,000. All data
is synthetic teaching data; no live R610 capture is claimed.
Tools: Python 3.12 standard library only, runs on the Muse VM.

## Future

The rest of the v2 Deep scope is the v1.1 backlog in ROADMAP.md.
Scenario work stays held for Jesun's batched sign-off and is not
drafted. Any forecast about this field is [unverified] unless a
dated primary source is added here.

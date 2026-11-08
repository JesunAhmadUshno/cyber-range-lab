# Proposal: cyber-range-lab (P24)

Status: NOT LOCKED. This repo is not pre-registered. Part 1 is a draft
plan for a confirmatory cycle; it becomes the lock only when the Owner
sets its pass lines and it is tagged proposal-v1 before any of its
runs. Part 2 keeps the original plans as they were written.

Scope: defensive only. Scenario work stays held for the Owner's
sign-off per scenario; nothing in this file drafts, lists or implies
scenario content, and no verdict depends on running one
(docs/decisions/0002).

## Why this repo is not pre-registered

Git history:

- 9fa3eb9 (2026-11-04), Wave 0 scaffold: SPEC.md, DOSSIER.md and
  NOVELTY.md came before any code, but they name scope and acceptance
  criteria only. There are no hypotheses, pass lines or analysis plan.
- 4556e11 (2026-11-05, Build): the build spec lived in the Build
  README and was committed in the same commit as the code and results
  it describes.
- c765fb6 (2026-11-05, Deep): DEEP-SPEC.md says "written before
  build", but it was committed together with the code and results, so
  git cannot show that it came first.

No plan with pass lines existed before a result, so the recorded
results are exploratory (REPORT.md) and the verdict is capped at
Functional until a locked confirmatory cycle runs. No tag is added
after the fact.

## Part 1. Confirmatory cycle (draft, not locked)

Question. On one real lab VM inside labnet, read without changing
anything, does the hardening checker report the VM's configuration
correctly, and does the detection loop parse its real logs without
silent loss?

Design, as drafted from the 2026-11-07 review (REPORT.md, open gaps
1, 2, 3 and 5). Every step is read-only and defensive; none needs a
scenario.

- Capture: one configuration snapshot and 24 hours of auth, sudo,
  service and firewall logs from a lab VM on the Dell R610 inside
  labnet, taken under docs/RUNBOOK.md and committed, dated, to
  experiments/ with secrets and exact versions removed.
- H1, checker agreement: each of the 10 controls as read by the
  checker matches a manual inspection of the VM by a second person.
  Pass line: to be set by the Owner before the lock.
- H2, parser coverage: the share of real log lines quarantined, per
  source. Pass line: to be set by the Owner before the lock.
- H3, benign false alarms: alerts raised on the 24 hours of normal
  admin activity, with every alert reviewed. Pass line: to be set by
  the Owner before the lock.
- Baseline comparison: fail2ban-regex with the stock sshd filter on
  the same auth log, reported next to R1.
- Reliability profile (METHOD section 4): a stated recovery target for
  the lab VM, a timed restore from its named snapshot, and the
  monitoring that would have caught the drift the drill injects
  (a hardening control switched off on the test VM, not an attack).

Analysis: every trial reported; no retry until it passes; misses
shown in REPORT.md.

## Part 2. Original plans, kept as written

Paths in Part 2 are those of the time: level-1-learn, level-2-build
and level-3-deep are now src/ (code), experiments/ (inputs) and
results/ (outputs); RUNBOOK.md is docs/RUNBOOK.md; ROADMAP.md is
CHANGELOG.md and REPORT.md (Future work).

### SPEC: cyber-range-lab (P24)

Phase skill: spec-driven-development (house engineering pipeline).
Status: Wave 0 scaffold spec, from Roadmap v2 text and the v3 decision pack. Scope and acceptance criteria below are the v2 section text, kept as the source of truth until the project's wave opens its own spec pass.

Fleet node: Dell R610. Wave: Wave 5 (after P13).
Hiring evidence: scored in the fleet pass (new candidates P23 to P29: see the decision pack Sections 4 and 5) [confirmed, fleet and scoring pass 2026-11-04, or the decision pack for P23 to P29].

#### Project section text (Roadmap v2, or the v3 candidate text for P23 to P29)

Subject: a cyber range on the isolated lab network (labnet 10.99.0.0/24, no route to the home LAN, no route to management interfaces) [confirmed, mission profile 2026-10-25].
Hard rules: snapshots are the reset; defensive work is the default scope; offensive work runs only as lab scenarios inside the isolation and only on Jesun's sign-off per scenario; no external targets; nothing leaves the range.
- Learn (this scaffold's scope): the hardening baseline on one lab VM: updates, least privilege, key-only access, logging on, with a before and after checklist.
- Build (later, gated): the detection loop end to end on one scenario: logs to one place, one alert on a named signal, one incident record.
- Deep (later, gated): further sign-off scenarios, each with a blue team report, plus the range runbook. Scenario content is NOT in this scaffold.

#### Acceptance criteria (scaffold level)

- Learn closes when the level-1-learn code runs, its README teaches the idea, and a fresh-eyes reader can follow it.
- Build closes when the system runs end to end, tests pass, and one benchmark or result table with method is in the README.
- Deep closes when the Deep scope in the section text is done, the failure modes are written, and the dossier is updated to ship state.
- No level closes on a claim. Evidence only: code, tests, numbers, links.

### Build spec: cyber-range-lab Level 2 (from the Build README, 2026-11-05)

1. Ingestion. Four synthetic sources (auth, sudo, service, firewall
   log text files in sample_logs/) are read into ONE central record
   list by detection.ingest. Central aggregation choice: the central
   store lives in memory and in the records list and per-source
   totals of results_build.json. No central_log.jsonl file is
   generated, so no generated log churn is committed.
2. Parser. Each source has its own line format. Every parsed line is
   normalised to {ts, source, host, user, event, detail}. A line
   that does not match its source format, or whose timestamp does
   not parse, is counted as quarantined and never crashes the run.
3. Detection rules, thresholds in code, defensive detection only.
   R1 repeated_failed_logins (high): 5 or more failed logins for one
   user on one host inside any 10 minute window; one firing per
   event that brings the in-window count to 5 or above.
   R2 sudo_by_non_admin_user (high): a sudo to root event whose user
   is not in the Learn admin list (labadmin, laboperator).
   R3 new_listening_port_not_in_baseline (medium): a listening port
   that is not in the Learn baseline ports (22, 9090).
   R4 automatic_updates_disabled (medium): a service log line that
   reports automatic_updates status=disabled.
4. Alerts. Firings are deduplicated by rule, host, and user: repeat
   firings inside a 10 minute dedup window collapse into one alert
   with a count, a first_seen time, and a last_seen time. Alert ids
   are assigned in first_seen order (A001, A002, and so on).
5. Incident record. For the highest severity alert set (high here),
   ONE incident record is created: id INC-001, opened_at taken from
   the log timestamps (never the wall clock), the high alert ids
   attached, affected hosts and users, defensive recommended
   response steps, and status open.
6. Runner. run_build.py loads the four sample log files, runs the
   loop, prints the totals, and writes results_build.json
   deterministically (sorted keys, log timestamps only).

### DEEP-SPEC: Level 3 Deep, cyber-range-lab (P24), compressed Deep

Status: written before build, 2026-11-05, ROADMAP-V3-BATCH December
Compression Protocol. Defensive scope only.

#### Compressed Deep definition for this project

Per the batch ledger: the range runbook plus the detection loop
hardened. That is the single hardest capability in the SPEC Deep
scope that can be built without held content. The rest of the v2
Deep scope is named in the repo root ROADMAP.md as the v1.1
backlog.

Held, not drafted: any offensive scenario content. Scenario work
stays held for Jesun's batched sign-off and no scenario, exploit,
or target content is drafted, listed, or implied in this level.

#### What is built

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

#### Acceptance criteria

- Full test suite passes, including new tests/test_deep_*.py.
- Runner run twice, results_deep.json identical across runs.
- Measured results table in level-3-deep/README.md matches
  results_deep.json exactly.
- Failure modes section written in the Deep README.
- Root README, DOSSIER.md, and root ROADMAP.md updated to ship
  state, with the rest of v2 Deep scope in ROADMAP.md as v1.1.
- No em dash character in any file. Standard library only.

### NOVELTY: cyber-range-lab (P24)

Status: DRAFT, PROPOSED. Not verified. This text does not move into any public post, paper, or profile until the Jev claim_check gate passes on the exact text.

#### Proposed claim

Against public cyber range guides and SIEM tutorials: this project aims to differ in the way its SPEC.md section text defines (a from-zero or self-hosted build, measured in public, on a named home fleet, with the failure modes written down). The exact difference is stated at the project's wave, after the prior art is re-read.

#### Prior art table

| Prior art | What it does | What this project does differently | Measured difference |
| --- | --- | --- | --- |
| public cyber range guides and SIEM tutorials | See DOSSIER.md, Past | PROPOSED, see the claim above | NO MEASUREMENT YET |

#### Honest size

If the novelty proves small, this file will say so and name the real value instead (a cleaner reproduction, a better benchmark, a first public dataset). No novelty is invented to fill this section.

### DOSSIER: cyber-range-lab (P24), ship state v1.0, 2026-11-05

Written under the documentation and publishing standard (past, present, future). Updated at ship time.

#### Past

Prior art for this project is named in NOVELTY.md (public cyber range guides and SIEM tutorials). The history of the problem, the key papers and systems, and what was tried before are recorded in the Roadmap v2 section text in SPEC.md and will be expanded with dated sources at the project's wave, before Build opens.

#### Present

Current demand evidence: hiring value scored in the fleet pass (new candidates P23 to P29: see the decision pack Sections 4 and 5) [confirmed, fleet and scoring pass 2026-11-04; for P23 to P29, the decision pack 2026-11-04]. The Round 3 research (2026-11-04) found the market centre at post-training, evals, environments, and inference depth [confirmed as the research finding; the report is at ~/workspace/research_notes/roadmap-v3-revaluation-research-20261104-0949/report.md]. Tools and versions are pinned at Build time, not in this v1.

#### Present state at v1.0 (2026-11-05)

Learn DONE: a 10-control hardening checker over synthetic before
and after snapshots (0 of 10 to 10 of 10).
Build DONE: a defensive detection loop on 26 synthetic log lines
(24 parsed, 2 quarantined, 7 firings, 4 alerts, incident INC-001).
Compressed Deep DONE: the range runbook
plus the hardened loop (configurable thresholds validated from
config.json, R5 baseline drift reusing the Learn checker, an
incident lifecycle with logged transitions and a closure
checklist), measured at 9 firings, 5 alerts at v1.0 (6 after the R5 dedup fix), drift on 2 controls,
incident closed, 71 total tests. All data
is synthetic teaching data; no live R610 capture is claimed.
Tools: Python 3.12 standard library only, runs on the Muse VM.

#### Future

The rest of the v2 Deep scope is the v1.1 backlog in ROADMAP.md.
Scenario work stays held for Jesun's batched sign-off and is not
drafted. Any forecast about this field is [unverified] unless a
dated primary source is added here.

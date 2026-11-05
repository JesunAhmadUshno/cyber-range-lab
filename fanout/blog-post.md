# Hardening First, Detection Second: Building cyber-range-lab in the Open

By Jesun Ahmad Ushno
Date: 2026-11-05
Status: DRAFT, written fan-out for P24 cyber-range-lab v1.0. Not posted.

## The problem

A lab host that is not hardened and not watched fails quietly.
Updates drift off, firewall defaults loosen, log lines pile up in
four places, and nobody can say which signal mattered or whether
an incident was ever closed. This project builds the defensive
side of that problem in the open, small enough to read and check
by hand: a hardening baseline, a detection loop, and a runbook.

This project, P24 in Roadmap v3, is defensive scope only at every
level. All data is synthetic teaching data. No live machine was
read, no live Dell R610 capture is claimed, and no system was
connected to, changed, or scanned. Scenario content is not in
this project: it stays held and needs Jesun's batched sign-off,
and none is drafted here or anywhere in the repo.

Repository: https://github.com/JesunAhmadUshno/cyber-range-lab

## Past, present, future (the dossier, condensed)

Past: public cyber range guides and SIEM tutorials already
exist. The prior art and the problem history are recorded in
DOSSIER.md and NOVELTY.md in the repo. The novelty claim there
stays marked PROPOSED. This post makes no novelty claim beyond
the measured work below.

Present: v1.0 closes three levels on 2026-11-05. Learn built a
10-control hardening checklist over synthetic before and after
lab VM snapshots (grade 8,500 of 10,000). Build added a defensive
detection loop end to end on synthetic logs: 4 sources to one
central record list, 4 named rules, deduplicated alerts, and one
incident record (grade 8,300 of 10,000). Compressed Deep added
the range runbook and hardened the loop: configurable thresholds
validated from config, a baseline drift rule reusing the Learn
checker, and an incident lifecycle with a closure checklist
(grade 8,400 of 10,000).

Future: the rest of the v2 Deep scope is named in ROADMAP.md in
the repo as the v1.1 backlog. It includes live operation on the
Dell R610 fleet node, streaming or scheduled log shipping,
cross-rule alert correlation, a persistent incident store, a
reviewed site policy, additional defensive rule types, and wider
parser coverage. None of that is done, and none of it is claimed
here. Scenario work stays held, not backlog.

## Main results claim

At v1.0, on synthetic teaching data only with no live machine read: Learn passed 22 tests on a 10-control hardening checklist over two synthetic lab VM snapshots, where the before snapshot passed 0 of 10 controls at 0 percent and the after snapshot passed 10 of 10 controls at 100 percent, an improvement of 10 controls, grade 8,500 of 10,000; Build passed 26 tests (48 tests in total) on 26 synthetic log lines from 4 sources, parsed 24 records and quarantined 2 malformed lines, produced 7 rule firings before deduplication (R1 2, R2 2, R3 1, R4 2) collapsed to 4 alerts after deduplication, and created 1 incident record INC-001 opened at 2026-11-05T10:08:00Z at high severity, grade 8,300 of 10,000; compressed Deep passed 23 tests (71 tests in total) on the same 26 synthetic log lines with 24 parsed and 2 quarantined, produced 9 rule firings before deduplication (R1 2, R2 2, R3 1, R4 2, R5 2) collapsed to 5 alerts after deduplication, found baseline drift on 2 controls (C01 and C07, baseline 10 of 10 against current snapshot 8 of 10), and closed incident INC-001 through its full lifecycle with 4 logged transitions and 4 of 4 closure checklist items, grade 8,400 of 10,000.

Every number in that claim comes from a run recorded in the
level READMEs and results files in the repo, on synthetic data.
Read the limits section below before quoting any of it.

## Results by level

### Level 1, Learn (release v0.1)

Learn scores one synthetic lab VM snapshot against 10 named
controls (C01 to C10): automatic updates on, SSH password
authentication off, key-only access, root login disabled, sudo
list bounded, logging and audit on, firewall default inbound
deny with only lab port 22 allowed, labnet isolation as
configuration fields (10.99.0.0/24, no route to home LAN or
management), unused services off, and a backup snapshot present.
A failed control carries defensive remediation text only.

| Measure | Result |
| --- | --- |
| Controls | 10 (C01 to C10) |
| Before snapshot | 0 of 10 passed (0 percent) |
| After snapshot | 10 of 10 passed (100 percent) |
| Improvement | Plus 10 controls |
| Tests | 22 |
| Determinism | results_learn.json identical across two runs (hash verified) |

Grade: 8,500 of 10,000, deductions itemized in the Learn README.

### Level 2, Build (release v0.5)

Build reads 4 synthetic sources (auth, sudo, service, firewall)
into one central record list, normalises each line, quarantines
malformed lines without crashing, applies 4 defensive rules,
deduplicates firings into alerts, and creates one incident
record for the high severity alerts.

| Measure | Result |
| --- | --- |
| Log lines, 4 sources (auth 12, sudo 5, service 6, firewall 3) | 26 |
| Parsed records | 24 |
| Quarantined malformed lines | 2 |
| Rule firings before dedup (R1 2, R2 2, R3 1, R4 2) | 7 |
| Alerts after dedup | 4 |
| Incident | INC-001, opened 2026-11-05T10:08:00Z, high severity, status open |
| Tests | 26 Build, 48 in total |
| Determinism | results_build.json identical across two runs (hash verified) |

Grade: 8,300 of 10,000, deductions itemized in the Build README.

### Level 3, Deep, compressed (release v1.0)

Deep moves detection policy into level-3-deep/config.json with
validation, adds one new defensive rule (R5 baseline_drift,
which reuses the Learn checker to compare the current snapshot
against the hardened baseline), adds an incident lifecycle
(open, triaged, contained, closed, in that order only, with a
4-item closure checklist), and ships the range runbook.

| Measure | Result |
| --- | --- |
| Log lines, 4 sources | 26 |
| Parsed records, quarantined | 24 parsed, 2 quarantined |
| Rule firings before dedup (R1 2, R2 2, R3 1, R4 2, R5 2) | 9 |
| Alerts after dedup | 5 |
| Baseline drift | 2 controls (C01, C07); baseline 10 of 10, current 8 of 10 |
| Threshold check, threshold 3 in config | R1 firings 6 (against 2 at threshold 5) |
| Incident | INC-001, lifecycle closed, 4 logged transitions, closure checklist 4 of 4 |
| Tests | 23 Deep, 71 in total |
| Determinism | results_deep.json identical across two runs (hash verified) |

Grade: 8,400 of 10,000. Deductions are itemized in the Deep
README: minus 600 for synthetic logs and snapshots with no live
capture, minus 300 for single host and batch only, minus 200
for running on the Muse VM instead of the Dell R610, minus 200
because config values are validated teaching defaults and not a
reviewed site policy, minus 200 because drift compares
configuration fields only and Deep adds one new rule type only,
and minus 100 because the lifecycle is an in-memory record with
no persistence or notification. Total deductions 1,600, and
10,000 minus 1,600 is 8,400.

## Honest limits

- Synthetic data only, at every level: hand-written JSON
  snapshots and hand-authored log files, not the state or logs
  of any real machine. No R610 capture is claimed.
- The checker and the drift rule read configuration fields at
  face value. A field that says a control is on is taken as on;
  neither level inspects enforced state on a real machine.
- Thresholds, the admin list (labadmin, laboperator), the
  baseline ports (22, 9090), and the dedup window are teaching
  values. In Deep they are configurable and validated, but they
  are not a reviewed site policy.
- One host, batch only: no streaming, no live log shipping, no
  fleet view, and no cross-rule correlation in v1.0.
- The parser covers only the authored line formats. A line in
  another format is quarantined and counted, which is safe but
  is also silent signal loss.
- The incident lifecycle is a record, not a service: no
  persistence across runs, no notification, and no assignment
  queue. The closed lifecycle uses fixed recorded review times.
- Compressed Deep is not the full v2 Deep scope. The remainder
  is the named v1.1 backlog in ROADMAP.md.
- The runs executed on the Muse VM, not the assigned Dell R610
  fleet node. That deduction is named in each level grade.

## Where to go next

- Tutorial: fanout/tutorial.md in the repo, a step-by-step
  module that runs all three levels and the full test suite.
- Releases: v0.1 (Learn), v0.5 (Build), v1.0 (Learn, Build,
  compressed Deep) on the GitHub repo linked above.
- Runbook: level-3-deep/RUNBOOK.md in the repo, defensive
  operations only.
- License: code Apache-2.0, tutorials CC BY 4.0.

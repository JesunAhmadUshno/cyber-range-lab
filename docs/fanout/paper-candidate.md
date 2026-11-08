# Paper candidate brief: the defensive detection loop and baseline drift

Project: P24 cyber-range-lab
Status: CANDIDATE, brief written 2026-11-05
Submission note: submission is Jesun's tap. Nothing is submitted by
this brief, and no venue has been contacted. The publications
tracker is updated by the coordinator, not by this file.

## Working title

From hardening baseline to drift alert: a defensive detection loop with configurable policy and a closure-checked incident lifecycle, measured on synthetic lab data

## Abstract draft

Based only on the measured v1.0 results recorded in the repo.
Numbers below are from synthetic teaching data and are stated
as such. No live machine was read, and no live capture is
claimed. Defensive scope only.

A small lab host needs three linked defences: a hardening
baseline it can be scored against, a detection loop that turns
log lines into a small set of reviewed alerts, and a way to
notice when the host drifts away from its own baseline. This
work presents an open, dependency-free implementation of that
loop and measures it on synthetic data. At Learn level, a
10-control hardening checklist scored a synthetic before
snapshot at 0 of 10 (0 percent) and a synthetic after snapshot
at 10 of 10 (100 percent), an improvement of 10 controls, with
22 unit tests. At Build level, a detection loop over 26
synthetic log lines from 4 sources parsed 24 records,
quarantined 2 malformed lines, produced 7 rule firings (R1 2,
R2 2, R3 1, R4 2) collapsed to 4 alerts after deduplication,
created incident INC-001 opened at 2026-11-05T10:08:00Z at high
severity, and passed 26 tests (48 in total). At Deep level, the
hardened loop with configurable validated policy produced 9
firings (R1 2, R2 2, R3 1, R4 2, R5 2) collapsed to 5 alerts,
detected baseline drift on 2 controls (C01 and C07, baseline 10
of 10 against current 8 of 10) by reusing the Learn checker as
rule R5, closed INC-001 through a 4-transition lifecycle with a
4 of 4 closure checklist, and passed 23 tests (71 in total).
The stack ships with 71 unit tests. All data is synthetic,
thresholds are teaching values, and drift reads configuration
fields only; the paper claims the loop design and its measured
behaviour on these synthetic sets, not performance on a live
host.

## Method outline

1. Hardening layer: 10 named controls (C01 to C10) evaluated in
   fixed order over a validated synthetic snapshot, each
   returning pass or fail with defensive remediation text.
2. Ingestion and parsing: 4 synthetic sources (auth, sudo,
   service, firewall) normalised to one record shape (ts,
   source, host, user, event, detail), with malformed lines
   quarantined and counted, never crashing the run.
3. Detection rules: R1 counts failed logins per user and host
   in a window, R2 checks sudo use against the admin list, R3
   checks listening ports against the baseline ports, and R4
   checks the automatic updates status field.
4. Deduplication and incident creation: firings deduplicated
   by rule, host, and user inside a dedup window into alerts,
   with one incident record created for the highest severity
   alert set.
5. Configurable policy (Deep): thresholds, windows, admin
   users, and baseline ports held in a validated config file,
   with default values equal to the Build constants so Build is
   the regression. A threshold change to 3 raises R1 firings
   from 2 to 6 on the same records, proving the config path.
6. Baseline drift (Deep): rule R5 imports and reuses the Learn
   checker to compare the current snapshot against the hardened
   baseline, firing once per control that passed in the
   baseline and fails now.
7. Incident lifecycle (Deep): open, triaged, contained, closed
   in that order only, every transition logged, and closure
   refused until all 4 checklist items are true.
8. Determinism: each runner writes its results file with
   sorted keys and timestamps from the data only, verified
   identical across two runs at every level.

## Results table

Measured 2026-11-05, synthetic data only, from the level READMEs
in the repo.

| Level | Set | Headline result | Detail | Tests |
| --- | --- | --- | --- | --- |
| Learn | 2 synthetic snapshots, 10 controls | 0 of 10 to 10 of 10 | Improvement plus 10 controls | 22 |
| Build | 26 synthetic log lines, 4 sources | 24 parsed, 2 quarantined, 7 firings to 4 alerts | Incident INC-001 opened 2026-11-05T10:08:00Z, high | 26 (48 total) |
| Deep | Same 26 lines, baseline and current snapshots | 9 firings to 5 alerts, drift 2 controls | Baseline 10 of 10, current 8 of 10, C01 and C07; incident closed, checklist 4 of 4 | 23 (71 total) |

## Venue class note

Per SPEC.md, the paper angle for P24 is the defensive loop and
its runbook evidence. This brief is the synthetic-measurement
form, stated as such. Venue class is a workshop or conference
in security education, defensive operations, or ML systems
operations, or a journal of the AJSE class, per the
publications pipeline tracker rules. One venue at a time. No
venue is named as submitted, accepted, or contacted in this
brief. Fees, if any, arise only after acceptance and remain
Jesun's call under the free-only rule.

## Limits the paper must carry

- Synthetic data only. No live host, live logs, or live drift
  was measured. Synthetic separation does not prove live
  detection performance.
- Hardening and drift read configuration fields at face value.
  Enforced state on a real machine is not inspected.
- Thresholds, admin users, and baseline ports are teaching
  values, not a reviewed site policy, even in configurable form.
- One host, batch only, 5 rule types in total. No streaming,
  no cross-rule correlation, and no persistent incident store
  in v1.0; those items are the v1.1 backlog in ROADMAP.md.
- The lifecycle record uses fixed recorded review times and
  holds no persistence or notification. It is a walkthrough,
  not a handled live incident.
- Defensive scope only. No scenario content is part of this
  candidate, and scenario work stays held for Jesun's sign-off.

## Submission gate

Submission is Jesun's tap and nothing is submitted. This brief is
the candidate only.

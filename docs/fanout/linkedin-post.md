# LinkedIn post draft: P24 cyber-range-lab v1.0

Status: DRAFT NOT POSTED
Date drafted: 2026-11-05
Author: Jesun Ahmad Ushno
Rule for this platform: the link goes in the first comment, not in the
post body. The first comment line is at the end of this file.

## Post body

A lab host that is not hardened and not watched fails quietly.
So I built the defensive side in the open, and labelled every
synthetic number as synthetic.

cyber-range-lab v1.0 is done: Learn, Build, and a compressed
Deep, Python standard library only. All data is synthetic
teaching data. No live machine was read, and no live capture is
claimed. Defensive scope only throughout.

Learn: a 10-control hardening checklist (C01 to C10) over two
synthetic lab VM snapshots. Before: 0 of 10 passed, 0 percent.
After: 10 of 10 passed, 100 percent. Improvement: plus 10
controls. 22 tests.

Build: a detection loop on 26 synthetic log lines from 4
sources (auth, sudo, service, firewall). 24 parsed, 2
quarantined, 7 rule firings before deduplication collapsed to
4 alerts. One incident, INC-001, opened 2026-11-05T10:08:00Z at
high severity. 48 tests in total.

Deep (compressed): policy moved into a validated config file,
one new rule (R5 baseline drift, reusing the Learn checker),
and an incident lifecycle with a closure checklist, plus the
range runbook. 9 firings to 5 alerts. Drift on 2 controls, C01
and C07: baseline 10 of 10, current snapshot 8 of 10. Incident
closed with 4 logged transitions and 4 of 4 checklist items.
71 tests in total, with the limits named in the repo.

The honest limits, in the post and not in a footnote: synthetic
snapshots and logs only; hardening and drift read configuration
fields at face value, not enforced state; thresholds and policy
values are teaching values, not a reviewed site policy; one
host, batch only, with no streaming. The rest of the Deep scope
is named as the v1.1 backlog in the repo, not claimed as done.
Scenario content stays held for sign-off and is not drafted.

If you run a small lab: which do you check first when a host
drifts, the hardening baseline, the alert list, or the incident
record?

## First comment (post this as the first comment, per the standing rule)

Repo, releases v0.1, v0.5, and v1.0, and the full tutorial: https://github.com/JesunAhmadUshno/cyber-range-lab

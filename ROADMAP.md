# ROADMAP: cyber-range-lab (P24)

## Shipped

- v0.1 Learn (2026-11-05): 10-control hardening checker on
  synthetic snapshots.
- v0.5 Build (2026-11-05): defensive detection loop on synthetic
  logs, 4 rules, one incident record.
- v1.0 compressed Deep (2026-11-05): range runbook plus hardened
  detection loop: configurable thresholds, R5 baseline drift,
  incident lifecycle with closure checklist. Grade 8,400 of
  10,000, deductions in level-3-deep/README.md.

## v1.1 backlog (the rest of the v2 Deep scope)

- Live operation on the Dell R610 fleet node inside labnet,
  replacing the synthetic snapshots and logs with a real lab
  capture taken under the runbook.
- Streaming or scheduled log shipping into the loop, replacing
  the batch-only runner.
- Cross-rule alert correlation, so related alerts from
  different rules can be grouped into one incident.
- Persistent incident store across runs, with assignment and
  notification, replacing the in-memory lifecycle record.
- A reviewed site policy for thresholds, admin users, and
  baseline ports, replacing the teaching defaults in
  config.json.
- Additional defensive detection rule types beyond counts,
  membership, status, and drift checks, each with its own
  measured synthetic case set.
- Parser coverage for real log formats beyond the authored
  synthetic formats, with quarantine rates measured per format.

## Held, not backlog

- Scenario work: HELD for Jesun's batched sign-off. It is not
  drafted, not listed in detail, and not part of v1.1 planning
  until that sign-off is given. This line is the full record.

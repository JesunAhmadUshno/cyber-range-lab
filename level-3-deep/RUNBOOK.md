# RUNBOOK: cyber-range-lab (P24), defensive operations

Scope: operating the lab and the detection loop in this repo.
Defensive operations only. No scenario content is in this runbook,
and none is added by following it. All data in this repo is
synthetic teaching data; adapt host names and paths to the real
lab host only inside the isolated lab network.

## 1. Isolation

- The lab network is labnet, 10.99.0.0/24.
- The lab host has no route to the home LAN and no route to
  management interfaces. Check both route fields before any work:
  the snapshot fields routes_to_home_lan and
  routes_to_management must both be false (Learn control C08).
- Nothing leaves the range: no log, snapshot, or result file is
  copied off the lab host except the reviewed evidence set in
  section 6.
- If an isolation field is wrong, stop, correct the configuration,
  and record the correction in the incident or run notes before
  any detection run.

## 2. Snapshot and reset

- Before a run, confirm a named snapshot of the hardened lab VM
  exists and record its snapshot id (Learn control C10).
- The snapshot is the reset. To reset the lab, restore the named
  hardened snapshot; do not rebuild the VM by hand.
- After a restore, re-run the baseline check in section 3 before
  trusting the host state.

## 3. Baseline check

- Run the Learn checker against the current snapshot:
  python level-1-learn/run_learn.py
- Expected hardened result: 10 of 10 controls pass on the after
  snapshot.
- Any control that passed in the baseline and fails now is drift.
  The Deep loop reports it as rule R5; treat drift as work to
  correct, not as noise.

## 4. Detection run

- Confirm the config first: level-3-deep/config.json holds the
  failed login threshold and window, the dedup window, the admin
  users, and the baseline ports. Changing a value changes the
  results; record any change in the run notes.
- Run: python level-3-deep/run_deep.py
- Read results_deep.json: per-source parse and quarantine counts,
  per-rule firings and alerts, the drift summary, and the
  incident record with its lifecycle log.
- Run the runner a second time and compare the file hash. The
  results must be identical; a difference means nondeterminism
  has entered the loop and the run is not evidence yet.

## 5. Incident handling

- The incident opens on the highest severity alerts, status open.
- Triage: confirm each alert against the raw synthetic log lines,
  record who reviewed it and when, then move the incident to
  triaged with a transition note.
- Containment, defensive steps only: confirm the affected
  accounts with their owners, check listening ports against the
  baseline ports, re-enable automatic updates where the drift or
  the service log shows them disabled, and correct any drifted
  hardening control back to the baseline value. Then move the
  incident to contained.
- Closure: complete the four item closure checklist
  (accounts_reviewed, ports_checked, updates_confirmed,
  closure_note_recorded). The loop refuses to close an incident
  with an incomplete checklist. Move to closed only with the
  checklist complete, and keep the transition log with the
  incident record.

## 6. Evidence checklist

For each run, keep together:

- The config file used, or its hash if it is unchanged.
- results_deep.json and its hash, plus the second run hash that
  proves determinism.
- The baseline and current snapshot files used for the drift
  check.
- The incident record with the full transition log and the
  completed closure checklist.
- The test output for the full suite for that run.

## 7. Teardown

- Close or record every open incident before teardown; an open
  incident is handed over in writing, never dropped silently.
- Restore the named hardened snapshot so the next run starts from
  the baseline.
- Confirm the isolation fields in section 1 one last time.
- Remove only files created by the run itself, inside the lab.
  Snapshots, results, and evidence from section 6 are kept.

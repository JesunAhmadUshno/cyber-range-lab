# Research review: cyber-range-lab (P24)

Reviewed 2026-11-07 against a doctoral research rubric. The repo is a defensive teaching range built in three levels on synthetic data, so the rubric is applied strictly and the grades are low where the evidence is thin. Every number here is in a committed results file or a level README.

Rule for this review: a gap that can be fixed without GPU time, paid APIs, long runs or new data is fixed in this change. Every gap left open names the exact data or compute it needs.

## Grades

| Criterion | Grade | Evidence and reasoning |
| --- | --- | --- |
| Research question | Weak | The repo asks an engineering question (can one hardening checker and one rule loop cover baseline, detection, drift and response on one VM?), not a research one. There is no question about detection quality that the data could answer. |
| Hypotheses | Absent, by design | Nothing is predicted before measurement. The hand checks in level-2-build/README.md and level-3-deep/README.md state expected counts, and the code reproduces them, but those are specifications, not hypotheses. |
| Method | Adequate for the stated scope | Standard-library Python, deterministic runners, results written with sorted keys, hash-checked across two runs, CI on Python 3.11 and 3.12. Rules, thresholds and the dedup policy are fully specified in code and config. |
| Baselines | Absent | No comparison with any existing tool (fail2ban, Wazuh, OSSEC, Sigma rules) on the same lines. See open gap 3. |
| Statistics and uncertainty | Not applicable as run, with a reason | Every output is a deterministic count on a fixed 26-line corpus: there is no sampling, so there is no sampling uncertainty to report. The real uncertainty is external validity, which no interval on this corpus can express. The new sensitivity sweep is the honest substitute: it shows how the counts move with the two R1 parameters. |
| Reproducibility | Strong | `python3 level-3-deep/run_deep.py` and `python3 level-3-deep/evaluate_deep.py` regenerate the committed results byte for byte; CI now fails if any committed results file differs from a fresh run. The dashboard's in-browser port is held to the same files by site/src/engine.check.mjs. |
| Threats to validity | Adequate after this change | Failure modes are written per level. This review adds the main one plainly: the corpus is circular (see below). |
| Related work | Weak | NOVELTY.md is a placeholder ("NO MEASUREMENT YET") and DOSSIER.md defers prior art. A short related-work note is added below; a measured comparison is open gap 3. |
| Limitations | Adequate | Written in every level README and quoted on the dashboard. |

## The central threat: a circular corpus

The 26 log lines were written by the same hand that wrote the rules, so every rule fires on lines written so that it would fire. The counts (9 firings, 6 alerts) show the rules behave as designed. They say nothing about detection on real logs: there is no benign background volume, one host, 52 minutes of activity, and no adversary who tries to avoid the five signals.

## Fixed in this change

1. **R5 dedup collapse (correctness).** Dedup keyed on (rule, host, user), so the two drift firings for C01 and C07, which share a timestamp, merged into one alert whose text named only C01. Dedup now also keys on the control id. Alerts go from 5 to 6 (A005 C01, A006 C07); firings stay at 9. Regression test: `test_each_drifted_control_gets_its_own_alert`.
2. **R1 detail text.** It said "in 10 minutes" whatever the configured window. It now states the configured window; the default text is unchanged. Test: `test_r1_detail_uses_configured_window`.
3. **Medium alerts outside the incident.** The incident took only the top-severity alerts, while its response steps asked the reader to act on ports and updates. It now lists `related_alert_ids` (A003 to A006), linked but not escalated. Test: `test_incident_links_lower_severity_alerts`.
4. **Unargued thresholds.** level-3-deep/evaluate_deep.py sweeps failed_login_threshold 1 to 10 against windows of 60, 300, 600, 900 and 1800 seconds and writes level-3-deep/results_eval.json. At the 600 second window only thresholds 5 and 6 fire on alice's burst without firing on bob's near miss, so the default is one of two working values on these lines, not an arbitrary constant. The recorded anchors match: threshold 5 gives 2 R1 firings, threshold 3 gives 6.
5. **No detection metrics at all.** level-3-deep/authored_intent.json labels each line with the episode it was written for, from the README hand checks, and evaluate_deep.py reports precision and episode recall per rule. At the default config every rule scores 1.0 on both. This is labelled everywhere as a circular sanity check, not an evaluation.
6. **No threat model or framework mapping.** README.md now has a threat model statement and a candidate ATT&CK table (R1 T1110, R2 T1548.003, R4 T1562.001; R3 and R5 left unmapped as hygiene and drift), marked candidate.
7. **No independent check of the published numbers.** The dashboard runs a JavaScript port of all three levels, and its build fails unless the port reproduces every committed results file, including alert ids, order and text.

## Related work (short note, not a measured comparison)

- fail2ban's shipped defaults (`maxretry = 5`, `findtime = 10m` in jail.conf) match R1's threshold of 5 and window of 600 seconds. fail2ban bans the source address; R1 raises an alert per user and host. Not run on these logs.
- Host intrusion detection systems such as OSSEC and Wazuh ship rule sets for SSH authentication failures and sudo use; SigmaHQ publishes vendor-neutral rules for Linux auth logs. None was run on this corpus, so no claim of difference is made.
- Configuration drift detection against a hardening baseline is the core of benchmark scanners such as CIS-Benchmark tooling and OpenSCAP. R5 is a ten-control teaching version of that idea, reading configuration fields, not the system.

## Open gaps and exactly what each needs

1. **Ground truth and real detection metrics.** Needs a labelled log corpus that the rule author did not write: for example a public honeypot or lab SSH auth.log set with labels, or a capture from the Dell R610 lab VM under the runbook with an independent labeller. Compute: seconds on a CPU.
2. **False positive rate under benign volume.** Needs benign background logs at realistic volume (days of auth, sudo and service logs from a lab host with normal admin activity). The parser quarantines any format it was not written for, so the parsers would also need extending to real syslog prefixes.
3. **Baseline comparison.** Needs fail2ban (and optionally Wazuh) installed on a lab VM: `apt install fail2ban` then `fail2ban-regex level-2-build/sample_logs/auth.log /etc/fail2ban/filter.d/sshd.conf`. Not done here because the repo is standard-library only and this machine has no fail2ban package; it is a few minutes of free work on the R610 lab VM.
4. **Novelty.** Needs the prior-art reading that DOSSIER.md defers, then a measured row in NOVELTY.md. No compute, a reading task with dated sources.
5. **Fleet run.** Needs the Dell R610 node inside labnet; every run so far was on a VM. The level grades already deduct for this.
6. **External grading.** The 8,400 Deep grade is self-assessed. Needs a reviewer outside the project.
7. **Streaming, clock skew, time zones, log rotation.** Engineering scope for v1.1 (ROADMAP.md). Needs a log shipper on the lab VM and a long-running process; not a research gap the current batch data can answer.
8. **A real incident.** The lifecycle timestamps are fixed recorded review times from run_deep.py. Needs an actual handled event on the lab range, which also needs the scenario sign-off the repo keeps on hold.

## Scope note

Defensive only. The ATT&CK labels are detection-side names for what each rule watches; no attack content was added.

# Website project page copy: cyber-range-lab

Site: jesunahmadushno.com
Status: COPY ONLY, draft for the project page. Dated 2026-11-05.
Nothing on any website was changed by this file.

## Headline

cyber-range-lab: a 10-control hardening baseline, a defensive detection loop, and baseline drift review, built in the open

## Summary

cyber-range-lab is an open defensive security lab project built
by Jesun Ahmad Ushno as project P24 in Roadmap v3. It builds the
defensive side in three levels: a 10-control hardening checklist
over synthetic lab VM snapshots; a detection loop that reads 4
synthetic log sources into one central record list, applies
named rules, deduplicates alerts, and creates an incident
record; and a hardened loop with configurable validated policy,
a baseline drift rule that reuses the hardening checker, an
incident lifecycle with a closure checklist, and a defensive
operations runbook. It runs on the Python standard library only.
All data is synthetic teaching data. No live machine was read
and no live capture is claimed. Scenario content is held and is
not part of this project page.

Status: v1.0, 2026-11-05. Learn, Build, and compressed Deep are
done. Total tests: 71, all passing at v1.0. Level grades: Learn
8,500 of 10,000, Build 8,300 of 10,000, Deep 8,400 of 10,000.

## Results

All results below are measured runs on synthetic data, recorded
in the level READMEs in the GitHub repo. They prove the
hardening, detection, drift, and lifecycle machinery, not the
state of any real machine.

| Level | Set | Headline result | Notes |
| --- | --- | --- | --- |
| Learn | 2 synthetic snapshots, 10 controls | Before 0 of 10 (0 percent), after 10 of 10 (100 percent) | Improvement plus 10 controls; 22 tests |
| Build | 26 synthetic log lines, 4 sources | 24 parsed, 2 quarantined, 7 firings to 4 alerts | Incident INC-001 opened 2026-11-05T10:08:00Z, high severity; 26 tests, 48 total |
| Deep (compressed) | Same 26 lines plus baseline and current snapshots | 9 firings to 5 alerts, drift on C01 and C07 | Baseline 10 of 10, current 8 of 10; incident closed, 4 transitions, checklist 4 of 4; 23 tests, 71 total |

## Honest limits

- Synthetic data only, at every level. No live machine was read
  and no Dell R610 capture is claimed.
- Hardening and drift read configuration fields at face value,
  not enforced state on a real machine.
- Thresholds, admin users, and baseline ports are teaching
  values, not a reviewed site policy.
- One host, batch only. Compressed Deep is not the full v2 Deep
  scope. The remainder is the v1.1 backlog in the repo
  ROADMAP.md.

## Links

- GitHub repo: https://github.com/JesunAhmadUshno/cyber-range-lab
- Release v0.1 (Learn): https://github.com/JesunAhmadUshno/cyber-range-lab/releases/tag/v0.1
- Release v0.5 (Build): https://github.com/JesunAhmadUshno/cyber-range-lab/releases/tag/v0.5
- Release v1.0 (Learn, Build, compressed Deep): https://github.com/JesunAhmadUshno/cyber-range-lab/releases/tag/v1.0
- Tutorial: fanout/tutorial.md in the GitHub repo
- Blog post draft: fanout/blog-post.md in the GitHub repo

## License note

Code: Apache-2.0. Tutorials: CC BY 4.0.

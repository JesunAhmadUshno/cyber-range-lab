# cyber-range-lab

A working cyber range on an isolated lab network. Defense first: hardening, logging, detection, response. Offensive scenarios run only inside the isolation and only on Jesun's sign-off. This repo holds the defensive Learn, Build, and compressed Deep scope and the isolation rules. All data is synthetic teaching data, not a live capture.

- Learn: a 10-control hardening baseline checker over synthetic before and after lab VM snapshots. Before snapshot: 0 of 10 controls passed. After snapshot: 10 of 10 controls passed.
- Build: a defensive detection loop end to end on synthetic logs: 4 sources to one central record list, 4 named rules, deduplicated alerts, and one incident record. Of 26 log lines, 24 parsed and 2 were quarantined; 7 rule firings before dedup became 4 alerts after dedup, with one incident (INC-001).
- Deep (compressed): the range runbook plus the detection loop hardened: configurable thresholds, a baseline drift rule R5 reusing the Learn checker, and an incident lifecycle with a closure checklist. Rule firings before dedup: 9; alerts after dedup: 6 (5 at v1.0, before the R5 dedup fix); baseline drift on 2 controls (C01, C07); incident lifecycle closed with 4 logged transitions and a closure checklist at 4 of 4.

Grade on record (of 10,000): Deep 8,400.

Defensive scope only. Any scenario content stays held and needs Jesun's sign-off; none is drafted in this repo.

Every number above is already published in this repo (README.md level write-ups) and reproduced by the runners in this repo, checked in CI. The full write-ups are in the level folders: level-1-learn, level-2-build, level-3-deep.

Releases: https://github.com/JesunAhmadUshno/cyber-range-lab/releases

# 0001. Python standard library only, deterministic runners

Date: 2026-11-05 (recorded 2026-11-08). Status: accepted.

Context. The range had to run anywhere at no cost, with no network,
credential or package install, and every number had to be checkable
by hand.

Decision. Every module and test imports only the Python standard
library. Runners take timestamps from log lines and fixed recorded
review times, never the wall clock, and write JSON with sorted keys.
requirements.txt lists no packages and exists so Dependabot has a
manifest to watch.

Consequences. Results regenerate byte for byte and CI fails if they
change. A real log shipper, a persistent incident store and a baseline
tool such as fail2ban are outside the repo and are future work
(REPORT.md).

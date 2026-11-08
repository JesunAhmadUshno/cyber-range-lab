# 0003. Compressed Deep: runbook plus hardened loop, the rest to the backlog

Date: 2026-11-05 (recorded 2026-11-08). Status: accepted.

Context. The original Deep scope was "further sign-off scenarios, each
with a blue team report, plus the range runbook". Scenarios are held
(decision 0002), so the full scope could not be built.

Decision. Deep was compressed to the single hardest capability that
needs no held content: the range runbook (docs/RUNBOOK.md) plus the
detection loop hardened (validated config, rule R5 baseline drift
reusing the hardening checker, incident lifecycle with a closure
checklist). The rest of the scope became the v1.1 backlog
(REPORT.md, Future work).

Consequences. The SPEC's Deep acceptance criterion is scored as missed
in REPORT.md, not as met.

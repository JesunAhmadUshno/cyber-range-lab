# 0002. Defensive scope only; scenarios held behind the Owner's sign-off

Date: 2026-11-04 (recorded 2026-11-08). Status: accepted, standing rule.

Context. The project subject is a cyber range on the isolated lab
network (labnet 10.99.0.0/24, no route to the home LAN or to
management interfaces). Offensive scenarios are possible on a range
and carry risk.

Decision. Defensive work is the only scope of this repo: hardening,
logging, detection and response. Offensive work runs only as lab
scenarios inside the isolation and only on the Owner's sign-off per
scenario; no scenario content is drafted, listed or implied in the
repo until then. No external targets; nothing leaves the range. Under
the portfolio standard v2 (METHOD section 7), no verdict level for
this repo requires running a scenario.

Consequences. All inputs to date are synthetic. The next verdict step
(Functional) needs only a read-only defensive capture of a real lab
VM, and the reliability drills in PROPOSAL.md Part 1 inject faults by
switching a hardening control off on a test VM, never by attacking it.

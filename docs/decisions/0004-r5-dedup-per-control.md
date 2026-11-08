# 0004. Alert dedup keys on the control id for drift alerts

Date: 2026-11-07 (recorded 2026-11-08). Status: accepted.

Context. Dedup keyed on (rule, host, user). The two R5 drift firings
for C01 and C07 share a timestamp, so they merged into one alert whose
text named only C01; the firewall regression dropped out of the alert.

Decision. Dedup also keys on the control id, so each drifted control
keeps its own alert. The v1.0 behaviour is kept in the browser port as
a documented option (perControl: false) so the defect stays visible.

Consequences. Alerts went from 5 to 6 (A005 C01, A006 C07); firings
stayed at 9. Every number published before 2026-11-07 (the v1.0
release and docs/fanout/) says 5 alerts. Regression test:
test_each_drifted_control_gets_its_own_alert.

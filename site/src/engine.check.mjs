// Known-answer check, run by "npm run build" before vite: the JS port must reproduce
// the committed Python results exactly (counts, alert ids, order and text), or the build fails.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import * as E from './engine.js';

const root = new URL('../../', import.meta.url);
const read = (p) => fs.readFileSync(new URL(p, root), 'utf8');
const json = (p) => JSON.parse(read(p));
const learn = json('results/results_learn.json');
const build = json('results/results_build.json');
const deep = json('results/results_deep.json');
const evalRes = json('results/results_eval.json');
const before = json('experiments/snapshot_before.json');
const after = json('experiments/snapshot_after.json');
const current = json('experiments/snapshot_current.json');
const config = json('experiments/config.json');
const labels = json('experiments/authored_intent.json');
const sources = Object.fromEntries(['auth', 'sudo', 'service', 'firewall'].map((s) => [s, E.splitLines(read(`experiments/sample_logs/${s}.log`))]));

// Level 1: every control, remediation and score.
const strip = ({ label, synthetic, controls, passed, total, score_percent }) => ({ label, synthetic, controls, passed, total, score_percent });
assert.deepEqual(E.evaluateSnapshot(before), strip(learn.before));
assert.deepEqual(E.evaluateSnapshot(after), strip(learn.after));
assert.equal(E.evaluateSnapshot(current).passed, deep.baseline_drift.current_passed);
assert.throws(() => E.evaluateSnapshot({ ...after, synthetic: false }), /labelled synthetic/);

// Level 2: records, per-source stats, firings, alerts and incident.
const b = E.runBuild(sources, config);
for (const k of ['sources', 'records', 'per_rule', 'firings_total_before_dedup', 'alerts_total_after_dedup', 'alerts', 'incident'])
  assert.deepEqual(b[k], build[k], `build ${k}`);

// Level 3: alerts A001-A006 in order, drift, threshold-3 rerun, and the full recorded incident.
const d = E.runDeep(sources, config, after, current);
for (const k of ['config', 'sources', 'per_rule', 'firings_total_before_dedup', 'alerts_total_after_dedup', 'alerts', 'baseline_drift'])
  assert.deepEqual(d[k], deep[k], `deep ${k}`);
assert.equal(d.threshold_check_threshold_3.r1_firings, deep.threshold_check_threshold_3.r1_firings);
const inc = d.incident;
for (const t of deep.incident.transitions.slice(1))
  E.transition(inc, t.to, t.at, t.actor, t.note, t.to === 'closed' ? Object.fromEntries(E.CLOSURE_CHECKLIST.map((k) => [k, true])) : null);
assert.deepEqual(inc, deep.incident, 'deep incident');

// Lifecycle errors carry the Python messages.
const fresh = () => E.runDeep(sources, config, after, current).incident;
assert.throws(() => E.transition(fresh(), 'contained', 'x', 'a', 'n'), /invalid transition open to contained: only triaged is allowed/);
const c = fresh(); E.transition(c, 'triaged', 'x', 'a', 'n'); E.transition(c, 'contained', 'x', 'a', 'n');
assert.throws(() => E.transition(c, 'closed', 'x', 'a', 'n', { accounts_reviewed: true }), /cannot close: checklist incomplete: ports_checked, updates_confirmed, closure_note_recorded/);

// v1.0 dedup key: the two drift firings collapse into one alert naming only C01 (the documented defect).
const v1 = E.runDeep(sources, config, after, current, { perControl: false });
assert.equal(v1.alerts_total_after_dedup, 5);
assert.match(v1.alerts.at(-1).detail, /C01/);
assert.equal(v1.alerts.at(-1).count, 2);

// Sweep and authored-intent check: all 50 cells and the per-rule scores.
const drift = E.baselineDrift(after, current, d.records.map((r) => r.ts).sort().at(-1)).firings;
assert.deepEqual(E.sweep(sources, config, labels, drift, evalRes.thresholds, evalRes.windows_seconds), evalRes.sweep, 'sweep');
assert.deepEqual(E.intentScores(E.runRules(d.records, config), E.lineEpisodes(sources, labels), labels), evalRes.authored_intent_default_config);

// Docs read at build time.
const report = E.parseReport(read('REPORT.md'));
assert.ok(report.failureModes.length >= 5, 'REPORT.md failure modes');
assert.ok(report.sha256, 'REPORT.md records the results_deep.json hash');
const readme = E.parseReadme(read('README.md'));
assert.ok(readme.verdict, 'README.md verdict line');
assert.deepEqual(readme.lifecycle.map((s) => s.stage), ['Question', 'Proposal', 'Baseline', 'Build', 'Evaluate', 'Report', 'Review', 'Release']);
const tests = ['test_learn_hardening', 'test_build_detection', 'test_deep_hardened', 'test_deep_eval'].map((f) => E.countTests(read(`tests/${f}.py`)));
assert.deepEqual(tests.slice(0, 2), [22, 26]);

console.log('engine ok', { learn: '0/10 -> 10/10', build: `${b.firings_total_before_dedup} firings, ${b.alerts_total_after_dedup} alerts`,
  deep: `${d.firings_total_before_dedup} firings, ${d.alerts_total_after_dedup} alerts, drift ${d.baseline_drift.drifted_controls}`, sweepCells: evalRes.sweep.length, tests });

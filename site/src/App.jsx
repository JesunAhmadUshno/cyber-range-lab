import { useMemo, useState, useEffect, useId, useRef } from 'react';
import learn from '../../results/results_learn.json';
import build from '../../results/results_build.json';
import deep from '../../results/results_deep.json';
import evalRes from '../../results/results_eval.json';
import before from '../../experiments/snapshot_before.json';
import after from '../../experiments/snapshot_after.json';
import current from '../../experiments/snapshot_current.json';
import defaultConfig from '../../experiments/config.json';
import labels from '../../experiments/authored_intent.json';
import authLog from '../../experiments/sample_logs/auth.log?raw';
import sudoLog from '../../experiments/sample_logs/sudo.log?raw';
import serviceLog from '../../experiments/sample_logs/service.log?raw';
import firewallLog from '../../experiments/sample_logs/firewall.log?raw';
import reportMd from '../../REPORT.md?raw';
import readmeMd from '../../README.md?raw';
import tLearn from '../../tests/test_learn_hardening.py?raw';
import tBuild from '../../tests/test_build_detection.py?raw';
import tDeep from '../../tests/test_deep_hardened.py?raw';
import tEval from '../../tests/test_deep_eval.py?raw';
import * as E from './engine.js';

const REPO = 'https://github.com/JesunAhmadUshno/cyber-range-lab';
const blob = (p) => `${REPO}/blob/main/${p}`;
const tree = (p) => `${REPO}/tree/main/${p}`;
const SOURCES = { auth: E.splitLines(authLog), sudo: E.splitLines(sudoLog), service: E.splitLines(serviceLog), firewall: E.splitLines(firewallLog) };
const SOURCE_FILE = { auth: 'auth.log', sudo: 'sudo.log', service: 'service.log', firewall: 'firewall.log' };
const REPORT = E.parseReport(reportMd);
const README = E.parseReadme(readmeMd);
const TESTS = { Learn: E.countTests(tLearn), Build: E.countTests(tBuild), Deep: E.countTests(tDeep) + E.countTests(tEval) };
const RULES = { R1: 'repeated_failed_logins', R2: 'sudo_by_non_admin_user', R3: 'new_listening_port_not_in_baseline', R4: 'automatic_updates_disabled', R5: 'baseline_drift' };
const sevColor = (s) => (s === 'high' ? 'var(--bad)' : 'var(--warn)');
const hhmm = (ts) => ts.slice(11, 16);
const pct = (x) => (x == null ? 'n/a' : `${Math.round(x * 100)}%`);
const canon = (v) => (Array.isArray(v) ? v.map(canon) : v && typeof v === 'object' ? Object.fromEntries(Object.keys(v).sort().map((k) => [k, canon(v[k])])) : v);
const same = (a, b) => JSON.stringify(canon(a)) === JSON.stringify(canon(b));
const clone = (x) => structuredClone(x);
const LOG_USERS = [...new Set(build.records.filter((r) => r.user !== 'system').map((r) => r.user))].sort();
const LOG_PORTS = [...new Set(build.records.filter((r) => r.event === 'listening_port').map((r) => +r.detail.split(' ')[0].split('=')[1]))].sort((a, b) => a - b);

const LAST_TS = build.records.map((r) => r.ts).sort().at(-1);
const SEPARATING = evalRes.sweep.filter((r) => r.failed_login_window_seconds === deep.config.failed_login_window_seconds && r.r1_precision === 1 && r.r1_episode_recall === 1).map((r) => r.failed_login_threshold);
const SECTIONS = [['top', 'Overview', '◎'], ['harden', 'Harden', '✓'], ['ingest', 'Ingest', '≡'], ['detect', 'Detect', '⚑'], ['sweep', 'Sweep', '∿'], ['drift', 'Drift', 'Δ'], ['incident', 'Incident', '◷'], ['limits', 'Limits', '❯_']];

function useReveal() {
  useEffect(() => {
    const els = document.querySelectorAll('.reveal');
    if (!('IntersectionObserver' in window)) { els.forEach((e) => e.classList.add('in')); return; }
    const io = new IntersectionObserver((es) => es.forEach((e) => { if (e.isIntersecting) { e.target.classList.add('in'); io.unobserve(e.target); } }), { threshold: 0.08 });
    els.forEach((e) => io.observe(e));
    return () => io.disconnect();
  }, []);
}

function MenuBar() {
  const [now, setNow] = useState(() => new Date());
  useEffect(() => { const t = setInterval(() => setNow(new Date()), 30000); return () => clearInterval(t); }, []);
  return (
    <div className="menubar" role="banner">
      <span className="apple" aria-hidden="true">◆</span>
      <a className="app" href="#top">Cyber Range Lab</a>
      <a className="m" href={blob('docs/RUNBOOK.md')}>Runbook</a>
      <a className="m" href={blob('REPORT.md')}>Report</a>
      <a className="m" href={blob('PROPOSAL.md')}>Proposal</a>
      <span className="spacer" />
      <span className="status"><i /> Synthetic data · defensive only</span>
      <a href={REPO}>GitHub ↗</a>
      <span className="clock">{now.toLocaleString('en-US', { weekday: 'short', hour: 'numeric', minute: '2-digit' })}</span>
    </div>
  );
}

function Dock() {
  const [active, setActive] = useState('top');
  useEffect(() => {
    const io = new IntersectionObserver((es) => es.forEach((e) => e.isIntersecting && setActive(e.target.id)), { rootMargin: '-45% 0px -50% 0px' });
    SECTIONS.forEach(([id]) => { const el = document.getElementById(id); if (el) io.observe(el); });
    return () => io.disconnect();
  }, []);
  return (
    <nav className="dock" aria-label="Sections">
      {SECTIONS.map(([id, label, icon]) => (
        <a key={id} href={`#${id}`} className={active === id ? 'on' : ''} aria-current={active === id ? 'true' : undefined}>
          <span className="ico" aria-hidden="true">{icon}</span><span className="lbl">{label}</span>
        </a>
      ))}
    </nav>
  );
}

function Range({ label, value, min, max, step, onChange, show }) {
  const id = useId();
  return (
    <div className="field">
      <label htmlFor={id}>{label} <span>{show}</span></label>
      <input id={id} type="range" min={min} max={max} step={step} value={value} onChange={(e) => onChange(+e.target.value)} />
    </div>
  );
}

function Check({ label, checked, onChange }) {
  return <label className="chk"><input type="checkbox" checked={checked} onChange={(e) => onChange(e.target.checked)} /> <span>{label}</span></label>;
}

function Match({ ok, yes, no }) {
  return <span className={`pill ${ok ? 'good' : 'warn'}`}>{ok ? `✓ ${yes}` : `● ${no}`}</span>;
}

export default function App() {
  useReveal();
  const [snap, setSnap] = useState(() => clone(current));
  const [preset, setPreset] = useState({ name: 'current', n: 0 });
  const [cfg, setCfg] = useState(() => clone(defaultConfig));
  const [perControl, setPerControl] = useState(true);
  const live = useMemo(() => {
    try { return { ok: true, ...E.runDeep(SOURCES, cfg, after, snap, { perControl }) }; }
    catch (e) { return { ok: false, error: e.message }; }
  }, [cfg, snap, perControl]);
  const loadPreset = (name) => { setSnap(clone({ before, after, current }[name])); setPreset((p) => ({ name, n: p.n + 1 })); };
  return (
    <div className="wrap">
      <MenuBar />
      <div className="glow" aria-hidden="true" />
      <Hero />
      <Hardening snap={snap} setSnap={setSnap} preset={preset} loadPreset={loadPreset} />
      <Ingest live={live} />
      <Detection live={live} cfg={cfg} setCfg={setCfg} perControl={perControl} setPerControl={setPerControl} snap={snap} />
      <Sweep cfg={cfg} snap={snap} />
      <Drift snap={snap} cfg={cfg} />
      <Incident live={live} />
      <Limits />
      <Dock />
      <footer>
        Synthetic teaching data, defensive scope only: no live machine was read, changed or scanned. Code: Apache-2.0.
        Every number on this page is read from the repo's <code>results/</code>, <code>experiments/</code>, README and REPORT at build time, or computed in your browser by a port of the Python that a known-answer check holds to the committed results.
        {' '}<a href={REPO} style={{ color: '#e9e4da' }}>Repository</a> · <a href={`${REPO}/releases`} style={{ color: '#e9e4da' }}>Releases</a>
      </footer>
    </div>
  );
}

function Hero() {
  const t = deep.sources.total, s = learn.summary, d = deep.baseline_drift;
  return (
    <header className="card hero window" id="top" data-title="range.app — README">
      <div className="head">
        <p className="eyebrow">Defensive cyber range · verdict: {README.verdict}</p>
        <span className="pill warn" title={deep.scenario}>● Synthetic teaching data · defensive scope only</span>
      </div>
      <h1>{t.lines} synthetic log lines become {deep.firings_total_before_dedup} rule firings, {deep.alerts_total_after_dedup} alerts and <em>a closed incident</em>.</h1>
      <p className="sub">
        The same checker that hardens a lab VM from {s.before_passed} to {s.after_passed} of {s.controls_total} controls also catches it drifting back to {d.current_passed}.
        Everything below runs in your browser: a JavaScript port of the repo's standard-library Python, checked at build time against the committed results, on the repo's own synthetic logs and snapshots.
        Change a threshold, break a control, or try to close the incident early.
      </p>
      <div className="actions">
        <a className="btn primary" href="#detect">Open the detection playground</a>
        <a className="btn ghost" href="#harden">Edit the VM snapshot</a>
        <span className="hint">Reproduce with <code>python src/run_deep.py</code></span>
      </div>
      <div className="tiles">
        <div className="tile"><div className="num">{s.before_passed} → {s.after_passed}</div><div className="cap">Hardening controls passed, before and after, of {s.controls_total}</div></div>
        <div className="tile"><div className="num">{t.parsed}/{t.lines}</div><div className="cap">Log lines parsed; {t.quarantined} malformed lines quarantined</div></div>
        <div className="tile"><div className="num">{deep.firings_total_before_dedup} → {deep.alerts_total_after_dedup}</div><div className="cap">Rule firings deduplicated into alerts (R1 to R5)</div></div>
        <div className="tile"><div className="num">{d.current_passed}/{d.current_total}</div><div className="cap">Current snapshot; drift on {d.drifted_controls.join(' and ')} · {deep.incident.incident_id} {deep.incident.lifecycle}</div></div>
      </div>
    </header>
  );
}

function ListField({ label, value, onChange, numeric }) {
  const id = useId();
  const [text, setText] = useState(value.join(', '));
  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      <input id={id} type="text" value={text} onChange={(e) => {
        setText(e.target.value);
        onChange(e.target.value.split(',').map((x) => x.trim()).filter(Boolean).map((x) => (numeric && /^\d+$/.test(x) ? +x : x)));
      }} />
    </div>
  );
}

function TextField({ label, value, onChange }) {
  const id = useId();
  return <div className="field"><label htmlFor={id}>{label}</label><input id={id} type="text" value={value ?? ''} onChange={(e) => onChange(e.target.value || null)} /></div>;
}

function SelectField({ label, value, options, onChange }) {
  const id = useId();
  return <div className="field"><label htmlFor={id}>{label}</label><select id={id} value={value} onChange={(e) => onChange(e.target.value)}>{options.map((o) => <option key={o} value={o}>{o}</option>)}</select></div>;
}

function Hardening({ snap, setSnap, preset, loadPreset }) {
  const set = (path, v) => setSnap((s) => { const n = clone(s); let o = n; path.slice(0, -1).forEach((k) => { o = o[k]; }); o[path.at(-1)] = v; return n; });
  let res = null, err = null;
  try { res = E.evaluateSnapshot(snap); } catch (e) { err = e.message; }
  const known = same(E.evaluateSnapshot(before).controls, learn.before.controls) && same(E.evaluateSnapshot(after).controls, learn.after.controls)
    && E.evaluateSnapshot(current).passed === deep.baseline_drift.current_passed;
  const k = preset.n;
  return (
    <section id="harden" className="card window reveal" data-title={`hardening.py — ${E.CONTROLS.length} controls, live`}>
      <div className="head">
        <div>
          <p className="eyebrow">Level 1 · Learn · live checker</p>
          <h2>{E.CONTROLS.length} controls, checked as you <em>edit the snapshot</em>.</h2>
          <p className="sub">
            Load one of the repo's three synthetic snapshots of <span className="mono">lab-vm-01</span>, then change any field. The checker reads configuration fields only, exactly like <a href={blob('src/hardening.py')}>hardening.py</a>; it never touches a machine.
            Your edited snapshot also feeds the drift and detection windows below.
          </p>
        </div>
        <Match ok={known} yes={`Presets reproduce results_learn.json (${learn.summary.before_passed}/10, ${learn.summary.after_passed}/10)`} no="Presets differ from results" />
      </div>
      <div className="seg" role="group" aria-label="Load a snapshot">
        {[['before', 'snapshot_before.json'], ['after', 'snapshot_after.json'], ['current', 'snapshot_current.json']].map(([n, l]) => (
          <button key={n} aria-pressed={preset.name === n} onClick={() => loadPreset(n)}>{l}</button>
        ))}
      </div>
      <div className="grid2 harden-grid">
        <div key={k}>
          <h3>Snapshot fields</h3>
          <div className="checks">
            <Check label="automatic_updates" checked={snap.automatic_updates === true} onChange={(v) => set(['automatic_updates'], v)} />
            <Check label="ssh.password_authentication" checked={snap.ssh.password_authentication === true} onChange={(v) => set(['ssh', 'password_authentication'], v)} />
            <Check label="ssh.publickey_authentication" checked={snap.ssh.publickey_authentication === true} onChange={(v) => set(['ssh', 'publickey_authentication'], v)} />
            <Check label="logging.system_log_enabled" checked={snap.logging.system_log_enabled === true} onChange={(v) => set(['logging', 'system_log_enabled'], v)} />
            <Check label="logging.audit_enabled" checked={snap.logging.audit_enabled === true} onChange={(v) => set(['logging', 'audit_enabled'], v)} />
            <Check label="network.routes_to_home_lan" checked={snap.network.routes_to_home_lan === true} onChange={(v) => set(['network', 'routes_to_home_lan'], v)} />
            <Check label="network.routes_to_management" checked={snap.network.routes_to_management === true} onChange={(v) => set(['network', 'routes_to_management'], v)} />
            <Check label="backup.snapshot_present" checked={snap.backup.snapshot_present === true} onChange={(v) => set(['backup', 'snapshot_present'], v)} />
          </div>
          <div className="controls form2">
            <SelectField label="ssh.permit_root_login" value={snap.ssh.permit_root_login} options={['yes', 'no', 'prohibit-password']} onChange={(v) => set(['ssh', 'permit_root_login'], v)} />
            <SelectField label="firewall.default_inbound" value={snap.firewall.default_inbound} options={['allow', 'deny']} onChange={(v) => set(['firewall', 'default_inbound'], v)} />
            <ListField label="firewall.allowed_inbound_ports" value={snap.firewall.allowed_inbound_ports} numeric onChange={(v) => set(['firewall', 'allowed_inbound_ports'], v)} />
            <ListField label="sudo_users" value={snap.sudo_users} onChange={(v) => set(['sudo_users'], v)} />
            <ListField label="ssh.authorized_key_users" value={snap.ssh.authorized_key_users} onChange={(v) => set(['ssh', 'authorized_key_users'], v)} />
            <ListField label="services.enabled" value={snap.services.enabled} onChange={(v) => set(['services', 'enabled'], v)} />
            <TextField label="network.labnet_cidr" value={snap.network.labnet_cidr} onChange={(v) => set(['network', 'labnet_cidr'], v ?? '')} />
            <TextField label="backup.snapshot_id" value={snap.backup.snapshot_id} onChange={(v) => set(['backup', 'snapshot_id'], v)} />
          </div>
        </div>
        <div>
          {err ? <p className="err" role="alert">HardeningError: {err}</p> : (
            <>
              <div className="score" aria-live="polite">
                <span className="big">{res.passed}<small>/{res.total}</small></span>
                <span className="hint">{res.score_percent}% of controls pass · {snap.label}</span>
              </div>
              <ul className="ctl-list">
                {res.controls.map((c) => (
                  <li key={c.control_id}>
                    <span className={`pill ${c.passed ? 'good' : 'bad'}`}>{c.passed ? 'pass' : 'fail'}</span>
                    <div><b className="mono">{c.control_id}</b> {c.control}{c.remediation && <div className="hint">{c.remediation}</div>}</div>
                  </li>
                ))}
              </ul>
            </>
          )}
        </div>
      </div>
    </section>
  );
}

function Timeline({ firings }) {
  const parsed = Object.keys(SOURCES).flatMap((s) => SOURCES[s].filter((l) => l.trim()).map((l) => ({ s, r: E.parseLine(s, l) })));
  const lanes = ['firings', 'auth', 'sudo', 'service', 'firewall'];
  const W = 960, H = 220, pad = { l: 78, r: 96, t: 14, b: 28 }, lane = (H - pad.t - pad.b) / lanes.length;
  const t0 = E.parseTs('2026-11-05T10:00:00Z'), t1 = E.parseTs('2026-11-05T10:55:00Z');
  const x = (ts) => pad.l + ((E.parseTs(ts) - t0) / (t1 - t0)) * (W - pad.l - pad.r);
  const y = (name) => pad.t + lanes.indexOf(name) * lane + lane / 2;
  const q = (s) => parsed.filter((p) => p.s === s && !p.r).length;
  return (
    <div className="scroll-x chart-scroll"><svg className="chart" viewBox={`0 0 ${W} ${H}`} role="img" aria-label="Event timeline of all synthetic log lines by source from 10:00 to 10:55, with live rule firings overlaid">
      {[0, 10, 20, 30, 40, 50].map((m) => {
        const ts = `2026-11-05T10:${String(m).padStart(2, '0')}:00Z`;
        return <g key={m}><line className="axis" x1={x(ts)} x2={x(ts)} y1={pad.t} y2={H - pad.b} /><text x={x(ts)} y={H - 8} textAnchor="middle">{hhmm(ts)}</text></g>;
      })}
      {lanes.map((l) => <text key={l} x={pad.l - 10} y={y(l) + 4} textAnchor="end" style={{ fill: 'var(--text)' }}>{l === 'firings' ? 'rule firings' : `${l}.log`}</text>)}
      {parsed.filter((p) => p.r).map((p, i) => <circle key={i} cx={x(p.r.ts)} cy={y(p.s)} r="5" fill="var(--primary)" opacity="0.75" />)}
      {lanes.slice(1).map((s) => q(s) > 0 && <text key={s} x={W - pad.r + 10} y={y(s) + 4} style={{ fill: 'var(--bad)' }}>✕ {q(s)} quarantined</text>)}
      {firings.map((f, i) => {
        const cx = x(f.ts), cy = y('firings');
        return <g key={i}><path d={`M${cx} ${cy - 7} L${cx + 6} ${cy + 5} L${cx - 6} ${cy + 5} Z`} fill={sevColor(f.severity)} /><text x={cx} y={cy - 10} textAnchor="middle" style={{ fontSize: 10 }}>{f.rule}</text></g>;
      })}
    </svg></div>
  );
}

function Ingest({ live }) {
  const [src, setSrc] = useState('auth');
  const lines = SOURCES[src].filter((l) => l.trim());
  const stats = live.ok ? live.sources : deep.sources;
  return (
    <section id="ingest" className="card window reveal" data-title="sample_logs/ — 4 sources, parsed live">
      <div className="head">
        <div>
          <p className="eyebrow">Level 2 · Build · ingest</p>
          <h2>Every raw line, parsed or <em>quarantined</em>.</h2>
          <p className="sub">
            The four synthetic log files from <a href={tree('experiments/sample_logs')}>experiments/sample_logs/</a>, bundled as text and parsed in your browser with the same regular expressions as <a href={blob('src/detection.py')}>detection.py</a>.
            A line that matches no format for its source is counted and set aside, never a crash. Triangles on the timeline are the rule firings for the current playground settings.
          </p>
        </div>
        <Match ok={same(stats, deep.sources)} yes={`Counts match results_deep.json (${deep.sources.total.parsed} parsed, ${deep.sources.total.quarantined} quarantined)`} no="Counts differ" />
      </div>
      <Timeline firings={live.ok ? live.firings : []} />
      <div className="legend"><span><i style={{ background: 'var(--primary)' }} />parsed line</span><span><i style={{ background: 'var(--bad)' }} />high severity firing</span><span><i style={{ background: 'var(--warn)' }} />medium severity firing</span></div>
      <div className="head" style={{ marginTop: 20, marginBottom: 10 }}>
        <div className="seg" role="group" aria-label="Choose a log source">
          {Object.keys(SOURCES).map((s) => <button key={s} aria-pressed={src === s} onClick={() => setSrc(s)}>{SOURCE_FILE[s]} · {stats[s].lines}</button>)}
        </div>
        <span className="hint">{stats[src].parsed} parsed · {stats[src].quarantined} quarantined</span>
      </div>
      <div className="scroll-x loglines">
        <table>
          <tbody>
            {lines.map((l, i) => {
              const r = E.parseLine(src, l);
              return (
                <tr key={i}>
                  <td className="hint">{i + 1}</td>
                  <td><span className={`pill ${r ? 'good' : 'bad'}`}>{r ? r.event : 'quarantined'}</span></td>
                  <td className="mono raw">{l}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function Detection({ live, cfg, setCfg, perControl, setPerControl, snap }) {
  const setK = (k, v) => setCfg((c) => ({ ...c, [k]: v }));
  const toggle = (k, v, on) => setCfg((c) => ({ ...c, [k]: on ? [...c[k], v] : c[k].filter((x) => x !== v) }));
  const isDefault = same(cfg, defaultConfig) && perControl && same(snap, current);
  const ok = live.ok && same(live.alerts, deep.alerts) && live.firings_total_before_dedup === deep.firings_total_before_dedup;
  const maxBar = live.ok ? Math.max(4, ...Object.values(live.per_rule).map((r) => r.firings_before_dedup)) : 4;
  return (
    <section id="detect" className="card window reveal" data-title="detection_hardened.py — config.json playground">
      <div className="head">
        <div>
          <p className="eyebrow">Level 3 · Deep · detection loop</p>
          <h2>Tune the rules and watch firings <em>collapse into alerts</em>.</h2>
          <p className="sub">
            Rules R1 to R4 run over the parsed records from the logs, R5 from the drift between the hardened baseline and the snapshot you edited above.
            Firings that share a rule, host and user inside the dedup window become one alert. Defaults come from <a href={blob('experiments/config.json')}>config.json</a>.
          </p>
        </div>
        {isDefault
          ? <Match ok={ok} yes={`Defaults reproduce results_deep.json: ${deep.firings_total_before_dedup} firings, ${deep.alerts_total_after_dedup} alerts, ${deep.alerts[0].alert_id} to ${deep.alerts.at(-1).alert_id}`} no="Defaults differ from results_deep.json" />
          : <span className="pill info">Custom settings · <button className="linkish" onClick={() => { setCfg(clone(defaultConfig)); setPerControl(true); }}>reset config</button></span>}
      </div>
      <div className="controls">
        <Range label="failed_login_threshold" value={cfg.failed_login_threshold} min={1} max={10} step={1} onChange={(v) => setK('failed_login_threshold', v)} show={cfg.failed_login_threshold} />
        <Range label="failed_login_window_seconds" value={cfg.failed_login_window_seconds} min={60} max={1800} step={60} onChange={(v) => setK('failed_login_window_seconds', v)} show={`${cfg.failed_login_window_seconds}s`} />
        <Range label="dedup_window_seconds" value={cfg.dedup_window_seconds} min={60} max={3600} step={60} onChange={(v) => setK('dedup_window_seconds', v)} show={`${cfg.dedup_window_seconds}s`} />
      </div>
      <div className="grid2" style={{ marginBottom: 16 }}>
        <fieldset className="checks"><legend>admin_users (R2 ignores these)</legend>
          {LOG_USERS.map((u) => <Check key={u} label={u} checked={cfg.admin_users.includes(u)} onChange={(on) => toggle('admin_users', u, on)} />)}
        </fieldset>
        <fieldset className="checks"><legend>baseline_ports (R3 ignores these)</legend>
          {LOG_PORTS.map((p) => <Check key={p} label={String(p)} checked={cfg.baseline_ports.includes(p)} onChange={(on) => toggle('baseline_ports', p, on)} />)}
          <Check label="v1.0 dedup key (rule, host, user)" checked={!perControl} onChange={(v) => setPerControl(!v)} />
        </fieldset>
      </div>
      {!live.ok ? <p className="err" role="alert">DetectionConfigError: {live.error}</p> : (
        <div className="grid2">
          <div>
            <h3>Per rule: firings before dedup, alerts after</h3>
            <div className="bars" style={{ marginTop: 12 }}>
              {Object.entries(live.per_rule).map(([r, v]) => (
                <div className="bar-row" key={r}>
                  <div className="lab"><span><b className="mono">{r}</b> {RULES[r]}</span><b>{v.firings_before_dedup} → {v.alerts_after_dedup}</b></div>
                  <div className="track"><div className="fill" style={{ width: `${(v.firings_before_dedup / maxBar) * 100}%`, background: 'color-mix(in srgb, var(--primary) 35%, transparent)' }} /></div>
                  <div className="track thin"><div className="fill" style={{ width: `${(v.alerts_after_dedup / maxBar) * 100}%`, background: 'var(--primary)' }} /></div>
                </div>
              ))}
            </div>
            <div className="tiles" style={{ gridTemplateColumns: '1fr 1fr' }}>
              <div className="tile"><div className="num">{live.firings_total_before_dedup}</div><div className="cap">firings before dedup</div></div>
              <div className="tile"><div className="num">{live.alerts_total_after_dedup}</div><div className="cap">alerts after dedup</div></div>
            </div>
          </div>
          <div>
            <h3>Alerts</h3>
            <div className="scroll-x">
              <table>
                <thead><tr><th>Alert</th><th>Rule</th><th>Severity</th><th>User</th><th>First seen</th><th>Count</th></tr></thead>
                <tbody>
                  {live.alerts.map((a) => (
                    <tr key={a.alert_id} title={a.detail}><td className="mono">{a.alert_id}</td><td>{a.rule}</td><td><span className={`pill ${a.severity === 'high' ? 'bad' : 'warn'}`}>{a.severity}</span></td><td>{a.user}</td><td>{hhmm(a.first_seen)}</td><td>{a.count}</td></tr>
                  ))}
                </tbody>
              </table>
            </div>
            <ul className="details">{live.alerts.map((a) => <li key={a.alert_id}><b className="mono">{a.alert_id}</b> {a.detail}</li>)}</ul>
          </div>
        </div>
      )}
    </section>
  );
}

function Sweep({ cfg, snap }) {
  const [win, setWin] = useState(600);
  const rows = useMemo(() => {
    try {
      const { records } = E.ingest(SOURCES);
      const drift = E.baselineDrift(after, snap, records.map((r) => r.ts).sort().at(-1)).firings;
      return E.sweep(SOURCES, cfg, labels, drift, evalRes.thresholds, evalRes.windows_seconds);
    } catch { return null; }
  }, [cfg, snap]);
  if (!rows) return <section id="sweep" className="card window reveal" data-title="threshold_sweep — results_eval.json"><p className="err">The sweep needs a valid config and snapshot.</p></section>;
  const matches = same(rows, evalRes.sweep);
  const sel = rows.filter((r) => r.failed_login_window_seconds === win);
  const W = 960, H = 260, pad = { l: 40, r: 20, t: 18, b: 34 };
  const ymax = Math.max(8, ...rows.map((r) => Math.max(r.r1_firings, r.alerts_total)));
  const x = (t) => pad.l + ((t - 1) / 9) * (W - pad.l - pad.r);
  const y = (v) => pad.t + (1 - v / ymax) * (H - pad.t - pad.b);
  const recorded = win === deep.config.failed_login_window_seconds
    ? [[deep.config.failed_login_threshold, deep.per_rule.R1.firings_before_dedup], [3, deep.threshold_check_threshold_3.r1_firings]] : [];
  return (
    <section id="sweep" className="card window reveal" data-title="threshold_sweep — results_eval.json">
      <div className="head">
        <div>
          <p className="eyebrow">Sensitivity · computed live</p>
          <h2>Only thresholds {SEPARATING.join(' and ')} <em>separate</em> the burst from the near miss.</h2>
          <p className="sub">
            R1 rerun for every threshold from 1 to 10 at the chosen window. At the default {deep.config.failed_login_window_seconds} second window, lower thresholds also fire on bob's near miss and higher ones miss alice's burst (recorded in results_eval.json).
            The run uses your playground settings for everything except threshold and window. Its recorded twin is <a href={blob('results/results_eval.json')}>results_eval.json</a>, written by <a href={blob('src/evaluate_deep.py')}>evaluate_deep.py</a>.
          </p>
        </div>
        <Match ok={matches} yes={`All ${evalRes.sweep.length} cells match results_eval.json`} no="Differs from results_eval.json (custom settings)" />
      </div>
      <div className="seg" role="group" aria-label="R1 window in seconds">
        {evalRes.windows_seconds.map((w) => <button key={w} aria-pressed={win === w} onClick={() => setWin(w)}>{w}s</button>)}
      </div>
      <div className="scroll-x chart-scroll" style={{ marginTop: 12 }}><svg className="chart" viewBox={`0 0 ${W} ${H}`} role="img" aria-label={`R1 firings and total alerts against failed login threshold 1 to 10 at a ${win} second window`}>
        {[0, 2, 4, 6, 8, 10, 12].filter((v) => v <= ymax).map((v) => <g key={v}><line className="axis" x1={pad.l} x2={W - pad.r} y1={y(v)} y2={y(v)} /><text x={pad.l - 8} y={y(v) + 4} textAnchor="end">{v}</text></g>)}
        {evalRes.thresholds.map((t) => <text key={t} x={x(t)} y={H - 14} textAnchor="middle">{t}</text>)}
        <text x={(W + pad.l) / 2} y={H - 0} textAnchor="middle">failed_login_threshold</text>
        <line x1={x(cfg.failed_login_threshold)} x2={x(cfg.failed_login_threshold)} y1={pad.t} y2={H - pad.b} stroke="var(--muted)" strokeDasharray="4 4" />
        <polyline fill="none" stroke="var(--warn)" strokeWidth="2.5" points={sel.map((r) => `${x(r.failed_login_threshold)},${y(r.alerts_total)}`).join(' ')} />
        <polyline fill="none" stroke="var(--primary)" strokeWidth="2.5" points={sel.map((r) => `${x(r.failed_login_threshold)},${y(r.r1_firings)}`).join(' ')} />
        {sel.map((r) => <circle key={r.failed_login_threshold} cx={x(r.failed_login_threshold)} cy={y(r.r1_firings)} r="4" fill={r.r1_precision === 1 && r.r1_episode_recall === 1 ? 'var(--good)' : 'var(--primary)'} />)}
        {recorded.map(([t, v]) => <g key={t}><circle cx={x(t)} cy={y(v)} r="9" fill="none" stroke="var(--text)" strokeWidth="1.5" /><text x={x(t) + 12} y={y(v) - 8} style={{ fill: 'var(--text)' }}>recorded {v}</text></g>)}
      </svg></div>
      <div className="legend"><span><i style={{ background: 'var(--primary)' }} />R1 firings</span><span><i style={{ background: 'var(--warn)' }} />total alerts, R1 to R5</span><span><i style={{ background: 'var(--good)' }} />threshold where R1 fires on the burst only</span><span>○ recorded in results_deep.json</span></div>
      <h3 style={{ marginTop: 20 }}>R1 against authored intent, per threshold ({win}s window)</h3>
      <div className="scroll-x">
        <table>
          <thead><tr><th>Threshold</th>{sel.map((r) => <th key={r.failed_login_threshold}>{r.failed_login_threshold}</th>)}</tr></thead>
          <tbody>
            <tr><td>Firings</td>{sel.map((r) => <td key={r.failed_login_threshold}>{r.r1_firings}</td>)}</tr>
            <tr><td>Precision</td>{sel.map((r) => <td key={r.failed_login_threshold} className={r.r1_precision === 1 ? 'ok' : r.r1_precision == null ? '' : 'no'}>{pct(r.r1_precision)}</td>)}</tr>
            <tr><td>Episode recall</td>{sel.map((r) => <td key={r.failed_login_threshold} className={r.r1_episode_recall === 1 ? 'ok' : 'no'}>{pct(r.r1_episode_recall)}</td>)}</tr>
          </tbody>
        </table>
      </div>
      <p className="hint caveat">Circular sanity check, not an evaluation: {labels.caveat.replace(/^Circular sanity check, not an evaluation\. /, '')}</p>
    </section>
  );
}

function Drift({ snap, cfg }) {
  let data = null, err = null;
  try {
    const base = E.evaluateSnapshot(after), cur = E.evaluateSnapshot(snap);
    const d = E.baselineDrift(after, snap, LAST_TS);
    const c = E.validateConfig(cfg);
    data = { base, cur, d, v1: E.deduplicate(d.firings, c, { perControl: false }), fixed: E.deduplicate(d.firings, c) };
  } catch (e) { err = e.message; }
  if (err) return <section id="drift" className="card window reveal" data-title="R5 baseline_drift — snapshot diff"><p className="err" role="alert">{err}</p></section>;
  const { base, cur, d, v1, fixed } = data;
  const isRecorded = same(snap, current);
  return (
    <section id="drift" className="card window reveal" data-title="R5 baseline_drift — snapshot_after.json vs current">
      <div className="head">
        <div>
          <p className="eyebrow">R5 · baseline drift</p>
          <h2>The hardened VM <em>drifted back</em> on {d.summary.drift_count === 1 ? 'one control' : `${d.summary.drift_count} controls`}.</h2>
          <p className="sub">
            R5 runs the Learn checker on the hardened baseline (<span className="mono">snapshot_after.json</span>) and on the snapshot from the hardening window, and fires once per control that passed before and fails now.
            {isRecorded ? ` With the recorded current snapshot, that is ${deep.baseline_drift.drifted_controls.join(' and ')}.` : ' You are looking at your edited snapshot.'}
          </p>
        </div>
        <Match ok={isRecorded && same(d.summary, deep.baseline_drift)} yes={`Matches results_deep.json: ${deep.baseline_drift.baseline_passed}/10 → ${deep.baseline_drift.current_passed}/10`} no="Edited snapshot, live result" />
      </div>
      <div className="scroll-x drift-table">
        <table>
          <thead><tr><th>Control</th><th>Baseline</th><th>Current</th><th>R5</th></tr></thead>
          <tbody>
            {cur.controls.map((c, i) => {
              const b = base.controls[i].passed, drift = b && !c.passed;
              return (
                <tr key={c.control_id}>
                  <td><b className="mono">{c.control_id}</b> {c.control}</td>
                  <td className={b ? 'ok' : 'no'}>{b ? 'pass' : 'fail'}</td>
                  <td className={c.passed ? 'ok' : 'no'}>{c.passed ? 'pass' : 'fail'}</td>
                  <td>{drift ? <span className="pill bad">fires</span> : <span className="hint">{c.passed ? 'held' : 'failing in both, invisible to R5'}</span>}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      <h3 style={{ marginTop: 24 }}>Finding: the v1.0 dedup key hid a drifted control</h3>
      <p className="hint" style={{ maxWidth: '72ch' }}>
        Both drift firings share a rule, host, user and timestamp. Keyed on (rule, host, user), as at v1.0, they merged into one alert that named only the first control.
        The key now includes the control id, which is why the recorded results show {deep.per_rule.R5.alerts_after_dedup} R5 alerts. Both columns are recomputed live from your snapshot.
      </p>
      <div className="grid2" style={{ marginTop: 12 }}>
        {[['v1.0 key: (rule, host, user)', v1, 'warn'], ['fixed key: (rule, host, user, control id)', fixed, 'good']].map(([t, list, tone]) => (
          <div className="tile" key={t}>
            <div className="head" style={{ marginBottom: 6 }}><h3>{t}</h3><span className={`pill ${tone}`}>{list.length} alert{list.length === 1 ? '' : 's'}</span></div>
            {list.length ? <ul className="details">{list.map((a, i) => <li key={i}>count {a.count}: {a.detail}</li>)}</ul> : <p className="hint">No drift, no R5 alerts.</p>}
          </div>
        ))}
      </div>
    </section>
  );
}

function Incident({ live }) {
  const seed = live.ok ? live.incident : null;
  const seedKey = JSON.stringify(seed?.alert_ids ?? null) + JSON.stringify(seed?.related_alert_ids ?? null);
  const [inc, setInc] = useState(() => (seed ? clone(seed) : null));
  const [checks, setChecks] = useState(() => Object.fromEntries(E.CLOSURE_CHECKLIST.map((k) => [k, false])));
  const [msg, setMsg] = useState(null);
  const [replay, setReplay] = useState(deep.incident.transitions.length);
  const timer = useRef(null);
  const reset = () => { setInc(seed ? clone(seed) : null); setChecks(Object.fromEntries(E.CLOSURE_CHECKLIST.map((k) => [k, false]))); setMsg(null); };
  useEffect(reset, [seedKey]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => () => clearInterval(timer.current), []);
  const move = (to) => {
    try {
      const n = clone(inc);
      E.transition(n, to, new Date().toISOString().slice(0, 19) + 'Z', 'you (this browser)', 'Moved in the live stepper.', to === 'closed' ? checks : null);
      setInc(n); setMsg({ ok: true, text: `Moved to ${to}.` });
    } catch (e) { setMsg({ ok: false, text: `IncidentError: ${e.message}` }); }
  };
  const runReplay = () => {
    clearInterval(timer.current); setReplay(1);
    timer.current = setInterval(() => setReplay((r) => { if (r >= deep.incident.transitions.length) { clearInterval(timer.current); return r; } return r + 1; }), 800);
  };
  const rec = deep.incident.transitions.slice(0, replay);
  return (
    <section id="incident" className="card window reveal" data-title={`${deep.incident.incident_id}.json — lifecycle`}>
      <div className="head">
        <div>
          <p className="eyebrow">Incident lifecycle · state machine</p>
          <h2>Open, triaged, contained, closed. <em>No skipping.</em></h2>
          <p className="sub">
            The incident holds the highest-severity alerts and links the rest. It moves one step at a time, and closing needs every closure checklist item.
            Try a skip, a backward move or an early close: you get the same IncidentError the Python raises. On the right is the walkthrough recorded in results_deep.json.
          </p>
        </div>
      </div>
      {!inc ? <p className="err">No alerts, so no incident to drive. Reset the playground config.</p> : (
        <div className="grid2">
          <div>
            <h3>Live stepper · your session</h3>
            <p className="hint" style={{ margin: '4px 0 12px' }}>{inc.incident_id} · severity {inc.severity} · alerts {inc.alert_ids.join(', ')}{inc.related_alert_ids.length ? ` · linked ${inc.related_alert_ids.join(', ')}` : ''}</p>
            <ol className="stepper" aria-label="Lifecycle state">
              {E.LIFECYCLE.map((s, i) => <li key={s} className={E.LIFECYCLE.indexOf(inc.lifecycle) >= i ? 'done' : ''} aria-current={inc.lifecycle === s ? 'step' : undefined}>{s}</li>)}
            </ol>
            <div className="actions" style={{ marginTop: 12 }}>
              {E.LIFECYCLE.map((s) => <button key={s} className={`btn ${s === E.LIFECYCLE[E.LIFECYCLE.indexOf(inc.lifecycle) + 1] ? 'primary' : 'ghost'}`} onClick={() => move(s)}>→ {s}</button>)}
              <button className="btn ghost" onClick={reset}>Reset</button>
            </div>
            <fieldset className="checks" style={{ marginTop: 14 }}><legend>Closure checklist</legend>
              {E.CLOSURE_CHECKLIST.map((k) => <Check key={k} label={k} checked={checks[k]} onChange={(v) => setChecks((c) => ({ ...c, [k]: v }))} />)}
            </fieldset>
            <p className={`msg ${msg ? (msg.ok ? 'ok' : 'no') : 'hint'}`} aria-live="polite">{msg ? msg.text : 'Pick a state to move to.'}</p>
            <ul className="log">{inc.transitions.map((t, i) => <li key={i}><span className="mono">{t.at.slice(11, 19)}</span> {t.from ?? '∅'} → <b>{t.to}</b> <span className="hint">· {t.actor}</span></li>)}</ul>
          </div>
          <div>
            <div className="head" style={{ marginBottom: 8 }}>
              <h3>Recorded walkthrough · results_deep.json</h3>
              <button className="btn ghost" onClick={runReplay}>Replay recorded</button>
            </div>
            <p className="hint" style={{ margin: '0 0 12px' }}>A replay, not a live run: fixed review times from <a href={blob('src/run_deep.py')}>run_deep.py</a>, not a real incident on a live host.</p>
            <ol className="log recorded">
              {rec.map((t, i) => (
                <li key={i}><span className="mono">{t.at.slice(11, 16)}</span> <b>{t.from ?? '∅'} → {t.to}</b> <span className="hint">· {t.actor}</span><div className="hint">{t.note}</div></li>
              ))}
            </ol>
            <p className="hint">Checklist at close: {Object.values(deep.incident.closure_checklist).filter(Boolean).length} of {E.CLOSURE_CHECKLIST.length} · final state {deep.incident.lifecycle}</p>
          </div>
        </div>
      )}
    </section>
  );
}

function Limits() {
  const total = Object.values(TESTS).reduce((a, b) => a + b, 0);
  const attack = [
    ['R1', 'T1110 Brute Force', 'repeated failed SSH logins'],
    ['R2', 'T1548.003 Sudo and Sudo Caching', 'sudo to root by a non-admin'],
    ['R4', 'T1562.001 Disable or Modify Tools', 'automatic updates disabled'],
    ['R3', 'unmapped (hygiene)', 'new listening port'],
    ['R5', 'unmapped (configuration drift)', 'hardening control regressed'],
  ];
  const docs = [
    ['README.md', 'Abstract', 'Question, verdict, reproduce'], ['PROPOSAL.md', 'Proposal', 'Not locked; original specs'], ['REPORT.md', 'Report', 'Method, results, review, threats'],
    ['docs/RUNBOOK.md', 'Runbook', 'Isolation, reset, teardown'], ['docs/decisions/', 'Decisions', 'Hard-to-reverse choices'], ['CHANGELOG.md', 'Changelog', 'Releases and changes'],
  ];
  return (
    <section id="limits" className="card window reveal" data-title="README.md — method and limits">
      <p className="eyebrow">Method and limits</p>
      <h2>What these numbers <em>can't</em> tell you.</h2>
      <p className="sub">
        Quoted from <a href={blob('REPORT.md')}>REPORT.md</a> at build time. The biggest one first: there is no ground truth. The logs were written by the same hand as the rules, so every count above shows the rules behave as designed, not that they detect anything in the wild.
      </p>
      <div className="grid2" style={{ marginTop: 16 }}>
        <div>
          <h3>Failure modes</h3>
          <ul className="details">{REPORT.failureModes.map((f, i) => <li key={i}>{f}</li>)}</ul>
        </div>
        <div>
          <h3>Lifecycle · verdict: {README.verdict}</h3>
          <ul className="details">{README.lifecycle.map((s) => <li key={s.stage}><b>{s.stage}</b>: {s.status}{s.date ? ` ${s.date}` : ''}</li>)}</ul>
          <p className="hint">Stages and verdict are read from README.md at build time. No verdict here depends on running any scenario.</p>
          <div className="tiles" style={{ gridTemplateColumns: 'repeat(4, minmax(0, 1fr))' }}>
            {Object.entries(TESTS).map(([k, v]) => <div className="tile" key={k}><div className="num">{v}</div><div className="cap">{k} tests</div></div>)}
            <div className="tile"><div className="num">{total}</div><div className="cap">unit tests</div></div>
          </div>
          <p className="hint">Test counts are read from <span className="mono">tests/*.py</span> at build time. Determinism: two runs of run_deep.py hash to <span className="mono">{REPORT.sha256.slice(0, 12)}…</span></p>
        </div>
      </div>
      <h3 style={{ marginTop: 20 }}>Candidate ATT&amp;CK mapping (detection-side labels, not validated)</h3>
      <div className="scroll-x">
        <table>
          <thead><tr><th>Rule</th><th>Candidate technique</th><th>Signal</th></tr></thead>
          <tbody>{attack.map(([r, t, s]) => <tr key={r}><td className="mono">{r}</td><td>{t}</td><td>{s}</td></tr>)}</tbody>
        </table>
      </div>
      <div className="docs" style={{ marginTop: 20 }}>
        {docs.map(([p, t, d]) => <a key={p} href={blob(p)}><b>{t}</b><small>{d}</small></a>)}
      </div>
    </section>
  );
}

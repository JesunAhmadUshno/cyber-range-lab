// JS port of src/hardening.py, src/detection.py,
// src/detection_hardened.py and src/evaluate_deep.py.
// Same rules, same sort keys, same messages. engine.check.mjs runs before
// every build and fails it if this port stops reproducing the committed results.

export class HardeningError extends Error {}
export class DetectionConfigError extends Error {}
export class IncidentError extends Error {}

const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const isBool = (v) => typeof v === 'boolean';
const isInt = (v) => typeof v === 'number' && Number.isInteger(v);
// Python compares tuples element by element; ASCII strings compare the same way in JS.
const byKey = (f) => (a, b) => {
  const x = f(a), y = f(b);
  for (let i = 0; i < x.length; i++) { if (x[i] < y[i]) return -1; if (x[i] > y[i]) return 1; }
  return 0;
};

/* ---------- Level 1: hardening checker ---------- */

const ALLOWED_SUDO_USERS = ['labadmin', 'laboperator'];
const MAX_SUDO_USERS = 2;
const ALLOWED_LAB_PORTS = [22];
export const LABNET_CIDR = '10.99.0.0/24';
const UNUSED_SERVICES = ['ftp', 'rsh', 'telnet'];

export function validateSnapshot(c) {
  if (!isObj(c)) throw new HardeningError('snapshot must be an object');
  if (c.synthetic !== true) throw new HardeningError('snapshot must be labelled synthetic: true');
  for (const k of ['label', 'automatic_updates', 'ssh', 'sudo_users', 'logging', 'firewall', 'network', 'services', 'backup'])
    if (!(k in c)) throw new HardeningError(`snapshot missing field: '${k}'`);
  if (!isBool(c.automatic_updates)) throw new HardeningError('automatic_updates must be a boolean');
  if (!isObj(c.ssh)) throw new HardeningError('ssh must be an object');
  for (const k of ['password_authentication', 'publickey_authentication', 'permit_root_login', 'authorized_key_users'])
    if (!(k in c.ssh)) throw new HardeningError(`ssh missing field: '${k}'`);
  if (!Array.isArray(c.sudo_users) || !c.sudo_users.every((u) => typeof u === 'string'))
    throw new HardeningError('sudo_users must be a list of strings');
  for (const s of ['logging', 'firewall', 'network', 'services', 'backup'])
    if (!isObj(c[s])) throw new HardeningError(`${s} must be an object`);
  return true;
}

export const CONTROLS = [
  ['C01', 'automatic_updates_on', (c) => c.automatic_updates === true,
    'Enable automatic security updates for the lab VM.'],
  ['C02', 'password_ssh_off', (c) => c.ssh.password_authentication === false,
    'Set SSH password authentication to off in the lab VM configuration.'],
  ['C03', 'key_only_access', (c) => c.ssh.publickey_authentication === true && Array.isArray(c.ssh.authorized_key_users)
    && c.ssh.authorized_key_users.length >= 1 && c.ssh.password_authentication === false,
    'Enable public key authentication, add an authorized key for each named lab user, and keep password authentication off.'],
  ['C04', 'root_login_disabled', (c) => c.ssh.permit_root_login === 'no',
    'Set SSH permit root login to no; use a named account with sudo instead.'],
  ['C05', 'sudo_list_bounded', (c) => c.sudo_users.length >= 1 && c.sudo_users.length <= MAX_SUDO_USERS
    && c.sudo_users.every((u) => ALLOWED_SUDO_USERS.includes(u)) && new Set(c.sudo_users).size === c.sudo_users.length,
    'Trim the sudo list to at most 2 named allowed lab users and remove every other entry.'],
  ['C06', 'logging_and_audit_on', (c) => c.logging.system_log_enabled === true && c.logging.audit_enabled === true,
    'Turn on the system log and the audit service for the lab VM.'],
  ['C07', 'firewall_default_deny', (c) => {
    const p = c.firewall.allowed_inbound_ports;
    return c.firewall.default_inbound === 'deny' && Array.isArray(p) && p.length >= 1 && p.every((x) => ALLOWED_LAB_PORTS.includes(x));
  }, 'Set the inbound firewall default to deny and allow only the named lab ports (22).'],
  ['C08', 'labnet_isolated', (c) => c.network.labnet_cidr === LABNET_CIDR && c.network.routes_to_home_lan === false
    && c.network.routes_to_management === false,
    'Keep the lab VM on labnet 10.99.0.0/24 with no route to the home LAN and no route to management interfaces, as configuration fields.'],
  ['C09', 'unused_services_off', (c) => Array.isArray(c.services.enabled) && !c.services.enabled.some((s) => UNUSED_SERVICES.includes(s)),
    'Disable unused services (ftp, rsh, telnet) on the lab VM.'],
  ['C10', 'backup_snapshot_present', (c) => c.backup.snapshot_present === true && typeof c.backup.snapshot_id === 'string'
    && c.backup.snapshot_id.length > 0,
    'Take a named snapshot of the hardened lab VM and record its id.'],
];

export function evaluateSnapshot(config) {
  validateSnapshot(config);
  const controls = CONTROLS.map(([control_id, control, fn, remediation]) => {
    const passed = Boolean(fn(config));
    return { control_id, control, passed, remediation: passed ? '' : remediation };
  });
  const passed = controls.filter((r) => r.passed).length;
  return { label: config.label, synthetic: true, controls, passed, total: controls.length, score_percent: Math.round((100 * passed) / controls.length) };
}

/* ---------- Level 2: parsing and ingest ---------- */

const TS = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z$/;
// ponytail: accepts the zero-padded form only; strptime also takes 1-digit fields, which these logs never use.
export function parseTs(text) {
  const m = TS.exec(text);
  if (!m) throw new Error(`bad timestamp: ${text}`);
  const [y, mo, d, h, mi, s] = m.slice(1).map(Number);
  const ms = Date.UTC(y, mo - 1, d, h, mi, s);
  const dt = new Date(ms);
  if (dt.getUTCMonth() !== mo - 1 || dt.getUTCDate() !== d || h > 23 || mi > 59 || s > 61) throw new Error(`bad timestamp: ${text}`);
  return ms;
}

const RX = {
  authFail: /^(\S+) (\S+) sshd\[\d+\]: Failed password for (\S+) from \S+ port \d+$/,
  authOk: /^(\S+) (\S+) sshd\[\d+\]: Accepted password for (\S+) from \S+ port \d+$/,
  sudo: /^(\S+) (\S+) sudo: (\S+) : .*USER=(\S+) ; COMMAND=(.+)$/,
  svcUpdates: /^(\S+) (\S+) systemd\[\d+\]: automatic_updates status=(\S+)$/,
  svcPort: /^(\S+) (\S+) service-monitor: listening port=(\d+) protocol=(\S+)$/,
  svcStart: /^(\S+) (\S+) systemd\[\d+\]: Started (\S+)$/,
  fw: /^(\S+) (\S+) firewall: action=(\S+) port=(\d+) src=\S+$/,
};
const rec = (ts, source, host, user, event, detail) => ({ ts, source, host, user, event, detail });

export function parseLine(source, raw) {
  const line = raw.trim();
  if (!line) return null;
  try {
    let m;
    if (source === 'auth') {
      if ((m = RX.authFail.exec(line))) { parseTs(m[1]); return rec(m[1], source, m[2], m[3], 'failed_login', 'ssh password login failed'); }
      if ((m = RX.authOk.exec(line))) { parseTs(m[1]); return rec(m[1], source, m[2], m[3], 'successful_login', 'ssh password login accepted'); }
      return null;
    }
    if (source === 'sudo') {
      if (!(m = RX.sudo.exec(line))) return null;
      parseTs(m[1]);
      return rec(m[1], source, m[2], m[3], m[4] === 'root' ? 'sudo_to_root' : 'sudo', `sudo target=${m[4]}`);
    }
    if (source === 'service') {
      if ((m = RX.svcUpdates.exec(line))) { parseTs(m[1]); return rec(m[1], source, m[2], 'system', 'automatic_updates_status', `status=${m[3]}`); }
      if ((m = RX.svcPort.exec(line))) { parseTs(m[1]); return rec(m[1], source, m[2], 'system', 'listening_port', `port=${m[3]} protocol=${m[4]}`); }
      if ((m = RX.svcStart.exec(line))) { parseTs(m[1]); return rec(m[1], source, m[2], 'system', 'service_started', `service=${m[3]}`); }
      return null;
    }
    if (source === 'firewall') {
      if (!(m = RX.fw.exec(line))) return null;
      parseTs(m[1]);
      return rec(m[1], source, m[2], 'system', `firewall_${m[3]}`, `port=${m[4]}`);
    }
  } catch { return null; }
  return null;
}

export const splitLines = (text) => text.split(/\r?\n/);

export function ingest(sources) {
  const records = [], stats = {}, total = { lines: 0, parsed: 0, quarantined: 0 };
  for (const source of Object.keys(sources).sort()) {
    let parsed = 0, quarantined = 0;
    for (const line of sources[source]) {
      if (!line.trim()) continue;
      const r = parseLine(source, line);
      if (r === null) quarantined++; else { parsed++; records.push(r); }
    }
    stats[source] = { lines: parsed + quarantined, parsed, quarantined };
    total.lines += parsed + quarantined; total.parsed += parsed; total.quarantined += quarantined;
  }
  records.sort(byKey((r) => [r.ts, r.source, r.event, r.user]));
  stats.total = total;
  return { records, stats };
}

/* ---------- Level 3: configurable rules, drift, dedup, lifecycle ---------- */

export const SEVERITY_RANK = { low: 1, medium: 2, high: 3 };

export function validateConfig(config) {
  if (!isObj(config)) throw new DetectionConfigError('config must be an object');
  for (const k of ['failed_login_threshold', 'failed_login_window_seconds', 'dedup_window_seconds', 'admin_users', 'baseline_ports'])
    if (!(k in config)) throw new DetectionConfigError(`config missing field: '${k}'`);
  const out = {};
  for (const k of ['failed_login_threshold', 'failed_login_window_seconds', 'dedup_window_seconds']) {
    if (!isInt(config[k]) || config[k] < 1) throw new DetectionConfigError(`${k} must be a positive integer`);
    out[k] = config[k];
  }
  const u = config.admin_users;
  if (!Array.isArray(u) || !u.length || !u.every((x) => typeof x === 'string' && x) || new Set(u).size !== u.length)
    throw new DetectionConfigError('admin_users must be a non-empty list of unique strings');
  out.admin_users = [...u];
  const p = config.baseline_ports;
  if (!Array.isArray(p) || !p.length || !p.every((x) => isInt(x) && x >= 1 && x <= 65535) || new Set(p).size !== p.length)
    throw new DetectionConfigError('baseline_ports must be a non-empty list of unique ports');
  out.baseline_ports = [...p];
  return out;
}

export const windowText = (s) => (s % 60 === 0 ? `${s / 60} ${s === 60 ? 'minute' : 'minutes'}` : `${s} seconds`);
const firing = (rule, rule_name, severity, ts, host, user, detail) => ({ rule, rule_name, severity, ts, host, user, detail });

// legacyDetail: Build's R1 text ("in 10 minutes" whatever the window); used only to check Build parity.
export function runRules(records, config, { legacyDetail = false } = {}) {
  const cfg = validateConfig(config);
  const out = [];
  const ordered = [...records].sort(byKey((r) => [r.ts, r.source, r.user]));
  const groups = new Map();
  for (const r of ordered.filter((x) => x.event === 'failed_login')) {
    const k = JSON.stringify([r.host, r.user]);
    if (!groups.has(k)) groups.set(k, { key: [r.host, r.user], events: [] });
    groups.get(k).events.push(r);
  }
  for (const g of [...groups.values()].sort(byKey((g) => g.key))) {
    const times = g.events.map((r) => parseTs(r.ts));
    const win = cfg.failed_login_window_seconds;
    g.events.forEach((r, i) => {
      const start = times[i] - win * 1000;
      const count = times.slice(0, i + 1).filter((t) => start <= t && t <= times[i]).length;
      if (count >= cfg.failed_login_threshold)
        out.push(firing('R1', 'repeated_failed_logins', 'high', r.ts, r.host, r.user, `${count} failed logins in ${legacyDetail ? '10 minutes' : windowText(win)}`));
    });
  }
  for (const r of ordered) if (r.event === 'sudo_to_root' && !cfg.admin_users.includes(r.user))
    out.push(firing('R2', 'sudo_by_non_admin_user', 'high', r.ts, r.host, r.user, `sudo to root by non-admin user ${r.user}`));
  for (const r of ordered) if (r.event === 'listening_port') {
    const port = parseInt(r.detail.split(' ')[0].split('=')[1], 10);
    if (!cfg.baseline_ports.includes(port))
      out.push(firing('R3', 'new_listening_port_not_in_baseline', 'medium', r.ts, r.host, r.user, `listening port ${port} not in baseline`));
  }
  for (const r of ordered) if (r.event === 'automatic_updates_status' && r.detail === 'status=disabled')
    out.push(firing('R4', 'automatic_updates_disabled', 'medium', r.ts, r.host, r.user, 'automatic_updates status=disabled'));
  return out.sort(byKey((f) => [f.ts, f.rule, f.host, f.user]));
}

export function baselineDrift(baselineSnap, currentSnap, atTs, host = 'lab-vm-01') {
  const base = evaluateSnapshot(baselineSnap), cur = evaluateSnapshot(currentSnap);
  const basePass = Object.fromEntries(base.controls.map((c) => [c.control_id, c.passed]));
  const firings = [], drifted = [];
  for (const c of cur.controls) if (basePass[c.control_id] && !c.passed) {
    drifted.push(c.control_id);
    firings.push({ ...firing('R5', 'baseline_drift', 'medium', atTs, host, 'system',
      `control ${c.control_id} ${c.control} passed in baseline and fails in current snapshot`), control_id: c.control_id });
  }
  return { firings, summary: { baseline_passed: base.passed, baseline_total: base.total, current_passed: cur.passed, current_total: cur.total, drifted_controls: drifted, drift_count: drifted.length } };
}

// perControl false reproduces the v1.0 key (rule, host, user) that merged simultaneous drift firings.
export function deduplicate(firings, config, { perControl = true } = {}) {
  const win = validateConfig(config).dedup_window_seconds * 1000;
  const groups = new Map();
  for (const f of firings) {
    const key = [f.rule, f.host, f.user, perControl ? f.control_id ?? '' : ''];
    const k = JSON.stringify(key);
    if (!groups.has(k)) groups.set(k, { key, items: [] });
    groups.get(k).items.push(f);
  }
  const alerts = [];
  for (const g of [...groups.values()].sort(byKey((g) => g.key))) {
    let cur = null;
    for (const f of [...g.items].sort(byKey((x) => [x.ts]))) {
      if (cur && parseTs(f.ts) - parseTs(cur.first_seen) <= win) { cur.count++; cur.last_seen = f.ts; }
      else { cur = { rule: f.rule, rule_name: f.rule_name, severity: f.severity, host: f.host, user: f.user, first_seen: f.ts, last_seen: f.ts, count: 1, detail: f.detail }; alerts.push(cur); }
    }
  }
  alerts.sort(byKey((a) => [a.first_seen, a.rule, a.host, a.user]));
  return alerts.map((a, i) => ({ alert_id: `A${String(i + 1).padStart(3, '0')}`, ...a }));
}

export const RESPONSE_STEPS = [
  'Review the affected accounts and confirm each login and sudo use with the account owner.',
  'Check the host listening ports against the baseline ports 22 and 9090 and remove any service that is not approved.',
  'Re-enable automatic updates and confirm the update service reports status enabled.',
  'Keep the incident open until a reviewer confirms the signals are explained, then record the closure note.',
];

export function buildIncident(alerts) {
  if (!alerts.length) return null;
  const top = Math.max(...alerts.map((a) => SEVERITY_RANK[a.severity]));
  const sel = alerts.filter((a) => SEVERITY_RANK[a.severity] === top);
  return {
    incident_id: 'INC-001', opened_at: sel.map((a) => a.first_seen).sort()[0], severity: sel[0].severity, status: 'open',
    alert_ids: sel.map((a) => a.alert_id), affected_hosts: [...new Set(sel.map((a) => a.host))].sort(),
    affected_users: [...new Set(sel.map((a) => a.user))].sort(), recommended_response: [...RESPONSE_STEPS],
  };
}

export const LIFECYCLE = ['open', 'triaged', 'contained', 'closed'];
export const CLOSURE_CHECKLIST = ['accounts_reviewed', 'ports_checked', 'updates_confirmed', 'closure_note_recorded'];

export function newIncident(alerts) {
  const base = buildIncident(alerts);
  if (!base) return null;
  base.related_alert_ids = alerts.filter((a) => !base.alert_ids.includes(a.alert_id) && base.affected_hosts.includes(a.host)).map((a) => a.alert_id);
  base.lifecycle = 'open';
  base.transitions = [{ from: null, to: 'open', at: base.opened_at, actor: 'detection-loop', note: 'Incident opened from the highest severity alerts.' }];
  base.closure_checklist = Object.fromEntries(CLOSURE_CHECKLIST.map((k) => [k, false]));
  return base;
}

// Mutates and returns the incident, like the Python. Callers in React pass a clone.
export function transition(incident, toState, at, actor, note, checklist = null) {
  if (!incident) throw new IncidentError('no incident to transition');
  const current = incident.lifecycle;
  if (!LIFECYCLE.includes(current)) throw new IncidentError(`unknown lifecycle state: ${current}`);
  const i = LIFECYCLE.indexOf(current);
  if (i + 1 >= LIFECYCLE.length || LIFECYCLE[i + 1] !== toState)
    throw new IncidentError(`invalid transition ${current} to ${toState}: only ${i + 1 < LIFECYCLE.length ? LIFECYCLE[i + 1] : 'none'} is allowed`);
  if (checklist !== null) {
    if (!isObj(checklist)) throw new IncidentError('checklist must be an object');
    for (const item of CLOSURE_CHECKLIST) if (item in checklist) {
      if (!isBool(checklist[item])) throw new IncidentError(`checklist item ${item} must be a boolean`);
      incident.closure_checklist[item] = checklist[item];
    }
  }
  if (toState === 'closed') {
    const missing = CLOSURE_CHECKLIST.filter((k) => incident.closure_checklist[k] !== true);
    if (missing.length) throw new IncidentError(`cannot close: checklist incomplete: ${missing.join(', ')}`);
  }
  incident.transitions.push({ from: current, to: toState, at, actor, note });
  incident.lifecycle = toState;
  incident.status = toState;
  return incident;
}

const perRule = (rules, firings, alerts) => Object.fromEntries(rules.map((r) => [r, {
  firings_before_dedup: firings.filter((f) => f.rule === r).length, alerts_after_dedup: alerts.filter((a) => a.rule === r).length }]));

export function runBuild(sources, buildConfig) {
  const { records, stats } = ingest(sources);
  const firings = runRules(records, buildConfig, { legacyDetail: true });
  const alerts = deduplicate(firings, buildConfig);
  return { sources: stats, records, per_rule: perRule(['R1', 'R2', 'R3', 'R4'], firings, alerts),
    firings_total_before_dedup: firings.length, alerts_total_after_dedup: alerts.length, alerts, incident: buildIncident(alerts) };
}

export function runDeep(sources, config, baselineSnap, currentSnap, { perControl = true } = {}) {
  const cfg = validateConfig(config);
  const { records, stats } = ingest(sources);
  const firings = runRules(records, cfg);
  const lastTs = records.length ? records.map((r) => r.ts).sort().at(-1) : null;
  const drift = baselineDrift(baselineSnap, currentSnap, lastTs);
  const all = [...firings, ...drift.firings].sort(byKey((f) => [f.ts, f.rule, f.host, f.user]));
  const alerts = deduplicate(all, cfg, { perControl });
  const alt = runRules(records, { ...cfg, failed_login_threshold: 3 });
  return { config: cfg, sources: stats, records, firings: all, per_rule: perRule(['R1', 'R2', 'R3', 'R4', 'R5'], all, alerts),
    firings_total_before_dedup: all.length, alerts_total_after_dedup: alerts.length, alerts, baseline_drift: drift.summary,
    threshold_check_threshold_3: { r1_firings: alt.filter((f) => f.rule === 'R1').length }, incident: newIncident(alerts) };
}

/* ---------- evaluate_deep.py: sweep and authored-intent check ---------- */

const RULE_SOURCE = { R1: 'auth', R2: 'sudo', R3: 'service', R4: 'service' };
const round4 = (x) => Math.round(x * 1e4) / 1e4;

export function lineEpisodes(sources, labels) {
  const out = {};
  for (const [source, lines] of Object.entries(sources)) {
    const tags = labels.lines[source];
    lines.filter((x) => x.trim()).forEach((line, i) => {
      const r = parseLine(source, line);
      if (r && tags[i] != null) out[`${source}|${r.ts}`] = tags[i];
    });
  }
  return out;
}

export function intentScores(firings, episodesOf, labels) {
  const eps = labels.episodes, out = {};
  for (const [rule, source] of Object.entries(RULE_SOURCE)) {
    const fired = firings.filter((f) => f.rule === rule).map((f) => episodesOf[`${source}|${f.ts}`]);
    const hits = fired.filter((e) => eps[e].intent === 'suspicious');
    const expected = Object.keys(eps).filter((e) => eps[e].expected_rule === rule).sort();
    const found = [...new Set(fired.filter((e) => expected.includes(e)))].sort();
    out[rule] = { firings: fired.length, firings_on_suspicious_lines: hits.length, precision: fired.length ? round4(hits.length / fired.length) : null,
      episodes_expected: expected, episodes_found: found, episode_recall: expected.length ? round4(found.length / expected.length) : null,
      benign_episodes_fired: [...new Set(fired.filter((e) => eps[e].intent === 'benign'))].sort() };
  }
  return out;
}

export function sweep(sources, config, labels, driftFirings, thresholds, windows) {
  const { records } = ingest(sources);
  const episodesOf = lineEpisodes(sources, labels);
  const rows = [];
  for (const w of windows) for (const t of thresholds) {
    const cfg = { ...config, failed_login_threshold: t, failed_login_window_seconds: w };
    const firings = runRules(records, cfg);
    const alerts = deduplicate([...firings, ...driftFirings], cfg);
    const r1 = intentScores(firings, episodesOf, labels).R1;
    rows.push({ failed_login_window_seconds: w, failed_login_threshold: t, r1_firings: r1.firings, r1_alerts: alerts.filter((a) => a.rule === 'R1').length,
      alerts_total: alerts.length, r1_precision: r1.precision, r1_episode_recall: r1.episode_recall });
  }
  return rows;
}

/* ---------- reading the repo's own docs at build time ---------- */

const section = (md, heading) => {
  const start = md.indexOf(`\n## ${heading}`);
  if (start < 0) return '';
  const rest = md.slice(start + heading.length + 4);
  const end = rest.indexOf('\n## ');
  return end < 0 ? rest : rest.slice(0, end);
};
const bullets = (text) => text.split(/\n- /).slice(1).map((b) => b.replace(/\s*\n\s*/g, ' ').trim());

// REPORT.md: failure modes (bullets) and the recorded determinism hash of results_deep.json.
export function parseReport(md) {
  const hash = /results_deep\.json sha256 ([0-9a-f]{64})/.exec(md);
  return { failureModes: bullets(section(md, 'Failure modes and limits')), sha256: hash ? hash[1] : null };
}

// README.md: the verdict's first clause and the "- Stage: STATUS date" lifecycle lines.
export function parseReadme(md) {
  const verdict = (/^\*\*Verdict\.\*\* ([^.]+)/m.exec(md) || [])[1] || null;
  const lifecycle = [...section(md, 'Lifecycle').matchAll(/^- (\w+): (\w+)(?: (\d{4}-\d{2}-\d{2}))?$/gm)]
    .map(([, stage, status, date]) => ({ stage, status, date: date || null }));
  return { verdict, lifecycle };
}

export const countTests = (py) => (py.match(/^\s+def test_/gm) || []).length;

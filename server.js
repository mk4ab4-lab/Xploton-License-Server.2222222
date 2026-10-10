'use strict';
// Xploton License Server — safe, non-destructive licensing and abuse logging.
// Requires Node.js 18+. Put behind HTTPS (Caddy/nginx/cloud proxy) in production.
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = Number(process.env.PORT || 3000);
const ADMIN_TOKEN = process.env.XPLOT_ADMIN_TOKEN || '';
if (ADMIN_TOKEN.length < 24) {
  console.error('Set XPLOT_ADMIN_TOKEN to a random secret of at least 24 characters before starting.');
  process.exit(1);
}

const DATA_DIR = path.join(__dirname, 'xploton_server_data');
const DB_FILE = path.join(DATA_DIR, 'licenses.json');
const LOG_FILE = path.join(DATA_DIR, 'security.log');
fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(DB_FILE)) fs.writeFileSync(DB_FILE, JSON.stringify({ licenses: [] }, null, 2));

const allowedDurations = {
  minute: new Set([1, 5, 10, 30]),
  hour: new Set([1, 6, 12, 24]),
  day: new Set([1, 7, 30, 90, 180, 365]),
};
const multipliers = { minute: 60, hour: 3600, day: 86400 };
const failures = new Map();
const blockedUntil = new Map();

function loadDb() { return JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); }
function saveDb(db) {
  const tmp = DB_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(db, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, DB_FILE);
}
function hash(value) { return crypto.createHash('sha256').update(String(value)).digest('hex'); }
function logEvent(event, req, extra = {}) {
  const record = { at: new Date().toISOString(), event, ip: req.socket.remoteAddress || 'unknown', ...extra };
  fs.appendFileSync(LOG_FILE, JSON.stringify(record) + '\n', { mode: 0o600 });
}
function send(res, status, text, contentType = 'text/plain; charset=utf-8') {
  res.writeHead(status, { 'Content-Type': contentType, 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' });
  res.end(text);
}
function json(res, status, obj) { send(res, status, JSON.stringify(obj), 'application/json; charset=utf-8'); }
function readBody(req, limit = 8192) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk;
      if (body.length > limit) { reject(new Error('BODY_TOO_LARGE')); req.destroy(); }
    });
    req.on('end', () => resolve(body));
    req.on('error', reject);
  });
}
function parseBody(req, raw) {
  if ((req.headers['content-type'] || '').includes('application/json')) return JSON.parse(raw || '{}');
  return Object.fromEntries(new URLSearchParams(raw));
}
function isBlocked(ip) { return (blockedUntil.get(ip) || 0) > Date.now(); }
function noteFailure(req, event, key) {
  const ip = req.socket.remoteAddress || 'unknown';
  const now = Date.now();
  const recent = (failures.get(ip) || []).filter(t => now - t < 10 * 60 * 1000);
  recent.push(now);
  failures.set(ip, recent);
  logEvent(event, req, { keyHashPrefix: key ? hash(key).slice(0, 12) : undefined, failuresIn10m: recent.length });
  if (recent.length >= 8) {
    blockedUntil.set(ip, now + 15 * 60 * 1000);
    logEvent('RATE_LIMIT_BLOCK_15M', req, { failuresIn10m: recent.length });
  }
}
function adminAuthorized(req) {
  const token = req.headers['x-admin-token'] || '';
  const a = Buffer.from(String(token));
  const b = Buffer.from(ADMIN_TOKEN);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
function validDevice(device) { return /^[A-F0-9]{32}$/.test(String(device || '').toUpperCase()); }
function remainingSeconds(rec) { return Math.max(0, Math.ceil((rec.expiresAt - Date.now()) / 1000)); }

async function handle(req, res) {
  const url = new URL(req.url, 'http://localhost');
  const route = url.pathname;
  if (req.method === 'GET' && route === '/health') return json(res, 200, { ok: true, service: 'Xploton License Server', version: '2.0.0' });

  if (req.method === 'GET' && (route === '/' || route === '/admin')) {
    return send(res, 200, fs.readFileSync(path.join(__dirname, 'public', 'admin.html'), 'utf8'), 'text/html; charset=utf-8');
  }

  if (req.method === 'POST' && route.startsWith('/admin/')) {
    if (!adminAuthorized(req)) {
      logEvent('ADMIN_AUTH_FAILED', req, { route });
      return send(res, 403, 'ERR|ADMIN_AUTH');
    }
    const body = parseBody(req, await readBody(req));
    if (route === '/admin/create-key') {
      const unit = String(body.unit || 'day');
      const value = Number(body.value ?? 30);
      const tier = String(body.tier || 'VIP').slice(0, 20);
      const deviceLimit = Math.max(1, Math.min(10, Number(body.deviceLimit ?? 3)));
      const owner = String(body.owner || '').trim().slice(0, 100);
      const notes = String(body.notes || '').trim().slice(0, 500);
      if (!allowedDurations[unit] || !allowedDurations[unit].has(value)) {
        return json(res, 400, { error: 'المدة غير مدعومة. اختر day: 1,7,30,90,180,365 أو hour/minute من الخيارات المسموحة.' });
      }
      const key = 'XPL-' + crypto.randomBytes(24).toString('hex').toUpperCase();
      const db = loadDb();
      db.licenses.push({
        keyHash: hash(key), durationUnit: unit, durationValue: value, tier, deviceLimit, owner, notes,
        durationSeconds: value * multipliers[unit], createdAt: Date.now(),
        activatedAt: null, expiresAt: null, deviceId: null, deviceIds: [], revoked: false,
      });
      saveDb(db);
      logEvent('KEY_CREATED', req, { keyHashPrefix: hash(key).slice(0, 12), duration: `${value} ${unit}(s)`, tier, deviceLimit });
      return json(res, 201, { key, duration: `${value} ${unit}(s)`, tier, deviceLimit, startsAt: 'first activation' });
    }
    if (route === '/admin/licenses') {
      const db = loadDb();
      const licenses = db.licenses.map(r => ({ keyHint: r.keyHash.slice(0, 12), durationUnit: r.durationUnit, durationValue: r.durationValue, tier: r.tier || 'Standard', deviceLimit: r.deviceLimit || 1, owner: r.owner || '', notes: r.notes || '', createdAt: r.createdAt, activatedAt: r.activatedAt, expiresAt: r.expiresAt, revoked: !!r.revoked, devicesUsed: (r.deviceIds || (r.deviceId ? [r.deviceId] : [])).length, status: r.revoked ? 'revoked' : (!r.activatedAt ? 'unused' : (r.expiresAt <= Date.now() ? 'expired' : 'active')) }));
      return json(res, 200, { licenses });
    }
    if (route === '/admin/revoke-key') {
      const key = String(body.key || '').trim().toUpperCase();
      const keyHint = String(body.keyHint || '').trim();
      const db = loadDb();
      const rec = db.licenses.find(x => key ? x.keyHash === hash(key) : (keyHint && x.keyHash.startsWith(keyHint)));
      if (!rec) return json(res, 404, { error: 'Key not found' });
      rec.revoked = true;
      saveDb(db);
      logEvent('KEY_REVOKED', req, { keyHashPrefix: rec.keyHash.slice(0, 12) });
      return json(res, 200, { ok: true, revoked: true });
    }
    return send(res, 404, 'Not found');
  }

  if (req.method === 'POST' && (route === '/activate' || route === '/validate')) {
    const ip = req.socket.remoteAddress || 'unknown';
    if (isBlocked(ip)) return send(res, 429, 'ERR|RATE_LIMIT');
    let body;
    try { body = parseBody(req, await readBody(req)); }
    catch { noteFailure(req, 'BAD_REQUEST_BODY'); return send(res, 200, 'ERR|INVALID'); }
    const key = String(body.key || '').trim().toUpperCase();
    const device = String(body.device || '').trim().toUpperCase();
    if (!/^XPL-[A-F0-9]{48}$/.test(key) || !validDevice(device)) {
      noteFailure(req, 'INVALID_KEY_OR_DEVICE', key);
      return send(res, 200, 'ERR|INVALID');
    }
    const db = loadDb();
    const rec = db.licenses.find(x => x.keyHash === hash(key));
    if (!rec) { noteFailure(req, 'INVALID_KEY', key); return send(res, 200, 'ERR|INVALID'); }
    if (rec.revoked) { noteFailure(req, 'REVOKED_KEY_USE', key); return send(res, 200, 'ERR|REVOKED'); }

    if (!rec.activatedAt && route === '/activate') {
      rec.activatedAt = Date.now();
      rec.expiresAt = rec.activatedAt + rec.durationSeconds * 1000;
      rec.deviceId = device;
      rec.deviceIds = Array.isArray(rec.deviceIds) ? rec.deviceIds : (rec.deviceId ? [rec.deviceId] : []);
      if (!rec.deviceIds.includes(device)) rec.deviceIds.push(device);
      saveDb(db);
      logEvent('KEY_ACTIVATED', req, { keyHashPrefix: rec.keyHash.slice(0, 12), duration: `${rec.durationValue} ${rec.durationUnit}(s)` });
    } else if (!rec.activatedAt) {
      noteFailure(req, 'VALIDATION_BEFORE_ACTIVATION', key);
      return send(res, 200, 'ERR|INVALID');
    }

    rec.deviceIds = Array.isArray(rec.deviceIds) ? rec.deviceIds : (rec.deviceId ? [rec.deviceId] : []);
    if (!rec.deviceIds.includes(device)) {
      if (route !== '/activate' || rec.deviceIds.length >= (rec.deviceLimit || 1)) {
        noteFailure(req, 'DEVICE_MISMATCH', key);
        return send(res, 200, 'ERR|DEVICE');
      }
      rec.deviceIds.push(device);
      saveDb(db);
      logEvent('DEVICE_ADDED', req, { keyHashPrefix: rec.keyHash.slice(0, 12), devicesUsed: rec.deviceIds.length });
    }
    const remaining = remainingSeconds(rec);
    if (remaining <= 0) {
      logEvent('EXPIRED_KEY_USE', req, { keyHashPrefix: rec.keyHash.slice(0, 12) });
      return send(res, 200, 'ERR|EXPIRED');
    }
    logEvent(route === '/activate' ? 'ACTIVATE_OK' : 'VALIDATE_OK', req, { keyHashPrefix: rec.keyHash.slice(0, 12) });
    return send(res, 200, `OK|${remaining}`);
  }

  return send(res, 404, 'Not found');
}

const server = http.createServer((req, res) => {
  handle(req, res).catch(err => {
    console.error('Request error:', err.message);
    if (!res.headersSent) send(res, 500, 'ERR|SERVER'); else res.destroy();
  });
});
server.listen(PORT, '0.0.0.0', () => {
  console.log(`Xploton License Server listening on 127.0.0.1:${PORT}`);
  console.log('Xploton License Manager ready. Use HTTPS on the public Railway domain.');
});

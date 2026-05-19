/**
 * ShieldWatch RASP Sensor — ZynChat Integration v2
 * ─────────────────────────────────────────────────────────────────────────────
 * Environment variables:
 *
 *   SW_ENABLED=true
 *   SW_CEREBRO_ADDR=abc123.ngrok-free.app     ← ngrok HTTP tunnel (no port)
 *                OR localhost:3002             ← local testing
 *   SW_APP_ID=zynchat
 *   SW_LOG_ONLY=false   (true = detect but never block — passive mode)
 *
 * ─────────────────────────────────────────────────────────────────────────────
 */

const http   = require('http');
const https  = require('https');
const crypto = require('crypto');

const RAW_ADDR  = process.env.SW_CEREBRO_ADDR || 'localhost:3002';
const APP_ID    = process.env.SW_APP_ID       || 'zynchat';
const LOG_ONLY  = process.env.SW_LOG_ONLY === 'true';
const API_TOKEN = process.env.SW_API_TOKEN;
if (!API_TOKEN || API_TOKEN === 'sw-internal-token-xyz') {
  console.error('[ShieldWatch] 🚨 FATAL: SW_API_TOKEN not set or using insecure default!');
  process.exit(1);
}

// ─── Shared Helpers ──────────────────────────────────────────────────────────
function extractIP(req) {
  const raw = (req.headers['x-forwarded-for'] || req.socket?.remoteAddress || '127.0.0.1')
              .split(',')[0].trim();
  return raw.replace(/^::ffff:/, '');
}

const MAX_TRACKER_SIZE = 10_000;

// ─── Parse the collector address ──────────────────────────────────────────────
// Supports:
//   localhost:3002          → http, port 3002
//   abc123.ngrok-free.app  → https, port 443  (ngrok HTTP tunnel)
//   0.tcp.ngrok.io:12345   → http, port 12345 (ngrok TCP tunnel)
function parseAddr(addr) {
  // Clean up: remove protocol, trailing slashes, and whitespace
  let clean = addr.trim().replace(/^https?:\/\//, '').replace(/\/+$/, '');
  
  if (clean.includes(':')) {
    const [host, portStr] = clean.split(':');
    const port = parseInt(portStr, 10);
    return { host, port: isNaN(port) ? 3002 : port, useHttps: false };
  }
  // No port = ngrok HTTPS domain (default to 443)
  return { host: clean, port: 443, useHttps: true };
}

const COLLECTOR = parseAddr(RAW_ADDR);
const COLLECTOR_URL = `${COLLECTOR.useHttps ? 'https' : 'http'}://${COLLECTOR.host}${COLLECTOR.port === 443 || COLLECTOR.port === 80 ? '' : ':' + COLLECTOR.port}`;
console.log(`[ShieldWatch] 📡 Collector URL: ${COLLECTOR_URL}`);

// ─── IP Blocklist (synced from ShieldWatch collector every 30s) ──────────────
const blockedIPs = new Set();

let isInitialized = false;

async function fetchWithRetry(fn, label, retries = 3, delay = 2000) {
  for (let i = 1; i <= retries; i++) {
    try {
      await fn();
      return true;
    } catch (e) {
      console.warn(`[ShieldWatch] ⚠️ ${label} attempt ${i} failed: ${e.message}`);
      if (i < retries) await new Promise(r => setTimeout(r, delay));
    }
  }
  return false;
}

async function init() {
  console.log(`[ShieldWatch] 🛡️ Initializing RASP Sensor (Collector: ${COLLECTOR_URL})...`);
  
  const success = await fetchWithRetry(async () => {
    await Promise.all([
      new Promise((resolve, reject) => {
        const module_ = COLLECTOR.useHttps ? https : http;
        const options = {
          hostname: COLLECTOR.host,
          port: COLLECTOR.port,
          path: '/api/blocked',
          method: 'GET',
          headers: { 'x-shieldwatch-token': API_TOKEN },
          timeout: 4000,
        };
        const req = module_.request(options, res => {
          let data = '';
          res.on('data', c => data += c);
          res.on('end', () => {
            try {
              const list = JSON.parse(data);
              blockedIPs.clear();
              list.forEach(ip => blockedIPs.add(ip));
              resolve();
            } catch (e) { reject(e); }
          });
        });
        req.on('error', reject);
        req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
        req.end();
      }),
      new Promise((resolve, reject) => {
        const module_ = COLLECTOR.useHttps ? https : http;
        const options = {
          hostname: COLLECTOR.host,
          port: COLLECTOR.port,
          path: '/api/blocked-fp',
          method: 'GET',
          headers: { 'x-shieldwatch-token': API_TOKEN },
          timeout: 4000,
        };
        const req = module_.request(options, res => {
          let data = '';
          res.on('data', c => data += c);
          res.on('end', () => {
            try {
              const list = JSON.parse(data);
              blockedFingerprints.clear();
              list.forEach(fp => blockedFingerprints.add(fp));
              resolve();
            } catch (e) { reject(e); }
          });
        });
        req.on('error', reject);
        req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
        req.end();
      }),
      // [FIX] Session blocklist was missing from init — blocks only applied after first 30s interval
      new Promise((resolve, reject) => {
        const module_ = COLLECTOR.useHttps ? https : http;
        const options = {
          hostname: COLLECTOR.host,
          port: COLLECTOR.port,
          path: '/api/blocked-sessions',
          method: 'GET',
          headers: { 'x-shieldwatch-token': API_TOKEN },
          timeout: 4000,
        };
        const req = module_.request(options, res => {
          let data = '';
          res.on('data', c => data += c);
          res.on('end', () => {
            try {
              const list = JSON.parse(data);
              blockedSessions.clear();
              list.forEach(s => blockedSessions.add(s));
              resolve();
            } catch (e) { reject(e); }
          });
        });
        req.on('error', reject);
        req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
        req.end();
      })
    ]);
  }, 'Initial sync');

  if (success) {
    console.log('[ShieldWatch] ✅ RASP sensor initialized successfully.');
    isInitialized = true;
    // [FIX] Reduced from 30s to 5s so blocks apply near-immediately after dashboard action
    setInterval(fetchBlocklist, 5_000);
    setInterval(fetchFingerprintBlocklist, 5_000);
    setInterval(fetchSessionBlocklist, 5_000);
    return true;
  } else {
    console.error('[ShieldWatch] ❌ Critical: Could not connect to collector. Running in PASSIVE mode.');
    return false;
  }
}

function fetchBlocklist() {
  if (!isInitialized && process.env.NODE_ENV === 'production') return;
  const module_ = COLLECTOR.useHttps ? https : http;
  const options  = {
    hostname: COLLECTOR.host,
    port:     COLLECTOR.port,
    path:     '/api/blocked',
    method:   'GET',
    headers:  { 
      'ngrok-skip-browser-warning': 'true',
      'x-shieldwatch-token': API_TOKEN
    },
    timeout:  4000,
  };
  const req = module_.request(options, res => {
    let data = '';
    res.on('data', c => data += c);
    res.on('end', () => {
      try {
        const list = JSON.parse(data);
        blockedIPs.clear();
        list.forEach(ip => blockedIPs.add(ip));
        if (list.length > 0) console.log(`[ShieldWatch] 🚫 Blocklist synced: ${list.length} IPs`);
      } catch {}
    });
  });
  req.on('error',   () => {});
  req.on('timeout', () => req.destroy());
  req.end();
}

const blockedFingerprints = new Set();
function fetchFingerprintBlocklist() {
  if (!isInitialized && process.env.NODE_ENV === 'production') return;
  const module_ = COLLECTOR.useHttps ? https : http;
  const options  = {
    hostname: COLLECTOR.host,
    port:     COLLECTOR.port,
    path:     '/api/blocked-fp',
    method:   'GET',
    headers:  { 
      'ngrok-skip-browser-warning': 'true',
      'x-shieldwatch-token': API_TOKEN
    },
    timeout:  4000,
  };
  const req = module_.request(options, res => {
    let data = '';
    res.on('data', c => data += c);
    res.on('end', () => {
      try {
        const list = JSON.parse(data);
        blockedFingerprints.clear();
        list.forEach(fp => blockedFingerprints.add(fp));
      } catch (e) {}
    });
  });
  req.on('error',   () => {});
  req.on('timeout', () => req.destroy());
  req.end();
}

const blockedSessions = new Set();
function fetchSessionBlocklist() {
  if (!isInitialized && process.env.NODE_ENV === 'production') return;
  const module_ = COLLECTOR.useHttps ? https : http;
  const options  = {
    hostname: COLLECTOR.host,
    port:     COLLECTOR.port,
    path:     '/api/blocked-sessions',
    method:   'GET',
    headers:  { 
      'ngrok-skip-browser-warning': 'true',
      'x-shieldwatch-token': API_TOKEN
    },
    timeout:  4000,
  };
  const req = module_.request(options, res => {
    let data = '';
    res.on('data', c => data += c);
    res.on('end', () => {
      try {
        const list = JSON.parse(data);
        blockedSessions.clear();
        list.forEach(s => blockedSessions.add(s));
      } catch {}
    });
  });
  req.on('error',   () => {});
  req.on('timeout', () => req.destroy());
  req.end();
}

// ─── IDOR Detection ──────────────────────────────────────────────────────────
function checkIDOR(req) {
  const rawPath = (req.path || req.url || '/').split('?')[0];
  // /api/user/:id — accessing another user's full record
  const match = rawPath.match(/^\/api\/user\/(\d+)$/);
  if (!match) return null;
  const requestedId  = parseInt(match[1], 10);
  const sessionUserId = req.session?.userId;
  // Accessing ANY user record without owning it = IDOR
  if (!sessionUserId || requestedId !== sessionUserId) {
    return {
      type:    'idor',
      matched: 'Shield (App): Unauthorized object access (IDOR)',
      raw:     `GET /api/user/${requestedId} — session belongs to user:${sessionUserId || 'anonymous'}`,
    };
  }
  return null;
}

// ─── Session Fixation Detection ───────────────────────────────────────────────
const SESSION_FIXATION_PATHS = new Map([
  ['/api/session/id',  'session ID exposure endpoint accessed'],
  ['/api/session/fix', 'session fixation attack — forced session ID injection'],
]);

function checkSessionFixation(req) {
  const rawPath = (req.path || req.url || '/').split('?')[0];
  const desc = SESSION_FIXATION_PATHS.get(rawPath);
  if (!desc) return null;
  return {
    type:    'sessionFixation',
    matched: desc,
    raw:     `${req.method} ${rawPath} from ${req.session?.username || 'anonymous'}`,
  };
}

// ─── CSRF Detection ──────────────────────────────────────────────────────────
// State-changing endpoints that must only be called via JSON (not form POST)
const CSRF_PROTECTED = new Set(['/api/profile/update', '/api/settings', '/api/user/delete']);

function checkCSRF(req) {
  const rawPath = (req.path || req.url || '/').split('?')[0];
  if (!CSRF_PROTECTED.has(rawPath)) return null;
  if (!['POST', 'PUT', 'DELETE', 'PATCH'].includes(req.method)) return null;

  const ct = (req.headers['content-type'] || '').toLowerCase();
  // Legitimate app calls always use application/json
  // A CSRF form submission arrives as application/x-www-form-urlencoded or multipart
  if (ct.includes('application/x-www-form-urlencoded') || ct.includes('multipart/form-data')) {
    const origin  = req.headers['origin']  || '';
    const referer = req.headers['referer'] || '';
    return {
      type:    'csrf',
      matched: 'Shield (App): Unauthorized state-changing form submission (CSRF)',
      raw:     `${req.method} ${rawPath} | Origin: ${origin || 'none'} | Referer: ${referer || 'none'}`,
    };
  }
  return null;
}

// ─── Brute Force Detection ────────────────────────────────────────────────────
const loginFailTracker = new Map(); // ip → [timestamp, ...]
const BF_WINDOW_MS = 60_000;        // 60-second window
const BF_THRESHOLD = 5;             // ≥ 5 failures in 60s = brute force

function trackLoginFailure(req) {
  const ip  = extractIP(req);
  const now = Date.now();
  const prev = (loginFailTracker.get(ip) || []).filter(t => now - t < BF_WINDOW_MS);
  prev.push(now);

  if (loginFailTracker.size >= MAX_TRACKER_SIZE && !loginFailTracker.has(ip)) {
    loginFailTracker.delete(loginFailTracker.keys().next().value);
  }
  loginFailTracker.set(ip, prev);

  if (prev.length >= BF_THRESHOLD) {
    const threat  = {
      type:    'bruteforce',
      matched: 'Shield (App): Login Brute Force detected',
      raw:     `${prev.length} failed login attempts from ${ip}`,
    };
    const verdict = LOG_ONLY ? 'LOGGED' : 'BLOCKED';
    const event   = buildEvent(req, threat, verdict);
    console.log(`[ShieldWatch] 🔐 BRUTE FORCE | ${ip} | ${prev.length} failures | ${verdict}`);
    report('/api/event', event);
    return verdict === 'BLOCKED'; // true = caller should return 429
  }
  return false;
}

// ─── Registration Spam Protection ─────────────────────────────────────────────
const registrationTracker = new Map(); // ip → [timestamp, ...]
const REG_WINDOW_MS = 3600_000;        // 1 hour
const REG_LIMIT = 5;                   // Max 5 accounts per hour

function checkRegistrationSpam(req) {
  const rawPath = (req.path || req.url || '/').split('?')[0];
  if (rawPath !== '/api/register' || req.method !== 'POST') return null;
  
  const ip  = extractIP(req);
  const now = Date.now();
  const prev = (registrationTracker.get(ip) || []).filter(t => now - t < REG_WINDOW_MS);
  prev.push(now);
  
  if (registrationTracker.size >= MAX_TRACKER_SIZE && !registrationTracker.has(ip)) {
    registrationTracker.delete(registrationTracker.keys().next().value);
  }
  registrationTracker.set(ip, prev);
  
  if (prev.length > REG_LIMIT) {
    return { 
      type: 'registration-spam',
      matched: 'Shield (App): Registration rate limit exceeded',
      raw: `${prev.length} registrations in 1 hour from ${ip}`
    };
  }
  return null;
}

// ─── DDoS / Rate-Limit Detection ─────────────────────────────────────────────
const requestTracker = new Map();   // ip → [timestamp, ...]
const DDOS_WINDOW_MS = 10_000;      // 10-second sliding window
const DDOS_THRESHOLD = 20;          // > 20 API requests in 10s = flood

function checkDDoS(ip) {
  const now  = Date.now();
  const prev = (requestTracker.get(ip) || []).filter(t => now - t < DDOS_WINDOW_MS);
  prev.push(now);

  if (requestTracker.size >= MAX_TRACKER_SIZE && !requestTracker.has(ip)) {
    requestTracker.delete(requestTracker.keys().next().value);
  }
  requestTracker.set(ip, prev);
  if (prev.length > DDOS_THRESHOLD) {
    return {
      type:    'ddos',
      matched: 'Shield (App): API Request Flood detected',
      raw:     `${prev.length} requests in 10s from ${ip}`,
    };
  }
  return null;
}

// Purge stale entries every 30 seconds to avoid memory growth
setInterval(() => {
  const cutoff = Date.now() - DDOS_WINDOW_MS;
  for (const [ip, times] of requestTracker) {
    const fresh = times.filter(t => t > cutoff);
    if (fresh.length === 0) requestTracker.delete(ip);
    else requestTracker.set(ip, fresh);
  }
}, 30_000);

// ─── Honeypot paths ──────────────────────────────────────────────────────────
const HONEYPOT_PATHS = new Set([
  '/api/admin/users', '/api/admin/config', '/api/export',
  '/api/export/database', '/api/backup', '/api/db-dump',
  '/api/config', '/api/secret', '/admin', '/phpmyadmin',
  '/wp-admin', '/.env',
]);

// ─── Attack Patterns (Hardened) ──────────────────────────────────────────────
const PATTERNS = {
  sqli: [
    /'\s*(--|#|\/\*)/i,
    /'\s*(OR|AND)\s+['"\d]/i,
    /\bunion\b.+\bselect\b/i,
    /\bselect\b.+\bfrom\b/i,
    /\bdrop\s+table\b/i,
    /\binsert\s+into\b/i,
    /'\s*=\s*'/i,
    /;\s*(DROP|ALTER|CREATE|INSERT|UPDATE|DELETE)\b/i,
    /\bsleep\s*\(/i,
    /\bpg_sleep\s*\(/i,
    /\bwaitfor\s+delay\b/i,
    /benchmark\s*\(/i,
    /load_file\s*\(/i,
    /into\s+outfile\b/i,
  ],
  xss: [
    /<script[\s>]/i,
    /javascript\s*:/i,
    /on\w+\s*=\s*['"`]/i,
    /<img[^>]+onerror/i,
    /<iframe[\s>]/i,
    /\balert\s*\(/i,
    /document\.cookie/i,
    /eval\s*\(/i,
    /<svg[^>]+on\w+/i,
    /srcdoc\s*=/i,
    /data\s*:\s*text\/html/i,
    /expression\s*\(/i,
    /vbscript\s*:/i,
    /<base[^>]+href/i,
    /&#x?[0-9a-f]+;/i,
    /String\.fromCharCode/i,
    /atob\s*\(/i,
  ],
  pathTraversal: [
    /\.\.\//,
    /\.\.\\/,
    /%2e%2e%2f/i,
    /%2e%2e\//i,
    /\.\.%2f/i,
    /%252e%252e/i,
    /\/etc\/passwd/i,
    /\/proc\/self/i,
    /\/windows\/win\.ini/i,
    /\/boot\.ini/i,
  ],
  cmdInjection: [
    /[;&|`$]\s*(ls|cat|pwd|id|whoami|uname|curl|wget|bash|sh|python|perl|nc|netcat|ncat|php)\b/i,
    /`[^`]+`/,
    /\$\([^)]+\)/,
    /\{[^\}]+\}/, // Braces expansion
  ],
};

// ─── Detect threat (Hardened) ────────────────────────────────────────────────
function detectThreats(value, depth = 0) {
  if (value == null || typeof value !== 'string') return null;
  if (depth > 3) return null; // Prevent recursion issues

  // Create variants of the payload to test against signatures
  const variants = [
    value,                               // Raw
    value.toLowerCase(),                 // Lowercase normalization
    value.replace(/\s+/g, '')            // Whitespace removal
  ];

  // Try URL decoding
  try {
    const uriDecoded = decodeURIComponent(value);
    if (uriDecoded !== value) variants.push(uriDecoded);
  } catch {}

  // Try Base64 decoding (if it looks like base64)
  if (value.length > 8 && /^[A-Za-z0-9+/=]+$/.test(value)) {
    try {
      const b64Decoded = Buffer.from(value, 'base64').toString('utf8');
      // If it results in printable ASCII, it might be a payload
      if (/^[\x20-\x7E\s]+$/.test(b64Decoded)) variants.push(b64Decoded);
    } catch {}
  }

  for (const variant of variants) {
    for (const [type, patterns] of Object.entries(PATTERNS)) {
      for (const re of patterns) {
        if (re.test(variant)) {
          const typeMap = { sqli: 'SQL Injection', xss: 'XSS Attempt', pathTraversal: 'Path Traversal', cmdInjection: 'Command Injection' };
          return { 
            type, 
            matched: `Shield (App): ${typeMap[type] || type} signature detected`, 
            raw: value.slice(0, 200),
            encoding: variant !== value ? 'encoded' : 'raw'
          };
        }
      }
    }
  }
  return null;
}

// ─── Scan request inputs ──────────────────────────────────────────────────────
function scanRequest(req) {
  const sensitiveKeys = ['password', 'pass', 'pwd', 'secret', 'token', 'apiKey', 'credential'];
  
  // Scan query params
  if (req.query && Object.keys(req.query).length > 0) {
    console.log(`[ShieldWatch] Scanning query:`, JSON.stringify(req.query));
    for (const [key, val] of Object.entries(req.query)) {
      if (typeof val !== 'string') continue;
      const t = detectThreats(val);
      if (t) return t;
    }
  }

  // Scan body (with masking for sensitive fields)
  for (const [key, val] of Object.entries(req.body || {})) {
    if (typeof val !== 'string') continue;
    const t = detectThreats(val);
    if (t) {
      const lowerKey = key.toLowerCase();
      if (sensitiveKeys.some(sk => lowerKey.includes(sk))) {
        t.raw = '[REDACTED]'; // Hide the actual password/token
      }
      return t;
    }
  }

  // Scan URL params
  for (const [key, val] of Object.entries(req.params || {})) {
    if (typeof val !== 'string') continue;
    const t = detectThreats(val);
    if (t) return t;
  }
  
  return null;
}

// ─── Send to ShieldWatch Collector ───────────────────────────────────────────
// Non-blocking, fail-open — if ShieldWatch is down ZynChat keeps running
function report(endpoint, payload) {
  const body    = JSON.stringify(payload);
  const module_ = COLLECTOR.useHttps ? https : http;

  const options = {
    hostname: COLLECTOR.host,
    port:     COLLECTOR.port,
    path:     endpoint,
    method:   'POST',
    headers:  {
      'Content-Type':   'application/json',
      'Content-Length': Buffer.byteLength(body),
      'ngrok-skip-browser-warning': 'true',
      'x-shieldwatch-token': API_TOKEN
    },
    timeout: 4000,
  };

  console.log(`[ShieldWatch] 📡 Reporting to ${options.hostname}:${options.port}${options.path}`);

  const req = module_.request(options, res => { 
    if (res.statusCode !== 200) {
      console.error(`[ShieldWatch] ❌ Report failed: ${res.statusCode} to ${endpoint}`);
    }
    res.resume(); 
  });
  req.on('error',   (e) => {
    console.error(`[ShieldWatch] ❌ Report error: ${e.message}`);
  }); 
  req.on('timeout', () => req.destroy());
  req.write(body);
  req.end();
}

// ─── Build event ──────────────────────────────────────────────────────────────
function buildEvent(req, threat, verdict) {
  return {
    id:        crypto.randomUUID(),
    app:       APP_ID,
    timestamp: new Date().toISOString(),
    ip:        extractIP(req),
    method:    req.method,
    path:      req.path || req.url || '/',
    ua:        req.headers['user-agent'] || '',
    threat,
    verdict,
    session:   req.session?.username || 'anonymous',
    sid:       req.sessionID, // Raw session ID for enforcement
  };
}

// ─── HTTP Middleware ───────────────────────────────────────────────────────────
function httpMiddleware(req, res, next) {
  const rawPath = (req.path || req.url || '/').split('?')[0];

  // ── IP Blocklist check (highest priority) ────────────────────────────────────
  const reqIP = extractIP(req);
  if (blockedIPs.has(reqIP)) {
    console.log(`[ShieldWatch] 🚫 BLOCKED IP: ${reqIP} tried ${rawPath}`);
    return res.status(403).json({
      ok: false, blocked: true,
      error:  `Your IP (${reqIP}) has been permanently blocked by ShieldWatch.`,
      threat: 'blocked_ip',
    });
  }

  // ── Fingerprint block (survives VPN / IP rotation) ───────────────────────
  const fpId = req.session?.fpId;
  if (fpId && blockedFingerprints.has(fpId)) {
    console.log(`[ShieldWatch] 🔒 BLOCKED FINGERPRINT: ${fpId.slice(0,12)}… | IP: ${reqIP} | path: ${rawPath}`);
    return res.status(403).json({
      ok: false, blocked: true,
      error:  'Your device has been permanently blocked by ShieldWatch. Changing your IP will not help.',
      threat: 'blocked_fingerprint',
    });
  }

  // ── Session block (Surgical cookie ID OR Username check) ───────────────────
  const sid = req.sessionID;
  const usr = req.session?.username;
  if ((sid && blockedSessions.has(sid)) || (usr && blockedSessions.has(usr))) {
    console.log(`[ShieldWatch] ⛔ BLOCKED SESSION: ${sid || usr} | IP: ${reqIP} | path: ${rawPath}`);
    return res.status(403).json({
      ok: false, blocked: true,
      error:  'Your current session has been terminated by an administrator.',
      threat: 'blocked_session',
    });
  }

  // IDOR check
  const idorThreat = checkIDOR(req);
  if (idorThreat) {
    const verdict = LOG_ONLY ? 'LOGGED' : 'BLOCKED';
    const event   = buildEvent(req, idorThreat, verdict);
    console.log(`[ShieldWatch] 🔓 IDOR | ${rawPath} | ${verdict}`);
    report('/api/event', event);
    if (!LOG_ONLY) {
      return res.status(403).json({
        ok: false, blocked: true,
        error:  'Access denied. IDOR attack blocked by ShieldWatch.',
        threat: 'idor',
        ref:    event.id,
      });
    }
  }

  // Session Fixation check
  const sfThreat = checkSessionFixation(req);
  if (sfThreat) {
    const verdict = LOG_ONLY ? 'LOGGED' : 'BLOCKED';
    const event   = buildEvent(req, sfThreat, verdict);
    console.log(`[ShieldWatch] 🔑 SESSION FIXATION | ${rawPath} | ${verdict}`);
    report('/api/event', event);
    if (!LOG_ONLY) {
      return res.status(403).json({
        ok: false, blocked: true,
        error:  'Session fixation attack blocked by ShieldWatch.',
        threat: 'sessionFixation',
        ref:    event.id,
      });
    }
  }

  // CSRF check (form-encoded POST to protected endpoints)
  const csrfThreat = checkCSRF(req);
  if (csrfThreat) {
    const verdict = LOG_ONLY ? 'LOGGED' : 'BLOCKED';
    const event   = buildEvent(req, csrfThreat, verdict);
    console.log(`[ShieldWatch] 🎭 CSRF | ${req.method} ${rawPath} | ${verdict}`);
    report('/api/event', event);
    if (!LOG_ONLY) {
      return res.status(403).json({
        ok: false, blocked: true,
        error:  'CSRF attack detected and blocked by ShieldWatch.',
        threat: 'csrf',
        ref:    event.id,
      });
    }
  }

  // DDoS rate-limit check (API endpoints only — skip static files)
  if (rawPath.startsWith('/api/') || rawPath.startsWith('/socket')) {
    const ip    = extractIP(req);
    const flood = checkDDoS(ip);
    if (flood) {
      const verdict = LOG_ONLY ? 'LOGGED' : 'BLOCKED';
      const event   = buildEvent(req, flood, verdict);
      console.log(`[ShieldWatch] 🌊 DDOS | ${ip} | ${flood.raw} | ${verdict}`);
      report('/api/event', event);
      if (!LOG_ONLY) {
        return res.status(429).json({
          ok: false, blocked: true,
          error:  'Too many requests. DDoS flood detected by ShieldWatch.',
          threat: 'ddos',
          ref:    event.id,
        });
      }
    }
  }

  // Honeypot check
  if (HONEYPOT_PATHS.has(rawPath)) {
    const event = buildEvent(req, { type: 'honeypot', raw: rawPath }, 'DECOY');
    console.log(`[ShieldWatch] 🍯 HONEYPOT: ${rawPath} | user:${event.session} | ip:${event.ip}`);
    report('/api/event', event);
    req._swHoneypot = true;
    return next(); // Let honeypot handler serve fake data
  }

  // Registration spam check
  const spam = checkRegistrationSpam(req);
  if (spam) {
    const verdict = LOG_ONLY ? 'LOGGED' : 'BLOCKED';
    const event   = buildEvent(req, spam, verdict);
    console.log(`[ShieldWatch] 🛡️ REGISTRATION SPAM | ${reqIP} | ${verdict}`);
    report('/api/event', event);
    if (!LOG_ONLY) {
      return res.status(429).json({
        ok: false, blocked: true,
        error: 'Too many registrations from this IP. Please try again later.',
        threat: 'registration-spam',
        ref: event.id
      });
    }
  }

  const threat = scanRequest(req);
  if (!threat) return next();

  const verdict = LOG_ONLY ? 'LOGGED' : 'BLOCKED';
  const event   = buildEvent(req, threat, verdict);

  console.log(`[ShieldWatch] 🚨 ${threat.type.toUpperCase()} | ${req.method} ${rawPath} | ${verdict} | user:${event.session} | ip:${event.ip}`);
  report('/api/event', event);

  if (LOG_ONLY) return next();

  return res.status(403).json({
    ok: false, blocked: true,
    error:  'Request blocked by ShieldWatch RASP.',
    threat: threat.type,
    ref:    event.id,
  });
}

// ─── Socket.io Message Hook ───────────────────────────────────────────────────
function inspectMessage(msg, socket) {
  // 1. Enforcement Check: Is this sender blocked?
  const req   = socket.request;
  const ip    = extractIP(req);
  const fpId  = req.session?.fpId;
  const sid   = req.sessionID;
  const usr   = req.session?.username;

  if (blockedIPs.has(ip) || (fpId && blockedFingerprints.has(fpId)) || 
     (sid && blockedSessions.has(sid)) || (usr && blockedSessions.has(usr))) {
    console.warn(`[ShieldWatch] 🛡️ Socket message dropped from BLOCKED user: ${usr || 'unknown'}`);
    return true; // Return true to indicate it was blocked
  }

  // 2. Content Inspection: Detect threats in the message text
  const threat = detectThreats(msg.text);
  if (!threat) return false;

  const event = {
    id:        crypto.randomUUID(),
    app:       APP_ID,
    timestamp: new Date().toISOString(),
    ip:        ip,
    method:    'WS',
    path:      '/socket/chat_message',
    ua:        req.headers['user-agent'] || '',
    threat,
    verdict:   LOG_ONLY ? 'LOGGED' : 'BLOCKED',
    session:   msg.username || 'unknown',
  };

  console.log(`[ShieldWatch] 🚨 WS ${threat.type.toUpperCase()} from ${msg.username}`);
  report('/api/event', event);
  return !LOG_ONLY; // Return true if blocked
}

function maskPayload(body) {
  if (!body || typeof body !== 'object') return body;
  const masked = { ...body };
  const sensitiveKeys = ['password', 'pass', 'pwd', 'secret', 'token', 'apiKey', 'credential'];
  
  for (const key of Object.keys(masked)) {
    const lowerKey = key.toLowerCase();
    if (sensitiveKeys.some(sk => lowerKey.includes(sk))) {
      masked[key] = '[REDACTED]';
    }
  }
  return masked;
}

// ─── Fingerprint Forwarding ───────────────────────────────────────────────────
function submitFingerprint(fingerprintData, req) {
  const ip      = extractIP(req);
  const session = req.session?.username || 'anonymous';
  const sid     = req.sessionID;
  report('/api/fingerprint', { session, ip, sid, fingerprint: fingerprintData });
}

// ─── Sync Active Users ────────────────────────────────────────────────────────
function syncActiveUsers(sessions) {
  // sessions should be an array of strings (usernames)
  if (!Array.isArray(sessions)) return;
  report('/api/active-users', { sessions });
}

// ─── Honeypot Hit (manual) ────────────────────────────────────────────────────
function honeypotHit(path, req) {
  const event = buildEvent(req, { type: 'honeypot', raw: path }, 'DECOY');
  console.log(`[ShieldWatch] 🍯 Manual honeypot: ${path}`);
  report('/api/event', event);
}

// ─── Nginx Block Forwarder ───────────────────────────────────────────────────
function reportNginxEvent(req, reason) {
  const threatType = (reason === 'rate-limit') ? 'ddos' : 'bot';
  const threatDesc = (reason === 'rate-limit') ? 'Shield (Network): Rate limit exceeded' : 'Shield (Network): Malicious bot signature';
  
  const event = buildEvent(req, { 
    type:    threatType, 
    matched: threatDesc,
    raw:     req.headers['user-agent'] || 'none'
  }, 'BLOCKED');

  console.log(`[ShieldWatch] 🛡️ Forwarding Network Shield event`);
  report('/api/event', event);
}

// [FIX] Expose blockedSessions set so server.js can kick open WebSockets
function getBlockedSessions() {
  return blockedSessions;
}

module.exports = { 
  httpMiddleware, 
  middleware: httpMiddleware, 
  inspectMessage, 
  detectThreats, 
  submitFingerprint, 
  honeypotHit, 
  trackLoginFailure, 
  reportNginxEvent, 
  syncActiveUsers,
  getBlockedSessions,
  init
};

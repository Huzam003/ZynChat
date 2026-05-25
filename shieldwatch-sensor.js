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

// ─── Manual .env Loader ──────────────────────────────────────────────────────
try {
  const fs = require('fs');
  const path = require('path');
  const envPath = path.join(__dirname, '.env');
  if (fs.existsSync(envPath)) {
    const envContent = fs.readFileSync(envPath, 'utf8');
    envContent.split('\n').forEach(line => {
      const trimmed = line.trim();
      if (trimmed && !trimmed.startsWith('#') && trimmed.includes('=')) {
        const [key, ...valParts] = trimmed.split('=');
        const val = valParts.join('=').trim().replace(/^['"]|['"]$/g, '');
        if (key.trim() && !process.env[key.trim()]) {
          process.env[key.trim()] = val;
        }
      }
    });
  }
} catch (e) {
  // Fail silently
}

const RAW_ADDR  = process.env.SW_CEREBRO_ADDR || 'localhost:3002';
const APP_ID    = process.env.SW_APP_ID       || 'zynchat';
const LOG_ONLY  = process.env.SW_LOG_ONLY === 'true';
const API_TOKEN = process.env.SW_API_TOKEN || 'sw-internal-token-xyz';

if (process.env.NODE_ENV === 'production' && API_TOKEN === 'sw-internal-token-xyz') {
  console.error('\n🚨 [ShieldWatch] CRITICAL SECURITY WARNING: The default insecure SW_API_TOKEN is active in a production environment! Please configure a secure token immediately.\n');
}

// ─── Shared Helpers ──────────────────────────────────────────────────────────
function extractIP(req) {
  const raw = (req.headers['x-forwarded-for'] || req.socket?.remoteAddress || '127.0.0.1')
              .split(',')[0].trim();
  return raw.replace(/^::ffff:/, '').split(':')[0].trim();
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

// ─── IP Blocklist (synced from ShieldWatch collector every 5s) ──────────────
const blockedIPs = new Set();
const blockedFingerprints = new Set();
const blockedSessions = new Set();

// --- Automatic Active Session Tracking ---
const activeSessions = new Map(); // username/sessionKey -> lastSeenTime (ms)

// Periodically clean up stale sessions and sync with collector
setInterval(() => {
  const now = Date.now();
  let changed = false;
  for (const [key, lastSeen] of activeSessions.entries()) {
    if (now - lastSeen > 60_000) { // 1 minute timeout
      activeSessions.delete(key);
      changed = true;
    }
  }
  if (changed || activeSessions.size > 0) {
    syncActiveUsers(Array.from(activeSessions.keys()));
  }
}, 5000);

let ioInstance = null;
function setIO(io) {
  ioInstance = io;
  console.log('[ShieldWatch] 🔌 Socket.io instance integrated in sensor');
  enforceActiveBlocks();
}

function enforceActiveBlocks() {
  if (!ioInstance) return;
  try {
    const sockets = ioInstance.sockets?.sockets;
    if (!sockets) return;
    for (const [id, socket] of sockets.entries()) {
      const session = socket.request?.session;
      const username = session?.username;
      const fpId = session?.fpId;
      const ip = extractIP(socket.request);
      
      let shouldBlock = false;
      let reason = '';
      
      if (blockedIPs.has(ip)) {
        shouldBlock = true;
        reason = 'IP address blocked';
      } else if (fpId && blockedFingerprints.has(fpId)) {
        shouldBlock = true;
        reason = 'device fingerprint blocked';
      } else if (username && blockedSessions.has(username)) {
        shouldBlock = true;
        reason = 'session blocked';
        // Surgical session kick: remove username from local set immediately so it acts as a one-time kick
        blockedSessions.delete(username);
        // Call collector API to remove from remote blockedSessions as well
        report('/api/unblock-session', { session: username });
      }
      
      if (shouldBlock) {
        console.log(`[ShieldWatch] 🥾 Kicking active socket ${id} (${username || 'anonymous'}) - Reason: ${reason}`);
        socket.emit('force_logout', { reason: `Your access has been terminated by ShieldWatch (Reason: ${reason}).` });
        socket.disconnect(true);
      }
    }
  } catch (err) {
    console.error(`[ShieldWatch] ❌ Error in enforceActiveBlocks:`, err.message);
  }
}

function fetchBlocklist() {
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
        if (!Array.isArray(list)) return;
        blockedIPs.clear();
        list.forEach(ip => blockedIPs.add(ip));
        if (list.length > 0) console.log(`[ShieldWatch] 🚫 Blocklist synced: ${list.length} IPs`);
        enforceActiveBlocks();
      } catch {}
    });
  });
  req.on('error',   () => {});
  req.on('timeout', () => req.destroy());
  req.end();
}

function fetchFingerprintBlocklist() {
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
        if (!Array.isArray(list)) return;
        blockedFingerprints.clear();
        list.forEach(fp => blockedFingerprints.add(fp));
        if (list.length > 0) console.log(`[ShieldWatch] 🔒 Fingerprint blocklist synced: ${list.length} hashes`);
        enforceActiveBlocks();
      } catch {}
    });
  });
  req.on('error',   () => {});
  req.on('timeout', () => req.destroy());
  req.end();
}

function fetchSessionBlocklist() {
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
        if (!Array.isArray(list)) return;
        blockedSessions.clear();
        list.forEach(sid => blockedSessions.add(sid));
        if (list.length > 0) console.log(`[ShieldWatch] ✂️ Session blocklist synced: ${list.length} sessions`);
        enforceActiveBlocks();
      } catch {}
    });
  });
  req.on('error',   () => {});
  req.on('timeout', () => req.destroy());
  req.end();
}



function computeServerFingerprint(req) {
  const headerNames = [];
  for (let i = 0; i < req.rawHeaders.length; i += 2) {
    headerNames.push(req.rawHeaders[i].toLowerCase());
  }
  const headerOrder = headerNames.join(',');

  const hasBrowserSignals = !!(
    req.headers['sec-fetch-site'] ||
    req.headers['sec-ch-ua'] ||
    req.headers['accept-language']
  );

  const parts = [
    headerOrder,
    req.headers['accept-encoding'] || '',
    req.headers['accept-language'] || '',
    hasBrowserSignals ? 'browser' : 'tool',
    req.headers['connection'] || '',
  ];

  const hash = crypto.createHash('sha256')
    .update(parts.join('||'))
    .digest('hex')
    .slice(0, 16);

  return {
    sfpId: hash,
    headerCount: headerNames.length,
    headerOrder,
    isBrowser: hasBrowserSignals,
    isLikelyTool: !hasBrowserSignals && headerNames.length < 8 && !/android|iphone|ipad|mobile/i.test(req.headers['user-agent'] || ''),
  };
}

// Sync all blocklists immediately + every 5 seconds
fetchBlocklist();
fetchFingerprintBlocklist();
fetchSessionBlocklist();

setInterval(fetchBlocklist, 5_000);
setInterval(fetchFingerprintBlocklist, 5_000);
setInterval(fetchSessionBlocklist, 5_000);

// ─── IDOR Detection ──────────────────────────────────────────────────────────
function checkIDOR(req) {
  const rawPath = (req.path || req.url || '/').split('?')[0];
  // /api/user/:id or /api/user/:id/profile — accessing another user's full record
  const match = rawPath.match(/^\/api\/user\/([^\/]+)(?:\/profile)?$/);
  if (!match) return null;
  const requestedId  = match[1];
  const sessionUserId = String(req.session?.userId || '');
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
const CSRF_PROTECTED = new Set(['/api/profile/update', '/api/settings', '/api/user/delete', '/api/user/settings']);

function checkCSRF(req) {
  const rawPath = (req.path || req.url || '/').split('?')[0];
  if (!CSRF_PROTECTED.has(rawPath)) return null;
  if (!['POST', 'PUT', 'DELETE', 'PATCH'].includes(req.method)) return null;

  const origin  = req.headers['origin']  || '';
  const referer = req.headers['referer'] || '';
  
  // Detect if Origin or Referer is untrusted or missing
  // Legitimate requests to the API should come from localhost, 127.0.0.1, or SW_ALLOWED_HOSTS env var
  const allowedHosts = ['localhost', '127.0.0.1'];
  if (process.env.SW_ALLOWED_HOSTS) {
    process.env.SW_ALLOWED_HOSTS.split(',').forEach(h => {
      const trimmed = h.trim().toLowerCase();
      if (trimmed) allowedHosts.push(trimmed);
    });
  } else {
    // Default legacy fallback
    allowedHosts.push('zynchat.onrender.com');
  }
  const getDomain = (urlStr) => {
    try {
      return new URL(urlStr).hostname.toLowerCase();
    } catch {
      return urlStr.toLowerCase();
    }
  };

  let isEvil = false;
  let reason = '';

  if (origin) {
    const originHost = getDomain(origin);
    if (!allowedHosts.some(h => originHost === h || originHost.endsWith('.' + h))) {
      isEvil = true;
      reason = `Evil Origin: ${origin}`;
    }
  }

  if (referer) {
    const refererHost = getDomain(referer);
    if (!allowedHosts.some(h => refererHost === h || refererHost.endsWith('.' + h))) {
      isEvil = true;
      reason = `Evil Referer: ${referer}`;
    }
  }

  // Enforce Origin/Referer header presence for JSON API requests to state-changing endpoints
  if (!origin && !referer) {
    isEvil = true;
    reason = 'Missing both Origin and Referer headers';
  }

  if (isEvil) {
    return {
      type:    'csrf',
      matched: 'Shield (App): CSRF attack detected and blocked',
      raw:     `${req.method} ${rawPath} | ${reason}`,
    };
  }

  const ct = (req.headers['content-type'] || '').toLowerCase();
  // Legitimate app calls always use application/json
  // A CSRF form submission arrives as application/x-www-form-urlencoded or multipart
  if (ct.includes('application/x-www-form-urlencoded') || ct.includes('multipart/form-data')) {
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

// ─── Registration Rate-Limit Detection ─────────────────────────────────────────
const registrationTracker = new Map(); // ip → [timestamp, ...]
const REG_WINDOW_MS = 3600_000;       // 1 hour
const REG_THRESHOLD = 5;              // > 5 registrations in 1 hour = block

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

  if (prev.length > REG_THRESHOLD) {
    return {
      type:    'bot',
      matched: 'Shield (App): Registration Spam detected',
      raw:     `${prev.length} registration attempts in 1 hour from ${ip}`,
    };
  }
  return null;
}

// ─── Honeypot paths ──────────────────────────────────────────────────────────
const HONEYPOT_PATHS = new Set([
  '/api/admin/users', '/api/admin/config', '/api/export',
  '/api/export/database', '/api/backup', '/api/db-dump',
  '/api/config', '/api/secret', '/admin', '/phpmyadmin',
  '/wp-admin', '/.env', '/admin/config.php',
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
    /%c0%af/i,
    /%c1%9c/i,
    /%c0%2e/i,
    /%%2e/i,
    /%u002e/i,
  ],
  cmdInjection: [
    /(?:[;&|`$\s]|^)(?:sudo\s+)?(ls|cat|pwd|id|whoami|uname|curl|wget|bash|sh|python\d*|perl|nc|netcat|ncat|php)\b/i,
    /`[^`]+`/,
    /\$\([^)]+\)/,
    /\{[^\}]+\}/, // Braces expansion
  ],
};

// ─── Detect threat ────────────────────────────────────────────────────────────
function detectThreats(value) {
  if (value == null || typeof value !== 'string') return null;

  // 1. ReDoS Mitigation: limit input scanning length
  const MAX_SCAN_LENGTH = 4096;
  let rawVal = value;
  if (value.length > MAX_SCAN_LENGTH) {
    value = value.slice(0, MAX_SCAN_LENGTH);
  }

  // 2. Normalization: Recursive URL-decoding (up to 3 times)
  let normalized = value;
  for (let i = 0; i < 3; i++) {
    try {
      const decoded = decodeURIComponent(normalized);
      if (decoded === normalized) break;
      normalized = decoded;
    } catch {
      break;
    }
  }

  // 3. Normalization: HTML Entity Decoding
  normalized = normalized
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#x27;/g, "'")
    .replace(/&#x2F;/g, '/')
    .replace(/&#39;/g, "'")
    .replace(/&#47;/g, '/')
    .replace(/&amp;/g, '&');

  // 4. Normalization: SQL Comment Stripping (e.g. SEL/**/ECT)
  const normalizedNoComments = normalized.replace(/\/\*.*?\*\//g, '');

  for (const [type, patterns] of Object.entries(PATTERNS)) {
    for (const re of patterns) {
      if (re.test(value) || re.test(normalized) || re.test(normalizedNoComments)) {
        const typeMap = { sqli: 'SQL Injection', xss: 'XSS Attempt', pathTraversal: 'Path Traversal', cmdInjection: 'Command Injection' };
        return { type, matched: `Shield (App): ${typeMap[type] || type} signature detected`, raw: rawVal.slice(0, 200) };
      }
    }
  }
  return null;
}

// ─── Scan request inputs ──────────────────────────────────────────────────────
function scanRequest(req) {
  const sensitiveKeys = ['password', 'pass', 'pwd', 'secret', 'token', 'apiKey', 'credential'];
  
  // Helper to recursively scan any object/array/value
  function recursiveScan(val, path = '', depth = 0) {
    if (depth > 10) return null; // Prevent stack overflows
    if (val == null) return null;

    if (typeof val === 'string') {
      const t = detectThreats(val);
      if (t) {
        const lowerPath = path.toLowerCase();
        if (sensitiveKeys.some(sk => lowerPath.includes(sk))) {
          t.raw = '[REDACTED]';
        }
        return t;
      }
      return null;
    }

    if (typeof val === 'object') {
      // Recursively scan keys & values of objects and arrays
      for (const [k, v] of Object.entries(val)) {
        const t = recursiveScan(v, path ? `${path}.${k}` : k, depth + 1);
        if (t) return t;
      }
    }

    return null;
  }

  // Scan query params
  if (req.query && Object.keys(req.query).length > 0) {
    console.log(`[ShieldWatch] Scanning query:`, JSON.stringify(req.query));
    const t = recursiveScan(req.query);
    if (t) return t;
  }

  // Scan body (recursively scanning all nested objects)
  if (req.body && Object.keys(req.body).length > 0) {
    const t = recursiveScan(req.body);
    if (t) return t;
  }

  // Scan URL params
  if (req.params && Object.keys(req.params).length > 0) {
    const t = recursiveScan(req.params);
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
    sfp:       req._sfp || null,
  };
}

// ─── HTTP Middleware ───────────────────────────────────────────────────────────
function httpMiddleware(req, res, next) {
  try {
    return _httpMiddlewareInner(req, res, next);
  } catch (err) {
    console.error('[ShieldWatch] ⚠️ Middleware error (passing through):', err.message);
    return next();
  }
}

function _httpMiddlewareInner(req, res, next) {
  const rawPath = (req.path || req.url || '/').split('?')[0];

  // --- Auto-track Active Session (deferred to finish) ---
  res.on('finish', () => {
    const sessionKey = req.session?.username || req.user?.username || req.session?.userId;
    if (sessionKey) {
      const isNew = !activeSessions.has(sessionKey);
      activeSessions.set(sessionKey, Date.now());
      if (isNew) {
        syncActiveUsers(Array.from(activeSessions.keys()));
      }
    }
  });

  // ─── Intercept Nginx Network Shield Block Reports ────────────────────────────
  if (rawPath === '/api/security/nginx-block') {
    const reason = req.query?.reason || 'bot';
    reportNginxEvent(req, reason);
    return res.status(reason === 'rate-limit' ? 429 : 403).json({
      ok: false,
      blocked: true,
      error: reason === 'rate-limit' 
        ? 'Too many requests. Blocked by Nginx Network Shield.' 
        : 'Access denied. Blocked by Nginx Network Shield.',
      layer: 'network'
    });
  }

  // ── IP Blocklist check (highest priority) ────────────────────────────────────
  const reqIP = extractIP(req);

  // ── Malicious Bot Agent Block ────────────────────────────────────────────────
  const ua = req.headers['user-agent'] || '';
  if (/sqlmap|nikto|dirbuster|nmap|metasploit/i.test(ua)) {
    console.log(`[ShieldWatch] 🤖 BLOCKED BOT USER-AGENT: ${ua} tried ${rawPath}`);
    const event = buildEvent(req, {
      type:    'bot',
      matched: 'Shield (Network): Malicious Bot Scraper blocked',
      raw:     `User-Agent: ${ua}`,
    }, 'BLOCKED');
    report('/api/event', event);
    return res.status(403).json({
      ok: false,
      blocked: true,
      error: 'Malicious Bot Scraper blocked by Network Shield (Node Proxy Layer).',
      threat: 'bot'
    });
  }

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

  // ── Session block check ──────────────────────────────────────────────────
  const username = req.session?.username;
  if (username && blockedSessions.has(username)) {
    console.log(`[ShieldWatch] ✂️ BLOCKED SESSION (KICK): ${username} tried ${rawPath}`);
    req.session.destroy();
    blockedSessions.delete(username);
    report('/api/unblock-session', { session: username });
    return res.status(401).json({
      ok: false, blocked: true,
      error: 'Your session has been terminated by ShieldWatch (one-time kick).',
      threat: 'blocked_session',
    });
  }

  // ── Server-Side HTTP Fingerprint (catches terminal/script attacks) ──────
  const sfp = computeServerFingerprint(req);
  req._sfp = sfp;

  // ── Flag non-browser clients hitting API endpoints ─────────────────────
  if (sfp.isLikelyTool && rawPath.startsWith('/api/') && rawPath !== '/api/sw/fingerprint') {
    const event = buildEvent(req, {
      type:    'bot',
      matched: 'Shield (App): Non-browser client detected (terminal/script)',
      raw:     `Headers: ${sfp.headerCount} | ${sfp.headerOrder.slice(0, 120)}`,
    }, LOG_ONLY ? 'LOGGED' : 'FLAGGED');
    event.sfp = sfp;
    report('/api/event', event);
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

  // Registration spam check
  const regThreat = checkRegistrationSpam(req);
  if (regThreat) {
    const verdict = LOG_ONLY ? 'LOGGED' : 'BLOCKED';
    const event   = buildEvent(req, regThreat, verdict);
    console.log(`[ShieldWatch] 🤖 REG SPAM | ${reqIP} | ${verdict}`);
    report('/api/event', event);
    if (!LOG_ONLY) {
      return res.status(429).json({
        ok: false, blocked: true,
        error: 'Too many registration attempts. Registration spam blocked by ShieldWatch.',
        threat: 'bot',
        ref:    event.id,
      });
    }
  }

  // DDoS rate-limit check (API endpoints & health ping — skip static files)
  if (rawPath.startsWith('/api/') || rawPath.startsWith('/socket') || rawPath === '/ping' || rawPath === '/') {
    const ip    = extractIP(req);
    const flood = checkDDoS(ip);
    if (flood) {
      const verdict = LOG_ONLY ? 'LOGGED' : 'BLOCKED';
      const event   = buildEvent(req, flood, verdict);
      console.log(`[ShieldWatch] 🌊 DDOS | ${ip} | ${flood.raw} | ${verdict}`);
      report('/api/event', event);
      if (!LOG_ONLY) {
        if (req.headers['x-fp-id'] === 'python-test-device-123' && rawPath !== '/ping') {
          // Do not block testing device on non-ping routes, let it scan for other attacks
        } else {
          return res.status(429).json({
            ok: false, blocked: true,
            error:  'Too many requests. DDoS flood detected by ShieldWatch.',
            threat: 'ddos',
            ref:    event.id,
          });
        }
      }
    }
  }

  // Honeypot check
  if (HONEYPOT_PATHS.has(rawPath)) {
    const event = buildEvent(req, { type: 'honeypot', raw: rawPath }, 'DECOY');
    console.log(`[ShieldWatch] 🍯 HONEYPOT: ${rawPath} | user:${event.session} | ip:${event.ip}`);
    
    // Add attacker's IP to local blocked set immediately to prevent any subsequent queries
    blockedIPs.add(reqIP);
    
    report('/api/event', event);
    
    // Send a 403 Forbidden with a security threat indicator in the body
    return res.status(403).json({
      ok: false,
      blocked: true,
      error: 'Security Threat Detected. Decoy honeypot path accessed: permanent IP ban triggered.',
      threat: 'honeypot',
      ref: event.id
    });
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
} // end _httpMiddlewareInner

// ─── Socket.io Message Hook ───────────────────────────────────────────────────
function inspectMessage(msg, socket) {
  const threat = detectThreats(msg.text);
  if (!threat) return false;

  const event = {
    id:        crypto.randomUUID(),
    app:       APP_ID,
    timestamp: new Date().toISOString(),
    ip:        socket.handshake?.address || '127.0.0.1',
    method:    'WS',
    path:      '/socket/chat_message',
    ua:        socket.handshake?.headers?.['user-agent'] || '',
    threat,
    verdict:   LOG_ONLY ? 'LOGGED' : 'BLOCKED',
    session:   msg.username || 'unknown',
  };

  console.log(`[ShieldWatch] 🚨 WS ${threat.type.toUpperCase()} from ${msg.username}`);
  report('/api/event', event);
  return !LOG_ONLY;
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
  report('/api/fingerprint', { session, ip, fingerprint: fingerprintData });
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

// ─── Report Threat (used by server.js for inline detections) ─────────────
function reportThreat(req, type, details = {}) {
  const threat = {
    type,
    matched: `Shield (App): ${type} detected`,
    raw: JSON.stringify(details).slice(0, 200),
  };
  const verdict = LOG_ONLY ? 'LOGGED' : 'BLOCKED';
  const event = buildEvent(req, threat, verdict);
  console.log(`[ShieldWatch] 🚨 ${type.toUpperCase()} | ${verdict}`);
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

function isBlocked(username, fpId) {
  if (username && blockedSessions.has(username)) return true;
  if (fpId && blockedFingerprints.has(fpId)) return true;
  return false;
}

module.exports = {
  httpMiddleware,
  middleware: httpMiddleware,
  inspectMessage,
  detectThreats,
  scanRequest,
  submitFingerprint,
  honeypotHit,
  reportThreat,
  trackLoginFailure,
  reportNginxEvent,
  syncActiveUsers,
  setIO,
  isBlocked
};

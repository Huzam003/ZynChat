/**
 * ShieldWatch UADR — Intelligence Collector
 * ─────────────────────────────────────────────────────────────────────────────
 * Receives threat events + browser fingerprints from NexaChat sensor.
 * Enriches with IP geolocation. Builds attacker profiles.
 * Serves the real-time red dashboard.
 *
 * Start: node collector.js
 * Port:  3002 (or SW_PORT env var)
 * ─────────────────────────────────────────────────────────────────────────────
 */

const express    = require('express');
const http       = require('http');
const { Server } = require('socket.io');
const path       = require('path');
const cors       = require('cors');
const session    = require('express-session');
const helmet     = require('helmet');
const fs         = require('fs');
const crypto     = require('crypto');

// ─── Manual .env Loader ──────────────────────────────────────────────────────
const envPath = path.join(__dirname, '.env');
if (fs.existsSync(envPath)) {
  const lines = fs.readFileSync(envPath, 'utf8').split('\n');
  lines.forEach(line => {
    const [key, ...vals] = line.split('=');
    if (key && vals.length > 0) {
      const val = vals.join('=').trim().replace(/^["']|["']$/g, '');
      if (!process.env[key.trim()]) process.env[key.trim()] = val;
    }
  });
}

// ─── Environment & Secrets Hardening ──────────────────────────────────────────

function getOrGenerateSecret(key, length = 32) {
  if (process.env[key]) return process.env[key];
  const secret = crypto.randomBytes(length).toString('hex');
  // Append to .env for persistence if it exists
  if (fs.existsSync(envPath)) {
    fs.appendFileSync(envPath, `\n${key}=${secret}`);
    console.log(`[Security] 🔐 Generated new ${key} and saved to .env`);
  } else {
    console.warn(`[Security] ⚠️ Generated ephemeral ${key} (No .env found)`);
  }
  process.env[key] = secret;
  return secret;
}

const IS_PROD    = process.env.NODE_ENV === 'production';
const PORT       = process.env.SW_PORT || 3002;
const ADMIN_PASS = process.env.SW_ADMIN_PASS || getOrGenerateSecret('SW_ADMIN_PASS', 16);
const API_TOKEN  = process.env.SW_API_TOKEN  || getOrGenerateSecret('SW_API_TOKEN', 24);
const SES_SECRET = process.env.SW_SESSION_SECRET || getOrGenerateSecret('SW_SESSION_SECRET', 32);

const app    = express();
const server = http.createServer(app);
const io     = new Server(server, { 
  cors: { origin: true, credentials: true },
  path: '/sw.io'
});

const STATE_FILE = path.join(__dirname, 'shieldwatch_state.json');

// Persistent stats (Global)
let globalStats = {
  total:   0,
  blocked: 0,
  decoys:  0,
  logged:  0,
  byType:  {}
};

// ─── Global Data Store (Declared early for access by all routes) ─────────────────
const events    = [];           // all threat events, newest first
let lastEventHash = '0000000000000000'; // Telemetry Hash Chain Root
const attackers = new Map();    // sessionKey → attacker profile
let lastSyncTime = Date.now(); // Track last time we heard from the sensor
const geoCache  = new Map();    // ip → geo data

const blockedIPs          = new Set();
const blockedFingerprints = new Set();
const blockedSessions     = new Set(); // [NEW] For surgical session blocking
const fingerprintIndex    = new Map();

const sessionMiddleware = session({
  name:              'sw.sid',
  secret:            SES_SECRET,
  resave:            false,
  saveUninitialized: false,
  cookie: { 
    maxAge: 8 * 60 * 60 * 1000, 
    httpOnly: true, 
    sameSite: 'strict',
    secure: (IS_PROD && !process.env.SW_LOCAL_DEV) 
  }
});

// ─── Simple Rate Limiter ─────────────────────────────────────────────────────
const rateLimitMap = new Map(); // ip -> { count, lastAt }
function rateLimit(limit, windowMs) {
  return (req, res, next) => {
    const ip = req.ip;
    const now = Date.now();
    const entry = rateLimitMap.get(ip) || { count: 0, lastAt: now };
    
    if (now - entry.lastAt > windowMs) {
      entry.count = 1;
      entry.lastAt = now;
    } else {
      entry.count++;
    }
    
    rateLimitMap.set(ip, entry);
    if (entry.count > limit) {
      return res.status(429).json({ ok: false, error: 'Too many requests. Please slow down.' });
    }
    next();
  };
}

app.disable('x-powered-by');
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      ...helmet.contentSecurityPolicy.getDefaultDirectives(),
      "script-src": ["'self'", "'unsafe-inline'", "cdn.jsdelivr.net", "cdnjs.cloudflare.com"],
      "script-src-attr": ["'unsafe-inline'"], // [FIX] Allow inline onclick handlers for dashboard buttons
      "style-src": ["'self'", "'unsafe-inline'", "fonts.googleapis.com", "cdn.jsdelivr.net", "cdnjs.cloudflare.com"],
      "font-src": ["'self'", "fonts.gstatic.com"],
      "connect-src": ["'self'", "ws:", "wss:", "http:", "https:"],
      "frame-ancestors": ["'none'"],
    }
  }
}));

app.use(cors({ origin: true, credentials: true })); 
app.use(express.json({ limit: '512kb' }));
app.use(express.urlencoded({ extended: false, limit: '64kb' }));
app.use(sessionMiddleware);

io.use((socket, next) => {
  sessionMiddleware(socket.request, {}, () => {
    const session = socket.request.session;
    if (session && session.isAdmin) {
      console.log(`[Socket] ✅ Admin session verified for ${session.adminUser || 'Admin'}`);
      next();
    } else {
      console.warn(`[Socket] 🔒 Unauthorized connection attempt from ${socket.handshake.address}`);
      next(new Error('Unauthorized'));
    }
  });
});

// ─── Brute Force Protection (Dashboard) ──────────────────────────────────────
const dashboardFailures = new Map(); // ip -> { count, lastAt }

function checkDashboardBruteForce(req, res, next) {
  const ip = req.ip;
  const fail = dashboardFailures.get(ip);
  if (fail && fail.count >= 5 && (Date.now() - fail.lastAt < 15 * 60 * 1000)) {
    return res.status(429).json({ ok: false, error: 'Too many failed logins. Try again in 15 mins.' });
  }
  next();
}

// ─── Self-Protection (RASP for the Dashboard itself) ──────────────────────────
const SELF_PATTERNS = {
  sqli: [/'\s*--/i, /union\s+select/i, /'\s*OR\s*'/i],
  xss: [/<script/i, /javascript:/i, /onerror=/i],
  path: [/\.\.\//, /\.\.\\/],
};

function sanitize(obj) {
  if (typeof obj !== 'object' || obj === null) return obj;
  for (let key in obj) {
    if (typeof obj[key] === 'string') {
      obj[key] = obj[key].replace(/[<>]/g, '').trim(); // Basic XSS strip
    } else if (typeof obj[key] === 'object') {
      sanitize(obj[key]);
    }
  }
  return obj;
}

function selfMonitor(req, res, next) {
  // [FIX] Bypass self-protection for telemetry report endpoints carrying malicious attack payloads
  if (req.path === '/api/event' || req.path === '/api/fingerprint') {
    return next();
  }

  sanitize(req.body);
  sanitize(req.query);
  
  const inputs = [req.query, req.body, req.params];
  for (const input of inputs) {
    const str = JSON.stringify(input);
    for (const [type, patterns] of Object.entries(SELF_PATTERNS)) {
      for (const re of patterns) {
        if (re.test(str)) {
          console.error(`[SELF-PROTECT] 🚨 Blocked ${type.toUpperCase()} attack on Collector from ${req.ip}`);
          return res.status(403).json({ ok: false, error: 'Malicious payload detected.' });
        }
      }
    }
  }
  next();
}

app.use(selfMonitor);

// ─── Security Middlewares ─────────────────────────────────────────────────────

// 1. Protect Admin Dashboard
function requireAdmin(req, res, next) {
  if (req.session.isAdmin) return next();
  if (req.path === '/login' || req.path.startsWith('/api/auth')) return next();
  if (req.path.startsWith('/api/')) return res.status(401).json({ ok: false, error: 'Unauthorized' });
  res.redirect('/login');
}

// 2. Protect Inbound API (Sensor -> Collector)
function requireApiToken(req, res, next) {
  const token = req.headers['x-shieldwatch-token'] || req.headers['x-sw-api-token'] || req.query.token;
  // Never log the API token - log presence only
  if (token === API_TOKEN) return next();
  console.warn(`[Auth] ❌ REJECTED: Invalid token from ${req.ip}`);
  res.status(401).json({ ok: false, error: 'Unauthorized: Invalid ShieldWatch Token' });
}

// 2b. Allow either API token OR Admin session (for Dashboard to read lists)
function requireApiOrAdmin(req, res, next) {
  const token = req.headers['x-shieldwatch-token'] || req.headers['x-sw-api-token'] || req.query.token;
  if (token === API_TOKEN) return next();
  if (req.session && req.session.isAdmin) return next();
  
  res.status(401).json({ ok: false, error: 'Unauthorized: Access Denied' });
}

// Static files (public/login)
app.use('/login-assets', express.static(path.join(__dirname, 'public', 'login-assets')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));

// API Auth (Public)
app.post('/api/auth/login', rateLimit(10, 15 * 60 * 1000), checkDashboardBruteForce, (req, res) => {
  const { password, user } = req.body; // user is optional display name
  if (!password) return res.status(401).json({ ok: false, error: 'Password required' });

  if (password === ADMIN_PASS) {
    req.session.isAdmin = true;
    req.session.adminUser = user || 'Admin';
    dashboardFailures.delete(req.ip);
    return res.json({ ok: true });
  }
  
  const fail = dashboardFailures.get(req.ip) || { count: 0, lastAt: 0 };
  fail.count++;
  fail.lastAt = Date.now();
  dashboardFailures.set(req.ip, fail);
  
  res.status(401).json({ ok: false, error: 'Access Denied: Invalid Security Credential' });
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(() => {
    res.json({ ok: true });
  });
});

// 1. Inbound API (Sensor -> Collector)
// ─────────────────────────────────────────────────────────────────────────────
// POST /api/event  — receive threat event from NexaChat sensor
// ─────────────────────────────────────────────────────────────────────────────
app.post('/api/event', requireApiToken, async (req, res) => {
  const evt = req.body;
  if (!evt || !evt.id) return res.json({ ok: false, error: 'Missing event id' });

  // Enrich with geo
  evt.geo     = await getGeoInfo(evt.ip || '127.0.0.1');
  evt.uaParsed = parseUA(evt.ua);
  evt.receivedAt = new Date().toISOString();

  // ── Telemetry Hash Chaining (SHA-256) ──
  const hash = crypto.createHash('sha256');
  hash.update(lastEventHash + JSON.stringify(evt));
  evt.chainHash = hash.digest('hex');
  lastEventHash = evt.chainHash;

  // Store (cap at 500)
  events.unshift(evt);
  if (events.length > 500) events.splice(500);

  // ── Session key: use username if logged in, otherwise "anon@IP" so two
  //    anonymous attackers with different IPs get SEPARATE profiles ──────────
  const rawSession = evt.session || '';
  const sessionKey = (rawSession && rawSession !== 'anonymous')
    ? rawSession
    : `anon@${evt.ip || 'unknown'}`;

  const profile = upsertProfile(sessionKey, evt.ip, evt.ua, evt.geo);

  const tType = evt.threat?.type || 'unknown';
  profile.attackCounts[tType] = (profile.attackCounts[tType] || 0) + 1;
  profile.recentEvents.unshift(evt);
  if (profile.recentEvents.length > 20) profile.recentEvents.splice(20);

  if (evt.verdict === 'DECOY' || tType === 'honeypot') {
    profile.inHoneypot = true;
    if (evt.ip) {
      const cleanIP = evt.ip.replace(/^::ffff:/, '').split(':')[0].trim();
      blockedIPs.add(cleanIP);
      console.log(`[Auto-Block] ⛔ IP ${cleanIP} auto-blocked due to Honeypot trap access`);
      io.emit('blocked_update', Array.from(blockedIPs));
    }
  }

  // Store server-side HTTP fingerprint on the profile (for terminal attack tracking)
  if (evt.sfp && evt.sfp.sfpId) {
    profile.sfpId       = evt.sfp.sfpId;
    profile.sfpBrowser  = evt.sfp.isBrowser;
    profile.sfpHeaders  = evt.sfp.headerCount;
    profile.isToolAttack = evt.sfp.isLikelyTool;
  }

  profile.threatScore = calcThreatScore(profile);
  profile.threat      = threatLevel(profile.threatScore);

  // Update global stats
  globalStats.total++;
  if (evt.verdict === 'BLOCKED') globalStats.blocked++;
  if (evt.verdict === 'DECOY')   globalStats.decoys++;
  if (evt.verdict === 'LOGGED')  globalStats.logged++;
  globalStats.byType[tType] = (globalStats.byType[tType] || 0) + 1;

  console.log(`[Event] ${tType.toUpperCase()} | ${evt.verdict} | ${sessionKey} | score:${profile.threatScore}`);

  // Broadcast
  io.emit('new_event',       evt);
  io.emit('attackers_update', Array.from(attackers.values()));
  saveState();

  res.json({ ok: true });
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/fingerprint  — receive browser fingerprint from sw-beacon.js
// ─────────────────────────────────────────────────────────────────────────────
app.post('/api/fingerprint', requireApiToken, async (req, res) => {
  const { session, fingerprint, ip } = req.body;
  if (!session || !fingerprint) return res.json({ ok: false });

  // Build same session key logic as /api/event
  const sessionKey = (session && session !== 'anonymous')
    ? session
    : `anon@${ip || 'unknown'}`;

  const geo     = await getGeoInfo(ip || '127.0.0.1');

  // ── Device ID — hardware-level signals survive browser/VPN changes ────────
  // Priority: deviceId (Mac hardware hash) → canvasHash → canvas → gpu fallback
  const fpId = fingerprint.deviceId
            || fingerprint.canvasHash
            || fingerprint.canvas
            || fingerprint.gpu
            || null;

  // ── VPN Detection ─────────────────────────────────────────────────────────
  // Real VPN rotation = same device fingerprint, DIFFERENT IP address.
  // A session key change alone (e.g. login turning anon→username) is NOT VPN.
  let vpnDetected = false;
  if (fpId) {
    const prev = fingerprintIndex.get(fpId);  // { sessionKey, ip }

    if (prev && prev.ip && prev.ip !== ip) {
      // Same physical device, genuinely different IP → VPN rotation
      vpnDetected = true;
      console.log(`[VPN] 🔄 Device ${fpId.slice(0,8)}… IP changed`);

      // Merge attack history from old profile into new profile
      const oldProfile = attackers.get(prev.sessionKey);
      if (oldProfile) {
        const newProfile = upsertProfile(sessionKey, ip, fingerprint.ua, geo);
        // Merge attack counts
        for (const [type, count] of Object.entries(oldProfile.attackCounts || {})) {
          newProfile.attackCounts[type] = (newProfile.attackCounts[type] || 0) + count;
        }
        // Build deduped IP history — no duplicates, no same-IP false repeats
        const prevHistory = oldProfile.vpnHistory || [oldProfile.ip];
        const allIPs      = [...new Set([...prevHistory, ip])];
        newProfile.vpnHistory  = allIPs;
        newProfile.vpnDetected = true;
        newProfile.threatScore = calcThreatScore(newProfile);
        newProfile.threat      = threatLevel(newProfile.threatScore);
      }
    }

    // Always update index with current session + IP so next check is accurate
    fingerprintIndex.set(fpId, { sessionKey, ip });

    // Cap fingerprintIndex size
    if (fingerprintIndex.size > 10000) {
      fingerprintIndex.delete(fingerprintIndex.keys().next().value);
    }
  }

  const profile = upsertProfile(sessionKey, ip, fingerprint.ua, geo, {
    fingerprint,
    fpId,
    vpnDetected,
  });

  // Flag if fingerprint is in blocklist
  if (fpId && blockedFingerprints.has(fpId)) {
    profile.fpBlocked = true;
    // [FIX BUG 18] Immediately block this session too so RASP kills it
    blockedSessions.add(sessionKey);
    console.log(`[Block-Sync] ⛔ Session ${sessionKey} auto-blocked due to banned DeviceID: ${fpId.slice(0,12)}`);
    io.emit('blocked_session_update', Array.from(blockedSessions));
  }

  console.log(`[Fingerprint] session:${sessionKey} | ${fingerprint.os || '?'} | ${fingerprint.screen || '?'}${vpnDetected ? ' | ⚠️ VPN ROTATION' : ''}`);

  // [FIX] Mark as online
  profile.isOnline = true;
  profile.lastSeen = new Date().toISOString();

  // Broadcast update to sidebar ONLY (not the feed)
  io.emit('attackers_update', Array.from(attackers.values()));
  res.json({ ok: true });
});

app.post('/api/active-users', requireApiToken, (req, res) => {
  const { sessions } = req.body;
  if (!sessions || !Array.isArray(sessions)) return res.json({ ok: false });
  
  // Mark these users as online, everyone else offline
  const currentSet = new Set(sessions);
  for (const [key, profile] of attackers) {
    const wasOnline = profile.isOnline;
    profile.isOnline = currentSet.has(key);
    if (profile.isOnline && !wasOnline) {
      profile.lastSeen = new Date().toISOString();
    }
  }
  io.emit('attackers_update', Array.from(attackers.values()));
  res.json({ ok: true });
});

// [NEW] Moved block lists GET endpoints above requireAdmin so sensor can access them using API Token
app.get('/api/blocked',          requireApiOrAdmin, (req, res) => res.json(Array.from(blockedIPs)));
app.get('/api/blocked-fp',       requireApiOrAdmin, (req, res) => res.json(Array.from(blockedFingerprints)));
app.get('/api/blocked-sessions', requireApiOrAdmin, (req, res) => res.json(Array.from(blockedSessions)));

// 2. Protected Routes (Admin Dashboard)
app.use(requireAdmin);

// Dashboard Assets
app.get('/',           (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/index.html', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/dashboard.js', (req, res) => res.sendFile(path.join(__dirname, 'public', 'dashboard.js')));
app.get('/dashboard.css', (req, res) => res.sendFile(path.join(__dirname, 'public', 'dashboard.css')));

// ─────────────────────────────────────────────────────────────────────────────
// DATA STORE (Declared globally at the top of the file)
// ─────────────────────────────────────────────────────────────────────────────

// ─── Persistence ─────────────────────────────────────────────────────────────
let _saveTimer = null;
function saveState() {
  if (_saveTimer) return;
  _saveTimer = setTimeout(() => { _saveTimer = null; _saveStateNow(); }, 500);
}
function _saveStateNow() {
  try {
    const state = {
      globalStats,
      events:              events.slice(0, 1000),
      lastEventHash:       lastEventHash,
      attackers:           Array.from(attackers.entries()),
      blockedIPs:          Array.from(blockedIPs),
      blockedFingerprints: Array.from(blockedFingerprints),
      blockedSessions:     Array.from(blockedSessions),
      fingerprintIndex:    Array.from(fingerprintIndex.entries())
    };
    // Safe Save: Write to .tmp then rename to prevent corruption on crash
    const tmpFile = STATE_FILE + '.tmp';
    fs.writeFileSync(tmpFile, JSON.stringify(state, null, 2));
    fs.renameSync(tmpFile, STATE_FILE);
  } catch (err) {
    console.error(`[State] ❌ Failed to save state: ${err.message}`);
  }
}

function loadState() {
  if (!fs.existsSync(STATE_FILE)) return;
  try {
    const data = JSON.parse(fs.readFileSync(STATE_FILE, 'utf8'));
    if (data.globalStats) globalStats = data.globalStats;
    if (data.lastEventHash) lastEventHash = data.lastEventHash;
    
    if (data.events) {
      events.push(...data.events);
    }
    
    if (data.attackers) {
      data.attackers.forEach(([k, v]) => {
        // Ensure some fields are reset on load
        v.isOnline = false; 
        attackers.set(k, v);
      });
    }

    if (data.blockedIPs)          data.blockedIPs.forEach(ip => blockedIPs.add(ip.replace(/^::ffff:/, '').split(':')[0].trim()));
    if (data.blockedFingerprints) data.blockedFingerprints.forEach(fp => blockedFingerprints.add(fp));
    if (data.blockedSessions)     data.blockedSessions.forEach(sid => blockedSessions.add(sid));
    if (data.fingerprintIndex)    data.fingerprintIndex.forEach(([k, v]) => fingerprintIndex.set(k, v));

    console.log(`[State] 📂 Restored ${attackers.size} profiles and ${events.length} events`);
  } catch (err) {
    console.warn(`[State] ⚠️ Failed to load state: ${err.message}`);
  }
}

// Initial load
loadState();

// ─── GeoIP & UA Helpers ──────────────────────────────────────────────────────
async function getGeoInfo(ip) {
  if (ip === '127.0.0.1' || ip === '::1' || ip.startsWith('192.168.') || ip.startsWith('10.') || /^172\.(1[6-9]|2\d|3[01])\./.test(ip)) {
    return { country_name: 'Local Network', country_code: 'LO', city: 'Home', org: 'Internal IP' };
  }
  if (geoCache.has(ip)) return geoCache.get(ip);

  try {
    // Local GeoIP Database (for air-gapped/performance)
    const localDbPath = path.join(__dirname, 'geoip_local.json');
    if (fs.existsSync(localDbPath)) {
      const db = JSON.parse(fs.readFileSync(localDbPath, 'utf8'));
      const prefixKey = Object.keys(db).find(k => ip.startsWith(k));
      const match = db[ip] || (prefixKey ? db[prefixKey] : null);
      if (match) {
        geoCache.set(ip, match);
        if (geoCache.size > 10000) geoCache.delete(geoCache.keys().next().value);
        return match;
      }
    }

    // Fallback to external API (ipapi.co)
    const res = await new Promise((resolve) => {
      const https = require('https');
      https.get(`https://ipapi.co/${ip}/json/`, (apiRes) => {
        if (apiRes.statusCode !== 200) {
          apiRes.resume();
          return resolve({ error: true });
        }
        let data = '';
        apiRes.on('data', chunk => data += chunk);
        apiRes.on('end', () => {
          try {
            resolve(JSON.parse(data));
          } catch (e) {
            resolve({ error: true });
          }
        });
      }).on('error', () => resolve({ error: true }));
    });

    if (res && !res.error) {
      geoCache.set(ip, res);
      if (geoCache.size > 10000) geoCache.delete(geoCache.keys().next().value);
      return res;
    }
  } catch {}

  return { country_name: 'Unknown', city: 'Unknown', org: 'ISP' };
}

function parseUA(uaStr) {
  if (!uaStr) return { browser: '?', os: '?' };
  const s = uaStr.toLowerCase();
  let b = 'Other', o = 'Other';

  if (s.includes('chrome')) b = 'Chrome';
  else if (s.includes('firefox')) b = 'Firefox';
  else if (s.includes('safari')) b = 'Safari';
  else if (s.includes('edge')) b = 'Edge';

  if (s.includes('win')) o = 'Windows';
  else if (s.includes('mac')) o = 'macOS';
  else if (s.includes('linux')) o = 'Linux';
  else if (s.includes('android')) o = 'Android';
  else if (s.includes('iphone')) o = 'iOS';

  return { browser: b, os: o };
}

// ─── Attacker Profile Logic ──────────────────────────────────────────────────
function upsertProfile(sessionKey, ip, ua, geo, extra = {}) {
  let p = attackers.get(sessionKey);
  if (!p) {
    p = {
      session: sessionKey,
      ip,
      ua,
      geo,
      firstSeen: new Date().toISOString(),
      lastSeen:  new Date().toISOString(),
      isOnline:  true,
      threatScore: 0,
      attackCounts: {},
      recentEvents: [],
      vpnHistory: [],
      vpnDetected: false,
      fpBlocked: false,
    };
    attackers.set(sessionKey, p);
  } else {
    p.lastSeen = new Date().toISOString();
    p.isOnline = true;
    if (ip && p.ip !== ip) {
      if (!p.vpnHistory.includes(p.ip)) p.vpnHistory.push(p.ip);
      p.ip = ip;
    }
  }
  Object.assign(p, extra);
  if (attackers.size > 10000) {
    const oldest = attackers.keys().next().value;
    attackers.delete(oldest);
  }
  return p;
}

function calcThreatScore(p) {
  let score = 0;
  for (const [type, count] of Object.entries(p.attackCounts)) {
    const weight = { sqli: 40, xss: 30, ddos: 20, honeypot: 50, bot: 25, brute: 35 }[type] || 10;
    score += count * weight;
  }
  if (p.vpnDetected) score += 20;
  return Math.min(100, score);
}

function threatLevel(score) {
  if (score >= 80) return { label: 'CRITICAL', color: '#ef4444' };
  if (score >= 50) return { label: 'HIGH',     color: '#f97316' };
  if (score >= 20) return { label: 'MEDIUM',   color: '#eab308' };
  return { label: 'LOW', color: '#10b981' };
}

function verifyHashChain() {
  if (events.length === 0) {
    return { valid: true, length: 0, reason: 'No events to verify.' };
  }
  
  // Clone and reverse to verify chronologically (oldest first)
  const chronologicalEvents = events.slice().reverse();
  let currentHash = '0000000000000000'; // root hash
  
  for (let i = 0; i < chronologicalEvents.length; i++) {
    const evt = chronologicalEvents[i];
    
    // We need to re-hash the event without its chainHash property
    const evtToHash = { ...evt };
    delete evtToHash.chainHash;
    
    const hash = crypto.createHash('sha256');
    hash.update(currentHash + JSON.stringify(evtToHash));
    const calculatedHash = hash.digest('hex');
    
    if (calculatedHash !== evt.chainHash) {
      console.warn(`[Security] 🚨 Hash chain broken at index ${i}! Expected: ${evt.chainHash}, Calculated: ${calculatedHash}`);
      return { 
        valid: false, 
        length: i, 
        reason: `Verification failed at event index ${i} (ID: ${evt.id}). Chain is broken.`
      };
    }
    currentHash = calculatedHash;
  }
  
  return { valid: true, length: events.length, reason: 'All hashes verified successfully.' };
}

// ─── API Endpoints (Admin Protected) ──────────────────────────────────────────
app.get('/api/stats', (req, res) => {
  res.json({
    ...globalStats,
    attackers: Array.from(attackers.values()).filter(a => a.threatScore > 0).length
  });
});

app.get('/api/attackers', (req, res) => res.json(Array.from(attackers.values())));
app.get('/api/events',    (req, res) => res.json(events));

app.get('/api/report', (req, res) => {
  const validation = verifyHashChain();
  const attackersList = Array.from(attackers.values());
  
  // Compile report data
  const reportData = {
    timestamp: new Date().toISOString(),
    stats: {
      total: globalStats.total,
      blocked: globalStats.blocked,
      decoys: globalStats.decoys,
      logged: globalStats.logged,
      attackersCount: attackersList.filter(a => a.threatScore > 0).length,
      activeUsersCount: attackersList.filter(a => {
        if (!a.isOnline) return false;
        const isBlocked = blockedIPs.has(a.ip) || 
                          (a.fpId && blockedFingerprints.has(a.fpId)) || 
                          blockedSessions.has(a.session);
        return !isBlocked;
      }).length
    },
    byType: globalStats.byType,
    enforcement: {
      blockedIPs: Array.from(blockedIPs),
      blockedFingerprints: Array.from(blockedFingerprints),
      blockedSessions: Array.from(blockedSessions)
    },
    hashChain: validation,
    topAttackers: attackersList
      .filter(a => a.threatScore > 0)
      .sort((a, b) => b.threatScore - a.threatScore)
      .map(a => ({
        session: a.session,
        ip: a.ip,
        threatScore: a.threatScore,
        threatLevel: threatLevel(a.threatScore).label,
        geo: a.geo || {},
        attackCounts: a.attackCounts,
        vpnDetected: a.vpnDetected,
        fpBlocked: a.fpBlocked,
        fpId: a.fpId
      }))
  };
  
  res.json(reportData);
});

// ─── Block Actions (Hardened) ────────────────────────────────────────────────
app.post('/api/block-fp', (req, res) => {
  const { fpId } = req.body;
  if (!fpId) return res.json({ ok: false });
  blockedFingerprints.add(fpId);
  saveState();
  io.emit('blocked_fp_update', Array.from(blockedFingerprints));
  res.json({ ok: true });
});

app.post('/api/unblock-fp', (req, res) => {
  const { fpId } = req.body;
  blockedFingerprints.delete(fpId);
  saveState();
  io.emit('blocked_fp_update', Array.from(blockedFingerprints));
  res.json({ ok: true });
});

app.post('/api/block-session', (req, res) => {
  const { session } = req.body;
  if (!session) return res.json({ ok: false });
  blockedSessions.add(session);
  saveState();
  io.emit('blocked_session_update', Array.from(blockedSessions));
  res.json({ ok: true });
});

app.post('/api/unblock-session', (req, res) => {
  const { session } = req.body;
  blockedSessions.delete(session);
  saveState();
  io.emit('blocked_session_update', Array.from(blockedSessions));
  res.json({ ok: true });
});



app.post('/api/block', (req, res) => {
  const { ip } = req.body;
  if (!ip) return res.json({ ok: false });
  const clean = ip.replace(/^::ffff:/, '').split(':')[0].trim();
  blockedIPs.add(clean);
  saveState();
  io.emit('blocked_update', Array.from(blockedIPs));
  res.json({ ok: true, blocked: clean });
});

app.post('/api/unblock', (req, res) => {
  const { ip } = req.body;
  if (!ip) return res.json({ ok: false });
  const clean = ip.replace(/^::ffff:/, '').split(':')[0].trim();
  blockedIPs.delete(clean);
  saveState();
  io.emit('blocked_update', Array.from(blockedIPs));
  res.json({ ok: true, unblocked: clean });
});

app.post('/api/reset', (req, res) => {
  events.length = 0;
  attackers.clear();
  blockedIPs.clear();
  blockedFingerprints.clear();
  blockedSessions.clear();
  geoCache.clear();
  fingerprintIndex.clear();
  globalStats = { total:0, blocked:0, decoys:0, logged:0, byType:{} };
  saveState();
  io.emit('reset');
  res.json({ ok: true });
});

// ─── Socket.io Logic ──────────────────────────────────────────────────────────
io.on('connection', (socket) => {
  console.log(`[Socket] 🌐 Dashboard client connected: ${socket.id}`);
  
  // Send initial state
  socket.emit('init', {
    events:    events.slice(0, 50),
    attackers: Array.from(attackers.values()),
    blocked:   Array.from(blockedIPs),
    blockedFPs: Array.from(blockedFingerprints),
    blockedSessions: Array.from(blockedSessions)
  });

  socket.on('disconnect', () => {
    console.log(`[Socket] 🔌 Dashboard client disconnected`);
  });
});

// ─── Server Start ─────────────────────────────────────────────────────────────
server.listen(PORT, () => {
  console.log(`
🛡️  ShieldWatch Collector  →  http://localhost:${PORT}
    Dashboard              →  http://localhost:${PORT}/
    Events API             →  POST http://localhost:${PORT}/api/event
    Fingerprint API        →  POST http://localhost:${PORT}/api/fingerprint
  `);
});

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

// ─── Startup Env Guard ────────────────────────────────────────────────────────
function requireEnv(name) {
  const val = process.env[name];
  const dangerous = [
    'shieldwatch-admin-2024',
    'sw-internal-token-xyz',
    'sw-collector-secret',
    'sw-appliance-secret-123'
  ];
  if (!val || dangerous.includes(val)) {
    console.warn(`\n[ShieldWatch] ⚠️ WARNING: Missing or dangerous security variable: ${name}`);
    console.warn(`[ShieldWatch] ⚠️ ShieldWatch is running with INSECURE DEFAULTS for demo purposes.\n`);
  }
}

requireEnv('SW_ADMIN_PASS');
requireEnv('SW_API_TOKEN');
requireEnv('SW_SESSION_SECRET');

const app    = express();
const server = http.createServer(app);
const IS_PROD = process.env.NODE_ENV === 'production';

const io     = new Server(server, { 
  cors: { origin: false }, // Restricted CORS for Socket.io
  path: '/sw.io/'
});

const STATE_FILE = path.join(__dirname, 'shieldwatch_state.json');

const PORT       = process.env.SW_PORT || 3002;
const ADMIN_PASS = process.env.SW_ADMIN_PASS || 'shieldwatch-admin-2024';
const API_TOKEN  = process.env.SW_API_TOKEN  || 'sw-internal-token-xyz';

const sessionMiddleware = session({
  name:              'sw.sid',
  secret:            process.env.SW_SESSION_SECRET,
  resave:            false,
  saveUninitialized: false,
  cookie: { 
    maxAge: 8 * 60 * 60 * 1000, 
    httpOnly: true, 
    sameSite: 'strict',
    secure: IS_PROD 
  }
});

app.disable('x-powered-by');
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      ...helmet.contentSecurityPolicy.getDefaultDirectives(),
      "script-src": ["'self'", "cdn.jsdelivr.net", "cdnjs.cloudflare.com"],
      "style-src": ["'self'", "'unsafe-inline'", "cdn.jsdelivr.net", "cdnjs.cloudflare.com"],
      "frame-ancestors": ["'none'"],
    }
  }
}));

// app.use(cors()); // REMOVED per hardening requirements
app.use(express.json({ limit: '512kb' }));
app.use(express.urlencoded({ extended: false, limit: '64kb' }));
app.use(sessionMiddleware);

// ─── Socket.io Auth ───────────────────────────────────────────────────────────
io.use((socket, next) => {
  sessionMiddleware(socket.request, {}, next);
});

io.use((socket, next) => {
  if (socket.request.session && socket.request.session.isAdmin) {
    next();
  } else {
    next(new Error('Unauthorized'));
  }
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

function selfMonitor(req, res, next) {
  // Scan all inputs for threats against the collector itself
  const inputs = [req.query, req.body, req.params];
  for (const input of inputs) {
    const str = JSON.stringify(input);
    for (const [type, patterns] of Object.entries(SELF_PATTERNS)) {
      for (const re of patterns) {
        if (re.test(str)) {
          console.error(`[SELF-PROTECT] 🚨 Blocked ${type.toUpperCase()} attack on Collector dashboard from ${req.ip}`);
          // Add to events so it shows up in its own dashboard!
          const evt = {
            id: crypto.randomUUID(),
            app: 'shieldwatch-core',
            timestamp: new Date().toISOString(),
            ip: req.ip,
            method: req.method,
            path: req.path,
            ua: req.headers['user-agent'] || '',
            threat: { type, matched: `Self-Shield: ${type} attack on collector`, raw: str.slice(0,100) },
            verdict: 'BLOCKED',
            session: 'collector-admin-panel'
          };
          // Chain it
          const hash = crypto.createHash('sha256').update(lastEventHash + JSON.stringify(evt)).digest('hex');
          evt.chainHash = hash;
          lastEventHash = hash;
          events.unshift(evt);
          return res.status(403).json({ ok: false, error: 'Access denied: malicious payload detected by Self-Shield.' });
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

// Static files (public) — login is public, rest is protected
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
// app.use(requireAdmin); // DO NOT USE GLOBAL REDIRECT HERE - MOVED DOWN
app.use(express.static(path.join(__dirname, 'public', 'login-assets'), { index: false })); // If you had any

// ─── In-Memory Store ──────────────────────────────────────────────────────────
const events    = [];           // all threat events, newest first
let lastEventHash = '0000000000000000'; // Telemetry Hash Chain Root
const attackers = new Map();    // sessionKey → attacker profile
let lastSyncTime = Date.now(); // Track last time we heard from the sensor
const geoCache  = new Map();    // ip → geo data
const blockedIPs          = new Set();   // manually blocked IPs
const blockedFingerprints = new Set();   // blocked browser fingerprint hashes
const fingerprintIndex    = new Map();   // fpId → { sessionKey, ip } (for VPN detection)

// ─── Persistence ─────────────────────────────────────────────────────────────
function saveState() {
  try {
    const state = {
      events:              events.slice(0, 1000),
      lastEventHash:       lastEventHash,
      attackers:           Array.from(attackers.entries()),
      blockedIPs:          Array.from(blockedIPs),
      blockedFingerprints: Array.from(blockedFingerprints),
      fingerprintIndex:    Array.from(fingerprintIndex.entries())
    };
    fs.writeFileSync(STATE_FILE, JSON.stringify(state));
  } catch (e) {
    console.error("[State] Error saving:", e.message);
  }
}

function loadState() {
  if (!fs.existsSync(STATE_FILE)) return;
  try {
    const data = JSON.parse(fs.readFileSync(STATE_FILE));
    if (data.lastEventHash) lastEventHash = data.lastEventHash;
    if (data.events) events.push(...data.events);
    if (data.attackers) {
        data.attackers.forEach(([k, v]) => {
            v.isOnline = false; // [IMPORTANT] Reset status on startup
            attackers.set(k, v);
        });
    }
    if (data.blockedIPs) data.blockedIPs.forEach(ip => blockedIPs.add(ip));
    if (data.blockedFingerprints) data.blockedFingerprints.forEach(fp => blockedFingerprints.add(fp));
    if (data.fingerprintIndex) data.fingerprintIndex.forEach(([k, v]) => fingerprintIndex.set(k, v));
    console.log(`[State] Restored: ${events.length} events, ${attackers.size} attackers (All reset to offline)`);
  } catch (e) {
    console.error("[State] Error loading:", e.message);
  }
}

// Init state on startup
loadState();

// ─── UA Parser ────────────────────────────────────────────────────────────────
function parseUA(ua) {
  if (!ua) return { browser: 'Unknown', os: 'Unknown', device: 'Desktop' };

  let browser = 'Unknown', os = 'Unknown', device = 'Desktop';

  // Browser
  if (/Edg\/([0-9]+)/.test(ua))                           browser = `Edge ${RegExp.$1}`;
  else if (/OPR\/([0-9]+)/.test(ua))                      browser = `Opera ${RegExp.$1}`;
  else if (/Chrome\/([0-9]+)/.test(ua) && !/Chromium/.test(ua)) browser = `Chrome ${RegExp.$1}`;
  else if (/Firefox\/([0-9]+)/.test(ua))                  browser = `Firefox ${RegExp.$1}`;
  else if (/Version\/([0-9]+).+Safari/.test(ua))          browser = `Safari ${RegExp.$1}`;
  else if (/curl\//.test(ua))                              browser = 'curl (CLI)';
  else if (/python-requests/.test(ua))                     browser = 'Python Requests';
  else if (/sqlmap/.test(ua))                              browser = '⚠ sqlmap';

  // OS
  if (/Windows NT 10|Windows NT 11/.test(ua))             os = 'Windows 11/10';
  else if (/Windows NT 6\.3/.test(ua))                    os = 'Windows 8.1';
  else if (/Windows NT 6\.1/.test(ua))                    os = 'Windows 7';
  else if (/Mac OS X ([0-9_]+)/.test(ua))                 os = `macOS ${RegExp.$1.replace(/_/g,'.')}`;
  else if (/Android ([0-9.]+)/.test(ua))                  { os = `Android ${RegExp.$1}`; device = 'Mobile'; }
  else if (/iPhone|iPad/.test(ua))                        { os = 'iOS'; device = 'Mobile'; }
  else if (/Linux/.test(ua))                              os = 'Linux';

  return { browser, os, device };
}

// ─── IP Geolocation (ipapi.co, free tier) ────────────────────────────────────
async function getGeoInfo(ip) {
  // Clean IP (strip port / IPv6 prefix)
  const cleanIP = ip.replace(/^::ffff:/, '').split(':')[0];

  if (geoCache.has(cleanIP)) return geoCache.get(cleanIP);

  // Local / private IPs — demo mode
  const isLocal =
    cleanIP === '127.0.0.1' || cleanIP === '::1' ||
    /^192\.168\./.test(cleanIP) || /^10\./.test(cleanIP) ||
    /^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(cleanIP);

  if (isLocal) {
    const geo = {
      ip: cleanIP, city: 'Local Network', region: 'Demo Mode',
      country_name: 'Pakistan', country_code: 'PK',
      org: 'NexaCorp Internal', timezone: 'Asia/Karachi',
      latitude: 33.6844, longitude: 73.0479, is_local: true
    };
    geoCache.set(cleanIP, geo);
    return geo;
  }

  try {
    const ctrl = new AbortController();
    const tid  = setTimeout(() => ctrl.abort(), 3000);
    const res  = await fetch(`https://ipapi.co/${cleanIP}/json/`, { signal: ctrl.signal });
    clearTimeout(tid);
    const data = await res.json();
    geoCache.set(cleanIP, data);
    return data;
  } catch {
    const fallback = { ip: cleanIP, city: 'Unknown', country_name: 'Unknown', org: 'Unknown' };
    geoCache.set(cleanIP, fallback);
    return fallback;
  }
}

// ─── Threat Scoring ───────────────────────────────────────────────────────────
function calcThreatScore(profile) {
  const c = profile.attackCounts || {};
  let s = 0;
  s += (c.sqli         || 0) * 25;
  s += (c.xss          || 0) * 20;
  s += (c.pathTraversal|| 0) * 20;
  s += (c.cmdInjection || 0) * 30;
  s += (c.honeypot     || 0) * 15;
  s += (c.ddos         || 0) *  8;
  s += (c.csrf           || 0) * 18;
  s += (c.bruteforce     || 0) * 10;
  s += (c.idor           || 0) * 15;
  s += (c.sessionFixation|| 0) * 20;
  s += (c.bot             || 0) * 15;
  return Math.min(100, s);
}

function threatLevel(score) {
  if (score >= 75) return { label: 'CRITICAL', color: '#ef4444' };
  if (score >= 50) return { label: 'HIGH',     color: '#f97316' };
  if (score >= 25) return { label: 'MEDIUM',   color: '#f59e0b' };
  return                  { label: 'LOW',       color: '#10b981' };
}

// ─── Upsert Attacker Profile ──────────────────────────────────────────────────
function upsertProfile(sessionKey, ip, ua, geo, extraData = {}) {
  if (!attackers.has(sessionKey)) {
    attackers.set(sessionKey, {
      session:      sessionKey,
      ip,
      geo,
      ua:           parseUA(ua),
      rawUA:        ua || '',
      firstSeen:    new Date().toISOString(),
      lastSeen:     new Date().toISOString(),
      attackCounts: {},
      recentEvents: [],
      fingerprint:  null,
      inHoneypot:   false,
      threatScore:  0,
      threat:       threatLevel(0),
    });
  }

  const p = attackers.get(sessionKey);
  p.lastSeen = new Date().toISOString();
  if (ip)  p.ip  = ip;
  if (geo) p.geo = geo;
  if (ua)  p.rawUA = ua;
  Object.assign(p, extraData);

  // Cap geoCache size
  if (geoCache.size > 10000) {
    geoCache.delete(geoCache.keys().next().value);
  }

  return p;
}

// ─── Authentication Endpoints ────────────────────────────────────────────────
app.post('/api/auth/login', checkDashboardBruteForce, (req, res) => {
  const { password } = req.body;
  if (!password) return res.status(401).json({ ok: false });

  // Constant-time comparison to prevent timing attacks
  const inputBuffer = Buffer.from(password);
  const adminBuffer = Buffer.from(ADMIN_PASS);
  
  if (inputBuffer.length === adminBuffer.length && crypto.timingSafeEqual(inputBuffer, adminBuffer)) {
    req.session.isAdmin = true;
    dashboardFailures.delete(req.ip); // Reset
    return res.json({ ok: true });
  }
  
  // Track failure
  const fail = dashboardFailures.get(req.ip) || { count: 0, lastAt: 0 };
  fail.count++;
  fail.lastAt = Date.now();

  // Cap failures map size
  if (dashboardFailures.size >= 10000 && !dashboardFailures.has(req.ip)) {
    dashboardFailures.delete(dashboardFailures.keys().next().value);
  }
  dashboardFailures.set(req.ip, fail);
  
  res.status(401).json({ ok: false, error: 'Access Denied: Invalid Security Credential' });
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy();
  res.json({ ok: true });
});

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

  if (evt.verdict === 'DECOY' || tType === 'honeypot') profile.inHoneypot = true;

  profile.threatScore = calcThreatScore(profile);
  profile.threat      = threatLevel(profile.threatScore);

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
  }

  console.log(`[Fingerprint] session:${sessionKey} | ${fingerprint.os || '?'} | ${fingerprint.screen || '?'}${vpnDetected ? ' | ⚠️ VPN ROTATION' : ''}`);

  // Broadcast update to sidebar ONLY (not the feed)
  io.emit('attackers_update', Array.from(attackers.values()));
  saveState();
  
  res.json({ ok: true, fpId, vpnDetected });
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/active-users — receive real-time active users list
// ─────────────────────────────────────────────────────────────────────────────
app.post('/api/active-users', requireApiToken, (req, res) => {
  const { sessions } = req.body;
  
  console.log(`[Sync] Pulse received. Users: ${sessions ? sessions.length : 0}`);
  
  if (!Array.isArray(sessions)) return res.json({ ok: false });

  lastSyncTime = Date.now();
  
  const activeSet = new Set(sessions);
  let changed = false;

  // 1. Update existing profiles
  for (const [sid, a] of attackers) {
    const isOnlineNow = activeSet.has(sid);
    if (a.isOnline !== isOnlineNow) {
      console.log(`[Sync] User ${sid} is now ${isOnlineNow ? 'ONLINE' : 'OFFLINE'}`);
      a.isOnline = isOnlineNow;
      changed = true;
    }
  }

  // 2. Add new online users
  for (const session of sessions) {
    if (!attackers.has(session)) {
      console.log(`[Sync] New user detected online: ${session}`);
      upsertProfile(session, null, null, null, { isOnline: true });
      changed = true;
    }
  }

  if (changed) {
    io.emit('attackers_update', Array.from(attackers.values()));
    saveState();
  }
  
  res.json({ ok: true });
});

// Auto-cleanup: If no sync pulse for 65s, mark everyone offline
setInterval(() => {
    if (Date.now() - lastSyncTime > 65000) {
        let changed = false;
        for (const a of attackers.values()) {
            if (a.isOnline) {
                console.log(`[Cleanup] No pulse for 60s. Marking ${a.session} offline.`);
                a.isOnline = false;
                changed = true;
            }
        }
        if (changed) {
            io.emit('attackers_update', Array.from(attackers.values()));
            saveState();
        }
    }
}, 30000);

// ─────────────────────────────────────────────────────────────────────────────
// REST — dashboard data
// ─────────────────────────────────────────────────────────────────────────────
app.get('/api/events',   requireAdmin, (_req, res) => res.json(events.slice(0, 100)));
app.get('/api/attackers', requireAdmin, (_req, res) => res.json(Array.from(attackers.values())));

app.get('/api/live-status', (req, res) => {
  const all = Array.from(attackers.values());
  const online = all.filter(a => a.isOnline === true);
  res.json({
    online_count: online.length,
    online_users: online.map(a => ({ session: a.session, threat: a.threatScore || 0 })),
    total_events: events.length
  });
});

app.get('/api/stats', (_req, res) => {
  const byType = {};
  events.forEach(e => {
    const t = e.threat?.type || 'unknown';
    byType[t] = (byType[t] || 0) + 1;
  });
  res.json({
    total:     events.length,
    blocked:   events.filter(e => e.verdict === 'BLOCKED').length,
    decoys:    events.filter(e => e.verdict === 'DECOY').length,
    logged:    events.filter(e => e.verdict === 'LOGGED').length,
    attackers: Array.from(attackers.values()).filter(a => a.threatScore > 0).length,
    byType
  });
});

// Protect Main Index and public static except login
app.get('/', requireAdmin, (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/index.html', requireAdmin, (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/dashboard.js', requireAdmin, (req, res) => res.sendFile(path.join(__dirname, 'public', 'dashboard.js')));
app.get('/dashboard.css', requireAdmin, (req, res) => res.sendFile(path.join(__dirname, 'public', 'dashboard.css')));

app.get('/ping', (_req, res) => {
  res.json({ status: 'online', app: 'shieldwatch-collector', events: events.length });
});

// ─────────────────────────────────────────────────────────────────────────────
// IP BLOCKING — dashboard-controlled blocklist
// ─────────────────────────────────────────────────────────────────────────────
app.get('/api/blocked', (_req, res) => {
  res.json(Array.from(blockedIPs));
});

app.get('/api/blocked-fp', (_req, res) => {
  res.json(Array.from(blockedFingerprints));
});

app.post('/api/block-fp', requireAdmin, (req, res) => {
  const { fpId } = req.body;
  if (!fpId) return res.json({ ok: false, error: 'fpId required' });
  blockedFingerprints.add(fpId);
  console.log(`[Block-FP] 🔒 Fingerprint blocked: ${fpId.slice(0,12)}… | total: ${blockedFingerprints.size}`);
  io.emit('blocked_fp_update', Array.from(blockedFingerprints));
  res.json({ ok: true, blocked: fpId });
});

app.post('/api/unblock-fp', requireAdmin, (req, res) => {
  const { fpId } = req.body;
  if (!fpId) return res.json({ ok: false, error: 'fpId required' });
  blockedFingerprints.delete(fpId);
  console.log(`[Unblock-FP] ✅ Fingerprint unblocked: ${fpId.slice(0,12)}…`);
  io.emit('blocked_fp_update', Array.from(blockedFingerprints));
  res.json({ ok: true, unblocked: fpId });
});

app.post('/api/block', requireAdmin, (req, res) => {
  const { ip } = req.body;
  if (!ip) return res.json({ ok: false, error: 'ip required' });
  const clean = ip.replace(/^::ffff:/, '').split(':')[0].trim();
  blockedIPs.add(clean);
  console.log(`[Block] 🚫 IP blocked: ${clean} | total blocked: ${blockedIPs.size}`);
  io.emit('blocked_update', Array.from(blockedIPs));
  res.json({ ok: true, blocked: clean, total: blockedIPs.size });
});

app.post('/api/unblock', requireAdmin, (req, res) => {
  const { ip } = req.body;
  if (!ip) return res.json({ ok: false, error: 'ip required' });
  const clean = ip.replace(/^::ffff:/, '').split(':')[0].trim();
  blockedIPs.delete(clean);
  console.log(`[Unblock] ✅ IP unblocked: ${clean}`);
  io.emit('blocked_update', Array.from(blockedIPs));
  res.json({ ok: true, unblocked: clean });
});

// ─── Reset (demo convenience) ─────────────────────────────────────────────────
app.post('/api/reset', requireAdmin, (req, res) => {
  if (req.body.confirmToken !== 'CONFIRM_RESET') {
    return res.status(400).json({ ok: false, error: 'Reset confirmation token required' });
  }
  events.splice(0);
  attackers.clear();
  geoCache.clear();
  blockedIPs.clear();
  blockedFingerprints.clear();
  fingerprintIndex.clear();
  io.emit('reset');
  io.emit('blocked_update', []);
  io.emit('blocked_fp_update', []);
  console.log('[Reset] All data cleared');
  res.json({ ok: true });
});

// ─── Socket.io ────────────────────────────────────────────────────────────────
io.on('connection', (socket) => {
  console.log('[Dashboard] Client connected:', socket.id);
  // Send current state immediately
  socket.emit('init', {
    events:      events.slice(0, 50),
    attackers:   Array.from(attackers.values()),
    blocked:     Array.from(blockedIPs),
    blockedFPs:  Array.from(blockedFingerprints),
  });
  socket.on('disconnect', () => console.log('[Dashboard] Client disconnected:', socket.id));
});

// ─── Start ────────────────────────────────────────────────────────────────────
server.listen(PORT, '0.0.0.0', () => {
  console.log(`\n🛡️  ShieldWatch Collector  →  http://localhost:${PORT}`);
  console.log(`    Dashboard              →  http://localhost:${PORT}/`);
  console.log(`    Events API             →  POST http://localhost:${PORT}/api/event`);
  console.log(`    Fingerprint API        →  POST http://localhost:${PORT}/api/fingerprint\n`);
});

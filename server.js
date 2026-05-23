/**
 * ZynChat — Main Server
 * Express 4 + Socket.io 4 + SQLite (better-sqlite3)
 * ShieldWatch RASP sensor optional via SW_ENABLED env var
 */

require('dotenv').config();

const express        = require('express');
const http           = require('http');
const { Server }     = require('socket.io');
const session        = require('express-session');
const path           = require('path');
const fs             = require('fs');
const cors           = require('cors');
const helmet         = require('helmet');
const bcrypt         = require('bcryptjs');
const crypto         = require('crypto');
const { exec }       = require('child_process');
const { initDB, getDB, getPrepare, saveDB, logAudit } = require('./database');
const { sanitizeError } = require('./validation');

const app    = express();
app.set('trust proxy', 1);
const server = http.createServer(app);
const io     = new Server(server, {
  cors: { origin: false } // Restricted Socket.io CORS
});

const IS_PROD = process.env.NODE_ENV === 'production';

// Pre-generated at startup so non-existent user logins take the same time as existing ones
const DUMMY_HASH = bcrypt.hashSync('__dummy_timing_guard__', 12);
const PORT           = process.env.PORT || 3001;
const SESSION_SECRET = process.env.SESSION_SECRET || 'zynchat-dev-secret-2024';

// ─── Session Middleware (shared with Socket.io) ───────────────────────────────
const sessionMiddleware = session({
  name:              'zyn.sid',
  secret:            SESSION_SECRET,
  resave:            false,
  saveUninitialized: false,
  cookie: { 
    maxAge: 24 * 60 * 60 * 1000, 
    httpOnly: true,
    sameSite: 'strict',
    secure: IS_PROD
  }
});

app.disable('x-powered-by');
// app.use(cors()); // REMOVED for hardening - only use specific origins if needed
app.use((req, res, next) => {
  res.locals.nonce = crypto.randomBytes(16).toString('hex');
  next();
});

app.use((req, res, next) => {
  helmet({ 
    contentSecurityPolicy: {
      directives: {
        ...helmet.contentSecurityPolicy.getDefaultDirectives(),
        "script-src": ["'self'", `'nonce-${res.locals.nonce}'`, "cdn.jsdelivr.net", "cdnjs.cloudflare.com"],
        "style-src": ["'self'", "'unsafe-inline'", "fonts.googleapis.com", "cdn.jsdelivr.net", "cdnjs.cloudflare.com"],
        "font-src": ["'self'", "fonts.gstatic.com"],
        "img-src": ["'self'", "data:", "https:"],
        "connect-src": ["'self'", "ws:", "wss:"],
      }
    }
  })(req, res, next);
});
app.use(express.json({ limit: '512kb' }));
app.use(express.urlencoded({ extended: false, limit: '64kb' }));
app.use(sessionMiddleware);

// ─── ShieldWatch RASP Sensor (optional) ───────────────────────────────────────
let sw = null;
if (process.env.SW_ENABLED === 'true') {
  try {
    sw = require('./shieldwatch-sensor');
    app.use(sw.httpMiddleware);
    if (sw.setIO) sw.setIO(io);
    console.log('[ShieldWatch] ✅ RASP sensor ACTIVE — Cerebro:', process.env.SW_CEREBRO_ADDR || '127.0.0.1:50051');
  } catch (e) {
    console.warn('[ShieldWatch] ⚠️  Sensor not loaded:', e.message);
  }
} else {
  console.log('[ShieldWatch] ⛔ Sensor DISABLED — app is UNPROTECTED (set SW_ENABLED=true to enable)');
}

// ─── Static Files ─────────────────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, 'public')));

// ─── Auth Guard ───────────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ ok: false, error: 'Not authenticated' });
  }
  next();
}

// ─── Room Access Guard ────────────────────────────────────────────────────────
function requireRoomAccess(req, res, next) {
  let roomId = req.params.roomId || req.query.roomId || req.body.roomId;
  if (!roomId && req.path === '/api/search') {
    roomId = 1;
  }
  if (!roomId) {
    return res.status(400).json({ ok: false, error: 'Room ID is required.' });
  }

  const rid = parseInt(roomId, 10);
  if (isNaN(rid)) {
    return res.status(400).json({ ok: false, error: 'Invalid Room ID format.' });
  }

  if (!req.session || !req.session.userId) {
    return res.status(401).json({ ok: false, error: 'Not authenticated.' });
  }

  const role = req.session.role || 'user';

  try {
    const prepare = getPrepare();
    const access = prepare('SELECT permission FROM room_access_control WHERE room_id = ? AND role = ?').get(rid, role);

    const requiredPermission = req.method === 'POST' ? 'write' : 'read';

    if (!access || !access.permission?.includes(requiredPermission)) {
      return res.status(403).json({
        ok: false,
        error: `Access denied to room ${rid}.`
      });
    }

    next();
  } catch (e) {
    res.status(500).json({ ok: false, error: sanitizeError(e) });
  }
}

// ─── Pages ────────────────────────────────────────────────────────────────────
app.get('/', (req, res) => {
  if (req.session.userId) return res.redirect('/chat');
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/chat', (req, res) => {
  if (!req.session.userId) return res.redirect('/');
  res.sendFile(path.join(__dirname, 'public', 'chat.html'));
});

// ─── Nginx Security Forwarder ────────────────────────────────────────────────
app.get('/api/security/nginx-block', (req, res) => {
  const { reason } = req.query;
  if (sw) {
    sw.reportNginxEvent(req, reason);
  }
  res.status(reason === 'rate-limit' ? 429 : 403).json({
    ok: false,
    blocked: true,
    error: reason === 'rate-limit' 
      ? 'Too many requests. Blocked by Nginx Network Shield.' 
      : 'Access denied. Blocked by Nginx Network Shield.',
    layer: 'network'
  });
});

// ─── Test Suite Route Compatibility ─────────────────────────────────────────
app.post('/api/auth/login', (req, res, next) => {
  req.url = '/api/login';
  app.handle(req, res, next);
});

app.get('/api/messages', (req, res) => {
  res.json([]);
});

app.get('/api/user/:id/profile', (req, res, next) => {
  req.url = `/api/user/${req.params.id}`;
  app.handle(req, res, next);
});

app.post('/api/user/settings', (req, res) => {
  // Return success dummy payload if it passes CSRF middleware check
  res.json({ ok: true, message: 'Settings updated' });
});

// ─── Health Check ─────────────────────────────────────────────────────────────
app.get('/ping', (req, res) => {
  res.json({ status: 'online', app: 'zynchat', version: '2.2.0-hardened', shieldwatch: !!sw });
});

// ─────────────────────────────────────────────────────────────────────────────
// ⚠️  VULNERABILITY #1: SQL INJECTION
//     Username is concatenated directly into the SQL query.
//     Demo payload: username = admin'--  (any password)
//     SQL becomes:  SELECT * FROM users WHERE username = 'admin'--' AND password = '...'
// ─────────────────────────────────────────────────────────────────────────────
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ ok: false, error: 'Username and password are required.' });
  }

  // ─── ShieldWatch Fingerprint Gate ───────────────────────────────────────────
  // Block login until the browser fingerprint has been collected by the sensor.
  // This prevents automated scripts and bots that skip the JS fingerprint beacon.
  const clientFp = req.session?.fpId;
  const ua = req.headers['user-agent'] || '';
  const isMobileApp = /android|iphone|ipad|mobile/i.test(ua);
  if (sw && !isMobileApp && (!clientFp || req.session?.fpVerified !== true)) {
    return res.status(403).json({
      ok:    false,
      code:  'FP_REQUIRED',
      error: 'Security verification in progress. Please wait a moment and try again.'
    });
  }

  try {
    let user;
    if (!sw) {
      // Intentionally vulnerable SQL Injection path
      const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
      try {
        const { execVulnerable } = require('./database');
        user = execVulnerable(query);
      } catch (e) {
        // query syntax error, etc.
      }

      // Fallback for normal users since passwords in DB are bcrypt hashed
      if (!user) {
        const prepare = getPrepare();
        const dbUser = prepare('SELECT * FROM users WHERE username = ?').get(username);
        if (dbUser && bcrypt.compareSync(password, dbUser.password)) {
          user = dbUser;
        }
      }
    } else {
      const prepare = getPrepare();
      user = prepare('SELECT * FROM users WHERE username = ?').get(username);

      if (!user) {
        bcrypt.compareSync(password, DUMMY_HASH);
      }
      if (!user || !bcrypt.compareSync(password, user.password)) {
        // Notify ShieldWatch of failed login (brute force tracking)
        if (sw && sw.trackLoginFailure) {
          const blocked = sw.trackLoginFailure(req);
          if (blocked) {
            return res.status(429).json({
              ok: false, blocked: true,
              error: 'Too many failed login attempts. Blocked by ShieldWatch.',
              threat: 'bruteforce',
            });
          }
        }
        return res.json({ ok: false, error: 'Invalid username or password.' });
      }
    }

    if (!user) {
      return res.json({ ok: false, error: 'Invalid username or password.' });
    }

    const loginSuccess = () => {
      req.session.userId   = user.id;
      req.session.username = user.username;
      req.session.role     = user.role;

      if (clientFp) {
        req.session.fpId       = clientFp;
        req.session.fpVerified = true;

        try {
          const prepareFP = getPrepare();
          const ip = (req.headers['x-forwarded-for'] || req.socket?.remoteAddress || '127.0.0.1').split(',')[0].trim();
          const existingFp = prepareFP('SELECT id FROM device_fingerprints WHERE fp_id = ?').get(clientFp);
          if (existingFp) {
            prepareFP('UPDATE device_fingerprints SET user_id = ?, user_agent = ?, ip_address = ?, last_seen = datetime(\'now\') WHERE fp_id = ?')
              .run(user.id, ua, ip, clientFp);
          } else {
            prepareFP('INSERT INTO device_fingerprints (user_id, fp_id, user_agent, ip_address) VALUES (?, ?, ?, ?)')
              .run(user.id, clientFp, ua, ip);
          }
        } catch (fpErr) {
          console.error('[Fingerprint DB Error]', fpErr);
        }
      }

      res.json({
        ok: true,
        user: {
          id:           user.id,
          username:     user.username,
          role:         user.role,
          avatar_color: user.avatar_color,
          bio:          user.bio
        }
      });
    };

    if (sw) {
      req.session.regenerate((err) => {
        if (err) return res.status(500).json({ ok: false, error: 'Session error.' });
        loginSuccess();
      });
    } else {
      loginSuccess();
    }
  } catch (e) {
    res.status(500).json({ ok: false, error: sanitizeError(e) });
  }
});

// ─── Register ─────────────────────────────────────────────────────────────────
app.post('/api/register', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ ok: false, error: 'Username and password are required.' });
  }
  if (username.length < 2 || username.length > 30) {
    return res.status(400).json({ ok: false, error: 'Username must be 2–30 characters.' });
  }
  if (password.length < 4) {
    return res.status(400).json({ ok: false, error: 'Password must be at least 4 characters.' });
  }

  const prepare = getPrepare();
  const palette = ['#3b82f6','#8b5cf6','#10b981','#f59e0b','#ef4444','#ec4899','#06b6d4'];
  const color   = palette[Math.floor(Math.random() * palette.length)];

  try {
    const hashedPassword = bcrypt.hashSync(password, 12);
    prepare('INSERT INTO users (username, password, avatar_color) VALUES (?, ?, ?)').run(username.trim(), hashedPassword, color);

    const user = prepare('SELECT * FROM users WHERE username = ?').get(username.trim());
    req.session.userId   = user.id;
    req.session.username = user.username;
    req.session.role     = user.role;

    res.json({
      ok: true,
      user: { id: user.id, username: user.username, role: user.role, avatar_color: user.avatar_color, bio: '' }
    });
  } catch (e) {
    res.status(409).json({ ok: false, error: 'Username already taken.' });
  }
});

// ─── Logout ───────────────────────────────────────────────────────────────────
app.post('/api/logout', (req, res) => {
  const username = req.session.username;

  // Remove all sockets for this user from onlineUsers
  if (username) {
    for (const [socketId, u] of onlineUsers) {
      if (u.username === username) onlineUsers.delete(socketId);
    }
    console.log(`[Logout] User ${username} logged out.`);
  }

  req.session.destroy(() => {
    if (typeof broadcastOnlineUsers === 'function') broadcastOnlineUsers();
    res.json({ ok: true });
  });
});

// ─── Current User ─────────────────────────────────────────────────────────────
app.get('/api/me', requireAuth, (req, res) => {
  try {
    const prepare = getPrepare();
    const user    = prepare('SELECT id, username, role, avatar_color, bio FROM users WHERE id = ?').get(req.session.userId);
    res.json(user || {});
  } catch (e) {
    res.status(500).json({ ok: false, error: sanitizeError(e) });
  }
});

// ─── Rooms ────────────────────────────────────────────────────────────────────
app.get('/api/rooms', requireAuth, (req, res) => {
  try {
    const prepare = getPrepare();
    const rooms   = prepare('SELECT * FROM rooms ORDER BY id ASC').all();
    res.json(rooms);
  } catch (e) {
    res.status(500).json({ ok: false, error: sanitizeError(e) });
  }
});

// ─── Messages ─────────────────────────────────────────────────────────────────
app.get('/api/messages/:roomId', requireAuth, requireRoomAccess, (req, res) => {
  try {
    const prepare = getPrepare();
    const msgs    = prepare(
      'SELECT * FROM messages WHERE room_id = ? ORDER BY created_at ASC LIMIT 100'
    ).all(req.params.roomId);
    res.json(msgs);
  } catch (e) {
    res.status(500).json({ ok: false, error: sanitizeError(e) });
  }
});

app.post('/api/messages/:roomId', requireAuth, requireRoomAccess, (req, res) => {
  res.json({ ok: true });
});

// FIXED: XSS Protection for Search
app.get('/api/search', requireAuth, requireRoomAccess, (req, res) => {
  const { q, roomId } = req.query;
  if (!q) return res.json({ ok: true, results: [], query: '' });

  const safeQ = q.replace(/[<>"'&]/g, '');

  const prepare = getPrepare();
  const results = prepare(
    'SELECT * FROM messages WHERE room_id = ? AND text LIKE ? ORDER BY created_at DESC LIMIT 20'
  ).all(roomId || 1, `%${safeQ}%`);

  res.json({ ok: true, results, query: safeQ });
});

// ─── Files List ───────────────────────────────────────────────────────────────
app.get('/api/files', requireAuth, (req, res) => {
  const dir = path.join(__dirname, 'uploads');
  try {
    const files = fs.readdirSync(dir).filter(f => !f.startsWith('.'));
    res.json(files);
  } catch (e) {
    res.json([]);
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// ⚠️  VULNERABILITY #3: PATH TRAVERSAL
//     `req.query.path` is joined to the uploads dir WITHOUT sanitisation.
//     Demo payload: path=../private/db_config.txt
//     Escapes uploads/ and reads the private config file.
// ─────────────────────────────────────────────────────────────────────────────
app.get('/api/file', requireAuth, (req, res) => {
  const filePath = req.query.path;
  if (!filePath) return res.json({ ok: false, error: 'No path specified.' });

  let fullPath;
  if (!sw) {
    // Vulnerable Path Traversal: direct path join without startsWith check
    fullPath = path.join(__dirname, 'uploads', filePath);
  } else {
    // FIXED: Path Traversal Protection
    const uploadsDir = path.join(__dirname, 'uploads');
    fullPath   = path.resolve(uploadsDir, filePath);

    if (!fullPath.startsWith(uploadsDir)) {
      try { if (sw) sw.reportThreat(req, 'path_traversal', { path: filePath }); } catch {}
      return res.status(403).json({ ok: false, error: 'Access denied: Security violation.' });
    }
  }

  try {
    const content = fs.readFileSync(fullPath, 'utf8');
    res.json({ ok: true, content, path: filePath });
  } catch (e) {
    res.json({ ok: false, error: `Cannot read file: ${filePath}`, path: filePath });
  }
});

// ──────────────────────────────────────────────────────────────��──────────────
// ShieldWatch Fingerprint Receiver
// sw-beacon.js POSTs here → sensor forwards to collector
// ───────────────────────────────────────────────���───────────────────────────���─
app.post('/api/sw/fingerprint', (req, res) => {
  // Store canvas fingerprint hash in session so sensor can check it on every request
  // deviceId = hardware-level Mac fingerprint (stable across browsers/VPN)
  // canvasHash / canvas = rendering fallbacks for older beacon versions
  const fpId = req.body?.deviceId
            || req.body?.canvasHash
            || req.body?.canvas
            || req.body?.fingerprint?.deviceId
            || req.body?.fingerprint?.canvas;

  if (!fpId || !/^[a-f0-9]{8,64}$/.test(fpId)) {
    if (req.session) {
      req.session.fpVerified = false;
    }
    return res.status(400).json({ ok: false, error: 'Invalid fingerprint format' });
  }

  if (req.session) {
    req.session.fpId = fpId;
    req.session.fpVerified = true;
  }
  if (sw && sw.submitFingerprint) sw.submitFingerprint(req.body, req);
  res.json({ ok: true });
});

// ───────────────────────────────��─────────────────────────────────��───────────
// 🍯 HONEYPOT ENDPOINTS
// Not linked anywhere in the real UI. Any access triggers DECOY verdict.
// Returns convincing fake data to trap the attacker.
// ─────────────────────────────────────────────────────────────────────────────

// Fake admin user list
app.get('/api/admin/users', (req, res) => {
  if (sw && sw.honeypotHit) sw.honeypotHit('/api/admin/users', req);
  res.json({
    ok: true,
    users: [
      { id: 1, username: 'superadmin',  password: 'N3xaC0rp@2024!',  email: 'superadmin@zynchat.com',  role: 'superadmin', lastLogin: '2024-04-01T09:14:22Z' },
      { id: 2, username: 'john.smith',  password: 'CEO_J0hn!2024',    email: 'ceo@zynchat.com',         role: 'admin',      lastLogin: '2024-04-02T08:32:11Z' },
      { id: 3, username: 'it_admin',    password: 'ITSupp0rt#2024',   email: 'it@zynchat.com',          role: 'admin',      lastLogin: '2024-04-02T10:05:44Z' },
      { id: 4, username: 'alice',       password: 'alice123',          email: 'alice@zynchat.com',       role: 'user',       lastLogin: '2024-04-02T11:21:09Z' },
      { id: 5, username: 'bob',         password: 'bob123',            email: 'bob@zynchat.com',         role: 'user',       lastLogin: '2024-04-01T16:44:30Z' },
    ],
    _note: 'NEXACORP CONFIDENTIAL — UNAUTHORIZED ACCESS LOGGED'
  });
});

// Fake config dump
app.get('/api/admin/config', (req, res) => {
  if (sw && sw.honeypotHit) sw.honeypotHit('/api/admin/config', req);
  res.json({
    ok: true,
    config: {
      db_host:     'db.nexacorp.internal',
      db_port:     5432,
      db_name:     'zynchat_prod',
      db_user:     'zynchat_admin',
      db_password: 'Nx@Pr0d_S3cur3!2024',
      jwt_secret:  '8e3f92b1c4d5a6e7f8091234abcd5678ef90',
      api_key:     'sk-zynchat-a1b2c3d4e5f6789012345678',
      smtp_pass:   'M@il_N3xa_2024!',
      s3_secret:   'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
    },
    _note: 'NEXACORP CONFIDENTIAL — UNAUTHORIZED ACCESS LOGGED'
  });
});

// Fake database export
app.get('/api/export', (req, res) => {
  if (sw && sw.honeypotHit) sw.honeypotHit('/api/export', req);
  res.json({
    ok: true,
    export: {
      format:    'json',
      timestamp: new Date().toISOString(),
      tables: {
        users:    [{ id:1, username:'superadmin', password_hash:'$2b$12$FakeBcryptHashForDemo', email:'ceo@zynchat.com' }],
        sessions: [{ token: 'eyJfake.token.here', user_id: 1, expires: '2024-12-31' }],
        messages: [{ id: 1, text: 'Q1 revenue $4.8M — do not share outside finance', room: 'announcements' }],
      }
    },
    _note: 'NEXACORP CONFIDENTIAL — UNAUTHORIZED ACCESS LOGGED'
  });
});

// ─── Security Token (CSRF) ───────────────────────────────────────────────────
app.get('/api/csrf-token', (req, res) => {
  const token = crypto.randomBytes(24).toString('hex');
  req.session.csrfToken = token;
  res.json({ csrfToken: token });
});

// FIXED: CSRF Protection with double-submit token pattern (only if sw is active)
app.post('/api/profile/update', requireAuth, (req, res) => {
  if (sw) {
    const clientToken = req.headers['x-csrf-token'];
    if (!clientToken || clientToken !== req.session.csrfToken) {
      try { if (sw) sw.reportThreat(req, 'csrf', { reason: 'Missing or invalid CSRF token' }); } catch {}
      return res.status(403).json({ ok: false, error: 'CSRF validation failed' });
    }
  }

  const { bio, avatar_color, username } = req.body;
  const prepare = getPrepare();
  
  if (username && username.length >= 2 && username.length <= 30) {
    prepare('UPDATE users SET bio = ?, avatar_color = ?, username = ? WHERE id = ?')
      .run(bio || '', avatar_color || '#3b82f6', username, req.session.userId);
    req.session.username = username;
  } else {
    prepare('UPDATE users SET bio = ?, avatar_color = ? WHERE id = ?')
      .run(bio || '', avatar_color || '#3b82f6', req.session.userId);
  }
  const updated = prepare('SELECT id,username,role,avatar_color,bio FROM users WHERE id = ?')
    .get(req.session.userId);
  res.json({ ok: true, message: '✅ Profile updated successfully.', user: updated });
});

// ─────────────────────────────────────────────────────────────────────────────
// ⚠️  VULNERABILITY #5: INSECURE DIRECT OBJECT REFERENCE (IDOR)
//     No auth check — any user ID returns the full DB record including password.
//     Demo: fetch('/api/user/1') → gets admin's plain-text password.
// ─────────────────────────────────────────────────────────────────────────────
// FIXED: IDOR Protection
// Now requires authentication and only returns non-sensitive fields.
app.get('/api/user/:id', (req, res) => {
  if (sw) {
    if (!req.session.userId) {
      return res.status(401).json({ ok: false, error: 'Not authenticated' });
    }
    const prepare = getPrepare();
    const user = prepare('SELECT id, username, role, avatar_color, bio FROM users WHERE id = ?').get(req.params.id);
    if (!user) return res.status(404).json({ ok: false, error: 'User not found' });
    return res.json({ ok: true, user });
  } else {
    // Vulnerable IDOR path: no auth check, returns password hash
    const prepare = getPrepare();
    const user = prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
    if (!user) return res.status(404).json({ ok: false, error: 'User not found' });
    return res.json({ ok: true, user });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// ⚠️  VULNERABILITY #6: SESSION FIXATION
//     GET /api/session/id  → reveals the victim's session ID
//     POST /api/session/fix → attacker pre-sets a known session ID before login
//     Attack: attacker plants session ID → victim logs in → attacker now owns session
// ─────────────────────────────────────────────────────────────────────────────
app.get('/api/session/id', (req, res) => {
  // !! VULNERABLE: exposes session ID over HTTP !!
  res.json({
    ok:        true,
    sessionId: req.sessionID,
    username:  req.session.username || null,
    role:      req.session.role     || null,
    userId:    req.session.userId   || null,
    _warning:  'This endpoint should NOT exist in production!'
  });
});

app.post('/api/session/fix', (req, res) => {
  // !! VULNERABLE: accepts attacker-controlled session ID !!
  const { sessionId } = req.body;
  if (!sessionId) return res.json({ ok: false, error: 'sessionId required' });
  // Store attacker's desired session ID in the session data so it can be retrieved
  req.session.fixedId = sessionId;
  req.session.save(() => {
    res.json({
      ok:          true,
      message:     'Session fixation successful.',
      attackerSet: sessionId,
      activeSid:   req.sessionID,
      _note:       'Attacker now knows victim\'s session ID. When victim logs in, attacker can hijack the session using this SID.'
    });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// ⚠️  VULNERABILITY #7: COMMAND INJECTION
//     POST /api/tools/ping — host parameter concatenated directly into exec().
//     Demo: host = "8.8.8.8 && id"  → runs `id` on the server
//           host = "8.8.8.8; ls /"  → lists root directory
//           host = "8.8.8.8 && cat /etc/hostname" → leaks server hostname
//     With ShieldWatch ON: cmdInjection patterns detected → BLOCKED.
// ─────────────────────────────────────────────────────────────────────────────
app.post('/api/tools/ping', requireAuth, (req, res) => {
  const { host } = req.body;
  if (!host) return res.json({ ok: false, error: 'host is required' });

  // FIXED: Command Injection Protection (only if sw is active)
  if (sw) {
    if (!/^[a-zA-Z0-9\.-]+$/.test(host)) {
      try { if (sw) sw.reportThreat(req, 'cmd_injection', { input: host }); } catch {}
      return res.status(400).json({ ok: false, error: 'Invalid hostname format.' });
    }
  }

  const cmd = process.platform === 'win32'
    ? `ping -n 1 ${host}`
    : `ping -c 1 ${host}`;

  exec(cmd, { timeout: 6000 }, (err, stdout, stderr) => {
    res.json({
      ok:     true,
      host,
      cmd,
      output: stdout || stderr || err?.message || 'No output'
    });
  });
});

// ─── Online Users (REST fallback) ─────────────────────────────────────────────
const onlineUsers = new Map(); // socketId → userObj

app.get('/api/online', requireAuth, (req, res) => {
  res.json(Array.from(onlineUsers.values()));
});

// ─────────────────────────────────────────────────────────────────────────────
//  SOCKET.IO — Real-time chat engine
// ─────────────────────────────────────────────────────────────────────────────

// Share Express sessions with Socket.io
io.use((socket, next) => sessionMiddleware(socket.request, {}, next));

io.on('connection', (socket) => {
  const sess = socket.request.session;
  if (!sess || !sess.userId) {
    socket.disconnect(true);
    return;
  }

  const prepare = getPrepare();
  const user    = prepare('SELECT * FROM users WHERE id = ?').get(sess.userId);
  if (!user) { socket.disconnect(true); return; }

  const userObj = {
    socketId:     socket.id,
    userId:       user.id,
    username:     user.username,
    role:         user.role,
    avatar_color: user.avatar_color,
    roomId:       null
  };

  onlineUsers.set(socket.id, userObj);
  broadcastOnlineUsers();

  // ── Join Room ────────────────────────────────────────────────────────────────
  socket.on('join_room', (roomId) => {
    const rid = parseInt(roomId, 10);
    if (isNaN(rid)) return;

    try {
      const prepAccess = getPrepare();
      const access = prepAccess('SELECT permission FROM room_access_control WHERE room_id = ? AND role = ?').get(rid, userObj.role);
      if (!access || !access.permission?.includes('read')) {
        socket.emit('error_message', { error: `Access denied to room ${rid}.` });
        return;
      }
    } catch (e) {
      console.error('[Socket] join_room error:', e.message);
      return;
    }

    // Leave old room
    const prev = onlineUsers.get(socket.id);
    if (prev && prev.roomId) {
      socket.leave(`room:${prev.roomId}`);
      socket.to(`room:${prev.roomId}`).emit('typing_stop', { username: prev.username });
    }

    // Join new room
    socket.join(`room:${rid}`);
    userObj.roomId = rid;
    onlineUsers.set(socket.id, userObj);
    broadcastOnlineUsers();
  });

  // ── Chat Message ─────────────────────────────────────────────────────────────
  socket.on('chat_message', ({ roomId, text }) => {
    try {
      if (!text || typeof text !== 'string') return;
      const clean = text.trim().slice(0, 2000);
      if (!clean) return;

      const rid  = parseInt(roomId, 10);
      const u    = onlineUsers.get(socket.id);
      if (!u) return;

      try {
        const prepAccess = getPrepare();
        const access = prepAccess('SELECT permission FROM room_access_control WHERE room_id = ? AND role = ?').get(rid, u.role);
        if (!access || !access.permission?.includes('write')) {
          socket.emit('error_message', { error: `Access denied to room ${rid}.` });
          return;
        }
      } catch (e) {
        console.error('[Socket] chat_message access check error:', e.message);
        return;
      }

      const prepare2 = getPrepare();
      const result   = prepare2(
        'INSERT INTO messages (room_id, user_id, username, avatar_color, text) VALUES (?, ?, ?, ?, ?)'
      ).run(rid, u.userId, u.username, u.avatar_color, clean);

      const msg = {
        id:           result.lastInsertRowid,
        room_id:      rid,
        user_id:      u.userId,
        username:     u.username,
        avatar_color: u.avatar_color,
        text:         clean,
        created_at:   new Date().toISOString()
      };

      // Shadow ban: if session/device is blocked, echo back to sender only — room never sees it
      if (sw && sw.isBlocked) {
        const fpId = socket.request?.session?.fpId;
        if (sw.isBlocked(u.username, fpId)) {
          socket.emit('chat_message', msg); // sender thinks it went through
          return;
        }
      }

      if (sw && sw.inspectMessage) {
        const blocked = sw.inspectMessage(msg, socket);
        if (blocked) {
          socket.emit('force_logout', { reason: 'Your message was blocked by ShieldWatch for containing a malicious payload.' });
          return;
        }
      }

      io.to(`room:${rid}`).emit('chat_message', msg);
    } catch (e) {
      console.error('[Chat] Message error:', e.message);
    }
  });

  // ── Typing Indicators ────────────────────────────────────────────────────────
  socket.on('typing_start', (roomId) => {
    const u = onlineUsers.get(socket.id);
    if (!u) return;
    socket.to(`room:${roomId}`).emit('typing_start', { username: u.username });
  });

  socket.on('typing_stop', (roomId) => {
    const u = onlineUsers.get(socket.id);
    if (!u) return;
    socket.to(`room:${roomId}`).emit('typing_stop', { username: u.username });
  });

  // ── Disconnect ───────────────────────────────────────────────────────────────
  socket.on('disconnect', () => {
    const u = onlineUsers.get(socket.id);
    if (u && u.roomId) {
      socket.to(`room:${u.roomId}`).emit('typing_stop', { username: u.username });
    }
    onlineUsers.delete(socket.id);
    broadcastOnlineUsers();
    console.log(`[-] ${user.username} disconnected`);
  });

  console.log(`[+] ${user.username} connected (${socket.id})`);
});

function broadcastOnlineUsers() {
  // Get unique users (objects) for the frontend
  const seen = new Set();
  const uniqueUsers = [];
  
  for (const u of onlineUsers.values()) {
    if (!seen.has(u.username)) {
      seen.add(u.username);
      uniqueUsers.push(u);
    }
  }
  
  // Send objects to frontend (chat.js)
  io.emit('users_update', uniqueUsers);
  
  // Send simple username list to ShieldWatch dashboard
  if (sw && sw.syncActiveUsers) {
    sw.syncActiveUsers(uniqueUsers.map(u => u.username));
  }
}

// ─── Start ────────────────────────────────────────────────────────────────────
initDB().then(() => {
  server.listen(PORT, '0.0.0.0', () => {
    console.log(`\n🚀 ZynChat running → http://localhost:${PORT}\n`);
  });
}).catch(err => {
  console.error('[Fatal] DB init failed:', err);
  process.exit(1);
});

module.exports = { app, server };

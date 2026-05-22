/* ─── ShieldWatch Dashboard — Real-Time Client ──────────────────────────── */

const socket = io({ path: '/sw.io' });

// ─── State ────────────────────────────────────────────────────────────────────
let allAttackers    = [];
let selectedSession = null;
let blockedIPSet    = new Set();
let blockedFPSet    = new Set();
let blockedSessionSet = new Set(); // [NEW] Surgical session blocks
let threatChart     = null;
const timelineBuckets = new Array(120).fill(0); // 120 seconds = 2 mins

// ─── DOM ──────────────────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);

// ─── Socket Events ────────────────────────────────────────────────────────────
socket.on('connect', () => {
  setStatus(true);
  console.log('[SW] Connected to collector');
});

socket.on('disconnect', () => {
  setStatus(false);
});

socket.on('connect_error', (err) => {
  if (err.message === 'Unauthorized') {
    window.location.href = 'login';
  }
});

socket.on('init', ({ events, attackers, blocked = [], blockedFPs = [], blockedSessions = [] }) => {
  allAttackers      = attackers;
  blockedIPSet      = new Set(blocked);
  blockedFPSet      = new Set(blockedFPs);
  blockedSessionSet = new Set(blockedSessions);
  events.slice().reverse().forEach(e => prependFeedItem(e, false));
  renderLeft(attackers);
  renderBlockedList();
  updateCounters(events, attackers);
  if (attackers.length > 0) selectAttacker(attackers[0]);
});

socket.on('blocked_update', list => {
  blockedIPSet = new Set(list);
  renderBlockedList();
});

socket.on('blocked_session_update', list => {
  blockedSessionSet = new Set(list);
  // Profile refresh happens on next select
});

socket.on('blocked_fp_update', (list) => {
  blockedFPSet = new Set(list);
  if (selectedSession) {
    const a = allAttackers.find(x => x.session === selectedSession);
    if (a) updateBlockBtn(a);
  }
});



socket.on('new_event', (evt) => {
  prependFeedItem(evt, true);
  fetchStats();
  // Update chart bucket
  timelineBuckets[timelineBuckets.length - 1]++;
  if (threatChart) threatChart.update('none');
});

socket.on('attackers_update', (attackers) => {
  allAttackers = attackers;
  renderLeft(attackers);
  updateCounters(null, attackers);
  // Refresh selected profile if still active
  if (selectedSession) {
    const current = attackers.find(a => a.session === selectedSession);
    if (current) renderProfile(current);
  } else if (attackers.length > 0) {
    selectAttacker(attackers[0]);
  }
});

socket.on('reset', () => {
  console.log('[Socket] 🛡️ Reset received, reloading...');
  location.reload();
});

// ─── Status ───────────────────────────────────────────────────────────────────
function setStatus(online) {
  const pill = $('statusPill');
  pill.classList.toggle('online', online);
  $('statusText').textContent = online ? 'LIVE — Connected' : 'Disconnected';
}

// ─── Fetch stats from REST ────────────────────────────────────────────────────
async function fetchStats() {
  try {
    const r = await fetch('/api/stats');
    const s = await r.json();
    animateNum('cntTotal',    s.total);
    animateNum('cntBlocked',  s.blocked);
    animateNum('cntDecoys',   s.decoys);
    animateNum('cntAttackers',s.attackers);
    animateNum('statTotal',   s.total);
    animateNum('statBlocked', s.blocked);
    animateNum('statDecoys',  s.decoys);
    animateNum('statLogged',  s.logged);
    renderAttackTypes(s.byType, s.total);
  } catch {}
}

function updateCounters(events, attackers) {
  const attackerCount = attackers.filter(a => a.threatScore > 0).length;
  animateNum('cntAttackers', attackerCount);
  fetchStats();
}

function animateNum(id, val) {
  const el = $(id);
  if (!el) return;
  const prev = parseInt(el.textContent) || 0;
  if (prev !== val) {
    el.textContent = val;
    el.classList.remove('bump');
    void el.offsetWidth;
    el.classList.add('bump');
  }
}

// ─── Render Left Panel ────────────────────────────────────────────────────────
function renderLeft(attackers) {
  // 1. Online Users: Anyone connected AND NOT BLOCKED
  const online = attackers.filter(a => {
    if (!a.isOnline) return false;
    const isBlocked = blockedIPSet.has(a.ip) || 
                      (a.fpId && blockedFPSet.has(a.fpId)) || 
                      blockedSessionSet.has(a.session);
    return !isBlocked;
  });
  
  // 2. Flagged Attackers: Anyone with a threatScore > 0
  const flagged = attackers.filter(a => (a.threatScore || 0) > 0);

  renderList('userList',     online,  'No active users');
  renderList('attackerList', flagged, 'No attackers identified');
  
  if ($('userCount'))     $('userCount').textContent     = online.length;
  if ($('attackerCount')) $('attackerCount').textContent = flagged.length;
}

function renderList(targetId, list, emptyMsg) {
  const el = $(targetId);
  if (!el) return;

  if (!list || !list.length) {
    el.innerHTML = `<div class="attack-empty">${emptyMsg}</div>`;
    return;
  }

  el.innerHTML = list.map(a => {
    if (!a || !a.session) return ''; // Skip corrupted entries
    const hasThreat  = (a.threatScore || 0) > 0;
    const isSelected = (a.session && selectedSession && a.session.trim() === selectedSession.trim());
    const chipClass  = hasThreat ? 'attacker-chip' : 'user-chip';
    const dotColor   = hasThreat ? (a.threat?.color || '#ef4444') : '#10b981';
    
    const displayName = a.session.replace(/^anon@/, 'Guest ');

    return `
      <div class="${chipClass} ${isSelected ? 'selected' : ''}" 
           style="cursor:pointer"
           data-session="${a.session}"
           onclick="selectAttackerBySession('${a.session}')">
        <div class="attacker-dot" style="background:${dotColor}"></div>
        <span class="attacker-icon">${hasThreat ? '🎯' : '👤'}</span>
        <span class="attacker-name">${displayName}</span>
        ${hasThreat ? `<span class="attacker-score">${a.threatScore}</span>` : ''}
      </div>`;
  }).join('');
}

window.selectAttackerBySession = (sessionID) => {
  if (!sessionID) return;
  const s = sessionID.trim();
  const attacker = allAttackers.find(x => x.session === s);
  if (attacker) selectAttacker(attacker);
  else {
    // Fallback: create a temporary profile for untracked sessions
    selectAttacker({ session: s, isOnline: true });
  }
};

// ─── Attack type meta (icon, display name, bar colour) ───────────────────────
const ATTACK_META = {
  sqli:           { icon: '💉', label: 'SQL Injection',    color: '#ef4444' },
  xss:            { icon: '📜', label: 'XSS',              color: '#f97316' },
  pathTraversal:  { icon: '📂', label: 'Path Traversal',   color: '#f59e0b' },
  cmdInjection:   { icon: '💻', label: 'Cmd Injection',    color: '#a855f7' },
  honeypot:       { icon: '🍯', label: 'Honeypot',         color: '#f97316' },
  ddos:           { icon: '🌊', label: 'DDoS Flood',       color: '#06b6d4' },
  csrf:           { icon: '🎭', label: 'CSRF',             color: '#ec4899' },
  bruteforce:     { icon: '🔐', label: 'Brute Force',      color: '#8b5cf6' },
  idor:           { icon: '🔓', label: 'IDOR',             color: '#10b981' },
  sessionFixation:{ icon: '🔑', label: 'Session Fixation', color: '#eab308' },
  fingerprint:    { icon: '👤', label: 'User Identified',  color: '#3b82f6' },
  bot:            { icon: '🤖', label: 'Malicious Bot',    color: '#f43f5e' },
  unknown:        { icon: '❓', label: 'Unknown',           color: '#6b7280' },
};

function attackMeta(type) {
  const t = (type || 'unknown').toLowerCase();
  return ATTACK_META[t] || { icon: '⚠️', label: t.toUpperCase(), color: '#6b7280' };
}

function renderAttackTypes(byType, total) {
  const el = $('attackTypes');
  const entries = Object.entries(byType).sort((a,b) => b[1]-a[1]);
  if (!entries.length) { el.innerHTML = '<div class="attack-empty">No attacks detected yet</div>'; return; }

  el.innerHTML = entries.map(([type, count]) => {
    const pct  = total > 0 ? Math.round((count / total) * 100) : 0;
    const meta = attackMeta(type);
    return `
      <div class="attack-type-row">
        <span class="attack-type-icon">${meta.icon}</span>
        <div style="flex:1">
          <div style="display:flex;align-items:center">
            <span class="attack-type-name">${meta.label}</span>
            <span class="attack-type-count" style="color:${meta.color}">${count}</span>
          </div>
          <div class="attack-type-bar">
            <div class="attack-type-bar-fill" style="width:${pct}%;background:${meta.color}"></div>
          </div>
        </div>
      </div>`;
  }).join('');
}


// ─── Feed ─────────────────────────────────────────────────────────────────────
function prependFeedItem(evt, animate) {
  const feedEmpty = $('feedEmpty');
  if (feedEmpty) feedEmpty.remove();

  const feed  = $('feed');
  const item  = document.createElement('div');
  item.className = `feed-item verdict-${evt.verdict || 'LOGGED'}`;
  item.style.animationDuration = animate ? '0.25s' : '0s';

  const threatType = evt.threat?.type || 'unknown';
  const payload    = evt.threat?.raw  || '';
  const time       = new Date(evt.timestamp || evt.receivedAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  const meta       = attackMeta(threatType);

  item.innerHTML = `
    <div class="feed-item-top">
      <span class="feed-verdict">${evt.verdict || 'LOGGED'}</span>
      <span class="feed-type">${meta.icon} ${meta.label}</span>
      ${evt.chainHash ? `<span class="feed-hash" title="SHA-256 Chain Hash: ${evt.chainHash}">#${evt.chainHash.slice(0,8)}</span>` : ''}
      <span class="feed-time">${time}</span>
    </div>
    <div class="feed-detail">
      <span class="feed-path">${escHtml(evt.method || 'HTTP')} ${escHtml(evt.path || '/')}</span>
      <span class="feed-sep">•</span>
      <span class="feed-session">${escHtml(evt.session || evt.ip || 'unknown')}</span>
    </div>
    ${payload ? `<div class="feed-payload">${escHtml(payload.slice(0, 120))}</div>` : ''}
  `;

  item.addEventListener('click', () => {
    const attacker = allAttackers.find(a => a.session === (evt.session || evt.ip));
    if (attacker) selectAttacker(attacker);
  });

  feed.insertBefore(item, feed.firstChild);

  // Keep feed trim
  while (feed.children.length > 100) feed.removeChild(feed.lastChild);
}

// ─── Attacker Profile ─────────────────────────────────────────────────────────
function selectAttacker(attacker) {
  if (!attacker) return;
  selectedSession = attacker.session;
  
  // Update details
  renderProfile(attacker);
  
  // Re-render lists to update highlights correctly across BOTH sections
  renderLeft(allAttackers);
}

function renderProfile(a) {
  if (!a) {
    console.warn("[Dashboard] Attempted to render null profile");
    return;
  }
  console.log("[Dashboard] Rendering profile for:", a.session);
  
  // 1. Reset Visibility
  $('profileEmpty').classList.add('hidden');
  $('profileContent').classList.remove('hidden');
  
  // 2. REFRESH Buttons for THIS specific user
  updateBlockBtn(a);

  // 3. Update Threat Score
  const score = a.threatScore || 0;
  const level = a.threat || { label: 'LOW', color: '#10b981' };
  const circumf = 264;
  const offset = circumf - (score / 100) * circumf;

  $('scoreValue').textContent = score;
  $('scoreLevel').textContent = level.label;
  $('scoreLevel').style.color = level.color;
  $('scoreCard').style.borderColor = level.color + '44';

  const ring = $('scoreRing');
  if (ring) {
    ring.style.strokeDashoffset = offset;
    ring.style.stroke = level.color;
  }

  // 4. Update Identity (Wipe old info first)
  const displayName = (a.session || '—').replace(/^anon@/, 'Guest ');
  $('pSession').textContent = displayName;
  $('pIP').textContent      = a.ip || '—';

  // Status — Device Ban, VPN, Honeypot, or Active
  const statusEl = $('pHoneypot');
  if (a.fpBlocked) {
    statusEl.innerHTML = `<span class="block-badge" style="background:#ef4444;color:#fff;padding:4px 10px;border-radius:10px;font-size:11px;font-weight:bold;letter-spacing:1px;">🚫 DEVICE PERMANENTLY BANNED</span>`;
  } else if (a.vpnDetected) {
    statusEl.innerHTML = `<span class="vpn-badge">🔄 VPN ROTATION DETECTED</span>`;
  } else if (a.inHoneypot) {
    statusEl.innerHTML = `<span class="hp-badge">🍯 IN HONEYPOT</span>`;
  } else {
    statusEl.innerHTML = a.isOnline 
      ? `<span class="active-badge" style="color:#10b981;font-weight:bold;">🟢 ONLINE / ACTIVE</span>` 
      : `<span style="color:var(--text-muted)">⚪ OFFLINE</span>`;
  }

  // VPN history
  const vpnHistEl = $('pVPNHistory');
  if (vpnHistEl) {
    if (a.vpnHistory && a.vpnHistory.length > 0) {
      vpnHistEl.textContent = a.vpnHistory.join(' → ');
      vpnHistEl.closest('.profile-row').style.display = 'flex';
    } else {
      vpnHistEl.closest('.profile-row').style.display = 'none';
    }
  }

  // Device ID (hardware fingerprint hash + human-readable raw if available)
  const fpEl = $('pFPID');
  if (fpEl) {
    if (a.fpId) {
      const raw = a.fingerprint?.deviceRaw || '';
      // Show hash + first meaningful hw segment (platform|cores|ram)
      const hint = raw ? ' · ' + raw.split('|').slice(0,3).join(' ') : '';
      fpEl.textContent = a.fpId + hint;
    } else {
      fpEl.textContent = '—';
    }
  }

  // HTTP Fingerprint (SFP)
  const sfpEl = $('pSFP');
  if (sfpEl) {
    sfpEl.textContent = a.sfpId || '—';
  }

  // ── Geo (Smart fallback for mobile) ──
  const geo = a.geo || {};
  $('pCountry').textContent = geo.country_name ? `${getFlagEmoji(geo.country_code)} ${geo.country_name}` : '🌐 Unknown Location';
  $('pCity').textContent    = [geo.city, geo.region].filter(Boolean).join(', ') || '—';
  $('pOrg').textContent     = geo.org || geo.asn_organization || 'Mobile/Private Network';
  $('pTZ').textContent      = geo.timezone || '—';

  // ── Device (UA parsed) ──
  const ua  = a.ua || {};
  const fp  = a.fingerprint || {};

  $('pBrowser').textContent = fp.browser || ua.browser || '—';
  $('pOS').textContent      = fp.os      || ua.os      || '—';
  $('pScreen').textContent  = fp.screen  || '—';
  $('pLang').textContent    = fp.language || '—';
  $('pFPTZ').textContent    = fp.timezone || geo.timezone || '—';
  $('pCores').textContent   = fp.cores != null ? `${fp.cores} cores` : '—';
  $('pGPU').textContent     = fp.gpu     || '—';
  $('pTouch').textContent   = fp.touch != null ? (fp.touch ? 'Yes' : 'No') : '—';
  $('pWebRTC').textContent  = fp.webrtcIPs || '—';
  $('pAudio').textContent   = fp.audioInfo || '—';
  $('pWebGLPrec').textContent = fp.webglPrecision || '—';
  $('pCPUSpeed').textContent = fp.cpuSpeedBucket != null ? `${fp.cpuSpeedBucket} ms (lower is faster)` : '—';

  // ── Attack Summary ──
  const summary  = $('attackSummary');
  const counts   = a.attackCounts || {};
  const entries  = Object.entries(counts);

  if (!entries.length) {
    summary.innerHTML = '<span style="color:var(--text-muted);font-size:12px">No attacks yet</span>';
  } else {
    summary.innerHTML = entries.map(([type, count]) => {
      const meta = attackMeta(type);
      return `<span class="atk-tag" style="background:${meta.color}18;color:${meta.color};border-color:${meta.color}33">
        ${meta.icon} ${meta.label} ×${count}
      </span>`;
    }).join('');
  }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────
function escHtml(s) {
  if (!s) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function getFlagEmoji(code) {
  if (!code || code.length !== 2) return '🌐';
  return String.fromCodePoint(...[...code.toUpperCase()].map(c => 0x1F1E6 + c.charCodeAt(0) - 65));
}

// ─── IP Blocking ──────────────────────────────────────────────────────────────
// ─── Block Actions ───────────────────────────────────────────────────────────
// ─── Block Actions (Hardened) ────────────────────────────────────────────────
async function blockCurrentSession() {
  const a = allAttackers.find(x => x.session === selectedSession);
  if (!a) return;
  const btn = $('blockSessionBtn');
  if (btn) btn.innerHTML = '✂️ Kicking...';
  try {
    const res = await fetch('/api/block-session', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ 
        session: a.session,
        sid: a.sid || null // Send the raw cookie ID for surgical block
      })
    });
    const data = await res.json();
    if (data.ok) {
      blockedSessionSet.add(a.session);
      updateBlockBtn(a);
      fetchStats();
      showToast(`✂️ Session ${a.session.slice(0,8)}... kicked!`, 'orange');
    }
  } catch (e) { console.error(e); }
  finally { if (btn) btn.innerHTML = '✂️ Block Session (Surgical)'; }
}

async function unblockCurrentSession() {
  const a = allAttackers.find(x => x.session === selectedSession);
  if (!a) return;
  try {
    const res = await fetch('/api/unblock-session', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ session: a.session })
    });
    const data = await res.json();
    if (data.ok) {
      blockedSessionSet.delete(a.session);
      updateBlockBtn(a);
      fetchStats();
      showToast(`✅ Session restored`, 'green');
    }
  } catch (e) { console.error(e); }
}

async function blockCurrentIP() {
  const a = allAttackers.find(x => x.session === selectedSession);
  if (!a || !a.ip) {
    showToast("⚠️ IP address missing", "orange");
    return;
  }
  const btn = $('blockIPBtn');
  if (btn) btn.innerHTML = '⚡ Blocking...';
  try {
    const res = await fetch('/api/block', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip: a.ip })
    });
    const data = await res.json();
    if (data.ok) {
      const cleanIP = (data.blocked || a.ip).replace(/^::ffff:/, '').split(':')[0].trim();
      blockedIPSet.add(cleanIP);
      updateBlockBtn(a);
      fetchStats();
      showToast(`🚫 IP ${cleanIP} blocked!`, 'red');
    }
  } catch (e) { console.error(e); }
  finally { if (btn) btn.innerHTML = '🚫 Block IP'; }
}

async function unblockCurrentIP() {
  const a = allAttackers.find(x => x.session === selectedSession);
  if (!a || !a.ip) return;
  try {
    const res = await fetch('/api/unblock', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip: a.ip })
    });
    const data = await res.json();
    if (data.ok) {
      const cleanIP = (data.unblocked || a.ip).replace(/^::ffff:/, '').split(':')[0].trim();
      blockedIPSet.delete(cleanIP);
      updateBlockBtn(a);
      fetchStats();
      showToast(`✅ IP ${cleanIP} unblocked`, 'green');
    }
  } catch (e) { console.error(e); }
}


async function blockCurrentFP() {
  const a = allAttackers.find(x => x.session === selectedSession);
  if (!a || !a.fpId) {
    showToast("⚠️ Device ID missing (waiting for scan)", "orange");
    return;
  }

  try {
    const res = await fetch('/api/block-fp', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ fpId: a.fpId })
    });
    const data = await res.json();
    if (data.ok) {
      blockedFPSet.add(a.fpId);
      updateBlockBtn(a);
      fetchStats();
      showToast(`🔒 Device Fingerprint blocked!`, 'red');
    }
  } catch (e) { console.error(e); }
}

async function unblockCurrentFP() {
  const a = allAttackers.find(x => x.session === selectedSession);
  if (!a || !a.fpId) return;

  try {
    const res = await fetch('/api/unblock-fp', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ fpId: a.fpId })
    });
    const data = await res.json();
    if (data.ok) {
      blockedFPSet.delete(a.fpId);
      updateBlockBtn(a);
      fetchStats();
      showToast(`✅ Device Fingerprint unblocked`, 'green');
    }
  } catch (e) { console.error(e); }
}





function updateBlockBtn(a) {
  const bIP = $('blockIPBtn');
  const uIP = $('unblockIPBtn');
  const bS = $('blockSessionBtn');
  const uS = $('unblockSessionBtn');
  const bF = $('blockFPBtn');
  const uF = $('unblockFPBtn');
  const cleanIP = a.ip ? a.ip.replace(/^::ffff:/, '').split(':')[0].trim() : '';
  const ipB = cleanIP && blockedIPSet.has(cleanIP);
  const sB = blockedSessionSet.has(a.session);
  const fB = a.fpId && blockedFPSet.has(a.fpId);

  if (bIP) { bIP.style.display = ipB ? 'none' : 'block'; uIP.style.display = ipB ? 'block' : 'none'; }
  if (bS) { bS.style.display = sB ? 'none' : 'block'; uS.style.display = sB ? 'block' : 'none'; }
  if (bF) { bF.style.display = fB ? 'none' : 'block'; uF.style.display = fB ? 'block' : 'none'; }
}


function renderBlockedList() {
  const el    = $('blockedList');
  const count = $('blockedCount');
  
  // Aggregate all blocks for the counter
  const totalCount = blockedIPSet.size + blockedFPSet.size + blockedSessionSet.size;
  if (count) count.textContent = totalCount;

  if (totalCount === 0) {
    el.innerHTML = '<div class="attack-empty">No active blocks</div>';
    return;
  }

  let html = '';

  // 1. IPs (Legacy/Shield)
  blockedIPSet.forEach(ip => {
    html += `
      <div class="blocked-ip-row">
        <span class="blocked-ip-addr"><span class="badge badge-yellow">IP</span> 🚫 ${escHtml(ip)}</span>
        <button class="unblock-btn" onclick="unblockIP('${escHtml(ip)}')">Unblock</button>
      </div>`;
  });

  // 2. Fingerprints (Device)
  blockedFPSet.forEach(fp => {
    html += `
      <div class="blocked-ip-row">
        <span class="blocked-ip-addr"><span class="badge badge-purple">DEV</span> 🚫 ${escHtml(fp.slice(0,12))}…</span>
        <button class="unblock-btn" onclick="unblockFingerprint('${escHtml(fp)}')">Unblock</button>
      </div>`;
  });

  // 3. Sessions (Surgical)
  blockedSessionSet.forEach(sid => {
    html += `
      <div class="blocked-ip-row">
        <span class="blocked-ip-addr"><span class="badge badge-red">SESS</span> 🚫 ${escHtml(sid)}</span>
        <button class="unblock-btn" onclick="unblockSession('${escHtml(sid)}')">Unblock</button>
      </div>`;
  });



  el.innerHTML = html;
}

// Helper to find attacker by session/fp/sfp for UI convenience
function findAttackerBySession(sid) { return allAttackers.find(a => a.session === sid); }
function findAttackerByFP(fp) { return allAttackers.find(a => a.fpId === fp); }


async function unblockFingerprint(fpId) {
  try {
    const res = await fetch('/api/unblock-fp', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ fpId })
    });
    const data = await res.json();
    if (data.ok) {
      blockedFPSet.delete(fpId);
      const a = findAttackerByFP(fpId);
      if (a) updateBlockBtn(a);
      renderBlockedList();
      fetchStats();
      showToast(`✅ Device Fingerprint unblocked`, 'green');
    }
  } catch (e) { console.error(e); }
}

async function unblockSession(session) {
  try {
    const res = await fetch('/api/unblock-session', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ session })
    });
    const data = await res.json();
    if (data.ok) {
      blockedSessionSet.delete(session);
      const a = findAttackerBySession(session);
      if (a) updateBlockBtn(a);
      renderBlockedList();
      fetchStats();
      showToast(`✅ Session unblocked`, 'green');
    }
  } catch (e) { console.error(e); }
}

async function unblockIP(ip) {
  try {
    const res = await fetch('/api/unblock', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip }),
    });
    const data = await res.json();
    if (data.ok) {
      blockedIPSet.delete(ip);
      renderBlockedList();
      showToast(`✅ ${ip} unblocked`, 'green');
    }
  } catch (e) { console.error(e); }
}

// ─── Toast notification ───────────────────────────────────────────────────────
function showToast(msg, color = 'red') {
  const t = document.createElement('div');
  t.className = 'sw-toast';
  const colorMap = { green: '#10b981', orange: '#f97316', red: '#ef4444' };
  const hex = colorMap[color] || '#ef4444';
  t.style.borderColor = hex;
  t.style.color       = hex;
  t.textContent = msg;
  document.body.appendChild(t);
  setTimeout(() => t.classList.add('show'), 10);
  setTimeout(() => { t.classList.remove('show'); setTimeout(() => t.remove(), 300); }, 2500);
}

// ─── Reset button ─────────────────────────────────────────────────────────────
$('resetBtn').addEventListener('click', async () => {
  if (!confirm('🚨 CRITICAL: Wipe all ShieldWatch threat data?')) return;
  try {
    const res = await fetch('/api/reset', { method: 'POST' });
    if (res.ok) {
      showToast('🛡️ All data cleared!', 'green');
      setTimeout(() => location.reload(), 800);
    } else {
      const err = await res.json();
      showToast('❌ Reset failed: ' + (err.error || 'Unauthorized'), 'red');
    }
  } catch (e) {
    showToast('❌ Network error during reset', 'red');
  }
});

// ─── Logout handler ───
const logoutBtn = $('logoutBtn');
if (logoutBtn) {
  logoutBtn.onclick = async () => {
    try {
      logoutBtn.disabled = true;
      logoutBtn.textContent = 'Logging out...';
      const res = await fetch('/api/auth/logout', { method: 'POST' });
      if (res.ok) {
        window.location.href = '/login';
      } else {
        showToast('❌ Logout failed — try refreshing', 'red');
        logoutBtn.disabled = false;
        logoutBtn.textContent = 'Logout';
      }
    } catch (e) {
      console.error('Logout error:', e);
      window.location.href = '/login'; // Force redirect anyway
    }
  };
}

// ─── Theme Toggle ─────────────────────────────────────────────────────────────
const themeToggle = $('themeToggle');
if (themeToggle) {
  // Load saved theme
  const savedTheme = localStorage.getItem('sw-theme') || 'dark';
  if (savedTheme === 'light') {
    document.body.classList.add('light-theme');
  }

  themeToggle.addEventListener('click', () => {
    const isLight = document.body.classList.toggle('light-theme');
    localStorage.setItem('sw-theme', isLight ? 'light' : 'dark');
    
    // Add a little rotation effect to the button
    themeToggle.style.transform = 'rotate(360deg)';
    setTimeout(() => { themeToggle.style.transform = ''; }, 500);
  });
}

// ─── Boot ─────────────────────────────────────────────────────────────────────
fetchStats();
// ─── Timeline Chart ──────────────────────────────────────────────────────────
function initTimeline() {
  const ctx = $('threatTimeline').getContext('2d');
  threatChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels: new Array(120).fill(''),
      datasets: [{
        label: 'Threats/sec',
        data: timelineBuckets,
        borderColor: '#ef4444',
        backgroundColor: 'rgba(239, 68, 68, 0.1)',
        borderWidth: 2,
        fill: true,
        tension: 0.4,
        pointRadius: 0
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { display: false },
        y: { 
          beginAtZero: true, 
          ticks: { stepSize: 1, color: '#6b7280' },
          grid: { color: 'rgba(255,255,255,0.05)' }
        }
      }
    }
  });

  // Shift buckets every second
  setInterval(() => {
    timelineBuckets.shift();
    timelineBuckets.push(0);
    if (threatChart) threatChart.update('none');
  }, 1000);
}

// ─── Boot ─────────────────────────────────────────────────────────────────────
initTimeline();

// Final Hard-Binding for Block/Unblock buttons
function bindButtons() {
  const bS = $('blockSessionBtn');
  const uS = $('unblockSessionBtn');
  const bF = $('blockFPBtn');
  const uF = $('unblockFPBtn');
  const bIP = $('blockIPBtn');
  const uIP = $('unblockIPBtn');
  if (bS) bS.onclick = blockCurrentSession;
  if (uS) uS.onclick = unblockCurrentSession;
  if (bF) bF.onclick = blockCurrentFP;
  if (uF) uF.onclick = unblockCurrentFP;
  if (bIP) bIP.onclick = blockCurrentIP;
  if (uIP) uIP.onclick = unblockCurrentIP;

  // Report Feature Bindings
  const rep = $('reportBtn');
  if (rep) rep.onclick = openReportModal;
  const cRep = $('closeReportBtn');
  if (cRep) cRep.onclick = closeReportModal;
  const dRep = $('downloadReportBtn');
  if (dRep) dRep.onclick = downloadReportMarkdown;
  const pRep = $('printReportBtn');
  if (pRep) pRep.onclick = () => window.print();

  const modal = $('reportModal');
  if (modal) {
    modal.onclick = (e) => {
      if (e.target === modal) closeReportModal();
    };
  }
}

// ─── Report Logic ────────────────────────────────────────────────────────────
let currentReportData = null;

async function openReportModal() {
  const modal = $('reportModal');
  const body = $('reportModalBody');
  if (!modal || !body) return;
  
  modal.classList.remove('hidden');
  body.innerHTML = `
    <div class="modal-loading-wrapper">
      <div class="spinner-loader"></div>
      <span>Querying Security Telemetry Node...</span>
    </div>
  `;
  
  try {
    const res = await fetch('/api/report');
    if (!res.ok) throw new Error('Failed to query node');
    const data = await res.json();
    currentReportData = data;
    
    // Render report HTML
    body.innerHTML = renderReportHTML(data);
  } catch (err) {
    console.error(err);
    body.innerHTML = `
      <div style="display:flex; flex-direction:column; justify-content:center; align-items:center; height:100%; color:var(--red); gap:12px;">
        <span style="font-size:32px;">⚠️</span>
        <span style="font-weight:bold;">Failed to generate report</span>
        <span style="font-size:11px; color:var(--text-muted);">${err.message}</span>
      </div>
    `;
    showToast('❌ Report generation failed', 'red');
  }
}

function closeReportModal() {
  const modal = $('reportModal');
  if (modal) modal.classList.add('hidden');
}

function renderReportHTML(r) {
  const hc = r.hashChain;
  const hcBadge = hc.valid 
    ? `<div class="status-success-badge" title="Cryptographically verified SHA-256 chain log state.">✅ Log Integrity Secured (${hc.length} events verified)</div>`
    : `<div class="status-fail-badge" title="${escHtml(hc.reason)}">🚨 Log Tampering Detected: ${escHtml(hc.reason)}</div>`;
    
  let html = `
    <!-- ── 1. CRYPTO AUDIT ── -->
    <div class="report-section">
      <div class="report-section-title">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:13px;height:13px;"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
        Cryptographic Integrity Audit
      </div>
      <div style="display:flex; align-items:center; justify-content:space-between; background:var(--surface2); border:1px solid var(--border); padding:12px 16px; border-radius:var(--radius-sm);">
        <div>
          <div style="font-weight:bold; color:var(--text); margin-bottom:4px;">SHA-256 Telemetry Chain Verification</div>
          <div style="font-size:11px; color:var(--text-muted);">${escHtml(hc.reason)}</div>
        </div>
        ${hcBadge}
      </div>
    </div>
    
    <!-- ── 2. METRICS OVERVIEW ── -->
    <div class="report-section">
      <div class="report-section-title">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:13px;height:13px;"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"/><line x1="9" y1="3" x2="9" y2="21"/><line x1="15" y1="3" x2="15" y2="21"/><line x1="3" y1="9" x2="21" y2="9"/><line x1="3" y1="15" x2="21" y2="15"/></svg>
        Summary Metrics
      </div>
      <div class="report-grid">
        <div class="report-card">
          <div class="report-card-val">${r.stats.total}</div>
          <div class="report-card-lbl">Threat Events</div>
        </div>
        <div class="report-card" style="border-color:rgba(239,68,68,0.2);">
          <div class="report-card-val" style="color:var(--red);">${r.stats.blocked}</div>
          <div class="report-card-lbl">Blocked</div>
        </div>
        <div class="report-card" style="border-color:rgba(249,115,22,0.2);">
          <div class="report-card-val" style="color:var(--orange);">${r.stats.decoys}</div>
          <div class="report-card-lbl">Decoy Traps</div>
        </div>
        <div class="report-card" style="border-color:rgba(168,85,247,0.2);">
          <div class="report-card-val" style="color:var(--purple);">${r.stats.attackersCount}</div>
          <div class="report-card-lbl">Attackers</div>
        </div>
        <div class="report-card" style="border-color:rgba(16,185,129,0.2);">
          <div class="report-card-val" style="color:var(--green);">${r.stats.activeUsersCount}</div>
          <div class="report-card-lbl">Active Users</div>
        </div>
      </div>
    </div>
    
    <!-- ── 3. THREAT DISTRIBUTION ── -->
    <div class="report-section">
      <div class="report-section-title">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:13px;height:13px;"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/></svg>
        Attack Distribution
      </div>
      <table class="report-table">
        <thead>
          <tr>
            <th>Attack Category</th>
            <th>Type Code</th>
            <th>Occurrences</th>
            <th>Proportion</th>
          </tr>
        </thead>
        <tbody>
  `;
  
  const types = Object.entries(r.byType).sort((a,b) => b[1] - a[1]);
  if (types.length === 0) {
    html += `<tr><td colspan="4" style="text-align:center; color:var(--text-muted); font-style:italic;">No security events logged yet</td></tr>`;
  } else {
    types.forEach(([type, count]) => {
      const meta = attackMeta(type);
      const pct = r.stats.total > 0 ? Math.round((count / r.stats.total) * 100) : 0;
      html += `
        <tr>
          <td><span style="font-size:14px; margin-right:6px;">${meta.icon}</span><strong>${meta.label}</strong></td>
          <td><code class="mono" style="background:var(--surface3); padding:2px 6px; border-radius:4px; font-size:11px;">${type}</code></td>
          <td style="font-weight:bold; color:${meta.color};">${count}</td>
          <td>
            <div style="display:flex; align-items:center; gap:8px;">
              <span style="min-width:30px; font-weight:bold; font-size:11px;">${pct}%</span>
              <div style="flex:1; height:4px; background:var(--surface3); border-radius:2px; overflow:hidden;">
                <div style="width:${pct}%; height:100%; background:${meta.color};"></div>
              </div>
            </div>
          </td>
        </tr>
      `;
    });
  }
  
  html += `
        </tbody>
      </table>
    </div>
    
    <!-- ── 4. BLOCKLISTS ── -->
    <div class="report-section">
      <div class="report-section-title">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:13px;height:13px;"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>
        Active Enforcement Blocklists
      </div>
      <div style="display:grid; grid-template-columns:1fr 1fr 1fr; gap:12px;">
        <div style="background:var(--surface2); border:1px solid var(--border); border-radius:var(--radius-sm); padding:12px;">
          <div style="font-weight:bold; color:var(--text); font-size:11px; margin-bottom:8px; display:flex; align-items:center; justify-content:space-between;">
            <span>🚫 Blocked IPs</span>
            <span style="background:rgba(239,68,68,0.15); color:var(--red); padding:1px 6px; border-radius:10px; font-size:10px;">${r.enforcement.blockedIPs.length}</span>
          </div>
          <div style="max-height:100px; overflow-y:auto; font-family:monospace; font-size:11px; color:var(--text-sec); display:flex; flex-direction:column; gap:4px;">
            ${r.enforcement.blockedIPs.map(ip => `<div>${escHtml(ip)}</div>`).join('') || '<div style="color:var(--text-muted); font-style:italic;">None</div>'}
          </div>
        </div>
        
        <div style="background:var(--surface2); border:1px solid var(--border); border-radius:var(--radius-sm); padding:12px;">
          <div style="font-weight:bold; color:var(--text); font-size:11px; margin-bottom:8px; display:flex; align-items:center; justify-content:space-between;">
            <span>🔒 Banned Devices</span>
            <span style="background:rgba(168,85,247,0.15); color:var(--purple); padding:1px 6px; border-radius:10px; font-size:10px;">${r.enforcement.blockedFingerprints.length}</span>
          </div>
          <div style="max-height:100px; overflow-y:auto; font-family:monospace; font-size:11px; color:var(--text-sec); display:flex; flex-direction:column; gap:4px;">
            ${r.enforcement.blockedFingerprints.map(fp => `<div>${escHtml(fp.slice(0,12))}…</div>`).join('') || '<div style="color:var(--text-muted); font-style:italic;">None</div>'}
          </div>
        </div>
        
        <div style="background:var(--surface2); border:1px solid var(--border); border-radius:var(--radius-sm); padding:12px;">
          <div style="font-weight:bold; color:var(--text); font-size:11px; margin-bottom:8px; display:flex; align-items:center; justify-content:space-between;">
            <span>✂️ Kicked Sessions</span>
            <span style="background:rgba(234,179,8,0.15); color:var(--yellow); padding:1px 6px; border-radius:10px; font-size:10px;">${r.enforcement.blockedSessions.length}</span>
          </div>
          <div style="max-height:100px; overflow-y:auto; font-family:monospace; font-size:11px; color:var(--text-sec); display:flex; flex-direction:column; gap:4px;">
            ${r.enforcement.blockedSessions.map(sid => `<div>${escHtml(sid.slice(0,12))}…</div>`).join('') || '<div style="color:var(--text-muted); font-style:italic;">None</div>'}
          </div>
        </div>
      </div>
    </div>
    
    <!-- ── 5. HIGHEST THREAT ATTACKERS ── -->
    <div class="report-section" style="margin-bottom:0;">
      <div class="report-section-title">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:13px;height:13px;"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>
        High-Threat Profile Directory
      </div>
      <table class="report-table">
        <thead>
          <tr>
            <th>Session Name</th>
            <th>IP Address</th>
            <th>Threat Score</th>
            <th>Level</th>
            <th>Location</th>
            <th>VPN Status</th>
            <th>Device Ban</th>
          </tr>
        </thead>
        <tbody>
  `;
  
  if (r.topAttackers.length === 0) {
    html += `<tr><td colspan="7" style="text-align:center; color:var(--text-muted); font-style:italic;">No high-threat attacker profiles identified</td></tr>`;
  } else {
    r.topAttackers.forEach(a => {
      const displayName = a.session.replace(/^anon@/, 'Guest ');
      const geoStr = a.geo.country_name ? `${getFlagEmoji(a.geo.country_code)} ${a.geo.country_name}` : 'Unknown';
      const threatColor = a.threatScore >= 80 ? 'var(--red)' : (a.threatScore >= 50 ? 'var(--orange)' : 'var(--yellow)');
      html += `
        <tr>
          <td class="mono" style="font-weight:bold; color:var(--text-sec);">${escHtml(displayName)}</td>
          <td class="mono">${escHtml(a.ip)}</td>
          <td style="font-weight:bold; color:${threatColor};">${a.threatScore}</td>
          <td><span style="font-weight:bold; color:${threatColor}; font-size:10px;">${a.threatLevel}</span></td>
          <td>${geoStr}</td>
          <td>${a.vpnDetected ? '<span style="color:var(--orange); font-weight:bold;">ROTATION</span>' : '<span style="color:var(--text-muted);">None</span>'}</td>
          <td>${a.fpBlocked ? '<span style="color:var(--red); font-weight:bold;">BANNED</span>' : '<span style="color:var(--text-muted);">Active</span>'}</td>
        </tr>
      `;
    });
  }
  
  html += `
        </tbody>
      </table>
    </div>
  `;
  
  return html;
}

function downloadReportMarkdown() {
  if (!currentReportData) return;
  const r = currentReportData;
  const ts = new Date(r.timestamp).toLocaleString();
  
  let md = `# ShieldWatch UADR — Security Telemetry Report\n`;
  md += `*Generated at: ${ts}*\n\n`;
  
  md += `## 1. Cryptographic Log Integrity Audit\n`;
  md += `* **Status**: ${r.hashChain.valid ? '✅ SECURE / VERIFIED' : '🚨 COMPROMISED / CHAIN BROKEN'}\n`;
  md += `* **Verified Event Log Length**: ${r.hashChain.length} entries\n`;
  md += `* **Audit Log Details**: ${r.hashChain.reason}\n\n`;
  
  md += `## 2. Statistical Summary\n`;
  md += `* **Total Threat Events**: ${r.stats.total}\n`;
  md += `* **Enforced Blocks**: ${r.stats.blocked}\n`;
  md += `* **Decoy Traps Triggered**: ${r.stats.decoys}\n`;
  md += `* **Flagged Attackers**: ${r.stats.attackersCount}\n`;
  md += `* **Active Legitimate Sessions**: ${r.stats.activeUsersCount}\n\n`;
  
  md += `## 3. Threat Distribution\n`;
  const types = Object.entries(r.byType);
  if (types.length === 0) {
    md += `*No threats recorded.*\n\n`;
  } else {
    md += `| Attack Type | Frequency | Percentage |\n`;
    md += `| :--- | :---: | :---: |\n`;
    types.forEach(([type, count]) => {
      const pct = r.stats.total > 0 ? Math.round((count / r.stats.total) * 100) : 0;
      const meta = attackMeta(type);
      md += `| ${meta.icon} ${meta.label} | ${count} | ${pct}% |\n`;
    });
    md += `\n`;
  }
  
  md += `## 4. Enforcement Blocklists\n`;
  md += `* **Blocked IP Addresses (${r.enforcement.blockedIPs.length})**: ${r.enforcement.blockedIPs.join(', ') || 'None'}\n`;
  md += `* **Banned Device Fingerprints (${r.enforcement.blockedFingerprints.length})**: ${r.enforcement.blockedFingerprints.map(x => x.slice(0, 12) + '...').join(', ') || 'None'}\n`;
  md += `* **Kicked Sessions (${r.enforcement.blockedSessions.length})**: ${r.enforcement.blockedSessions.join(', ') || 'None'}\n\n`;
  
  md += `## 5. High-Threat Attacker Profiles\n`;
  if (r.topAttackers.length === 0) {
    md += `*No high-threat attacker profiles recorded.*\n\n`;
  } else {
    md += `| Session ID | IP Address | Threat Score | Level | Geolocation | VPN Active? | Device Banned? |\n`;
    md += `| :--- | :--- | :---: | :--- | :--- | :---: | :---: |\n`;
    r.topAttackers.forEach(a => {
      const geoStr = a.geo.country_name ? `${a.geo.country_name} (${a.geo.city || '?'})` : 'Unknown';
      md += `| ${a.session} | ${a.ip} | ${a.threatScore} | ${a.threatLevel} | ${geoStr} | ${a.vpnDetected ? 'Yes' : 'No'} | ${a.fpBlocked ? 'Yes' : 'No'} |\n`;
    });
    md += `\n`;
  }
  
  md += `\n---\n*Report compiled by ShieldWatch Runtime Application Self-Protection Node.*\n`;
  
  // Download file trigger
  const blob = new Blob([md], { type: 'text/markdown;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.setAttribute('href', url);
  link.setAttribute('download', `shieldwatch-security-report-${Date.now()}.md`);
  link.style.visibility = 'hidden';
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
}

// Bind now and on load
bindButtons();
document.addEventListener('DOMContentLoaded', bindButtons);

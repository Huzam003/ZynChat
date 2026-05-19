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
  $('pCPUSpeed').textContent = fp.cpuSpeedBucket != null ? `${fp.cpuSpeedBucket} bucket` : '—';

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
  if (bS) bS.onclick = blockCurrentSession;
  if (uS) uS.onclick = unblockCurrentSession;
  if (bF) bF.onclick = blockCurrentFP;
  if (uF) uF.onclick = unblockCurrentFP;
}

// Bind now and on load
bindButtons();
document.addEventListener('DOMContentLoaded', bindButtons);

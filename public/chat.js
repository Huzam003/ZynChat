// ─── Theme Management ────────────────────────────────────────────────────────
const themeToggle = document.getElementById('themeToggle');
const body = document.body;

function setTheme(theme) {
  if (theme === 'light') {
    body.classList.add('light-theme');
    localStorage.setItem('zynchat-theme', 'light');
  } else {
    body.classList.remove('light-theme');
    localStorage.setItem('zynchat-theme', 'dark');
  }
}

// Init theme
const savedTheme = localStorage.getItem('zynchat-theme') || 'dark';
setTheme(savedTheme);

if (themeToggle) {
  themeToggle.addEventListener('click', () => {
    setTheme(body.classList.contains('light-theme') ? 'dark' : 'light');
  });
}


// ─── State ────────────────────────────────────────────────────────────────────
let currentUser  = null;
let currentRoom  = null;
let rooms        = [];
let onlineUsers  = [];
const typingUsers = new Set();
let typingTimer   = null;
let isTyping      = false;

// ─── DOM Refs ─────────────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);

const msgsList        = $('messagesList');
const msgInput        = $('msgInput');
const sendBtn         = $('sendBtn');
const roomListEl      = $('roomList');
const onlineListEl    = $('onlineList');
const onlineCount     = $('onlineCount');
const channelName     = $('channelName');
const channelDesc     = $('channelDesc');
const channelIcon     = $('channelIcon');
const welcomeRoom     = $('welcomeRoom');
const memberCount     = $('memberCount');
const typingBar       = $('typingBar');
const typingText      = $('typingText');
const myAvatar        = $('myAvatar');
const myUsername      = $('myUsername');
const myRole          = $('myRole');
// ─── Socket.io ────────────────────────────────────────────────────────────────
const socket = io({ transports: ['websocket', 'polling'] });

socket.on('connect', () => {
  console.log('[Socket] Connected', socket.id);
  if (currentRoom) socket.emit('join_room', currentRoom.id);
});

socket.on('disconnect', () => {
  console.log('[Socket] Disconnected');
});

// [FIX] ShieldWatch: kick blocked users back to login instantly
socket.on('force_logout', (data) => {
  const reason = (data && data.reason) || 'Your session has been terminated by an administrator.';
  console.warn('[ShieldWatch] Force logout:', reason);
  alert(reason);
  window.location.href = '/';
});
socket.on('chat_message', (msg) => {
  appendMessage(msg);
  scrollToBottom();
});

socket.on('users_update', (users) => {
  onlineUsers = users;
  renderOnlineUsers();
  renderMemberCount();
});

// ─── Typing Indicators ────────────────────────────────────────────────────────
socket.on('typing_start', ({ username }) => {
  typingUsers.add(username);
  renderTyping();
});

socket.on('typing_stop', ({ username }) => {
  typingUsers.delete(username);
  renderTyping();
});

function renderTyping() {
  const names = Array.from(typingUsers).filter(u => u !== currentUser?.username);
  if (names.length === 0) {
    typingBar.classList.remove('visible');
  } else {
    const label = names.length === 1
      ? `${names[0]} is typing`
      : `${names.slice(0,-1).join(', ')} and ${names[names.length-1]} are typing`;
    typingText.textContent = label;
    typingBar.classList.add('visible');
  }
}

// ─── Bootstrap ────────────────────────────────────────────────────────────────
async function init() {
  try {
    const [meRes, roomsRes, pingRes] = await Promise.all([
      fetch('/api/me'),
      fetch('/api/rooms'),
      fetch('/ping')
    ]);

    if (meRes.status === 401) { window.location.href = '/'; return; }

    currentUser = await meRes.json();
    rooms       = await roomsRes.json();
    const sysData = await pingRes.json();

    if (!sysData.shieldwatch) {
      const swWidget = $('securityWidget');
      if (swWidget) swWidget.style.display = 'none';
    }

    // Render current user
    myUsername.textContent      = currentUser.username;
    myRole.textContent          = currentUser.role === 'admin' ? '⚑ Admin' : 'Member';
    myAvatar.textContent        = currentUser.username[0].toUpperCase();
    myAvatar.style.background   = currentUser.avatar_color || '#3b82f6';
    myAvatar.style.borderRadius = '10px';

    $('userProfile').addEventListener('click', () => showProfile(currentUser.username, currentUser.avatar_color, currentUser.role, currentUser.bio));

    renderRooms();

    // Auto-join first room
    if (rooms.length > 0) joinRoom(rooms[0]);

  } catch (e) {
    console.error('Init error', e);
    window.location.href = '/';
  }
}

// ─── Render Rooms ─────────────────────────────────────────────────────────────
function renderRooms() {
  roomListEl.innerHTML = '';
  rooms.forEach(room => {
    const li = document.createElement('li');
    li.className = 'room-item';
    li.dataset.id = room.id;
    li.innerHTML = `
      <span class="room-hash">#</span>
      <span class="room-name">${escapeHTML(room.name)}</span>
    `;
    li.addEventListener('click', () => joinRoom(room));
    roomListEl.appendChild(li);
  });
}

// ─── Join Room ────────────────────────────────────────────────────────────────
async function joinRoom(room) {
  currentRoom = room;

  // Update active state
  document.querySelectorAll('.room-item').forEach(el => {
    el.classList.toggle('active', parseInt(el.dataset.id) === room.id);
  });

  // Update header
  channelName.textContent  = room.name;
  channelDesc.textContent  = room.description || '';
  channelIcon.textContent  = room.icon || '💬';
  welcomeRoom.textContent  = room.name;
  msgInput.placeholder     = `Message #${room.name}`;
  document.title           = `#${room.name} — ZynChat`;

  // Clear messages & typing
  msgsList.innerHTML = '';
  appendWelcome(room);
  typingUsers.clear();
  renderTyping();

  // Tell server
  socket.emit('join_room', room.id);
  checkMobileClose();

  // Load history
  try {
    const res  = await fetch(`/api/messages/${room.id}`);
    const msgs = await res.json();
    msgs.forEach(m => appendMessage(m, false));
    scrollToBottom(false);
  } catch (e) {
    console.error('Failed to load messages', e);
  }

  renderMemberCount();
}

// ─── Append Welcome Banner ────────────────────────────────────────────────────
function appendWelcome(room) {
  const div = document.createElement('div');
  div.className = 'messages-welcome';
  div.innerHTML = `
    <div class="welcome-icon">${room.icon || '💬'}</div>
    <div class="welcome-title">Welcome to #${escapeHTML(room.name)}</div>
    <div class="welcome-desc">${escapeHTML(room.description || '')}</div>
  `;
  msgsList.appendChild(div);
}

// ─── Append Message ───────────────────────────────────────────────────────────
let lastMsgUser = null;

function appendMessage(msg, animate = true) {
  const isMine = (msg.username === currentUser.username);
  
  const div = document.createElement('div');
  div.className = 'message' + (isMine ? ' mine' : '');
  div.dataset.msgId = msg.id;

  const time = formatTime(msg.created_at);
  const initial = msg.username[0].toUpperCase();
  const color = msg.avatar_color || '#6366f1';

  div.innerHTML = `
    <div class="msg-avatar" style="background:${escapeHTML(color)}" data-user="${escapeHTML(msg.username)}">${escapeHTML(initial)}</div>
    <div class="msg-content">
      <div class="msg-header">
        <span class="msg-user" data-user="${escapeHTML(msg.username)}">${escapeHTML(msg.username)}</span>
        <span class="msg-time">${time}</span>
      </div>
      <div class="msg-bubble">
        <div class="msg-text">${escapeHTML(msg.text)}</div>
      </div>
    </div>
  `;

  // Avatar / username click → profile
  div.querySelectorAll('[data-user]').forEach(el => {
    el.addEventListener('click', () => showProfile(msg.username, msg.avatar_color, msg.role, msg.bio));
  });

  msgsList.appendChild(div);
  scrollToBottom(animate);
}

// ─── Render Online Users ──────────────────────────────────────────────────────
function renderOnlineUsers() {
  const unique = dedupeByUserId(onlineUsers);
  if (onlineCount) onlineCount.textContent = unique.length;

  if (onlineListEl) {
    onlineListEl.innerHTML = '';
    unique.forEach(u => {
      const li = document.createElement('li');
      const isMe = (u.username === currentUser.username);
      li.className = 'online-user' + (isMe ? ' active' : ''); 
      li.innerHTML = `
        <div class="online-avatar" style="background:${escapeHTML(u.avatar_color || '#3b82f6')}">${u.username[0].toUpperCase()}</div>
        <div class="online-info">
          <span class="online-name">${escapeHTML(u.username)}</span>
          <span class="online-status-text">${isMe ? 'You' : 'Available'}</span>
        </div>
        <div class="user-status status-online"></div>
      `;
      li.addEventListener('click', () => showProfile(u.username, u.avatar_color, u.role, u.bio));
      onlineListEl.appendChild(li);
    });
  }
}

function renderMemberCount() {
  if (!currentRoom) return;
  const inRoom = onlineUsers.filter(u => u.roomId === currentRoom.id);
  memberCount.textContent = dedupeByUserId(inRoom).length;
}

function dedupeByUserId(arr) {
  const seen = new Set();
  return arr.filter(u => {
    if (seen.has(u.userId)) return false;
    seen.add(u.userId);
    return true;
  });
}

// ─── Send Message ─────────────────────────────────────────────────────────────
function sendMessage() {
  const text = msgInput.value.trim();
  if (!text || !currentRoom) return;

  socket.emit('chat_message', { roomId: currentRoom.id, text });
  msgInput.value = '';

  // Stop typing indicator
  if (isTyping) {
    isTyping = false;
    socket.emit('typing_stop', currentRoom.id);
  }
  clearTimeout(typingTimer);
}

sendBtn.addEventListener('click', sendMessage);
msgInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && !e.shiftKey) {
    e.preventDefault();
    sendMessage();
  }
});

// ─── Typing Emit ──────────────────────────────────────────────────────────────
msgInput.addEventListener('input', () => {
  if (!currentRoom) return;

  if (!isTyping) {
    isTyping = true;
    socket.emit('typing_start', currentRoom.id);
  }

  clearTimeout(typingTimer);
  typingTimer = setTimeout(() => {
    isTyping = false;
    socket.emit('typing_stop', currentRoom.id);
  }, 1500);
});

// ─── Scroll to Bottom ─────────────────────────────────────────────────────────
function scrollToBottom(smooth = true) {
  const c = $('messagesContainer');
  if (!c) return;
  setTimeout(() => {
    if (smooth) {
      c.scrollTo({ top: c.scrollHeight, behavior: 'smooth' });
    } else {
      c.scrollTop = c.scrollHeight;
    }
  }, 100);
}

// ─── Sidebar Toggle (mobile) ──────────────────────────────────────────────────
function toggleSidebar(force) {
  const isOpen = $('sidebar').classList.toggle('open', force);
  $('sidebarBackdrop').classList.toggle('active', isOpen);
}

$('sidebarToggle').addEventListener('click', (e) => {
  e.stopPropagation();
  toggleSidebar();
});

// Click backdrop to close
$('sidebarBackdrop').addEventListener('click', () => toggleSidebar(false));

// Auto-close on mobile when room changes
function checkMobileClose() {
  if (window.innerWidth <= 900) toggleSidebar(false);
}

// ─── Logout ───────────────────────────────────────────────────────────────────
$('logoutBtn').addEventListener('click', async () => {
  await fetch('/api/logout', { method: 'POST' });
  window.location.href = '/';
});

// ─── Jump to message ──────────────────────────────────────────────────────────
function jumpToMsg(id) {
  const el = document.querySelector(`[data-msg-id="${id}"]`);
  if (el) {
    el.scrollIntoView({ behavior: 'smooth', block: 'center' });
    el.style.background = 'rgba(59,130,246,0.1)';
    setTimeout(() => el.style.background = '', 1500);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// FILE SHARING MODAL
// ─────────────────────────────────────────────────────────────────────────────
$('filesBtn').addEventListener('click', openFilesModal);
$('filesClose').addEventListener('click', closeFilesModal);
$('filesModal').addEventListener('click', (e) => { if (e.target === $('filesModal')) closeFilesModal(); });

function openFilesModal() {
  $('filesModal').classList.add('open');
  loadFiles();
}

function closeFilesModal() {
  $('filesModal').classList.remove('open');
  $('fileViewer').classList.remove('open');
}

async function loadFiles() {
  const fileList = $('fileList');
  fileList.innerHTML = '<div class="file-loading">Loading files…</div>';

  try {
    const res   = await fetch('/api/files');
    const files = await res.json();

    fileList.innerHTML = '';

    if (files.length === 0) {
      fileList.innerHTML = '<div class="file-loading">No files available.</div>';
      return;
    }

    files.forEach(name => {
      const item = document.createElement('div');
      item.className = 'file-item';
      item.innerHTML = `
        <span class="file-icon">📄</span>
        <span class="file-name">${escapeHTML(name)}</span>
        <button class="file-view-btn" data-file="${escapeHTML(name)}">View</button>
      `;
      item.querySelector('.file-view-btn').addEventListener('click', () => viewFile(name));
      fileList.appendChild(item);
    });
  } catch (e) {
    fileList.innerHTML = '<div class="file-loading">Failed to load files.</div>';
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// ⚠️  FILE VIEWER — PATH TRAVERSAL entry point
//     The `filename` is sent to /api/file?path=<filename>
//     Server does NOT sanitise the path → ../private/db_config.txt works
// ─────────────────────────────────────────────────────────────────────────────
async function viewFile(filename) {
  const viewer    = $('fileViewer');
  const nameEl    = $('viewerFileName');
  const contentEl = $('viewerContent');

  nameEl.textContent    = filename;
  contentEl.textContent = 'Loading…';
  viewer.classList.add('open');

  try {
    const res  = await fetch(`/api/file?path=${encodeURIComponent(filename)}`);
    const data = await res.json();

    if (data.ok) {
      contentEl.textContent = data.content;
    } else {
      contentEl.textContent = `Error: ${data.error}`;
    }
  } catch (e) {
    contentEl.textContent = 'Network error.';
  }
}

$('viewerClose').addEventListener('click', () => $('fileViewer').classList.remove('open'));

// ─── Profile Modal ────────────────────────────────────────────────────────────
$('profileClose').addEventListener('click', () => $('profileModal').classList.remove('open'));
$('profileModal').addEventListener('click', (e) => { if (e.target === $('profileModal')) $('profileModal').classList.remove('open'); });

function showProfile(username, avatarColor, role, bio) {
  const body = $('profileBody');
  const isMe = (username === currentUser.username);
  
  if (isMe) {
    // Render Edit Form
    const palette = ['#3b82f6','#8b5cf6','#10b981','#f59e0b','#ef4444','#ec4899','#06b6d4'];
    let colorHtml = '';
    palette.forEach(c => {
      const active = (c.toLowerCase() === (avatarColor || '#3b82f6').toLowerCase());
      colorHtml += `<div class="color-swatch${active ? ' active' : ''}" style="background:${c}" data-color="${c}"></div>`;
    });

    body.innerHTML = `
      <div class="profile-card">
        <div class="profile-big-avatar" id="editAvatarPreview" style="background:${escapeHTML(avatarColor || '#3b82f6')}">${username[0].toUpperCase()}</div>
        <div class="profile-username">${escapeHTML(username)}</div>
        <div class="profile-role">${role === 'admin' ? '⚑ Admin' : 'Member'}</div>
        
        <div class="profile-form">
          <div class="form-group">
            <label>Bio</label>
            <textarea id="editBio" class="modal-input modal-textarea" placeholder="Tell us about yourself...">${escapeHTML(bio || '')}</textarea>
          </div>
          <div class="form-group">
            <label>Avatar Color</label>
            <div class="color-picker" id="editColorPicker">
              ${colorHtml}
            </div>
          </div>
          <div class="profile-actions">
            <button class="btn btn-primary" id="saveProfileBtn">Save Changes</button>
          </div>
        </div>
      </div>
    `;

    // Interaction for color picker
    let selectedColor = avatarColor || '#3b82f6';
    body.querySelectorAll('.color-swatch').forEach(el => {
      el.addEventListener('click', () => {
        body.querySelectorAll('.color-swatch').forEach(s => s.classList.remove('active'));
        el.classList.add('active');
        selectedColor = el.dataset.color;
        $('editAvatarPreview').style.background = selectedColor;
      });
    });

    $('saveProfileBtn').addEventListener('click', () => saveProfile(selectedColor));

  } else {
    // Render Static Card
    body.innerHTML = `
      <div class="profile-card">
        <div class="profile-big-avatar" style="background:${escapeHTML(avatarColor || '#3b82f6')}">${username[0].toUpperCase()}</div>
        <div class="profile-username">${escapeHTML(username)}</div>
        <div class="profile-role">${role === 'admin' ? '⚑ Admin' : 'Member'}</div>
        ${bio ? `<div class="profile-bio">${escapeHTML(bio)}</div>` : ''}
      </div>
    `;
  }
  
  $('profileModal').classList.add('open');
}

async function saveProfile(avatarColor) {
  const bio = $('editBio').value.trim();
  const btn = $('saveProfileBtn');
  
  btn.disabled = true;
  btn.textContent = 'Saving...';

  try {
    // 1. Fetch CSRF token
    const csrfRes = await fetch('/api/csrf-token');
    const { csrfToken } = await csrfRes.json();

    // 2. Submit update with token
    const res = await fetch('/api/profile/update', {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json',
        'x-csrf-token': csrfToken
      },
      body: JSON.stringify({ bio, avatar_color: avatarColor })
    });
    
    const data = await res.json();
    if (data.ok) {
      // Update local state
      currentUser.bio = data.user.bio;
      currentUser.avatar_color = data.user.avatar_color;
      
      // Update UI elements
      myAvatar.style.background = currentUser.avatar_color;
      
      // Close modal
      $('profileModal').classList.remove('open');
      
      // Emit update via socket if needed (server usually handles broadcast on next message)
      console.log('Profile updated successfully');
    } else {
      alert('Error: ' + data.error);
    }
  } catch (e) {
    alert('Failed to save profile.');
  } finally {
    btn.disabled = false;
    btn.textContent = 'Save Changes';
  }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

// escapeHTML — prevents XSS in all message rendering
// (Note: search results INTENTIONALLY bypass this for demo purposes)
function escapeHTML(str) {
  if (str == null) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function formatTime(isoString) {
  if (!isoString) return '';
  const d = new Date(isoString);
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

// ─── Keyboard shortcuts ───────────────────────────────────────────────────────
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') {
    $('filesModal').classList.remove('open');
    $('profileModal').classList.remove('open');
  }
});

// ─── Boot ─────────────────────────────────────────────────────────────────────
init();

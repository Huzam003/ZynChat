/* ─── ZynChat Login Page Logic ────────────────────────────────────────────── */

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

// ─── 3D Tilt Effect ──────────────────────────────────────────────────────────
const authCard = document.getElementById('authCard');
const wrapper = document.querySelector('.auth-wrapper');

if (authCard && wrapper) {
  wrapper.addEventListener('mousemove', (e) => {
    const { clientX, clientY } = e;
    const { left, top, width, height } = authCard.getBoundingClientRect();
    
    const centerX = left + width / 2;
    const centerY = top + height / 2;
    
    const rotateX = (centerY - clientY) / 20;
    const rotateY = (clientX - centerX) / 20;
    
    authCard.style.transform = `rotateX(${rotateX}deg) rotateY(${rotateY}deg)`;
  });

  wrapper.addEventListener('mouseleave', () => {
    authCard.style.transform = `rotateX(0deg) rotateY(0deg)`;
  });
}


// ─── Animated canvas background ───────────────────────────────────────────────
(function initCanvas() {
  const canvas = document.getElementById('bgCanvas');
  const ctx    = canvas.getContext('2d');
  let W, H, particles;

  function resize() {
    W = canvas.width  = window.innerWidth;
    H = canvas.height = window.innerHeight;
  }

  function mkParticle() {
    return {
      x:    Math.random() * W,
      y:    Math.random() * H,
      r:    Math.random() * 1.5 + 0.4,
      vx:   (Math.random() - 0.5) * 0.3,
      vy:   (Math.random() - 0.5) * 0.3,
      alpha: Math.random() * 0.5 + 0.1,
    };
  }

  function init() {
    resize();
    particles = Array.from({ length: 90 }, mkParticle);
  }

  function draw() {
    ctx.clearRect(0, 0, W, H);

    // Draw subtle grid
    ctx.strokeStyle = 'rgba(59,130,246,0.04)';
    ctx.lineWidth   = 1;
    const step = 60;
    for (let x = 0; x < W; x += step) {
      ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, H); ctx.stroke();
    }
    for (let y = 0; y < H; y += step) {
      ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(W, y); ctx.stroke();
    }

    // Connect close particles
    for (let i = 0; i < particles.length; i++) {
      for (let j = i + 1; j < particles.length; j++) {
        const dx = particles[i].x - particles[j].x;
        const dy = particles[i].y - particles[j].y;
        const d  = Math.sqrt(dx * dx + dy * dy);
        if (d < 120) {
          ctx.strokeStyle = `rgba(59,130,246,${0.06 * (1 - d / 120)})`;
          ctx.lineWidth   = 1;
          ctx.beginPath();
          ctx.moveTo(particles[i].x, particles[i].y);
          ctx.lineTo(particles[j].x, particles[j].y);
          ctx.stroke();
        }
      }
    }

    // Draw dots
    particles.forEach(p => {
      p.x += p.vx; p.y += p.vy;
      if (p.x < 0) p.x = W;
      if (p.x > W) p.x = 0;
      if (p.y < 0) p.y = H;
      if (p.y > H) p.y = 0;

      ctx.beginPath();
      ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(59,130,246,${p.alpha})`;
      ctx.fill();
    });

    requestAnimationFrame(draw);
  }

  window.addEventListener('resize', resize);
  init();
  draw();
})();

// ─── Tab switching ─────────────────────────────────────────────────────────────
const tabs         = document.querySelectorAll('.tab');
const loginForm    = document.getElementById('loginForm');
const registerForm = document.getElementById('registerForm');
const indicator    = document.getElementById('tabIndicator');

tabs.forEach((tab, idx) => {
  tab.addEventListener('click', () => {
    tabs.forEach(t => t.classList.remove('active'));
    tab.classList.add('active');

    if (tab.dataset.tab === 'login') {
      loginForm.classList.remove('hidden');
      registerForm.classList.add('hidden');
      indicator.classList.remove('right');
    } else {
      loginForm.classList.add('hidden');
      registerForm.classList.remove('hidden');
      indicator.classList.add('right');
    }
    clearErrors();
  });
});

// ─── Password visibility toggle ────────────────────────────────────────────────
document.getElementById('toggleLoginPw').addEventListener('click', () => {
  const inp = document.getElementById('loginPassword');
  inp.type = inp.type === 'password' ? 'text' : 'password';
});

// ─── Demo accounts ─────────────────────────────────────────────────────────────
const demoToggle = document.getElementById('demoToggle');
const demoList   = document.getElementById('demoList');
const demoChevron = document.getElementById('demoChevron');

demoToggle.addEventListener('click', () => {
  const open = demoList.classList.toggle('open');
  demoToggle.classList.toggle('open', open);
});

document.querySelectorAll('.demo-item').forEach(item => {
  item.addEventListener('click', () => {
    document.getElementById('loginUsername').value = item.dataset.user;
    document.getElementById('loginPassword').value = item.dataset.pass;
    // Switch to login tab
    tabs[0].click();
    // Flash the fields
    ['loginUsername','loginPassword'].forEach(id => {
      const el = document.getElementById(id);
      el.style.borderColor = '#3b82f6';
      setTimeout(() => el.style.borderColor = '', 600);
    });
  });
});

// ─── Helpers ───────────────────────────────────────────────────────────────────
function clearErrors() {
  document.getElementById('loginError').textContent    = '';
  document.getElementById('registerError').textContent = '';
}

function setLoading(btn, loading) {
  btn.classList.toggle('loading', loading);
  btn.disabled = loading;
}

function showError(id, msg) {
  const el = document.getElementById(id);
  el.textContent = msg;
  el.style.animation = 'none';
  void el.offsetWidth;
  el.style.animation = '';
}

// ─── Login Submit ──────────────────────────────────────────────────────────────
document.getElementById('loginForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  clearErrors();

  const username = document.getElementById('loginUsername').value.trim();
  const password = document.getElementById('loginPassword').value;
  const btn      = document.getElementById('loginBtn');

  if (!username || !password) {
    showError('loginError', 'Please enter username and password.');
    return;
  }

  setLoading(btn, true);

  try {
    const res  = await fetch('/api/login', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ username, password })
    });
    const data = await res.json();

    if (data.ok) {
      // Brief success flash
      btn.style.background = '#10b981';
      btn.querySelector('.btn-text').textContent = '✓ Signed in';
      setTimeout(() => { window.location.href = '/chat'; }, 50);
    } else {
      showError('loginError', data.error || 'Login failed.');
      setLoading(btn, false);
    }
  } catch (err) {
    showError('loginError', 'Network error. Please try again.');
    setLoading(btn, false);
  }
});

// ─── Register Submit ───────────────────────────────────────────────────────────
document.getElementById('registerForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  clearErrors();

  const username = document.getElementById('regUsername').value.trim();
  const password = document.getElementById('regPassword').value;
  const btn      = document.getElementById('registerBtn');

  if (!username || !password) {
    showError('registerError', 'Please fill in all fields.');
    return;
  }

  setLoading(btn, true);

  try {
    const res  = await fetch('/api/register', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ username, password })
    });
    const data = await res.json();

    if (data.ok) {
      btn.style.background = '#10b981';
      btn.querySelector('.btn-text').textContent = '✓ Account created';
      setTimeout(() => { window.location.href = '/chat'; }, 50);
    } else {
      showError('registerError', data.error || 'Registration failed.');
      setLoading(btn, false);
    }
  } catch (err) {
    showError('registerError', 'Network error. Please try again.');
    setLoading(btn, false);
  }
});

// ─── Enter key in fields ───────────────────────────────────────────────────────
document.getElementById('loginUsername').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') document.getElementById('loginPassword').focus();
});

// ─── ShieldWatch Fingerprint Gate ─────────────────────────────────────────────
// Keeps the Sign In button disabled until sw-beacon.js has sent the browser
// fingerprint to the sensor. This prevents bots/scripts that skip JS from
// ever reaching the login endpoint without a fingerprint on the session.
(function () {
  const loginBtn  = document.getElementById('loginBtn');
  const scanBar   = document.getElementById('swScanBar');
  const scanText  = document.getElementById('swScanText');

  // Expose ready flag so the submit handler can guard Enter-key submits too
  window._swFpReady = false;

  function unlock() {
    if (window._swFpReady) return; // already unlocked
    window._swFpReady = true;

    loginBtn.disabled = false;
    loginBtn.classList.remove('sw-locked');

    if (scanBar) {
      scanBar.classList.add('sw-scan-done');
      if (scanText) scanText.textContent = '✓ Verified — you may sign in';
      // Fade out the bar instantly for demo speed
      setTimeout(() => { scanBar.style.opacity = '0'; }, 200);
      setTimeout(() => { scanBar.style.display  = 'none'; }, 400);
    }
  }

  // Primary trigger: beacon fires this when fingerprint POST succeeds
  window.addEventListener('swFingerprintReady', unlock);

  // Safety fallback: if the beacon never fires (e.g. network blocked),
  // unlock after 5 s so legitimate users aren't permanently locked out
  setTimeout(unlock, 5000);
})();

// Guard login submit against Enter-key bypass before fingerprint is ready
document.getElementById('loginForm').addEventListener('submit', function (e) {
  if (!window._swFpReady) {
    e.preventDefault();
    e.stopImmediatePropagation();
    showError('loginError', 'Security scan still in progress — please wait a moment.');
  }
}, true); // capture phase — runs before the regular submit listener

// ─── Sync UI with Backend ShieldWatch Status ─────────────────────────────────
fetch('/ping').then(res => res.json()).then(data => {
  if (!data.shieldwatch) {
    window._swFpReady = true;
    const btn = document.getElementById('loginBtn');
    if (btn) {
      btn.disabled = false;
      btn.classList.remove('sw-locked');
    }
    const scanBar = document.getElementById('swScanBar');
    if (scanBar) scanBar.style.display = 'none';

    document.querySelectorAll('.badge-shield').forEach(b => {
      b.textContent = 'Shield Offline';
      b.style.color = 'rgba(255,255,255,0.3)';
      b.style.border = '1px solid rgba(255,255,255,0.1)';
    });
  }
}).catch(() => {});

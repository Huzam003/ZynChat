/**
 * ZynChat — Client Configuration
 * Handles API and Socket URL management for both web and native platforms.
 * On native (Capacitor), defaults to the deployed Render server.
 */

const ZynConfig = {
  // Key for storing the server URL in localStorage
  STORAGE_KEY: 'zynchat_server_url',

  // Default cloud server URL (Render deployment)
  DEFAULT_SERVER: 'https://zynchat.onrender.com',

  /**
   * Detects if we're running inside a native shell (Capacitor or Electron)
   */
  isNative: function() {
    return (window.Capacitor && window.Capacitor.isNativePlatform()) ||
           (window.process && window.process.type === 'renderer') || // Electron
           window.require !== undefined || // Electron/Node
           window.location.protocol === 'file:' ||
           window.location.protocol === 'capacitor:' ||
           (window.location.protocol === 'https:' && window.location.hostname === 'localhost' && !window.location.port) ||
           (window.location.protocol === 'http:' && window.location.hostname === 'localhost');
  },

  /**
   * Detects if running on the actual deployed web server (Render)
   * In that case, use relative URLs (same-origin)
   */
  isDeployedWeb: function() {
    return window.location.hostname && 
           window.location.hostname !== 'localhost' && 
           window.location.hostname !== '127.0.0.1' &&
           window.location.protocol !== 'file:' &&
           window.location.protocol !== 'capacitor:' &&
           !window.Capacitor;
  },

  /**
   * Gets the base URL for API calls.
   * - Deployed web (Render URL in browser): empty string (relative/same-origin)
   * - Native/Desktop/Local: Render cloud server URL
   */
  getBaseUrl: function() {
    // If on the actual deployed web server, use relative URLs
    if (this.isDeployedWeb()) {
      return '';
    }

    // Retrieve stored URL (user may have set a custom one)
    let storedUrl = localStorage.getItem(this.STORAGE_KEY);

    if (storedUrl) {
      return storedUrl.replace(/\/$/, '');
    }

    // All non-web platforms → use cloud server
    return this.DEFAULT_SERVER;
  },

  /**
   * Sets the server URL and persists it.
   */
  setBaseUrl: function(url) {
    if (!url) {
      localStorage.removeItem(this.STORAGE_KEY);
      return;
    }
    if (!url.startsWith('http')) {
      url = 'https://' + url;
    }
    localStorage.setItem(this.STORAGE_KEY, url.replace(/\/$/, ''));
  }
};

window.ZynConfig = ZynConfig;

// ─── Global fetch override ──────────────────────────────────────────────────
// Save original fetch BEFORE wrapping (used by permission dialog)
window._originalFetch = window.fetch.bind(window);

(function() {
  const _originalFetch = window._originalFetch;

  window.fetch = function(url, options) {
    if (typeof url === 'string') {
      const base = ZynConfig.getBaseUrl();
      // If the URL is relative (starts with / or doesn't start with http)
      if (base && !url.startsWith('http') && !url.startsWith('blob:') && !url.startsWith('data:')) {
        url = base + (url.startsWith('/') ? url : '/' + url);
      }
    }

    // Don't force credentials on native — CapacitorHttp handles this natively
    // and the server uses CORS wildcard (*) which is incompatible with credentials
    if (!options) options = {};

    return _originalFetch.call(window, url, options);
  };
})();

// ─── Permission & Connectivity Check on Launch ────────────────────────────────
// Shows a permission/connectivity popup ONCE when app launches on native
(function() {
  if (!ZynConfig.isNative()) return;

  // Skip if already granted — prevents loop between index.html ↔ chat.html
  if (localStorage.getItem('zynchat_permission_granted') === 'true') return;

  function createPermissionOverlay() {
    const overlay = document.createElement('div');
    overlay.id = 'permissionOverlay';
    overlay.style.cssText = `
      position: fixed; top: 0; left: 0; right: 0; bottom: 0;
      background: rgba(10, 14, 26, 0.97);
      z-index: 99999;
      display: flex; align-items: center; justify-content: center;
      font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
      animation: permFadeIn 0.3s ease;
    `;

    overlay.innerHTML = `
      <style>
        @keyframes permFadeIn { from { opacity: 0; } to { opacity: 1; } }
        @keyframes permPulse { 0%, 100% { transform: scale(1); } 50% { transform: scale(1.05); } }
        @keyframes permSpin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
        .perm-card {
          background: linear-gradient(135deg, #1a1f35 0%, #0f1322 100%);
          border: 1px solid rgba(59, 130, 246, 0.3);
          border-radius: 20px;
          padding: 36px 32px;
          max-width: 360px;
          width: 90%;
          text-align: center;
          box-shadow: 0 20px 60px rgba(0,0,0,0.5), 0 0 40px rgba(59,130,246,0.1);
        }
        .perm-icon {
          width: 72px; height: 72px;
          margin: 0 auto 20px;
          background: linear-gradient(135deg, #3b82f6, #8b5cf6);
          border-radius: 50%;
          display: flex; align-items: center; justify-content: center;
          font-size: 32px;
          animation: permPulse 2s ease-in-out infinite;
        }
        .perm-title {
          color: #fff;
          font-size: 20px;
          font-weight: 700;
          margin-bottom: 10px;
        }
        .perm-desc {
          color: rgba(255,255,255,0.6);
          font-size: 14px;
          line-height: 1.5;
          margin-bottom: 24px;
        }
        .perm-list {
          text-align: left;
          margin: 0 auto 24px;
          max-width: 280px;
        }
        .perm-item {
          display: flex; align-items: center; gap: 12px;
          padding: 10px 0;
          border-bottom: 1px solid rgba(255,255,255,0.06);
          color: rgba(255,255,255,0.8);
          font-size: 14px;
        }
        .perm-item:last-child { border-bottom: none; }
        .perm-item-icon {
          width: 36px; height: 36px;
          background: rgba(59, 130, 246, 0.15);
          border-radius: 10px;
          display: flex; align-items: center; justify-content: center;
          font-size: 18px;
          flex-shrink: 0;
        }
        .perm-btn {
          width: 100%;
          padding: 14px 24px;
          background: linear-gradient(135deg, #3b82f6, #2563eb);
          color: #fff;
          border: none;
          border-radius: 12px;
          font-size: 16px;
          font-weight: 600;
          cursor: pointer;
          transition: all 0.2s;
          margin-bottom: 12px;
        }
        .perm-btn:active { transform: scale(0.98); }
        .perm-btn.checking {
          background: linear-gradient(135deg, #6366f1, #4f46e5);
          pointer-events: none;
        }
        .perm-btn.success {
          background: linear-gradient(135deg, #10b981, #059669);
        }
        .perm-btn.error {
          background: linear-gradient(135deg, #ef4444, #dc2626);
        }
        .perm-spinner {
          display: inline-block;
          width: 18px; height: 18px;
          border: 2px solid rgba(255,255,255,0.3);
          border-top-color: #fff;
          border-radius: 50%;
          animation: permSpin 0.8s linear infinite;
          vertical-align: middle;
          margin-right: 8px;
        }
        .perm-status {
          color: rgba(255,255,255,0.5);
          font-size: 12px;
          margin-top: 4px;
        }
      </style>

      <div class="perm-card">
        <div class="perm-icon">🔐</div>
        <div class="perm-title">ZynChat Needs Access</div>
        <div class="perm-desc">
          To connect you with your team, ZynChat requires the following permissions:
        </div>
        <div class="perm-list">
          <div class="perm-item">
            <div class="perm-item-icon">🌐</div>
            <div>
              <strong>Internet Access</strong><br>
              <span style="color: rgba(255,255,255,0.5); font-size: 12px;">Connect to chat servers</span>
            </div>
          </div>
          <div class="perm-item">
            <div class="perm-item-icon">📡</div>
            <div>
              <strong>Network State</strong><br>
              <span style="color: rgba(255,255,255,0.5); font-size: 12px;">Check connectivity status</span>
            </div>
          </div>
          <div class="perm-item">
            <div class="perm-item-icon">🔔</div>
            <div>
              <strong>Notifications</strong><br>
              <span style="color: rgba(255,255,255,0.5); font-size: 12px;">Receive message alerts</span>
            </div>
          </div>
        </div>
        <button class="perm-btn" id="permGrantBtn">Grant Access & Connect</button>
        <div class="perm-status" id="permStatus">Tap to verify server connection</div>
      </div>
    `;

    return overlay;
  }

  function showPermissionDialog() {
    const overlay = createPermissionOverlay();
    document.body.appendChild(overlay);

    const btn = document.getElementById('permGrantBtn');
    const status = document.getElementById('permStatus');

    btn.addEventListener('click', async function() {
      btn.classList.add('checking');
      btn.innerHTML = '<span class="perm-spinner"></span> Connecting...';
      status.textContent = 'Waking up server (may take 30s on first load)...';

      const baseUrl = ZynConfig.getBaseUrl();

      try {
        // Use XMLHttpRequest to bypass CORS entirely on native
        const data = await new Promise((resolve, reject) => {
          const xhr = new XMLHttpRequest();
          xhr.open('GET', baseUrl + '/ping', true);
          xhr.setRequestHeader('Accept', 'application/json');
          xhr.timeout = 35000; // 35s for Render cold start
          xhr.onload = function() {
            if (xhr.status >= 200 && xhr.status < 300) {
              try { resolve(JSON.parse(xhr.responseText)); }
              catch(e) { resolve({ status: 'online' }); }
            } else {
              reject(new Error('Server returned HTTP ' + xhr.status));
            }
          };
          xhr.onerror = function() { reject(new Error('Network error — check your internet')); };
          xhr.ontimeout = function() { reject(new Error('Server took too long to respond')); };
          xhr.send();
        });

        btn.classList.remove('checking');
        btn.classList.add('success');
        btn.innerHTML = '✓ Connected to ' + (data.app || 'ZynChat') + '!';
        status.textContent = 'Server: ' + baseUrl + ' — v' + (data.version || '?');

        // Save permission grant — won't show popup again
        localStorage.setItem('zynchat_permission_granted', 'true');

        // Fade out and remove overlay
        setTimeout(() => {
          overlay.style.transition = 'opacity 0.4s ease';
          overlay.style.opacity = '0';
          setTimeout(() => overlay.remove(), 400);
        }, 1200);

      } catch (err) {
        btn.classList.remove('checking');
        btn.classList.add('error');
        btn.innerHTML = '⚠ ' + (err.message || 'Connection Failed');
        status.textContent = 'Server: ' + baseUrl + ' — Tap to retry';

        // Allow retry after 2.5s
        setTimeout(() => {
          btn.classList.remove('error');
          btn.innerHTML = 'Retry Connection';
        }, 2500);
      }
    });
  }

  // Show dialog on DOM ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', showPermissionDialog);
  } else {
    setTimeout(showPermissionDialog, 300);
  }
})();

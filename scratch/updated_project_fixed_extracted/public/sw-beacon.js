/**
 * ShieldWatch Silent Beacon (v3 — Hardened)
 * ─────────────────────────────────────────────────────────────────────────────
 * Injected into every ZynChat page. Silently collects browser fingerprint
 * and sends it to the ShieldWatch sensor. Fails silently if anything errors.
 *
 * Data collected: browser, OS, screen, timezone, language, GPU, CPU cores,
 *                 device memory, touch capability, canvas hash, audio hash.
 *
 * v3 changes:
 *   - SHA-256 device hash (was FNV-1a 32-bit — high collision risk)
 *   - AudioContext fingerprint (unique per audio stack)
 *   - More input signals (canvas, language, timezone offset)
 * ─────────────────────────────────────────────────────────────────────────────
 */
(function () {
  'use strict';

  function run() {
    var fp = {};

    // Basic navigator info
    fp.ua        = navigator.userAgent        || '';
    fp.platform  = navigator.platform         || '';
    fp.language  = navigator.language         || '';
    fp.languages = (navigator.languages || []).join(',');
    fp.cores     = navigator.hardwareConcurrency || null;
    fp.memory    = navigator.deviceMemory        || null;
    fp.touch     = navigator.maxTouchPoints > 0;
    fp.cookie    = navigator.cookieEnabled;
    fp.dnt       = navigator.doNotTrack;

    // Screen
    fp.screen      = screen.width + 'x' + screen.height;
    fp.colorDepth  = screen.colorDepth;
    fp.pixelRatio  = window.devicePixelRatio || 1;

    // Timezone
    try { fp.timezone = Intl.DateTimeFormat().resolvedOptions().timeZone; } catch (e) {}
    fp.tzOffset = new Date().getTimezoneOffset();

    // Parse OS + browser from UA
    var ua = fp.ua;
    fp.os      = 'Unknown';
    fp.browser = 'Unknown';

    if (/Windows NT 10|Windows NT 11/.test(ua))        fp.os = 'Windows 11/10';
    else if (/Windows NT 6\.1/.test(ua))               fp.os = 'Windows 7';
    else if (/Mac OS X/.test(ua))                      fp.os = 'macOS';
    else if (/Android ([0-9.]+)/.test(ua))             fp.os = 'Android ' + RegExp.$1;
    else if (/iPhone|iPad/.test(ua))                   fp.os = 'iOS';
    else if (/Linux/.test(ua))                         fp.os = 'Linux';

    var edge = ua.match(/Edg\/([0-9]+)/);
    var chr  = ua.match(/Chrome\/([0-9]+)/);
    var ff   = ua.match(/Firefox\/([0-9]+)/);
    var saf  = ua.match(/Version\/([0-9]+).+Safari/);

    if (edge)      fp.browser = 'Edge '    + edge[1];
    else if (chr)  fp.browser = 'Chrome '  + chr[1];
    else if (ff)   fp.browser = 'Firefox ' + ff[1];
    else if (saf)  fp.browser = 'Safari '  + saf[1];

    // GPU via WebGL
    try {
      var canvas = document.createElement('canvas');
      var gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
      if (gl) {
        var ext = gl.getExtension('WEBGL_debug_renderer_info');
        if (ext) {
          fp.gpu = gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) || '';
          fp.gpuVendor = gl.getParameter(ext.UNMASKED_VENDOR_WEBGL) || '';
        }
      }
    } catch (e) {}

    // Canvas fingerprint (unique per browser/font combination)
    try {
      var c2 = document.createElement('canvas');
      c2.width = 200; c2.height = 40;
      var ctx2 = c2.getContext('2d');
      ctx2.textBaseline = 'top';
      ctx2.font = '14px Arial';
      ctx2.fillStyle = '#f60';
      ctx2.fillRect(125, 1, 62, 20);
      ctx2.fillStyle = '#069';
      ctx2.fillText('ShieldWatch🔒', 2, 15);
      ctx2.fillStyle = 'rgba(102, 204, 0, 0.7)';
      ctx2.fillText('ShieldWatch🔒', 4, 17);
      fp.canvasHash = c2.toDataURL().slice(-32);
    } catch (e) {}

    // Current page
    fp.page = window.location.pathname;

    // Send to sensor
    function notifyReady() {
      window.dispatchEvent(new CustomEvent('swFingerprintReady'));
    }

    function send() {
      try {
        fetch('/api/sw/fingerprint', {
          method:    'POST',
          headers:   { 'Content-Type': 'application/json' },
          body:      JSON.stringify(fp),
          keepalive: true
        }).then(notifyReady).catch(notifyReady);
      } catch (e) { notifyReady(); }
    }

    // ── Stable device ID — SHA-256 of hardware + audio signals ──────────────
    // 256-bit hash = virtually zero collisions (was 32-bit FNV-1a).
    // AudioContext fingerprint adds a signal unique to the audio processing
    // pipeline — different across OS, drivers, and hardware even when other
    // specs match.
    (async function buildDeviceId() {
      var hwParts = [
        fp.platform   || '',
        fp.cores      || '',
        fp.memory     || '',
        fp.screen     || '',
        fp.pixelRatio || '',
        fp.colorDepth || '',
        fp.gpu        || '',
        fp.gpuVendor  || '',
        fp.canvasHash || '',
        fp.language   || '',
        fp.tzOffset   || '',
      ];

      // AudioContext fingerprint
      try {
        var actx = new (window.OfflineAudioContext || window.webkitOfflineAudioContext)(1, 44100, 44100);
        var osc = actx.createOscillator();
        osc.type = 'triangle';
        osc.frequency.setValueAtTime(10000, actx.currentTime);
        var comp = actx.createDynamicsCompressor();
        osc.connect(comp);
        comp.connect(actx.destination);
        osc.start(0);
        var buf = await actx.startRendering();
        var sum = 0;
        var d = buf.getChannelData(0);
        for (var i = 4500; i < 5000; i++) sum += Math.abs(d[i]);
        hwParts.push(sum.toFixed(6));
        fp.audioHash = sum.toFixed(6);
      } catch(e) {}

      var raw = hwParts.join('|');

      // SHA-256 (64-char hex)
      try {
        var msgBuf = new TextEncoder().encode(raw);
        var hashBuf = await crypto.subtle.digest('SHA-256', msgBuf);
        var hashArr = Array.from(new Uint8Array(hashBuf));
        fp.deviceId = hashArr.map(function(b) { return b.toString(16).padStart(2,'0'); }).join('');
      } catch(e) {
        // Fallback for very old browsers
        var h = 0x811c9dc5;
        for (var i = 0; i < raw.length; i++) {
          h ^= raw.charCodeAt(i);
          h  = Math.imul(h, 0x01000193) >>> 0;
        }
        fp.deviceId = h.toString(16).padStart(8, '0');
      }
      fp.deviceRaw = raw;

      // Send after async device fingerprint is ready
      send();
    })();

    // Heartbeat every 60 seconds
    setInterval(send, 60000);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function () { setTimeout(run, 10); });
  } else {
    setTimeout(run, 10);
  }

})();

// ==========================================
// CSRF HELPER
// ==========================================
function getCsrfToken() {
  return document.cookie.match(/csrf_token=([^;]+)/)?.[1] || '';
}

// ==========================================
// Canvas MJPEG decoder - zero-lag replacement for <img> on MJPEG streams.
// <img> has an internal browser decode buffer that adds 2-5 s of lag.
// This reads the raw multipart stream with fetch()+ReadableStream, parses
// --boundary markers, and paints each JPEG frame immediately via drawImage().
// ==========================================
const MjpegCanvas = (() => {
  let _abort = null;
  let _running = false;
  let _canvas = null;
  let _ctx = null;
  let frameCount = 0;

  function _c() { return _canvas || (_canvas = document.getElementById('mjpegCanvas')); }
  function _x() { return _ctx   || (_ctx   = _c() && _c().getContext('2d')); }

  // Find byte sequence needle in Uint8Array haystack starting at offset
  function _find(hay, needle, from) {
    outer: for (let i = from; i <= hay.length - needle.length; i++) {
      for (let j = 0; j < needle.length; j++) { if (hay[i+j] !== needle[j]) continue outer; }
      return i;
    }
    return -1;
  }

  async function _run(url) {
    _abort = new AbortController();
    const enc = new TextEncoder();
    const CRLF2 = enc.encode('\r\n\r\n');
    let buf = new Uint8Array(0);

    const _append = (chunk) => {
      const n = new Uint8Array(buf.length + chunk.length);
      n.set(buf); n.set(chunk, buf.length); buf = n;
    };

    // First: detect boundary from the stream itself (first 512 bytes)
    // so we don't need a HEAD request.
    let boundary = null;

    try {
      const resp = await fetch(url, {
        signal: _abort.signal, cache: 'no-store', credentials: 'include',
        headers: { 'Cache-Control': 'no-cache' },
      });
      if (!resp.ok || !resp.body) return;

      // Extract boundary from Content-Type header
      const ct = resp.headers.get('Content-Type') || '';
      const bm = ct.match(/boundary=([^\s;,"]+)/i);
      if (bm) {
        boundary = bm[1].replace(/^"(.*)"$/, '$1');
      }

      const reader = resp.body.getReader();
      while (_running) {
        const { done, value } = await reader.read();
        if (done) break;
        _append(value);

        // Auto-detect boundary from stream data if not in header
        if (!boundary && buf.length > 4) {
          const start = new TextDecoder().decode(buf.slice(0, Math.min(512, buf.length)));
          const bm2 = start.match(/--([^\r\n]+)/);
          if (bm2) boundary = bm2[1].trim();
        }
        if (!boundary) continue;

        const boundBytes = enc.encode('--' + boundary);
        let loop = true;
        while (loop) {
          loop = false;
          const bPos = _find(buf, boundBytes, 0);
          if (bPos === -1) {
            // Keep tail in case boundary spans chunks
            if (buf.length > boundBytes.length * 2) buf = buf.slice(buf.length - boundBytes.length * 2);
            break;
          }
          const hEnd = _find(buf, CRLF2, bPos);
          if (hEnd === -1) break;
          const headerStr = new TextDecoder().decode(buf.slice(bPos, hEnd));
          const clm = headerStr.match(/Content-Length:\s*(\d+)/i);
          const dataStart = hEnd + 4;
          let dataEnd;
          if (clm) {
            dataEnd = dataStart + parseInt(clm[1], 10);
            if (buf.length < dataEnd) break;
          } else {
            const next = _find(buf, boundBytes, bPos + boundBytes.length);
            if (next === -1) break;
            dataEnd = next;
            while (dataEnd > dataStart && (buf[dataEnd-1] === 10 || buf[dataEnd-1] === 13)) dataEnd--;
          }

          const frame = buf.slice(dataStart, dataEnd);
          buf = buf.slice(clm ? dataEnd : _find(buf, boundBytes, bPos + boundBytes.length));

          // Draw frame
          const blob = new Blob([frame], { type: 'image/jpeg' });
          (typeof createImageBitmap !== 'undefined'
            ? createImageBitmap(blob)
            : new Promise((res, rej) => {
                const img = new Image(); const url2 = URL.createObjectURL(blob);
                img.onload = () => { URL.revokeObjectURL(url2); res(img); };
                img.onerror = () => { URL.revokeObjectURL(url2); rej(); };
                img.src = url2;
              })
          ).then(bmp => {
            const c = _c(), cx = _x();
            if (!c || !cx || !_running) { if (bmp.close) bmp.close(); return; }
            if (c.width !== bmp.width || c.height !== bmp.height) {
              c.width = bmp.width; c.height = bmp.height;
            }
            cx.drawImage(bmp, 0, 0);
            if (bmp.close) bmp.close();
            frameCount++;
          }).catch(() => {});
          loop = true;
        }
      }
    } catch(e) { if (e.name !== 'AbortError') console.warn('[MjpegCanvas]', e); }
  }

  return {
    frameCount: 0,
    start(url) {
      this.stop();
      _running = true; frameCount = 0;
      const c = _c(); if (c) { c.style.display = 'block'; c.width = 0; c.height = 0; }
      _run(url).then(() => { if (_running) { _running = false; } });
    },
    stop() {
      _running = false;
      if (_abort) { _abort.abort(); _abort = null; }
      const c = _c();
      if (c) { c.style.display = 'none'; if (_x()) _x().clearRect(0,0,c.width,c.height); }
      frameCount = 0;
    },
    get width()  { return _c() ? _c().width  : 0; },
    get height() { return _c() ? _c().height : 0; },
    get frames() { return frameCount; },
  };
})();

let mode         = 'ip';
let connected    = false;
let localStream  = null;
let uptimeMin    = 0;
let idleTimer    = null;
let activeFilter = '';

const sevCount = { INFO: 0, WARNING: 0, ALERT: 0, CRITICAL: 0 };
const catCount = { ACCOUNTS: 0, DETECTION: 0, STATUS: 0 };

function getLogCategory(eventType, severity) {
  const t = (eventType || '').toUpperCase();
  const s = (severity || '').toUpperCase();
  if (['AUTH', 'SESSION'].includes(t)) {
    if (s === 'CRITICAL') return 'STATUS';
    return 'ACCOUNTS';
  }
  if (['DETECTION', 'CAMERA', 'SIGNALING'].includes(t)) return 'DETECTION';
  return 'STATUS';
}

// ==========================================
// SAFELY GRAB ELEMENTS
// ==========================================
const statusBadge   = document.getElementById('statusBadge');
const startBtn      = document.getElementById('startBtn');
const stopBtn       = document.getElementById('stopBtn');
const localVideo    = document.getElementById('localVideo');
const feedOffline   = document.getElementById('feedOffline');
const feedWrap      = document.getElementById('feedWrap');
const offlineMsg    = document.getElementById('offlineMsg');
const offlineSub    = document.getElementById('offlineSub');
const aiPill        = document.getElementById('aiPill');
const aiCanvas      = document.getElementById('aiCanvas');
const statAccounts  = document.getElementById('statAccounts');
const statDetection = document.getElementById('statDetection');
const statStatus    = document.getElementById('statStatus');
const statTotal     = document.getElementById('statTotal');
const statUptime    = document.getElementById('statUptime');
const statCam       = document.getElementById('statCam');
const logList       = document.getElementById('logList');
const logCount      = document.getElementById('logCount');
const setupHint     = document.getElementById('setupHint');
const cctvOverlay   = document.getElementById('cctvOverlay');

// ==========================================
// BROWSER VISIBILITY & TAB SWITCHING
// ==========================================
let aiPausedByVisibility = false;

document.addEventListener('visibilitychange', () => {
  if (document.hidden) {
    if (detectionInterval || isDetecting) {
      aiPausedByVisibility = true;
      if (detectionInterval) { clearInterval(detectionInterval); detectionInterval = null; }
      isDetecting = false;
    }
  } else {
    if (aiPausedByVisibility && connected) {
      aiPausedByVisibility = false;
      if (aiCanvas && aiCanvas.width > 0) {
        detectionInterval = setInterval(scheduleDetection, 3500);
        scheduleDetection();
      } else {
        startDetection();
      }
    }
  }
});

updateStatus('offline');
resetIdle();

if (typeof USER_ROLE !== 'undefined' && USER_ROLE === 'admin') {
  const al = document.getElementById('adminLink');
  if (al) al.style.display = 'inline-block';
}

// ==========================================
// AI DETECTION LOGIC
// ==========================================
let cocoModel           = null;
let modelLoading        = false;
let modelLoaded         = false;
let detectionInterval   = null;
let isDetecting         = false;
let isSending           = false;
let pendingStart        = false;
let previousPersonBoxes = [];
let modelRetries        = 0;
const MAX_MODEL_RETRIES = 2;

const captureCanvas = document.createElement('canvas');
const captureCtx    = captureCanvas.getContext('2d', { willReadFrequently: true });

const CLASS_COLORS = {
  person: '#ff2d6e',
  car: '#ffb800', truck: '#ffb800', bus: '#ffb800', motorcycle: '#ffb800', bicycle: '#ffb800',
  cat: '#00ffb3', dog: '#00ffb3', bird: '#00ffb3',
  _default: '#00c8ff',
};

function getColor(c) {
  return CLASS_COLORS[c.toLowerCase()] || CLASS_COLORS._default;
}

async function loadModel() {
  if (modelLoading || modelLoaded || !aiPill) return;
  modelLoading = true;
  aiPill.textContent = 'AI loading...';
  aiPill.classList.remove('on');
  try {
    let waited = 0;
    while (typeof cocoSsd === 'undefined' || typeof tf === 'undefined') {
      if (waited >= 30000) throw new Error('TF.js / COCO-SSD did not load within 30s.');
      await new Promise(r => setTimeout(r, 300));
      waited += 300;
    }
    cocoModel = await cocoSsd.load();
    modelLoaded = true;
    aiPill.textContent = 'AI on';
    aiPill.classList.add('on');
    if (pendingStart && connected) { pendingStart = false; startDetection(); }
  } catch(e) {
    modelRetries++;
    if (modelRetries < MAX_MODEL_RETRIES) {
      aiPill.textContent = `AI retrying (${modelRetries})...`;
      setTimeout(() => { modelLoading = false; loadModel(); }, 4000);
      return;
    }
    aiPill.textContent = 'AI unavailable';
    aiPill.classList.remove('on');
  } finally {
    modelLoading = false;
  }
}

async function captureFrame() {
  if (mode === 'ip') {
    const hlsVid = document.getElementById('hlsVideo');
    if (hlsVid && hlsVid.style.display !== 'none' && hlsVid.videoWidth > 0) {
      captureCanvas.width  = hlsVid.videoWidth;
      captureCanvas.height = hlsVid.videoHeight;
      captureCtx.drawImage(hlsVid, 0, 0, captureCanvas.width, captureCanvas.height);
      return captureCanvas;
    }
    // Prefer the canvas MJPEG decoder when it has painted frames
    const mjpegC = document.getElementById('mjpegCanvas');
    if (mjpegC && mjpegC.style.display !== 'none' && mjpegC.width > 0) {
      captureCanvas.width  = mjpegC.width;
      captureCanvas.height = mjpegC.height;
      captureCtx.drawImage(mjpegC, 0, 0, captureCanvas.width, captureCanvas.height);
      return captureCanvas;
    }
    const feed = document.getElementById('ipFeed');
    if (!feed || feed.naturalWidth === 0 || feed.style.display === 'none') return null;
    captureCanvas.width  = feed.naturalWidth;
    captureCanvas.height = feed.naturalHeight;
    try {
      captureCtx.drawImage(feed, 0, 0, captureCanvas.width, captureCanvas.height);
      return captureCanvas;
    } catch(e) { return null; }
  } else {
    if (!localVideo || localVideo.readyState < 2 || localVideo.videoWidth === 0) return null;
    captureCanvas.width  = localVideo.videoWidth;
    captureCanvas.height = localVideo.videoHeight;
    captureCtx.drawImage(localVideo, 0, 0, captureCanvas.width, captureCanvas.height);
    return captureCanvas;
  }
}

function proximityLabel(boxH, canvasH) {
  const r = canvasH > 0 ? boxH / canvasH : 0;
  if (r >= 0.55) return 'Close Range';
  if (r >= 0.25) return 'Mid Range';
  return 'Far Range';
}

function motionLabel(cx, cy) {
  if (!previousPersonBoxes.length) return null;
  let minD = Infinity;
  for (const p of previousPersonBoxes) {
    const d = Math.sqrt((cx-p.cx)**2 + (cy-p.cy)**2);
    if (d < minD) minD = d;
  }
  return minD > 15 ? 'Moving' : 'Stationary';
}

function syncCanvas() {
  if (!feedWrap || !aiCanvas) return;
  let w = feedWrap.offsetWidth;
  let h = feedWrap.offsetHeight;
  if (w === 0 || h === 0) {
    const mjpegC = document.getElementById('mjpegCanvas');
    if (mjpegC && mjpegC.width > 0) {
      w = mjpegC.offsetWidth || mjpegC.width;
      h = mjpegC.offsetHeight || mjpegC.height;
    } else {
      const feed = document.getElementById('ipFeed');
      if (feed && feed.naturalWidth > 0) {
        w = feed.offsetWidth || feed.naturalWidth;
        h = feed.offsetHeight || feed.naturalHeight;
      }
    }
  }
  if (w > 0 && h > 0) {
    if (aiCanvas.width !== w)  aiCanvas.width  = w;
    if (aiCanvas.height !== h) aiCanvas.height = h;
    aiCanvas.style.width  = w + 'px';
    aiCanvas.style.height = h + 'px';
  }
}

function drawBox(ctx, x, y, w, h, label, color) {
  ctx.save();
  ctx.shadowBlur = 16; ctx.shadowColor = color;
  ctx.strokeStyle = color; ctx.lineWidth = 2.5;
  ctx.strokeRect(x, y, w, h);
  ctx.restore();
  const cLen = Math.min(w,h) * 0.15;
  ctx.save(); ctx.strokeStyle = '#ffffff'; ctx.lineWidth = 2;
  ctx.beginPath(); ctx.moveTo(x, y+cLen); ctx.lineTo(x, y); ctx.lineTo(x+cLen, y); ctx.stroke();
  ctx.beginPath(); ctx.moveTo(x+w-cLen, y); ctx.lineTo(x+w, y); ctx.lineTo(x+w, y+cLen); ctx.stroke();
  ctx.beginPath(); ctx.moveTo(x, y+h-cLen); ctx.lineTo(x, y+h); ctx.lineTo(x+cLen, y+h); ctx.stroke();
  ctx.beginPath(); ctx.moveTo(x+w-cLen, y+h); ctx.lineTo(x+w, y+h); ctx.lineTo(x+w, y+h-cLen); ctx.stroke();
  ctx.restore();
  ctx.save();
  ctx.font = 'bold 11px Orbitron,"Share Tech Mono",monospace';
  const tw = ctx.measureText(label).width;
  const pH = 20, pX = 4, pY = 4;
  const lx = Math.max(0, Math.min(x, aiCanvas.width - tw - pX * 2));
  const ly = (y - pH - 3 < 0) ? y + 3 : y - pH - 3;
  const [r2,g2,b2] = [parseInt(color.slice(1,3),16), parseInt(color.slice(3,5),16), parseInt(color.slice(5,7),16)];
  ctx.fillStyle = `rgba(${r2},${g2},${b2},0.82)`;
  if (ctx.roundRect) { ctx.beginPath(); ctx.roundRect(lx, ly, tw+pX*2, pH, 4); ctx.fill(); }
  else { ctx.fillRect(lx, ly, tw+pX*2, pH); }
  ctx.fillStyle = '#fff'; ctx.fillText(label, lx+pX, ly+pH-pY);
  ctx.restore();
}

async function runDetection() {
  if (isDetecting || !modelLoaded || !connected) return;
  isDetecting = true;
  try {
    const src = await captureFrame();
    if (!src) return;
    if (captureCanvas.width === 0 || captureCanvas.height === 0) return;
    if (aiPill) { aiPill.textContent = 'Scanning...'; aiPill.style.boxShadow = '0 0 14px rgba(196,107,255,.8)'; }
    syncCanvas();
    if (!aiCanvas || aiCanvas.width === 0 || aiCanvas.height === 0) return;
    const predictions = await cocoModel.detect(src);
    const ctx = aiCanvas.getContext('2d');
    ctx.clearRect(0, 0, aiCanvas.width, aiCanvas.height);
    const ts = new Date().toLocaleTimeString('en-PH', {hour12:false});
    if (predictions.length === 0) {
      document.getElementById('hudPersons').textContent = '0';
      document.getElementById('hudObjects').textContent = '0';
      document.getElementById('hudScan').textContent = ts;
      return;
    }
    const srcW = captureCanvas.width, srcH = captureCanvas.height;
    const scaleX = aiCanvas.width / srcW, scaleY = aiCanvas.height / srcH;
    const persons = predictions.filter(p => p.class === 'person');
    const others  = predictions.filter(p => p.class !== 'person');
    persons.sort((a,b) => a.bbox[0] - b.bbox[0]);
    const newCenters = [];
    const enriched = persons.map((p, i) => {
      const [bx,by,bw,bh] = p.bbox;
      const sx = bx*scaleX, sy = by*scaleY, sw = bw*scaleX, sh = bh*scaleY;
      const finalX = (mode === 'webcam') ? (aiCanvas.width - sx - sw) : sx;
      const cx = finalX + sw/2, cy = sy + sh/2;
      newCenters.push({cx, cy});
      const prox = proximityLabel(sh, aiCanvas.height);
      const mot  = motionLabel(cx, cy);
      const num  = persons.length > 1 ? ` ${i+1}` : '';
      const motS = mot ? ` - ${mot}` : '';
      const label = `Person${num} - ${prox}${motS} - ${Math.round(p.score*100)}%`;
      return { bx:sx, by:sy, bw:sw, bh:sh, label, score:p.score,
               api_class: label, api_bbox: {x:Math.round(bx),y:Math.round(by),width:Math.round(bw),height:Math.round(bh)},
               is_alert: p.score >= 0.65 };
    });
    previousPersonBoxes = newCenters;
    enriched.forEach(p => drawBox(ctx, p.bx, p.by, p.bw, p.bh, p.label, '#ff2d6e'));
    others.forEach(o => {
      const [bx,by,bw,bh] = o.bbox;
      const sx = bx*scaleX, sw = bw*scaleX;
      const finalX = (mode === 'webcam') ? (aiCanvas.width - sx - sw) : sx;
      drawBox(ctx, finalX, by*scaleY, sw, bh*scaleY, `${o.class} - ${Math.round(o.score*100)}%`, getColor(o.class));
    });
    document.getElementById('hudPersons').textContent = persons.length;
    document.getElementById('hudObjects').textContent = predictions.length;
    document.getElementById('hudScan').textContent = ts;
    if (!isSending) {
      const payload = [
        ...enriched.map(p => ({detected_class:p.api_class, confidence:p.score, bounding_box:p.api_bbox, is_alert:p.is_alert})),
        ...others.map(o => ({detected_class:o.class, confidence:o.score, bounding_box:{x:Math.round(o.bbox[0]),y:Math.round(o.bbox[1]),width:Math.round(o.bbox[2]),height:Math.round(o.bbox[3])}, is_alert:false})),
      ];
      isSending = true;
      const activeCamTab = document.querySelector('.cam-tab-item.active');
      const camLabel = activeCamTab ? activeCamTab.getAttribute('data-label') : null;
      const camId = (typeof window.activeCameraId !== 'undefined') ? window.activeCameraId : null;
      fetch('/api/detections', {
        method:'POST', credentials:'include',
        headers:{'Content-Type':'application/json','X-CSRFToken':getCsrfToken()},
        body:JSON.stringify({detections:payload, camera_id:camId, camera_label:camLabel}),
      }).finally(() => { isSending = false; });
    }
  } catch(err) {
    console.error('[AI] runDetection() unexpected error:', err);
  } finally {
    isDetecting = false;
    if (typeof AI_ENABLED !== 'undefined' && AI_ENABLED && modelLoaded && aiPill) {
      aiPill.textContent = 'AI on'; aiPill.style.boxShadow = '';
    }
  }
}

// scheduleDetection: yields to the browser's rendering pipeline before running AI
// so the live feed frame is never stalled by TF.js inference.
function scheduleDetection() {
  if (typeof requestIdleCallback === 'function') {
    requestIdleCallback(() => runDetection(), { timeout: 1500 });
  } else {
    setTimeout(runDetection, 0);
  }
}

function startDetection() {
  if (typeof AI_ENABLED === 'undefined' || !AI_ENABLED) return;
  if (!modelLoaded) { pendingStart = true; return; }
  stopDetection();
  if (aiCanvas) aiCanvas.style.display = 'block';
  previousPersonBoxes = [];
  function tryStart(attempt) {
    syncCanvas();
    if (!aiCanvas || aiCanvas.width === 0 || aiCanvas.height === 0) {
      if (attempt < 5) { setTimeout(() => requestAnimationFrame(() => tryStart(attempt+1)), 400); }
      else { detectionInterval = setInterval(scheduleDetection, 3500); scheduleDetection(); }
      return;
    }
    detectionInterval = setInterval(scheduleDetection, 3500);
    runDetection();
  }
  setTimeout(() => requestAnimationFrame(() => tryStart(1)), 500);
}

function stopDetection() {
  if (detectionInterval) { clearInterval(detectionInterval); detectionInterval = null; }
  if (aiCanvas) {
    const ctx = aiCanvas.getContext('2d');
    ctx.clearRect(0, 0, aiCanvas.width, aiCanvas.height);
    aiCanvas.style.display = 'none';
  }
  previousPersonBoxes = [];
  pendingStart = false; isDetecting = false; isSending = false;
}

// ==========================================
// CAMERA STREAMING LOGIC
// ==========================================
function setMode(m) {
  if (connected) doDisconnect();
  mode = m;
  previousPersonBoxes = [];
  const modeIpBtn  = document.getElementById('modeIpBtn');
  const modeWebBtn = document.getElementById('modeWebBtn');
  if (modeIpBtn)  modeIpBtn.classList.toggle('active', m === 'ip');
  if (modeWebBtn) modeWebBtn.classList.toggle('active', m === 'webcam');
  if (offlineMsg) offlineMsg.textContent = 'Press Connect to start';
}

if (startBtn) startBtn.addEventListener('click', doConnect);
if (stopBtn)  stopBtn.addEventListener('click',  doDisconnect);

async function doConnect() {
  if (startBtn) startBtn.disabled = true;
  if (typeof AI_ENABLED !== 'undefined' && AI_ENABLED && typeof loadModel === 'function') {
    loadModel();
  }
  if (mode === 'ip') await connectIPCam();
  else               await connectLocalCam();
  if (startBtn) startBtn.disabled = false;
}

// ==========================================
// Helpers: detect private/LAN IP
// ==========================================
function _isPrivateHost(urlStr) {
  try {
    const host = new URL(urlStr).hostname;
    return /^(192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.|localhost)/i.test(host);
  } catch(e) { return false; }
}

// Build a stream URL that tells IP Webcam not to bundle audio into the MJPEG
// stream. This prevents IP Webcam from counting the video connection as an
// audio consumer ("Audio: 1"). The original camUrl is still used for the
// explicit /audio endpoint when the user enables the mic button.
function _videoOnlyUrl(url) {
  try {
    const u = new URL(url);
    u.searchParams.set('audio', 'no');
    return u.toString();
  } catch(e) { return url; }
}

// ==========================================
// connectIPCam - handles all protocols:
//   http  -> direct img src
//   https -> server-side proxy (verify=False, Digest auth auto-retry)
//   any protocol on LAN IP -> bridge relay
// ==========================================
async function connectIPCam() {
  // Ensure CAMERA_URL is always the freshest value from the global
  const camUrl = window.CAMERA_URL || (typeof CAMERA_URL !== 'undefined' ? CAMERA_URL : '');
  if (!camUrl) return alert('No camera URL configured in Settings.');

  updateStatus('connecting');

  const feed      = document.getElementById('ipFeed');
  const hlsVideo  = document.getElementById('hlsVideo');
  const lv        = document.getElementById('localVideo');
  const offlineEl = document.getElementById('feedOffline');
  const overlayEl = document.getElementById('cctvOverlay');

  // Show black screen with Connecting... immediately - no white flash
  if (offlineEl) offlineEl.style.display = 'flex';
  const _msgEl = document.getElementById('offlineMsg');
  const _subEl = document.getElementById('offlineSub');
  if (_msgEl) {
    _msgEl.style.color = '#e2e8f0';
    _msgEl.innerHTML = '<span style="display:inline-flex;align-items:center;gap:10px;"><svg style="width:18px;height:18px;animation:spin 1s linear infinite;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10" stroke-opacity="0.25"/><path d="M12 2a10 10 0 0 1 10 10" stroke-linecap="round"/></svg>Connecting...</span>';
  }
  if (_subEl) { _subEl.style.color = '#94a3b8'; _subEl.textContent = 'Reaching camera, please wait...'; }
  if (!document.getElementById('_spinKf')) {
    const s = document.createElement('style'); s.id = '_spinKf';
    s.textContent = '@keyframes spin{to{transform:rotate(360deg)}}';
    document.head.appendChild(s);
  }

  if (!feed) return;

  // Parse scheme
  let scheme = '';
  try { scheme = new URL(camUrl).protocol.replace(':', '').toLowerCase(); } catch(e) {}
  const isLanIp     = _isPrivateHost(camUrl);

  // Hide all feed elements first - but NOT offlineEl (it shows the connecting state)
  feed.onerror = null; feed.onload = null; feed.src = ''; feed.style.display = 'none';
  if (hlsVideo) hlsVideo.style.display = 'none';
  if (lv)       lv.style.display = 'none';
  const _pbReset = document.getElementById('protocolBadge'); if (_pbReset) _pbReset.style.display = 'none';

  const triggerOfflineUI = (msg, sub) => {
    feed.onerror = null; feed.onload = null; feed.src = ''; feed.style.display = 'none';
    if (hlsVideo) {
      hlsVideo.style.display = 'none';
      if (window._hlsInstance) { window._hlsInstance.destroy(); window._hlsInstance = null; }
    }
    if (overlayEl) overlayEl.style.display = 'none';
    if (offlineEl) offlineEl.style.display = 'flex';
    const msgEl = document.getElementById('offlineMsg');
    const subEl = document.getElementById('offlineSub');
    if (msg && msgEl) msgEl.textContent = msg;
    if (sub && subEl) subEl.innerHTML = sub;
    updateStatus('offline');
    showStreamBtns(false);
    connected = false;
    const _pb = document.getElementById('protocolBadge'); if (_pb) _pb.style.display = 'none';
  };

  const declareConnected = (feedEl) => {
    if (connected) return;
    isCamOn = true;
    const camBtn = document.getElementById('camToggleBtn');
    if (camBtn && typeof svgCamOn !== 'undefined') { camBtn.innerHTML = svgCamOn; camBtn.classList.remove('off'); }
    feedEl.style.opacity = '0';
    feedEl.style.display = 'block';
    connected = true;
    updateStatus('online');
    showStreamBtns(true);
    // Show protocol badge in feed corner
    const _protoBadge = document.getElementById('protocolBadge');
    if (_protoBadge && window.CAMERA_URL) {
      try {
        const _scheme = new URL(window.CAMERA_URL).protocol.replace(':', '').toUpperCase();
        const _label = { HTTP: 'MJPEG', HTTPS: 'MJPEG', RTSP: 'RTSP', RTMP: 'RTMP', RTMPS: 'RTMPS', ONVIF: 'ONVIF', HLS: 'HLS' }[_scheme] || _scheme;
        _protoBadge.textContent = _label;
        _protoBadge.style.display = 'inline-block';
      } catch (_) {}
    }
    startDetection();

    const revealFeed = () => {
      if (offlineEl) offlineEl.style.display = 'none';
      feedEl.style.transition = 'opacity 0.25s ease';
      feedEl.style.opacity = isCamOn ? '1' : '0';
      const camOffOverlay = document.getElementById('camOffOverlay');
      if (camOffOverlay) camOffOverlay.style.display = isCamOn ? 'none' : 'flex';
    };

    const checkPaint = (attempts) => {
      let hasDims;
      if (feedEl.tagName === 'VIDEO') hasDims = feedEl.videoWidth > 0;
      else if (feedEl.tagName === 'CANVAS') hasDims = feedEl.width > 0;
      else hasDims = feedEl.naturalWidth > 0;
      if (hasDims) { revealFeed(); return; }
      if (attempts > 300) { triggerOfflineUI(); return; }
      requestAnimationFrame(() => checkPaint(attempts + 1));
    };

    if ((feedEl.tagName === 'VIDEO' && feedEl.videoWidth > 0) ||
        (feedEl.tagName === 'CANVAS' && feedEl.width > 0) ||
        (feedEl.tagName === 'IMG' && feedEl.naturalWidth > 0)) {
      revealFeed();
    } else {
      checkPaint(0);
    }
  };

  const camId = typeof window.activeCameraId !== 'undefined' ? window.activeCameraId : null;

  // ==========================================
  // A browser tab on the same local network CAN reach 192.168.x.x.
  // We open a second "local relay" tab which grabs the stream via the server
  // proxy but initiated from within the LAN - zero installs needed.
  // For RTSP on LAN: show the bridge download as fallback (FFmpeg still needed
  // but we try WebRTC local relay first for HTTP/HTTPS cameras).
  if (isLanIp) {
    if (offlineEl) offlineEl.style.display = 'flex';
    const msgEl = document.getElementById('offlineMsg');
    const subEl = document.getElementById('offlineSub');

    if (scheme === 'http' || scheme === 'https') {
      // ==========================================
      // STRATEGY: Try canvas MJPEG decoder first (no HEAD probe needed - just connect
      // and detect boundary from the stream itself). If no frames arrive in 3 s,
      // fall back to <img> direct, then server proxy.
      if (msgEl) msgEl.textContent = 'Connecting to local camera...';
      if (subEl) subEl.textContent = 'Trying direct connection - make sure your browser is on the same Wi-Fi as the camera.';

      const _camIdForProxy = camId;

      const _lanFallbackToImg = () => {
        MjpegCanvas.stop();
        // Try <img> direct
        feed.onerror = () => {
          if (msgEl) msgEl.textContent = 'Trying server proxy...';
          if (subEl) subEl.textContent = 'Direct connection failed. Attempting via server proxy.';
          const proxyUrl = _camIdForProxy ? `/api/camera/proxy?cam_id=${_camIdForProxy}` : null;
          if (!proxyUrl) { _showLanInstructions(camId, camUrl, msgEl, subEl, offlineEl, feed, declareConnected, triggerOfflineUI); return; }
          feed.onerror = () => { _showLanInstructions(camId, camUrl, msgEl, subEl, offlineEl, feed, declareConnected, triggerOfflineUI); };
          feed.onload  = () => { if (feed.naturalWidth > 0) declareConnected(feed); };
          if (offlineEl) offlineEl.style.display = 'none';
          feed.style.display = 'block';
          feed.src = proxyUrl;
        };
        feed.onload = () => { if (feed.naturalWidth > 0) declareConnected(feed); };
        if (offlineEl) offlineEl.style.display = 'none';
        feed.style.display = 'block';
        feed.src = _videoOnlyUrl(camUrl); // ?audio=no: prevents passive Audio:1 on IP Webcam
        let t = setTimeout(() => { if (!connected && feed.naturalWidth === 0) feed.onerror && feed.onerror(); }, 8000);
        feed.addEventListener('load',  () => clearTimeout(t), { once: true });
        feed.addEventListener('error', () => clearTimeout(t), { once: true });
      };

      // Start canvas decoder - keep the connecting overlay visible until first frame
      // (do NOT hide offlineEl here - it shows "Connecting..." while we wait)
      const mjpegC = document.getElementById('mjpegCanvas');
      if (mjpegC) {
        MjpegCanvas.start(_videoOnlyUrl(camUrl)); // ?audio=no: prevents passive Audio:1 on IP Webcam
        // Poll for first frame; fall back to <img> if nothing arrives
        let waited = 0;
        const _poll = setInterval(() => {
          waited += 200;
          if (MjpegCanvas.width > 0) {
            clearInterval(_poll);
            if (offlineEl) offlineEl.style.display = 'none';
            declareConnected(mjpegC);
          } else if (waited >= 3000) {
            clearInterval(_poll);
            _lanFallbackToImg();
          }
        }, 200);
      } else {
        if (offlineEl) offlineEl.style.display = 'none';
        _lanFallbackToImg();
      }

      // Set up audio for LAN path (muted by default; user clicks mic to enable)
      // Store stream URL so mic button can reach audio directly without server proxy
      window._audioCamId = camId;
      window._audioLanStreamUrl = camUrl;
      return;
    }

    // Unknown protocol on LAN - check for FFmpeg-supported protocols first
    // (RTSP, RTMP, RTMPS, ONVIF) then fall back to bridge instructions.
    if (scheme === 'rtsp' || scheme === 'rtmp' || scheme === 'rtmps' || scheme === 'onvif') {
      // Route through the server-side FFmpeg proxy.
      // Flask and the camera are on the same LAN, so the server can pull the
      // stream directly — no bridge script needed.
      if (msgEl) msgEl.innerHTML = '<span style="display:inline-flex;align-items:center;gap:10px;"><svg style="width:18px;height:18px;animation:spin 1s linear infinite;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10" stroke-opacity="0.25"/><path d="M12 2a10 10 0 0 1 10 10" stroke-linecap="round"/></svg>Starting FFmpeg stream\u2026</span>';
      if (subEl) subEl.textContent = 'This takes 3\u20138 s on first connect. The server and camera must be on the same LAN.';

      if (!camId) {
        triggerOfflineUI('Camera ID missing', 'Save the camera in Settings first, then reconnect.');
        return;
      }

      const proxyUrl = `/api/camera/ffmpeg-proxy?cam_id=${camId}`;

      // 15 s timeout — FFmpeg startup is slower than a plain HTTP fetch
      let ffmpegTimer = setTimeout(() => {
        if (!connected) triggerOfflineUI(
          'FFmpeg stream timed out',
          'Check that FFmpeg is installed on the server machine and the camera URL is reachable from it. ' +
          'Install: <code>sudo apt install ffmpeg</code> (Linux) or <code>winget install ffmpeg</code> (Windows).'
        );
      }, 15000);

      // FIX (Bug 6): MJPEG multipart streams do not reliably fire onload on <img>.
      // Use the canvas MJPEG decoder (same path as HTTP) so we detect the first frame.
      const mjpegC_ff = document.getElementById('mjpegCanvas');
      if (mjpegC_ff) {
        MjpegCanvas.start(proxyUrl);
        let waited_ff = 0;
        const _ffPoll = setInterval(() => {
          waited_ff += 200;
          if (MjpegCanvas.width > 0) {
            clearInterval(_ffPoll);
            clearTimeout(ffmpegTimer);
            if (offlineEl) offlineEl.style.display = 'none';
            declareConnected(mjpegC_ff);
          } else if (waited_ff >= 15000) {
            clearInterval(_ffPoll);
            MjpegCanvas.stop();
            fetch(proxyUrl, { credentials: 'include' }).then(async errRes => {
              if (errRes.status === 503) {
                const errData = await errRes.json().catch(() => ({}));
                if (errData.error === 'ffmpeg_not_found') {
                  triggerOfflineUI(
                    'FFmpeg not installed on server',
                    'On the machine running CatchCatchTV, run: ' +
                    '<code>sudo apt install ffmpeg</code> (Linux) &nbsp;|&nbsp; ' +
                    '<code>winget install ffmpeg</code> (Windows) &nbsp;|&nbsp; ' +
                    '<code>brew install ffmpeg</code> (Mac). Then reconnect.'
                  );
                  return;
                }
              }
              triggerOfflineUI(
                'Stream error',
                'Could not reach the camera via FFmpeg. Check the URL, credentials, and that the camera is on the same network as the server.'
              );
            }).catch(() => triggerOfflineUI());
          }
        }, 200);
      } else {
        // Canvas element missing — fall back to <img>
        feed.onerror = async () => {
          clearTimeout(ffmpegTimer);
          try {
            const errRes = await fetch(proxyUrl, { credentials: 'include' });
            if (errRes.status === 503) {
              const errData = await errRes.json().catch(() => ({}));
              if (errData.error === 'ffmpeg_not_found') {
                triggerOfflineUI(
                  'FFmpeg not installed on server',
                  'On the machine running CatchCatchTV, run: ' +
                  '<code>sudo apt install ffmpeg</code> (Linux) &nbsp;|&nbsp; ' +
                  '<code>winget install ffmpeg</code> (Windows) &nbsp;|&nbsp; ' +
                  '<code>brew install ffmpeg</code> (Mac). Then reconnect.'
                );
                return;
              }
            }
          } catch (_) {}
          triggerOfflineUI(
            'Stream error',
            'Could not reach the camera via FFmpeg. Check the URL, credentials, and that the camera is on the same network as the server.'
          );
        };
        feed.onload = () => {
          if (feed.naturalWidth > 0) {
            clearTimeout(ffmpegTimer);
            if (offlineEl) offlineEl.style.display = 'none';
            declareConnected(feed);
          }
        };
        if (offlineEl) offlineEl.style.display = 'flex';
        feed.style.display = 'block';
        feed.src = proxyUrl;
      }

      // FIX (Bug 5): Set _audioCamId so the mic button uses /api/camera/ffmpeg-audio.
      // Leave _audioLanStreamUrl null so it routes to the server proxy, not LAN direct.
      window._audioCamId = camId;
      window._audioLanStreamUrl = null;
      return;
    }

    // Unknown protocol on LAN - show bridge instructions
    _showLanInstructions(camId, camUrl, msgEl, subEl, offlineEl, feed, declareConnected, triggerOfflineUI);
    return;
  }

  // ==========================================
  // http  -> load directly in img tag (no CORS issues for same-network/public cameras)
  // https -> route through server proxy which uses verify=False + Digest-auth retry
  //
  // CRITICAL FIX: camId must be resolved BEFORE building the URL.
  // Previously _camIdForProxy was read from window.activeCameraId which could be
  // stale during camera switching, causing the proxy to serve the wrong camera
  // or fall back to the direct HTTPS URL (which self-signed certs reject).
  const _camIdForProxy = camId;
  const isProxied = (scheme === 'https' && _camIdForProxy != null);
  const feedSrc   = isProxied ? `/api/camera/proxy?cam_id=${_camIdForProxy}` : camUrl;

  let connectTimer = setTimeout(() => {
    if (!connected) triggerOfflineUI('Camera timed out', 'The stream did not respond in 12 s. Check the URL and camera status.');
  }, 12000);

  const _publicFallbackToImg = (src) => {
    MjpegCanvas.stop();
    feed.onerror = () => {
      clearTimeout(connectTimer);
      if (isProxied && feed.src.includes('/api/camera/proxy')) {
        feed.src = camUrl;
        connectTimer = setTimeout(() => { if (!connected) triggerOfflineUI(); }, 8000);
        return;
      }
      triggerOfflineUI('Camera offline', 'Could not reach the camera. Check the URL and network.');
    };
    feed.onload = () => {
      if (feed.naturalWidth > 0) { clearTimeout(connectTimer); declareConnected(feed); }
    };
    feed.removeAttribute('crossorigin');
    feed.src = src;
  };

  const mjpegC = document.getElementById('mjpegCanvas');
  if (mjpegC) {
    MjpegCanvas.start(feedSrc);
    let waited = 0;
    const _poll = setInterval(() => {
      waited += 200;
      if (MjpegCanvas.width > 0) {
        clearInterval(_poll);
        clearTimeout(connectTimer);
        declareConnected(mjpegC);
      } else if (waited >= 4000) {
        clearInterval(_poll);
        _publicFallbackToImg(feedSrc);
      }
    }, 200);
  } else {
    _publicFallbackToImg(feedSrc);
  }

  window._audioCamId = camId;
}

// ==========================================
// Show LAN instructions with bridge download + polling
// ==========================================
function _showLanInstructions(camId, camUrl, msgEl, subEl, offlineEl, feed, declareConnected, triggerOfflineUI) {
  if (!offlineEl) return;

  // Guard: if bridge polling is already running for this camera, skip re-init
  if (window._bridgePollingCamId === camId && window._bridgePollingActive) {
    return;
  }

  // Take over the entire overlay so we can scroll and lay out freely
  offlineEl.style.display = 'flex';
  offlineEl.style.alignItems = 'flex-start';
  offlineEl.style.justifyContent = 'flex-start';
  offlineEl.style.overflowY = 'auto';
  offlineEl.style.padding = '0';

  const downloadBtn = camId
    ? `<a href="/api/camera/bridge/download/${camId}"
         style="display:inline-flex;align-items:center;gap:8px;padding:10px 20px;
                background:#2563eb;color:#fff;border-radius:8px;text-decoration:none;
                font-size:0.88rem;font-weight:700;box-shadow:0 2px 8px rgba(37,99,235,0.4);
                margin-top:4px;">&#8659; Download bridge.py</a>
       <div style="margin-top:6px;font-size:0.75rem;color:#94a3b8;">
         Requires: Python 3.8+ &middot; FFmpeg &middot; pip install requests
       </div>`
    : '';

  offlineEl.innerHTML = `
    <div style="width:100%;height:100%;overflow-y:auto;padding:20px 24px;box-sizing:border-box;
                font-family:sans-serif;font-size:0.83rem;line-height:1.6;color:#cbd5e1;text-align:left;">

      <div style="display:flex;align-items:center;gap:10px;margin-bottom:6px;">
        <svg style="width:18px;height:18px;flex-shrink:0;" fill="none" stroke="#60a5fa" stroke-width="2" viewBox="0 0 24 24">
          <path d="M1 6l5 5a8 8 0 0 1 12 0l5-5A16 16 0 0 0 1 6z"/>
          <path d="M5 10l4 4a6 6 0 0 1 6 0l4-4"/>
          <circle cx="12" cy="20" r="1" fill="#60a5fa"/>
        </svg>
        <div style="font-size:1rem;font-weight:700;color:#f1f5f9;">Camera on Local Network</div>
      </div>
      <p style="margin:0 0 14px;color:#b0bec5;font-size:0.8rem;">
        Your camera (<strong style="color:#e2e8f0;">${camUrl || 'this IP'}</strong>) is on your home network.
        Follow the steps below to connect it — takes about 2 minutes.
        The bridge works with <strong style="color:#e2e8f0;">all protocols</strong>: RTSP, RTMP, RTMPS, ONVIF, and HTTP cameras.
      </p>

      <div style="background:rgba(37,99,235,0.1);border:1px solid rgba(37,99,235,0.3);
                  border-radius:8px;padding:11px 14px;margin-bottom:16px;">
        <div style="display:flex;align-items:center;gap:8px;font-weight:700;color:#93c5fd;margin-bottom:4px;">
          <svg style="width:14px;height:14px;flex-shrink:0;" fill="none" stroke="#93c5fd" stroke-width="2" viewBox="0 0 24 24">
            <rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/>
          </svg>
          Quickest: Same Wi-Fi
        </div>
        <div style="color:#cbd5e1;">Open this page on a device connected to the <strong style="color:#e2e8f0;">same Wi-Fi as your camera</strong>, then press Connect. No extra setup needed.</div>
      </div>

      <div style="display:flex;align-items:center;gap:8px;font-weight:700;color:#f1f5f9;margin-bottom:10px;">
        <svg style="width:14px;height:14px;flex-shrink:0;" fill="none" stroke="#f1f5f9" stroke-width="2" viewBox="0 0 24 24">
          <path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/>
        </svg>
        Bridge Script Setup (works from anywhere)
      </div>

      <div style="display:flex;flex-direction:column;gap:12px;">

        <div style="display:flex;gap:12px;align-items:flex-start;">
          <div style="min-width:24px;height:24px;background:#2563eb;border-radius:50%;
                      display:flex;align-items:center;justify-content:center;
                      font-weight:700;font-size:0.75rem;color:#fff;flex-shrink:0;margin-top:2px;">1</div>
          <div style="color:#cbd5e1;">
            <strong style="color:#f1f5f9;">Download the bridge script</strong> and save it anywhere on your PC.<br>
            ${camId ? `<a href="/api/camera/bridge/download/${camId}"
              style="display:inline-flex;align-items:center;gap:6px;margin-top:7px;padding:7px 16px;
                     background:#2563eb;color:#fff;border-radius:7px;text-decoration:none;
                     font-size:0.82rem;font-weight:700;">&#8659; Download bridge.py</a>` : ''}
          </div>
        </div>

        <div style="display:flex;gap:12px;align-items:flex-start;">
          <div style="min-width:24px;height:24px;background:#2563eb;border-radius:50%;
                      display:flex;align-items:center;justify-content:center;
                      font-weight:700;font-size:0.75rem;color:#fff;flex-shrink:0;margin-top:2px;">2</div>
          <div style="color:#cbd5e1;">
            <strong style="color:#f1f5f9;">Download FFmpeg</strong> — this reads your camera stream.<br>
            <a href="/api/ffmpeg/download"
              style="display:inline-flex;align-items:center;gap:6px;margin-top:7px;padding:7px 16px;
                     background:#0f766e;color:#fff;border-radius:7px;text-decoration:none;
                     font-size:0.82rem;font-weight:700;">&#8659; Download ffmpeg.exe</a>
            <div style="margin-top:8px;background:rgba(15,118,110,0.12);border:1px solid rgba(15,118,110,0.3);
                        border-radius:6px;padding:8px 12px;font-size:0.78rem;color:#cbd5e1;">
              Just save <code style="color:#7dd3fc;">ffmpeg.exe</code> in the <strong style="color:#e2e8f0;">same folder as bridge.py</strong> — no setup, no PATH, no extracting zips.
            </div>
          </div>
        </div>

        <div style="display:flex;gap:12px;align-items:flex-start;">
          <div style="min-width:24px;height:24px;background:#2563eb;border-radius:50%;
                      display:flex;align-items:center;justify-content:center;
                      font-weight:700;font-size:0.75rem;color:#fff;flex-shrink:0;margin-top:2px;">3</div>
          <div style="color:#cbd5e1;">
            <strong style="color:#f1f5f9;">Open Command Prompt</strong> and run this one command:<br>
            <code style="display:inline-block;background:#0f172a;border:1px solid #334155;border-radius:5px;
                         padding:4px 12px;margin-top:6px;color:#7dd3fc;font-size:0.83rem;">pip install requests</code>
          </div>
        </div>

        <div style="display:flex;gap:12px;align-items:flex-start;">
          <div style="min-width:24px;height:24px;background:#2563eb;border-radius:50%;
                      display:flex;align-items:center;justify-content:center;
                      font-weight:700;font-size:0.75rem;color:#fff;flex-shrink:0;margin-top:2px;">4</div>
          <div style="color:#cbd5e1;">
            <strong style="color:#f1f5f9;">Run bridge.py</strong> — in CMD, go to where you saved it and run:<br>
            <code style="display:inline-block;background:#0f172a;border:1px solid #334155;border-radius:5px;
                         padding:4px 12px;margin-top:6px;color:#7dd3fc;font-size:0.83rem;">python bridge.py</code>
          </div>
        </div>

        <div style="display:flex;gap:12px;align-items:flex-start;">
          <div style="min-width:24px;height:24px;background:#16a34a;border-radius:50%;
                      display:flex;align-items:center;justify-content:center;
                      font-weight:700;font-size:0.75rem;color:#fff;flex-shrink:0;margin-top:2px;">5</div>
          <div style="color:#cbd5e1;">
            <strong style="color:#f1f5f9;">Leave CMD open</strong> and come back to this page.
            Your camera will connect automatically within seconds.
          </div>
        </div>

      </div>

      <div style="margin-top:16px;padding-top:10px;border-top:1px solid #1e293b;
                  display:flex;align-items:flex-start;gap:8px;font-size:0.75rem;color:#94a3b8;">
        <svg style="width:13px;height:13px;flex-shrink:0;margin-top:1px;" fill="none" stroke="#60a5fa" stroke-width="2" viewBox="0 0 24 24">
          <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
        </svg>
        No port forwarding needed — bridge.py connects outward to the app, your router needs no changes.
      </div>
    </div>`;

  updateStatus('offline');
  showStreamBtns(false);
  connected = false;

  if (!camId) return;

  // Mark polling active so double-clicks are ignored
  window._bridgePollingCamId    = camId;
  window._bridgePollingActive   = true;

  // Inject a large centered floating status badge visible in the middle of the screen
  const _statusId = '_bridgeStatusLine';
  let _existingStatus = document.getElementById(_statusId);
  if (!_existingStatus) {
    const _statusDiv = document.createElement('div');
    _statusDiv.id = _statusId;
    _statusDiv.style.cssText = [
      'position:fixed', 'bottom:28px', 'left:50%',
      'transform:translateX(-50%)',
      'background:#0d1526',
      'border:1.5px solid rgba(59,130,246,0.5)',
      'border-radius:14px',
      'padding:16px 24px',
      'display:flex', 'flex-direction:row', 'align-items:flex-start', 'gap:14px',
      'min-width:320px', 'max-width:min(560px,92vw)',
      'box-shadow:0 8px 32px rgba(0,0,0,0.85)',
      'z-index:9999',
      'pointer-events:none'
    ].join(';');
    _statusDiv.innerHTML = `
      <svg style="width:28px;height:28px;animation:spin 1s linear infinite;flex-shrink:0;margin-top:2px;" viewBox="0 0 24 24" fill="none" stroke="#3b82f6" stroke-width="2">
        <circle cx="12" cy="12" r="10" stroke-opacity="0.18"/>
        <path d="M12 2a10 10 0 0 1 10 10" stroke-linecap="round"/>
      </svg>
      <div style="min-width:0;">
        <div style="font-size:0.9rem;font-weight:700;color:#f1f5f9;margin-bottom:3px;">Waiting for Bridge</div>
        <div id="_bridgeStatusText" style="font-size:0.8rem;color:#94a3b8;line-height:1.4;margin-bottom:8px;">Checking in 3 s</div>
        <div style="display:flex;align-items:flex-start;gap:7px;">
          <svg style="width:13px;height:13px;flex-shrink:0;margin-top:1px;" fill="none" stroke="#60a5fa" stroke-width="2" viewBox="0 0 24 24">
            <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
          </svg>
          <span style="font-size:0.75rem;color:#94a3b8;line-height:1.5;">First-time check takes up to 10 min. Once your bridge is running, future connections are near-instant.</span>
        </div>
      </div>`;
    document.body.appendChild(_statusDiv);
  }
  const _setStatusText = (txt, color) => {
    const el = document.getElementById('_bridgeStatusText');
    if (el) { el.textContent = txt; if (color) el.style.color = color; }
  };

  // Poll for bridge connection
  let _pollCount = 0;
  const _poll = async () => {
    _pollCount++;
    if (_pollCount > 120) {
      _setStatusText('Bridge timed out — re-run bridge.py and press Connect.', '#f87171');
      window._bridgePollingActive = false;
      return;
    }
    _setStatusText(`Waiting for bridge… check ${_pollCount} of 120`, '#94a3b8');
    try {
      const r = await fetch(`/api/camera/bridge/status/${camId}`);
      if (!r.ok) { setTimeout(_poll, 5000); return; }
      const data = await r.json();
      if (data.connected) {
        window._bridgePollingActive = false;
        const _badge = document.getElementById('_bridgeStatusLine'); if (_badge) _badge.remove();
        // Restore the overlay to its original simple state so the feed can show
        if (offlineEl) {
          offlineEl.style.display = 'none';
          offlineEl.style.alignItems = '';
          offlineEl.style.justifyContent = '';
          offlineEl.style.overflowY = '';
          offlineEl.style.padding = '';
          // Restore original children (svg + two p tags) so feed shows properly
          offlineEl.innerHTML = `
            <svg style="width:56px;height:56px;color:#64748b;margin-bottom:16px;display:block;" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M16 16v1a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V7a2 2 0 0 1 2-2h2m5.66 0H14a2 2 0 0 1 2 2v3.34l1 1L23 7v10"></path>
              <line x1="2" y1="2" x2="22" y2="22" stroke-linecap="round" stroke-width="2"></line>
            </svg>
            <p id="offlineMsg" style="color:#94a3b8;font-weight:700;font-size:1.1rem;letter-spacing:0.08em;font-family:var(--display),sans-serif;text-align:center;margin:0;text-transform:uppercase;">Offline</p>
            <p id="offlineSub" style="color:#64748b;font-size:0.85rem;margin-top:8px;">Camera disconnected or unreachable</p>`;
        }
        feed.style.display = 'block';
        feed.src = `/api/camera/bridge/relay/${camId}`;
        feed.onload  = () => { if (feed.naturalWidth > 0) declareConnected(feed); };
        feed.onerror = triggerOfflineUI;
        setTimeout(_poll, 5000);
        return;
      } else {
        _setStatusText(`Bridge not connected yet — check ${_pollCount} of 120`, '#94a3b8');
      }
    } catch(e) { _setStatusText(`Retrying… (${_pollCount}/120)`, '#94a3b8'); }
    setTimeout(_poll, 5000);
  };
  setTimeout(_poll, 3000);
}

async function connectLocalCam() {
  try {
    localStream = await navigator.mediaDevices.getUserMedia({
      video: {width:720, height:480, facingMode:'environment'},
      audio: false
    });
    isCamOn = true;
    const camBtn = document.getElementById('camToggleBtn');
    if (camBtn && typeof svgCamOn !== 'undefined') { camBtn.innerHTML = svgCamOn; camBtn.classList.remove('off'); }
    const localVideo = document.getElementById('localVideo');
    if (localVideo) {
      localVideo.srcObject = localStream;
      localVideo.style.display = 'block';
      localVideo.style.opacity = isCamOn ? '1' : '0';
      localVideo.play().catch(e => console.warn(e));
    }
    const ipFeed = document.getElementById('ipFeed');
    if (ipFeed) ipFeed.style.display = 'none';
    const offlineUI = document.getElementById('feedOffline');
    if (offlineUI) offlineUI.style.display = 'none';
    const camOffUI = document.getElementById('camOffOverlay');
    if (camOffUI) camOffUI.style.display = isCamOn ? 'none' : 'flex';
    connected = true;
    updateStatus('online');
    showStreamBtns(true);
    startDetection();
  } catch(err) {
    console.error('Camera Error:', err);
    const offlineUI = document.getElementById('feedOffline');
    if (offlineUI) offlineUI.style.display = 'flex';
    updateStatus('offline');
  }
}

function doDisconnect() {
  connected = false;
  // Reset bridge polling guard so the next Connect press re-starts cleanly
  window._bridgePollingActive = false;
  window._bridgePollingCamId  = null;
  const _badge = document.getElementById('_bridgeStatusLine'); if (_badge) _badge.remove();
  stopDetection();

  const feed = document.getElementById('ipFeed');
  if (feed) { feed.onload = null; feed.onerror = null; feed.src = ''; feed.style.display = 'none'; }
  MjpegCanvas.stop();

  const hlsVideo = document.getElementById('hlsVideo');
  if (hlsVideo) { hlsVideo.pause(); hlsVideo.src = ''; hlsVideo.style.display = 'none'; }
  if (window._hlsInstance) { window._hlsInstance.destroy(); window._hlsInstance = null; }

  WebAudioStream.stop(); // stop any active fetch-stream audio
  _stopAudioDrainTimer();
  const audioFeed = document.getElementById('camAudio');
  if (audioFeed) { audioFeed.pause(); audioFeed.src = ''; audioFeed.muted = true; }
  window._audioCamId = null;
  window._audioLanStreamUrl = null;
  isMicOn = false;
  const _micBtnD = document.getElementById('micToggleBtn');
  if (_micBtnD && typeof svgMicOff !== 'undefined') { _micBtnD.innerHTML = svgMicOff; _micBtnD.classList.add('off'); }
  if (localStream) { localStream.getTracks().forEach(t => t.stop()); localStream = null; }
  if (localVideo)  { localVideo.srcObject = null; localVideo.style.display = 'none'; }
  if (feedOffline) feedOffline.style.display = 'flex';
  // Reset the offline message so the user sees 'Press Connect' after disconnecting,
  // not the stale 'Connecting to local camera...' text set during connectIPCam.
  const _omD = document.getElementById('offlineMsg');
  const _osD = document.getElementById('offlineSub');
  if (_omD) { _omD.style.color = ''; _omD.innerHTML = 'Press Connect to start'; }
  if (_osD) { _osD.style.color = ''; _osD.textContent = 'Camera disconnected or unreachable'; }

  updateStatus('offline');
  showStreamBtns(false);
  uptimeMin = 0;
  if (statUptime) statUptime.textContent = '0m';
}

function updateCCTVTime() {
  const now = new Date();
  const months = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
  const m = months[now.getMonth()], d = now.getDate(), y = now.getFullYear();
  let hr = now.getHours();
  const min = now.getMinutes().toString().padStart(2,'0');
  const sec = now.getSeconds().toString().padStart(2,'0');
  const ampm = hr >= 12 ? 'PM' : 'AM';
  hr = hr % 12 || 12;
  document.querySelectorAll('.live-timestamp').forEach(el => {
    el.textContent = `${m} ${d}, ${y} ${hr}:${min}:${sec} ${ampm}`;
  });
}
setInterval(updateCCTVTime, 1000);
updateCCTVTime();

function showStreamBtns(s) {
  const startBtn = document.getElementById('startBtn');
  const stopBtn  = document.getElementById('stopBtn');
  const cctvOverlay = document.getElementById('cctvOverlay');
  const controlsOverlay = document.getElementById('camControlsOverlay');
  if (startBtn) { startBtn.classList.toggle('hidden', s); startBtn.style.display = s ? 'none' : 'flex'; }
  if (stopBtn)  { stopBtn.classList.toggle('hidden', !s); stopBtn.style.display = s ? 'flex' : 'none'; }
  if (cctvOverlay) cctvOverlay.style.display = s ? 'flex' : 'none';
  if (controlsOverlay) controlsOverlay.style.display = s ? 'flex' : 'none';
  const statsOverlay = document.getElementById('cctvStatsOverlay');
  if (statsOverlay) statsOverlay.style.display = s ? 'flex' : 'none';
  if (!s) {
    const camOffOverlay = document.getElementById('camOffOverlay');
    if (camOffOverlay) camOffOverlay.style.display = 'none';
    isCamOn = false; isMicOn = false;
    const camBtn = document.getElementById('camToggleBtn');
    const micBtn = document.getElementById('micToggleBtn');
    if (camBtn && typeof svgCamOff !== 'undefined') { camBtn.innerHTML = svgCamOff; camBtn.classList.add('off'); }
    if (micBtn && typeof svgMicOff !== 'undefined') { micBtn.innerHTML = svgMicOff; micBtn.classList.add('off'); }
  }
}

function updateStatus(s) {
  const L  = {online:'Online', offline:'Offline', connecting:'Connecting...'};
  const C  = {online:'var(--green)', offline:'var(--red)', connecting:'#f59e0b'};
  const BG = {online:'rgba(16,185,129,0.10)', offline:'rgba(214,25,74,0.08)', connecting:'rgba(245,158,11,0.10)'};
  const BD = {online:'rgba(16,185,129,0.25)', offline:'rgba(214,25,74,0.20)', connecting:'rgba(245,158,11,0.30)'};
  const statusBadge = document.getElementById('statusBadge');
  if (statusBadge) { statusBadge.textContent = L[s]||s; statusBadge.className=`status-badge ${s}`; }
  const statCam = document.getElementById('statCam');
  if (statCam) {
    statCam.textContent = L[s]||s;
    statCam.style.color = C[s]||'var(--text2)';
    statCam.style.background = BG[s]||'transparent';
    statCam.style.borderColor = BD[s]||'transparent';
  }
}

setInterval(() => {
  if (!connected) return;
  uptimeMin++;
  if (statUptime) statUptime.textContent = uptimeMin > 59 ? `${Math.floor(uptimeMin/60)}h ${uptimeMin%60}m` : `${uptimeMin}m`;
}, 60000);

window.addEventListener('resize', () => { if (connected && typeof AI_ENABLED !== 'undefined' && AI_ENABLED) syncCanvas(); });
if (typeof ResizeObserver !== 'undefined' && feedWrap) {
  new ResizeObserver(() => { if (connected && typeof AI_ENABLED !== 'undefined' && AI_ENABLED) syncCanvas(); }).observe(feedWrap);
}

function updateKpiCounts() {
  const total = catCount.ACCOUNTS + catCount.DETECTION + catCount.STATUS;
  if (statTotal)     statTotal.textContent     = total;
  if (statAccounts)  statAccounts.textContent  = catCount.ACCOUNTS;
  if (statDetection) statDetection.textContent = catCount.DETECTION;
  if (statStatus)    statStatus.textContent    = catCount.STATUS;
}

function applyFilter(cat) {
  activeFilter = cat;
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.toggle('active', b.dataset.cat === cat));
  document.querySelectorAll('.stat-card, .feed-kpi-item').forEach(c => c.classList.toggle('active-filter', c.dataset.kpi === cat));
  if (typeof applyLiveFilters === 'function') applyLiveFilters();
}

document.querySelectorAll('.stat-card, .feed-kpi-item').forEach(card => {
  card.addEventListener('click', () => applyFilter(activeFilter === card.dataset.kpi ? '' : card.dataset.kpi));
});
document.querySelectorAll('.filter-btn').forEach(btn => {
  btn.addEventListener('click', () => applyFilter(btn.dataset.cat));
});
document.querySelectorAll('#logoutBtn, .logout-btn').forEach(btn => {
  btn.addEventListener('click', async (e) => { e.preventDefault(); doDisconnect(); window.location.href = '/logout'; });
});

function fmtTime(iso) {
  try { return new Date(iso).toLocaleTimeString('en-PH', {hour12:false}); } catch { return ''; }
}

const SEV_LABEL = { INFO:'Info', WARNING:'Notice', ALERT:'Alert', CRITICAL:'Critical' };

function logToUI(entry) {
  if (!logList) return;
  if (entry && entry.__action === 'clear') {
    logList.innerHTML = '<div class="log-placeholder">Logs cleared.</div>';
    sevCount.INFO = sevCount.WARNING = sevCount.ALERT = sevCount.CRITICAL = 0;
    catCount.ACCOUNTS = catCount.DETECTION = catCount.STATUS = 0;
    updateKpiCounts();
    if (logCount) logCount.textContent = '0 entries';
    return;
  }
  const ph = logList.querySelector('.log-placeholder');
  if (ph) ph.remove();
  const sev  = (entry.severity   || 'INFO').toUpperCase();
  const type = (entry.event_type || '').toUpperCase();
  if (sev in sevCount) sevCount[sev]++;
  const cat = getLogCategory(type, sev);
  if (cat in catCount) { catCount[cat]++; updateKpiCounts(); }
  const div = document.createElement('div');
  div.className   = `log-entry sev-${sev}`;
  div.dataset.sev = sev;
  div.dataset.cat = cat;
  if (typeof window.activeCameraId !== 'undefined' && window.activeCameraId) {
    div.dataset.camId = window.activeCameraId;
  }
  const dot      = document.createElement('div');  dot.className = 'sev-dot';
  const body     = document.createElement('div');
  const descRow  = document.createElement('div');  descRow.className = 'log-desc';
  const tag      = document.createElement('span'); tag.className = 'log-sev-tag'; tag.textContent = SEV_LABEL[sev]||sev;
  descRow.appendChild(tag);
  descRow.appendChild(document.createTextNode(entry.description || ''));
  const metaRow  = document.createElement('div');  metaRow.className = 'log-meta';
  metaRow.textContent = `${cat}${entry.ip ? ' - '+entry.ip : ''} - ${fmtTime(entry.timestamp)}`;
  body.appendChild(descRow); body.appendChild(metaRow);
  div.appendChild(dot); div.appendChild(body);
  const sortRadios = document.querySelectorAll('input[name="logSort"]');
  let sortOrder = 'newest';
  sortRadios.forEach(r => { if(r.checked) sortOrder = r.value; });
  if (sortOrder === 'newest') logList.prepend(div);
  else logList.appendChild(div);
  while (logList.children.length > 150) {
    if (sortOrder === 'newest') logList.removeChild(logList.lastChild);
    else logList.removeChild(logList.firstChild);
  }
  if (typeof applyLiveFilters === 'function') applyLiveFilters();
}

const clearLogsBtn = document.getElementById('clearLogsBtn');
if (clearLogsBtn) {
  clearLogsBtn.addEventListener('click', async () => {
    if (!confirm('Clear all your logs?')) return;
    const r = await fetch('/api/logs/clear', {method:'POST', credentials:'include', headers:{'X-CSRFToken':getCsrfToken()}});
    if (r.ok && logList) {
      logList.innerHTML = '<div class="log-placeholder">Logs cleared.</div>';
      sevCount.INFO = sevCount.WARNING = sevCount.ALERT = sevCount.CRITICAL = 0;
      catCount.ACCOUNTS = catCount.DETECTION = catCount.STATUS = 0;
      updateKpiCounts();
      if (logCount) logCount.textContent = '0 entries';
    }
  });
}

function connectSSE() {
  if (!logList) return;
  const initialPh = logList.querySelector('.log-placeholder');
  if (initialPh) initialPh.textContent = 'System active. Waiting for logs...';
  const es = new EventSource('/api/logs/stream', {withCredentials: true});
  es.onopen = () => {
    const ph = logList.querySelector('.log-placeholder');
    if (ph) ph.textContent = 'System active. Waiting for logs...';
  };
  es.onmessage = e => { try { logToUI(JSON.parse(e.data)); } catch(_){} };
  es.onerror = () => {
    es.close();
    const ph = logList.querySelector('.log-placeholder');
    if (ph) ph.textContent = 'Stream disconnected. Reconnecting...';
    setTimeout(connectSSE, 5000);
  };
}

function resetIdle() {
  clearTimeout(idleTimer);
  idleTimer = setTimeout(async () => { doDisconnect(); window.location.href = '/logout'; }, 30 * 60 * 1000);
}

['mousemove','keydown','click','scroll','touchstart'].forEach(ev => {
  document.addEventListener(ev, resetIdle, {passive:true});
});

setInterval(() => {
  fetch('/api/status', {credentials:'include'}).catch(err => console.error('Heartbeat error:', err));
}, 10 * 60 * 1000);

const TAB_ID = Date.now().toString();
if (startBtn) {
  startBtn.addEventListener('click', () => localStorage.setItem('cg_tab', TAB_ID));
}
window.addEventListener('storage', e => {
  if (e.key === 'cg_tab' && e.newValue !== TAB_ID && connected) {
    doDisconnect();
    if (offlineMsg) offlineMsg.textContent = 'Stream started in another tab';
  }
});

// ==========================================
// REAL-TIME FILTERING & SORTING
// ==========================================
function applyLiveFilters() {
  const searchInput = document.getElementById('logSearchInput');
  const sevSelect   = document.getElementById('logSevSelect');
  const query = searchInput ? searchInput.value.toLowerCase() : '';
  const sev   = sevSelect ? sevSelect.value : 'ALL';
  document.querySelectorAll('.log-entry').forEach(log => {
    const text    = log.textContent.toLowerCase();
    const logSev  = log.dataset.sev || 'INFO';
    const matchesSearch = text.includes(query);
    const matchesSev    = (sev === 'ALL' || logSev === sev);
    const matchesCat    = (!activeFilter || log.dataset.cat === activeFilter);
    if (matchesSearch && matchesSev && matchesCat) { log.style.display = ''; log.classList.remove('hidden-filter'); }
    else { log.style.display = 'none'; log.classList.add('hidden-filter'); }
  });
  const logCount = document.getElementById('logCount');
  if (logCount) logCount.textContent = document.querySelectorAll('.log-entry:not(.hidden-filter)').length + ' entries';
}

document.addEventListener('DOMContentLoaded', () => {
  if (aiPill) {
    if (typeof AI_ENABLED !== 'undefined' && AI_ENABLED) { aiPill.textContent = 'AI on'; aiPill.classList.add('on'); }
    else { aiPill.textContent = 'AI off'; aiPill.classList.remove('on'); }
  }
  if (setupHint) setupHint.style.display = (typeof CAMERA_URL !== 'undefined' && CAMERA_URL) ? 'none' : 'block';

  const searchInput = document.getElementById('logSearchInput');
  const sevSelect   = document.getElementById('logSevSelect');
  const filterBtn   = document.getElementById('logFilterBtn');
  const filterMenu  = document.getElementById('logFilterMenu');
  const sortRadios  = document.querySelectorAll('input[name="logSort"]');
  const logListEl   = document.getElementById('logList');

  setMode('ip');

  const modeIpBtn  = document.getElementById('modeIpBtn');
  const modeWebBtn = document.getElementById('modeWebBtn');
  if (modeIpBtn)  modeIpBtn.addEventListener('click',  () => setMode('ip'));
  if (modeWebBtn) modeWebBtn.addEventListener('click', () => setMode('webcam'));

  connectSSE();

  if (searchInput) searchInput.addEventListener('input', applyLiveFilters);
  if (sevSelect)   sevSelect.addEventListener('change', applyLiveFilters);

  if (filterBtn && filterMenu) {
    filterBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      filterMenu.style.display = filterMenu.style.display === 'none' ? 'block' : 'none';
      filterBtn.style.background  = filterMenu.style.display === 'block' ? 'rgba(0,120,200,0.1)' : 'transparent';
      filterBtn.style.borderColor = filterMenu.style.display === 'block' ? 'var(--blue)' : 'var(--border2)';
      filterBtn.style.color       = filterMenu.style.display === 'block' ? 'var(--blue)' : 'var(--text2)';
    });
    document.addEventListener('click', (e) => {
      if (!filterMenu.contains(e.target) && e.target !== filterBtn) {
        filterMenu.style.display = 'none';
        filterBtn.style.background = 'transparent';
        filterBtn.style.borderColor = 'var(--border2)';
        filterBtn.style.color = 'var(--text2)';
      }
    });
  }

  if (sortRadios.length > 0) {
    sortRadios.forEach(radio => {
      radio.addEventListener('change', () => {
        if (!logListEl) return;
        const logs = Array.from(document.querySelectorAll('.log-entry'));
        logs.reverse();
        logs.forEach(log => logListEl.appendChild(log));
      });
    });
  }
});

// ==========================================
// MEDIA CONTROLS & SNAPSHOTS
// ==========================================
let isMicOn = false;
let isCamOn = false;

const svgMicOn  = `<svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M12 1a3 3 0 0 0-3 3v8a3 3 0 0 0 6 0V4a3 3 0 0 0-3-3z"></path><path d="M19 10v2a7 7 0 0 1-14 0v-2"></path><line x1="12" y1="19" x2="12" y2="23"></line><line x1="8" y1="23" x2="16" y2="23"></line></svg>`;
const svgMicOff = `<svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><line x1="1" y1="1" x2="23" y2="23"></line><path d="M9 9v3a3 3 0 0 0 5.12 2.12M15 9.34V4a3 3 0 0 0-5.94-.6"></path><path d="M17 16.95A7 7 0 0 1 5 12v-2m14 0v2a7 7 0 0 1-.11 1.23"></path><line x1="12" y1="19" x2="12" y2="23"></line><line x1="8" y1="23" x2="16" y2="23"></line></svg>`;
const svgCamOn  = `<svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><polygon points="23 7 16 12 23 17 23 7"></polygon><rect x="1" y="5" width="15" height="14" rx="2" ry="2"></rect></svg>`;
const svgCamOff = `<svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M16 16v1a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V7a2 2 0 0 1 2-2h2m5.66 0H14a2 2 0 0 1 2 2v3.34l1 1L23 7v10"></path><line x1="1" y1="1" x2="23" y2="23"></line></svg>`;
const svgSnap   = `<svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M23 19a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4l2-3h6l2 3h4a2 2 0 0 1 2 2z"></path><circle cx="12" cy="13" r="4"></circle></svg>`;

const micBtn  = document.getElementById('micToggleBtn');
const camBtn  = document.getElementById('camToggleBtn');
const snapBtn = document.getElementById('snapshotBtn');

if (micBtn)  { micBtn.innerHTML  = svgMicOff; micBtn.classList.add('off'); }
if (camBtn)  { camBtn.innerHTML  = svgCamOff; camBtn.classList.add('off'); }
if (snapBtn)   snapBtn.innerHTML = svgSnap;

if (snapBtn) {
  snapBtn.addEventListener('click', async () => {
    if (!connected) return alert('Please connect to a camera first!');
    const canvas = await captureFrame();
    if (!canvas) return alert('Failed to capture frame. Stream might still be loading.');
    const link = document.createElement('a');
    link.download = `CatchCatchTV_Snapshot_${new Date().toISOString().replace(/[:.]/g,'-')}.png`;
    link.href = canvas.toDataURL('image/png');
    link.click();
  });
}

function _showAudioToast(msg, isError) {
  var existing = document.getElementById('audioToast');
  if (existing) existing.remove();
  var host = document.getElementById('feedWrap') || document.body;
  var inFeed = host !== document.body;
  var toast = document.createElement('div');
  toast.id = 'audioToast';
  toast.textContent = msg;
  var bg = isError ? 'rgba(214,25,74,0.92)' : 'rgba(16,185,129,0.88)';
  toast.style.cssText = 'position:' + (inFeed ? 'absolute' : 'fixed') +
    ';bottom:' + (inFeed ? '68px' : '80px') + ';left:50%;transform:translateX(-50%);background:' +
    bg + ';color:#fff;padding:9px 18px;border-radius:8px;font-size:13px;font-weight:600;' +
    'z-index:9999;pointer-events:none;transition:opacity 0.4s ease;text-align:center;' +
    'white-space:normal;max-width:' + (inFeed ? 'calc(100% - 32px)' : 'min(420px,calc(100vw - 32px))') + ';';
  host.appendChild(toast);
  setTimeout(function() { toast.style.opacity = '0'; setTimeout(function() { toast.remove(); }, 500); }, 3500);
}

let _audioDrainTimer = null;

function _stopAudioDrainTimer() {
  if (_audioDrainTimer) {
    clearInterval(_audioDrainTimer);
    _audioDrainTimer = null;
  }
}

function _startAudioDrainTimer(audioEl) {
  _stopAudioDrainTimer();
  _audioDrainTimer = setInterval(function() {
    if (!audioEl || audioEl.paused || audioEl.readyState < 2 || !audioEl.buffered.length) return;
    try {
      const liveEdge = audioEl.buffered.end(audioEl.buffered.length - 1);
      const lag = liveEdge - audioEl.currentTime;
      if (lag > 3.0) audioEl.currentTime = Math.max(0, liveEdge - 0.5);
    } catch(_) {}
  }, 3000);
}

// ==========================================
// WebAudioStream - zero-pre-buffer live audio via Web Audio API + fetch streaming.
//
// The browser's <audio> element always pre-buffers ~1-2 s before it starts
// playing - that's baked into its networking layer and can't be tuned away.
// The drain-loop trick can fix *accumulated* lag but can't fix the *initial*
// buffering delay because the browser hasn't started playing yet.
//
// Real fix: bypass <audio> entirely. We fetch() the raw HTTP stream ourselves,
// read it as a ReadableStream of bytes, decode each chunk with AudioContext
// .decodeAudioData(), and schedule the resulting AudioBuffers back-to-back on
// a precise timeline. This gives us <150 ms end-to-end latency instead of ~1 s.
//
// Used for same-origin server-proxied streams. LAN direct streams stay on
// <audio> because IP Webcam does not send CORS headers for browser fetch().
// Falls back to the old <audio> element path if Web Audio API is unavailable.
// ==========================================
const WebAudioStream = (() => {
  let _ctx = null;          // shared AudioContext
  let _abortCtrl = null;    // AbortController for the active fetch
  let _nextPlayAt = 0;      // AudioContext timestamp to schedule next buffer
  let _started = false;

  // Minimum chunk we try to decode at once (bytes). Smaller = lower latency
  // but more decode overhead. 8 KB is a sweet spot for 32-64 kbps audio.
  const CHUNK_BYTES = 8192;

  // How far ahead we allow the schedule to grow before we consider it "lagging"
  // and reset. Keeps us from building up a queue if decodes are slow.
  const MAX_AHEAD_SEC = 0.4;

  function _getCtx() {
    if (!_ctx || _ctx.state === 'closed') {
      const Ctor = window.AudioContext || window.webkitAudioContext;
      if (!Ctor) return null;
      _ctx = new Ctor({ latencyHint: 'interactive', sampleRate: 44100 });
    }
    return _ctx;
  }

  async function _resumeCtx(ctx) {
    if (ctx.state === 'suspended') {
      try { await ctx.resume(); } catch(_) {}
    }
  }

  // Accumulate bytes from the ReadableStream until we have at least CHUNK_BYTES,
  // then decode and schedule. Leftover bytes carry over to the next iteration.
  async function _pump(reader, ctx, signal) {
    let held = new Uint8Array(0);

    const _append = (a, b) => {
      const out = new Uint8Array(a.length + b.length);
      out.set(a, 0); out.set(b, a.length);
      return out;
    };

    while (!signal.aborted) {
      let chunk;
      try {
        const { value, done } = await reader.read();
        if (done || signal.aborted) break;
        chunk = value;
      } catch(e) {
        if (!signal.aborted) console.warn('[WebAudioStream] read error:', e);
        break;
      }

      held = _append(held, chunk);

      // Only attempt decode when we have enough data
      if (held.length < CHUNK_BYTES) continue;

      const buf = held.buffer.slice(held.byteOffset, held.byteOffset + held.length);
      held = new Uint8Array(0);

      let decoded;
      try {
        decoded = await ctx.decodeAudioData(buf);
      } catch(e) {
        // Chunk boundary may have split a frame - just skip and accumulate more
        console.debug('[WebAudioStream] decode miss (frame boundary), continuing');
        continue;
      }

      if (signal.aborted) break;

      // Schedule this buffer to play immediately after the previous one.
      // If we've fallen behind (shouldn't happen often), snap to now.
      const now = ctx.currentTime;
      if (_nextPlayAt < now || _nextPlayAt - now > MAX_AHEAD_SEC) {
        _nextPlayAt = now + 0.02; // tiny 20 ms leeway for scheduling jitter
      }

      const src = ctx.createBufferSource();
      src.buffer = decoded;
      src.connect(ctx.destination);
      src.start(_nextPlayAt);
      _nextPlayAt += decoded.duration;
    }
  }

  async function start(url, onError) {
    stop(); // clean up any previous session
    _started = true;

    const ctx = _getCtx();
    if (!ctx) {
      // Web Audio not available - signal caller to fall back
      if (onError) onError('NO_WEB_AUDIO');
      return;
    }

    await _resumeCtx(ctx);
    _nextPlayAt = ctx.currentTime;

    _abortCtrl = new AbortController();
    const signal = _abortCtrl.signal;

    let response;
    try {
      response = await fetch(url, {
        signal,
        credentials: 'include',
        // No-store prevents the browser from buffering the whole response
        cache: 'no-store',
        headers: { 'Accept': 'audio/*,*/*' }
      });
    } catch(e) {
      if (!signal.aborted) {
        console.warn('[WebAudioStream] fetch failed:', e);
        if (onError) onError('FETCH_FAILED');
      }
      return;
    }

    if (!response.ok) {
      if (onError) onError('HTTP_' + response.status);
      return;
    }

    const reader = response.body.getReader();
    // _pump runs until abort or stream end
    _pump(reader, ctx, signal).catch(e => {
      if (!signal.aborted) { console.warn('[WebAudioStream] pump error:', e); if (onError) onError('PUMP_ERROR'); }
    });
  }

  function stop() {
    _started = false;
    if (_abortCtrl) { _abortCtrl.abort(); _abortCtrl = null; }
    _nextPlayAt = 0;
    // Suspend (don't close) so we can reuse quickly
    if (_ctx && _ctx.state === 'running') {
      _ctx.suspend().catch(() => {});
    }
  }

  function isActive() { return _started; }

  return { start, stop, isActive };
})();

if (micBtn) {
  micBtn.addEventListener('click', async function() {
    if (!connected) { _showAudioToast('Connect to a camera first', true); return; }

    isMicOn = !isMicOn;
    micBtn.innerHTML = isMicOn ? svgMicOn : svgMicOff;
    micBtn.classList.toggle('off', !isMicOn);

    // Always stop any active audio path first
    WebAudioStream.stop();
    _stopAudioDrainTimer();

    // Also silence the <audio> element used by LAN cameras and old-browser fallback
    const audioFeed = document.getElementById('camAudio');
    audioFeed.pause();
    audioFeed.removeAttribute('src');
    audioFeed.load();
    audioFeed.muted = true;

    if (isMicOn) {
      const resolvedCamId = window._audioCamId ||
        (typeof window.activeCameraId !== 'undefined' ? window.activeCameraId : null);

      if (!resolvedCamId) {
        isMicOn = false; micBtn.innerHTML = svgMicOff; micBtn.classList.add('off');
        _showAudioToast('No camera connected', true);
        return;
      }

      const _lanStreamUrl = window._audioLanStreamUrl || '';
      const _isLanAudio = _lanStreamUrl && _isPrivateHost(_lanStreamUrl);

      // LAN path: use <audio> probing/playback because browser fetch() is CORS-blocked
      // by IP Webcam while media elements can load direct LAN streams.
      if (_isLanAudio) {
        _showAudioToast('Connecting to camera audio...', false);

        let _originBase = '';
        try { _originBase = new URL(_lanStreamUrl).origin; } catch(_) {}

        // IP Webcam commonly exposes audio at these suffixes.
        const _suffixes = ['/audio.opus', '/audio.wav', '/audio.aac', '/audio'];

        const _failLanAudio = function(reason) {
          console.warn('[audio] LAN audio element error:', reason);
          _stopAudioDrainTimer();
          audioFeed.pause();
          audioFeed.removeAttribute('src');
          audioFeed.load();
          audioFeed.muted = true;
          isMicOn = false; micBtn.innerHTML = svgMicOff; micBtn.classList.add('off');
          _showAudioToast('Audio stream error - check IP Webcam audio is enabled', true);
        };

        (function _playLanAudioElement(index) {
          if (!isMicOn) return;
          if (index >= _suffixes.length) { _failLanAudio('NO_WORKING_SUFFIX'); return; }

          const candidate = _originBase + _suffixes[index];
          let connectedToastShown = false;

          const cleanup = function() {
            audioFeed.removeEventListener('playing', onReady);
            audioFeed.removeEventListener('canplay', onReady);
            audioFeed.removeEventListener('loadeddata', onReady);
            audioFeed.removeEventListener('error', onError);
          };
          const onReady = function() {
            cleanup();
            if (!isMicOn) return;
            if (!connectedToastShown) {
              connectedToastShown = true;
              console.log('[audio] LAN stream via audio element:', candidate);
              _showAudioToast('Audio connected', false);
            }
          };
          const onError = function(e) {
            cleanup();
            console.debug('[audio] LAN audio failed for', candidate, e && e.message ? e.message : e);
            audioFeed.pause();
            audioFeed.removeAttribute('src');
            audioFeed.load();
            _playLanAudioElement(index + 1);
          };

          audioFeed.preload = 'none';
          audioFeed.muted = false;
          audioFeed.volume = 1.0;
          audioFeed.addEventListener('playing', onReady);
          audioFeed.addEventListener('canplay', onReady);
          audioFeed.addEventListener('loadeddata', onReady);
          audioFeed.addEventListener('error', onError);
          audioFeed.src = candidate + (candidate.includes('?') ? '&' : '?') + 't=' + Date.now();
          if (localStream) localStream.getAudioTracks().forEach(t => { t.enabled = true; });
          audioFeed.play().then(onReady).catch(onError);
        })(0);

        return; // async probe will keep the winning <audio> source playing

      }

      // ==========================================
      // Use a plain <audio> element for all server-proxied streams.
      // WebAudioStream.decodeAudioData() is a complete-file decoder and cannot
      // decode streaming chunks — it silently produces no output on live streams.
      // The browser's <audio> element handles HTTP audio streaming natively and
      // correctly for both AAC (RTSP/RTMP/ONVIF via ffmpeg-audio) and the
      // generic camera audio proxy.
      _showAudioToast('Connecting to audio...', false);

      // FIX: Only use ffmpeg-audio when we are actually connected via the FFmpeg
      // proxy path. Check connected=true AND _audioLanStreamUrl is explicitly null
      // (set only by the RTSP/RTMP/ONVIF connect path, not by a fresh page load).
      const _isFFmpegStream = connected && window._audioLanStreamUrl === null;
      const audioSrc = _isFFmpegStream
        ? '/api/camera/ffmpeg-audio?cam_id=' + resolvedCamId + '&t=' + Date.now()
        : '/api/camera/audio?cam_id=' + resolvedCamId + '&t=' + Date.now();

      const _failProxyAudio = function(reason) {
        console.warn('[audio] proxy audio error:', reason);
        _stopAudioDrainTimer();
        audioFeed.pause();
        audioFeed.removeAttribute('src');
        audioFeed.load();
        audioFeed.muted = true;
        isMicOn = false; micBtn.innerHTML = svgMicOff; micBtn.classList.add('off');
        const errMsg = _isFFmpegStream
          ? 'No audio track — camera may not have audio, or check FFmpeg is installed on the server'
          : 'Audio stream error — check that audio is enabled on the camera';
        _showAudioToast(errMsg, true);
      };

      const _onAudioReady = function() {
        audioFeed.removeEventListener('playing', _onAudioReady);
        audioFeed.removeEventListener('canplay', _onAudioReady);
        audioFeed.removeEventListener('error', _onAudioErr);
        if (!isMicOn) return;
        _startAudioDrainTimer(audioFeed);
        _showAudioToast('Audio connected', false);
      };
      const _onAudioErr = function(e) {
        audioFeed.removeEventListener('playing', _onAudioReady);
        audioFeed.removeEventListener('canplay', _onAudioReady);
        audioFeed.removeEventListener('error', _onAudioErr);
        _failProxyAudio(e && e.message ? e.message : 'media error');
      };

      audioFeed.addEventListener('playing', _onAudioReady);
      audioFeed.addEventListener('canplay', _onAudioReady);
      audioFeed.addEventListener('error', _onAudioErr);
      audioFeed.preload = 'none';
      audioFeed.muted = false;
      audioFeed.volume = 1.0;
      audioFeed.src = audioSrc;
      audioFeed.play().catch(e => {
        console.warn('[audio] play() blocked:', e);
        _failProxyAudio('play() blocked — user gesture required');
      });

    } else {
      // mic turned off - already stopped above
    }

    if (localStream) localStream.getAudioTracks().forEach(function(t) { t.enabled = isMicOn; });
  });
}
if (camBtn) {
  camBtn.addEventListener('click', () => {
    isCamOn = !isCamOn;
    camBtn.innerHTML = isCamOn ? svgCamOn : svgCamOff;
    camBtn.classList.toggle('off', !isCamOn);
    const ipFeed    = document.getElementById('ipFeed');
    const mjpegC    = document.getElementById('mjpegCanvas');
    const localVideo = document.getElementById('localVideo');
    const camOffOverlay = document.getElementById('camOffOverlay');
    if (ipFeed)     ipFeed.style.opacity    = isCamOn ? '1' : '0';
    if (mjpegC)     mjpegC.style.opacity    = isCamOn ? '1' : '0';
    if (localVideo) localVideo.style.opacity = isCamOn ? '1' : '0';
    if (camOffOverlay) camOffOverlay.style.display = isCamOn ? 'none' : 'flex';
    if (localStream) localStream.getVideoTracks().forEach(t => t.enabled = isCamOn);
  });
}

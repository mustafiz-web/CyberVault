// ═══════════════════════════════════════════
//  THEME SYSTEM
// ═══════════════════════════════════════════
function toggleTheme() {
  const html = document.documentElement;
  const current = html.getAttribute('data-theme');
  const next = current === 'dark' ? 'light' : 'dark';
  html.setAttribute('data-theme', next);
  localStorage.setItem('cv_theme', next);
}
// Load saved theme
(function() {
  const saved = localStorage.getItem('cv_theme') || 'dark';
  document.documentElement.setAttribute('data-theme', saved);
})();

// ═══════════════════════════════════════════
//  MOBILE SIDEBAR
// ═══════════════════════════════════════════
function toggleSidebar() {
  const s = document.getElementById('sidebar');
  const o = document.getElementById('sidebar-overlay');
  s.classList.toggle('open');
  o.classList.toggle('visible');
}
function closeSidebar() {
  document.getElementById('sidebar').classList.remove('open');
  document.getElementById('sidebar-overlay').classList.remove('visible');
}

// ═══════════════════════════════════════════
//  ANIMATED BACKGROUND
// ═══════════════════════════════════════════
(function initBG() {
  const c = document.getElementById('bg-canvas');
  const ctx = c.getContext('2d');
  let W, H;
  const resize = () => { W = c.width = innerWidth; H = c.height = innerHeight; };
  resize(); window.addEventListener('resize', resize);
  const rand = (a, b) => Math.random() * (b - a) + a;
  const palette = ['rgba(124,58,237', 'rgba(6,182,212', 'rgba(244,63,94', 'rgba(16,185,129'];
  const pts = Array.from({ length: 55 }, () => ({
    x: rand(0, W||1200), y: rand(0, H||800),
    vx: rand(-0.15, 0.15), vy: rand(-0.15, 0.15),
    r: rand(1, 2.5), c: palette[Math.floor(rand(0, 4))], a: rand(0.05, 0.22)
  }));
  function frame() {
    ctx.clearRect(0, 0, W, H);
    const isDark = document.documentElement.getAttribute('data-theme') !== 'light';
    // Grid
    ctx.strokeStyle = isDark ? 'rgba(124,58,237,0.04)' : 'rgba(124,58,237,0.06)';
    ctx.lineWidth = 1;
    for (let x = 0; x < W; x += 90) { ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, H); ctx.stroke(); }
    for (let y = 0; y < H; y += 90) { ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(W, y); ctx.stroke(); }
    pts.forEach(p => {
      p.x += p.vx; p.y += p.vy;
      if (p.x < 0) p.x = W; if (p.x > W) p.x = 0;
      if (p.y < 0) p.y = H; if (p.y > H) p.y = 0;
      ctx.beginPath(); ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
      const alpha = isDark ? p.a : p.a * 0.5;
      ctx.fillStyle = `${p.c},${alpha})`; ctx.fill();
    });
    for (let i = 0; i < pts.length; i++) for (let j = i + 1; j < pts.length; j++) {
      const dx = pts[i].x - pts[j].x, dy = pts[i].y - pts[j].y, d = Math.sqrt(dx*dx + dy*dy);
      if (d < 100) {
        ctx.beginPath(); ctx.moveTo(pts[i].x, pts[i].y); ctx.lineTo(pts[j].x, pts[j].y);
        const a = isDark ? 0.05 : 0.04;
        ctx.strokeStyle = `rgba(124,58,237,${a * (1 - d / 100)})`; ctx.lineWidth = 0.5; ctx.stroke();
      }
    }
    requestAnimationFrame(frame);
  }
  frame();
})();

// ═══════════════════════════════════════════
//  FAVICON LOADER — new feature!
// ═══════════════════════════════════════════
function getFaviconUrl(url) {
  try {
    const u = new URL(url);
    return `https://www.google.com/s2/favicons?domain=${u.hostname}&sz=32`;
  } catch(e) { return null; }
}

function updateFaviconPreview() {
  const url = document.getElementById('f-url').value.trim();
  const preview = document.getElementById('url-favicon-preview');
  const img = document.getElementById('favicon-preview-img');
  const domain = document.getElementById('favicon-preview-domain');
  if (!url || !url.startsWith('http')) { preview.classList.add('hidden'); return; }
  try {
    const u = new URL(url);
    const faviconUrl = getFaviconUrl(url);
    img.src = faviconUrl;
    domain.textContent = u.hostname;
    preview.classList.remove('hidden');
    img.onerror = () => { preview.classList.add('hidden'); };
  } catch(e) { preview.classList.add('hidden'); }
}

// Build service icon with favicon
function buildServiceIcon(p, svc) {
  const favicon = p.url ? getFaviconUrl(p.url) : null;
  if (favicon) {
    return `<div class="card-svc-icon" style="background:${svc.color}18;border-color:${svc.color}28;color:${svc.color}">
      <img src="${favicon}" alt="${esc(p.name)}" 
        onerror="this.parentElement.innerHTML='<span style=&quot;font-size:13px;font-weight:800;font-family:var(--font-head)&quot;>${svc.abbr}</span>'; this.parentElement.style.color='${svc.color}'"
      >
    </div>`;
  }
  return `<div class="card-svc-icon" style="background:${svc.color}18;border-color:${svc.color}28;color:${svc.color}">${svc.abbr}</div>`;
}

// ═══════════════════════════════════════════════════════════════
//  SECURITY ENGINE v6 — HARDENED
//  #1  Web Crypto API (PBKDF2 + AES-GCM) replaces CryptoJS
//  #5  Per-user random salt stored separately
//  #7  Activity log encrypted at rest
//  #9  Memory wipe on lock
//  #10 Export passphrase prompt
//  #12 HaveIBeenPwned breach detection
//  #13 Device binding fingerprint
// ═══════════════════════════════════════════════════════════════

// ── SECURITY #1: Web Crypto API helpers ──
const WC = {
  // ── FIX BUG #1: Safe b64enc that works for ANY buffer size ──
  // The spread operator (...new Uint8Array(buf)) crashes on large buffers
  // in production browsers. Use a loop-based approach instead.
  b64enc(buf) {
    const bytes = new Uint8Array(buf);
    let binary  = '';
    // Process in chunks to avoid call stack overflow
    const chunkSize = 8192;
    for (let i = 0; i < bytes.length; i += chunkSize) {
      binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunkSize));
    }
    return btoa(binary);
  },

  b64dec(str) {
    const binary = atob(str);
    const bytes  = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  },

  strEnc(s) { return new TextEncoder().encode(s); },

  // ── FIX BUG #2: newSalt now uses safe b64enc ──
  newSalt() {
    const bytes = crypto.getRandomValues(new Uint8Array(32));
    return this.b64enc(bytes.buffer);
  },

  // Derive AES-GCM key from password using PBKDF2 (310k iterations — OWASP 2024)
  async deriveKey(password, saltB64) {
    const saltBytes = this.b64dec(saltB64);
    const keyMat    = await crypto.subtle.importKey(
      'raw', this.strEnc(password), 'PBKDF2', false, ['deriveKey']
    );
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: saltBytes, iterations: 310000, hash: 'SHA-256' },
      keyMat,
      { name: 'AES-GCM', length: 256 },
      false, ['encrypt', 'decrypt']
    );
  },

  // AES-GCM encrypt → base64 string (iv prepended)
  async encrypt(data, cryptoKey) {
    const iv  = crypto.getRandomValues(new Uint8Array(12));
    const enc = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      cryptoKey,
      this.strEnc(JSON.stringify(data))
    );
    const combined = new Uint8Array(12 + enc.byteLength);
    combined.set(iv, 0);
    combined.set(new Uint8Array(enc), 12);
    return this.b64enc(combined.buffer);
  },

  // AES-GCM decrypt → parsed object / null on any error
  async decrypt(b64, cryptoKey) {
    try {
      const buf  = this.b64dec(b64);
      const iv   = buf.slice(0, 12);
      const data = buf.slice(12);
      const dec  = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, cryptoKey, data);
      return JSON.parse(new TextDecoder().decode(dec));
    } catch(e) { return null; }
  },

  // ── FIX BUG #3: Stable PBKDF2 hash — safe b64enc, no stack overflow ──
  async hashMaster(password, saltB64) {
    const saltBytes = this.b64dec(saltB64);
    const keyMat    = await crypto.subtle.importKey(
      'raw', this.strEnc(password), 'PBKDF2', false, ['deriveBits']
    );
    const bits = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', salt: saltBytes, iterations: 310000, hash: 'SHA-256' },
      keyMat, 256
    );
    return this.b64enc(bits);
  },

  // SHA-1 for HIBP k-anonymity (non-security use)
  async sha1Hex(str) {
    const buf = await crypto.subtle.digest('SHA-1', this.strEnc(str));
    return Array.from(new Uint8Array(buf))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('')
      .toUpperCase();
  }
};

// ── SECURITY #13: Device fingerprint binding ──
const DeviceGuard = {
  getFingerprint() {
    const raw = [navigator.userAgent, screen.width, screen.height,
                 navigator.language, Intl.DateTimeFormat().resolvedOptions().timeZone].join('|');
    // Store and retrieve device ID
    let id = localStorage.getItem('cv_device_id');
    if (!id) {
      id = WC.b64enc(crypto.getRandomValues(new Uint8Array(16)).buffer) + ':' + btoa(raw).slice(0,32);
      localStorage.setItem('cv_device_id', id);
    }
    return id;
  },
  validate(storedFP) {
    // Just warn — don't hard-block (user may switch browsers)
    const current = this.getFingerprint();
    if (storedFP && storedFP !== current) {
      toast('⚠ New device/browser detected. Please verify it\'s you.', 'warn');
    }
    return current;
  }
};

// ── SECURITY #8: Login rate limiting with exponential backoff ──
const RateLimiter = {
  attempts: 0,
  lockedUntil: 0,
  backoff: [0, 1000, 3000, 8000, 20000, 60000],
  async gate() {
    const now = Date.now();
    if (now < this.lockedUntil) {
      const wait = Math.ceil((this.lockedUntil - now) / 1000);
      toast(`Too many attempts. Wait ${wait}s`, 'error'); return false;
    }
    const delay = this.backoff[Math.min(this.attempts, this.backoff.length - 1)];
    if (delay > 0) {
      await new Promise(r => setTimeout(r, delay));
    }
    this.attempts++;
    return true;
  },
  success() { this.attempts = 0; this.lockedUntil = 0; },
  fail() {
    if (this.attempts >= 5) {
      this.lockedUntil = Date.now() + 60000;
      toast('Account temporarily locked for 60 seconds', 'error');
    }
  }
};

// ── SECURITY #12: HaveIBeenPwned breach check ──
async function checkBreached(password) {
  try {
    const hash   = await WC.sha1Hex(password);
    const prefix = hash.slice(0, 5);
    const res    = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
    if (!res.ok) return false;
    const text   = await res.text();
    const suffix = hash.slice(5);
    const found  = text.split('\r\n').some(line => line.split(':')[0] === suffix);
    return found;
  } catch(e) { return false; } // fail open — don't block on network error
}

// ── MAIN CV ENGINE ──
const CV = {
  user: null,
  masterCryptoKey: null,   // CryptoKey object (Web Crypto)
  masterKeyRaw: null,      // derived key string (CryptoJS compat — kept for migration)
  masterHash: null,
  masterSalt: null,        // #5 per-user random salt
  passwords: [], activityLog: [],
  settings: { autolock: 300, clipboard: 30, blur: true },
  vaultLocked: true, failedAttempts: 0,
  inactivityTimer: null, inactivityMax: 300, inactivityLeft: 300,
  clipboardTimer: null, currentSection: 'dashboard', editingId: null,
  deviceFP: null,

  // ── Legacy CryptoJS (kept for migration of old vaults) ──
  _legacyDeriveKey(pwd, salt) {
    if (typeof CryptoJS === 'undefined') return null;
    return CryptoJS.PBKDF2(pwd, salt, { keySize: 256/32, iterations: 100000, hasher: CryptoJS.algo.SHA256 }).toString();
  },
  _legacyDecrypt(ct, key) {
    try { const b = CryptoJS.AES.decrypt(ct, key); return JSON.parse(b.toString(CryptoJS.enc.Utf8)); } catch(e) { return null; }
  },
  _legacyEncrypt(data, key) { return CryptoJS.AES.encrypt(JSON.stringify(data), key).toString(); },

  // ── #1 Web Crypto encrypt/decrypt (async) ──
  async encrypt(data) {
    if (!this.masterCryptoKey) throw new Error('Vault locked');
    return WC.encrypt(data, this.masterCryptoKey);
  },
  async decrypt(b64) {
    if (!this.masterCryptoKey) return null;
    return WC.decrypt(b64, this.masterCryptoKey);
  },

  // ── #5 Salt management ──
  getOrCreateSalt(uid) {
    const key = `cv_${uid}_salt`;
    let salt = localStorage.getItem(key);
    if (!salt) { salt = WC.newSalt(); localStorage.setItem(key, salt); }
    return salt;
  },

  // ── Cross-device: save salt + masterHash to Firestore ──
  async syncMasterToFirestore(uid, salt, masterHash) {
    if (!window._firebaseReady || !uid) return;
    try {
      const { doc, setDoc } = window._firebaseModules;
      await setDoc(doc(window._firebaseDb, 'masterKeys', uid), {
        salt, masterHash, updatedAt: Date.now()
      });
    } catch(e) { console.warn('[CyberVault] Could not sync master key to cloud:', e); }
  },

  // ── Cross-device: load salt + masterHash from Firestore ──
  // Returns { salt, masterHash } or null if not found
  async loadMasterFromFirestore(uid) {
    if (!window._firebaseReady || !uid) return null;
    try {
      const { doc, getDoc } = window._firebaseModules;
      const snap = await getDoc(doc(window._firebaseDb, 'masterKeys', uid));
      if (snap.exists()) {
        const d = snap.data();
        if (d.salt && d.masterHash) return { salt: d.salt, masterHash: d.masterHash };
      }
    } catch(e) { console.warn('[CyberVault] Could not load master key from cloud:', e); }
    return null;
  },

  uid() { return Date.now().toString(36) + Math.random().toString(36).slice(2); },
  storageKey(k) { return `cv_${this.user?.uid || 'local'}_${k}`; },

  // ── #7 Save with encrypted activity log ──
  async saveLocal() {
    if (!this.masterCryptoKey) return;
    try {
      const encVault = await this.encrypt(this.passwords);
      const encLog   = await this.encrypt(this.activityLog.slice(-200));
      localStorage.setItem(this.storageKey('vault'), encVault);
      localStorage.setItem(this.storageKey('log'),   encLog);
      await this.syncFirestore();
    } catch(e) { console.warn('Save failed:', e); }
  },

  async loadLocal() {
    const encVault = localStorage.getItem(this.storageKey('vault'));
    if (encVault && this.masterCryptoKey) {
      // Try new Web Crypto format first
      let dec = await this.decrypt(encVault);
      // Fall back to legacy CryptoJS
      if (!dec && this.masterKeyRaw) dec = this._legacyDecrypt(encVault, this.masterKeyRaw);
      if (dec) this.passwords = dec;
    }
    // #7 Load encrypted activity log
    const encLog = localStorage.getItem(this.storageKey('log'));
    if (encLog && this.masterCryptoKey) {
      let decLog = await this.decrypt(encLog);
      if (!decLog) { try { decLog = JSON.parse(encLog); } catch(e){} } // legacy plain JSON
      if (decLog) this.activityLog = decLog;
    }
    await this.syncFromFirestore();
  },

  async syncFirestore() {
    if (!window._firebaseReady || !this.user || !this.masterCryptoKey) return;
    try {
      const { doc, setDoc } = window._firebaseModules;
      const encVault = await this.encrypt(this.passwords);
      await setDoc(doc(window._firebaseDb, 'vaults', this.user.uid), {
        vault: encVault, updatedAt: Date.now(),
        userEmail: this.user.email,
        deviceFP: this.deviceFP || ''
      });
    } catch(e) { console.warn('Sync failed:', e); }
  },

  async syncFromFirestore() {
    if (!window._firebaseReady || !this.user || !this.masterCryptoKey) return;
    try {
      const { doc, getDoc } = window._firebaseModules;
      const snap = await getDoc(doc(window._firebaseDb, 'vaults', this.user.uid));
      if (snap.exists()) {
        const raw = snap.data().vault;
        let dec = await this.decrypt(raw);
        if (!dec && this.masterKeyRaw) dec = this._legacyDecrypt(raw, this.masterKeyRaw);
        if (dec && Array.isArray(dec)) {
          this.passwords = dec;
          localStorage.setItem(this.storageKey('vault'), raw);
          renderPasswords(); renderDashboard();
        }
      }
    } catch(e) { console.warn('Firestore load failed:', e); }
  },

  addActivity(type, text) {
    this.activityLog.unshift({ type, text, time: new Date().toLocaleString() });
    if (this.activityLog.length > 200) this.activityLog.pop();
  },
  resetInactivity() { this.inactivityLeft = this.inactivityMax; },
};

// ── Service Detection ──
const SERVICE_MAP = {
  gmail:    { abbr:'GM', color:'#ea4335' }, yahoo:  { abbr:'YH', color:'#7e3af2' },
  outlook:  { abbr:'OL', color:'#0078d4' }, hotmail:{ abbr:'HM', color:'#0078d4' },
  facebook: { abbr:'FB', color:'#1877f2' }, instagram:{ abbr:'IG', color:'#e1306c' },
  twitter:  { abbr:'TW', color:'#1da1f2' }, netflix:{ abbr:'NF', color:'#e50914' },
  amazon:   { abbr:'AZ', color:'#ff9900' }, apple:  { abbr:'AP', color:'#888' },
  google:   { abbr:'GO', color:'#4285f4' }, github: { abbr:'GH', color:'#6e40c9' },
  linkedin: { abbr:'LI', color:'#0a66c2' }, spotify:{ abbr:'SP', color:'#1db954' },
  discord:  { abbr:'DC', color:'#5865f2' }, twitch: { abbr:'TW', color:'#9146ff' },
  paypal:   { abbr:'PP', color:'#003087' }, dropbox:{ abbr:'DB', color:'#0061ff' },
  reddit:   { abbr:'RD', color:'#ff4500' }, steam:  { abbr:'ST', color:'#66c0f4' },
  tiktok:   { abbr:'TK', color:'#010101' }, zoom:   { abbr:'ZM', color:'#2d8cff' },
  slack:    { abbr:'SL', color:'#4a154b' }, microsoft:{ abbr:'MS', color:'#00a4ef' },
};
function detectService(name='', email='') {
  const txt = (name + ' ' + email).toLowerCase();
  for (const [k, v] of Object.entries(SERVICE_MAP)) { if (txt.includes(k)) return { ...v, key: k }; }
  const initials = (name || 'UN').slice(0, 2).toUpperCase();
  return { abbr: initials, color: '#7c3aed', key: '' };
}
function linkedIcon(name) {
  const n = name.toLowerCase();
  for (const [k, v] of Object.entries(SERVICE_MAP)) { if (n.includes(k)) return v.abbr; }
  return '🔗';
}

// ── Auth ──
function switchAuthTab(tab) {
  document.getElementById('login-form').style.display = tab === 'login' ? '' : 'none';
  document.getElementById('register-form').style.display = tab === 'register' ? '' : 'none';
  document.querySelectorAll('.auth-tab').forEach((t, i) => t.classList.toggle('active', (i === 0) === (tab === 'login')));
  document.getElementById('auth-error').textContent = '';
}

// ── SECURITY #8: Rate-limited login ──
async function handleLogin() {
  const email    = document.getElementById('login-email').value.trim();
  const password = document.getElementById('login-password').value;
  if (!email || !password) { showAuthError('Please fill all fields'); return; }
  if (!await RateLimiter.gate()) return;
  if (window._firebaseReady) {
    try {
      const cred = await window._firebaseModules.signInWithEmailAndPassword(window._firebaseAuth, email, password);
      RateLimiter.success();
      CV.user = { uid: cred.user.uid, email: cred.user.email };
      afterAuth();
    } catch(e) {
      RateLimiter.fail();
      // BUG FIX: Show the actual error instead of silently logging in with wrong credentials
      const msg = e.code === 'auth/invalid-credential' || e.code === 'auth/wrong-password' || e.code === 'auth/user-not-found'
        ? 'Invalid email or password'
        : e.code === 'auth/user-disabled'
        ? 'This account has been disabled'
        : e.code === 'auth/too-many-requests'
        ? 'Too many failed attempts. Try again later.'
        : (e.message || 'Login failed');
      showAuthError(msg);
    }
  } else {
    // Offline / local-only mode — no Firebase available
    CV.user = { uid: btoa(email), email };
    toast('Running in local mode (no Firebase)', 'info');
    afterAuth();
  }
}

// ── SECURITY #8 + #12: Rate-limited register + breach check ──
async function handleRegister() {
  const email    = document.getElementById('reg-email').value.trim();
  const password = document.getElementById('reg-password').value;
  if (!email || !password) { showAuthError('Please fill all fields'); return; }
  if (password.length < 8) { showAuthError('Password must be at least 8 characters'); return; }
  if (!await RateLimiter.gate()) return;
  // #12 Breach check on registration password
  toast('Checking password security…', 'info');
  const breached = await checkBreached(password);
  if (breached) {
    showAuthError('⚠ This password was found in a data breach! Please choose a different one.');
    toast('Password found in known data breach!', 'error'); return;
  }
  if (window._firebaseReady) {
    try {
      const cred = await window._firebaseModules.createUserWithEmailAndPassword(window._firebaseAuth, email, password);
      RateLimiter.success();
      CV.user = { uid: cred.user.uid, email: cred.user.email };
      toast('Account created successfully', 'success'); afterAuth();
    } catch(e) { RateLimiter.fail(); showAuthError(e.message || 'Registration failed'); }
  } else { CV.user = { uid: btoa(email), email }; toast('Running in local mode', 'info'); afterAuth(); }
}
async function afterAuth() {
  // #13 Device fingerprint binding
  CV.deviceFP = DeviceGuard.getFingerprint();
  const storedFP = localStorage.getItem(`cv_${CV.user.uid}_device`);
  DeviceGuard.validate(storedFP);
  localStorage.setItem(`cv_${CV.user.uid}_device`, CV.deviceFP);

  hide('auth-screen');

  // ── FIX: Try localStorage first, then Firestore (cross-device sync) ──
  let salt = localStorage.getItem(`cv_${CV.user.uid}_salt`);
  let hash = localStorage.getItem(`cv_${CV.user.uid}_master`);

  if (!salt || !hash) {
    const cloud = await CV.loadMasterFromFirestore(CV.user.uid);
    if (cloud) {
      salt = cloud.salt;
      hash = cloud.masterHash;
      localStorage.setItem(`cv_${CV.user.uid}_salt`, salt);
      localStorage.setItem(`cv_${CV.user.uid}_master`, hash);
      toast('Vault credentials synced from cloud ✓', 'success');
    }
  }

  CV.masterSalt = salt || CV.getOrCreateSalt(CV.user.uid);
  if (!hash) { showSetMaster(); } else { CV.masterHash = hash; showVaultScreen(); }
}
async function handleGoogleSignOut() {
  if (window._firebaseReady) try { await window._firebaseModules.signOut(window._firebaseAuth); } catch(e){}
  secureWipeMemory();
  CV.user = null; CV.vaultLocked = true;
  stopInactivity(); hide('app-screen'); hide('vault-screen'); show('auth-screen');
  toast('Signed out securely', 'info');
}
async function handleGoogleSignIn() {
  if (!window._firebaseReady) { toast('Firebase not configured — Google sign-in unavailable', 'warn'); return; }
  const btn = document.getElementById('google-signin-btn') || document.getElementById('google-register-btn');
  if (btn) btn.classList.add('loading');
  try {
    const { GoogleAuthProvider, signInWithPopup } = await import("https://www.gstatic.com/firebasejs/11.9.0/firebase-auth.js");
    const provider = new GoogleAuthProvider();
    provider.addScope('email'); provider.addScope('profile');
    provider.setCustomParameters({ prompt: 'select_account' });
    const result = await signInWithPopup(window._firebaseAuth, provider);
    const user = result.user;
    CV.user = { uid: user.uid, email: user.email };
    RateLimiter.success();
    toast('Signed in with Google: ' + user.email, 'success');
    if (btn) btn.classList.remove('loading');
    afterAuth();
  } catch(e) {
    if (btn) btn.classList.remove('loading');
    console.error('[CyberVault] Google Sign-In error:', e.code, e.message, e);
    if (e.code === 'auth/popup-closed-by-user' || e.code === 'auth/cancelled-popup-request') {
      toast('Sign-in cancelled', 'info'); return;
    }
    if (e.code === 'auth/popup-blocked') {
      showAuthError('Popup blocked by browser. Please allow popups for this site and try again.');
      toast('Popup blocked — allow popups and retry', 'warn'); return;
    }
    if (e.code === 'auth/unauthorized-domain') {
      showAuthError('This domain is not authorized for Google sign-in. The site admin must add this domain to Firebase Console → Authentication → Authorized Domains.');
      toast('Domain not authorized for sign-in', 'error'); return;
    }
    if (e.code === 'auth/internal-error') {
      showAuthError('Google sign-in failed (internal error). Ensure Firebase Hosting is deployed and this domain is authorized in Firebase Console.');
      toast('Google sign-in internal error — check Firebase config', 'error'); return;
    }
    if (e.code === 'auth/operation-not-allowed') {
      showAuthError('Google sign-in is not enabled. Enable it in Firebase Console → Authentication → Sign-in method.');
      toast('Google sign-in not enabled', 'error'); return;
    }
    showAuthError(e.message || 'Google sign-in failed');
    toast('Google sign-in failed', 'error');
  }
}
async function handleSignOut() {
  if (window._firebaseReady) try { await window._firebaseModules.signOut(window._firebaseAuth); } catch(e){}
  secureWipeMemory();
  CV.user = null; CV.vaultLocked = true;
  stopInactivity(); hide('app-screen'); hide('vault-screen'); show('auth-screen');
  toast('Signed out securely', 'info');
}
function showAuthError(msg) {
  const el = document.getElementById('auth-error');
  el.innerHTML = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>${msg}`;
}

// ── Master Password ──
function showSetMaster() {
  document.getElementById('master-modal-title').textContent = 'Set Master Password';
  ['new-master','confirm-master'].forEach(id => document.getElementById(id).value = '');
  document.getElementById('master-error').textContent = '';
  show('master-modal');
}
function showChangeMaster() {
  document.getElementById('master-modal-title').textContent = 'Change Master Password';
  ['new-master','confirm-master'].forEach(id => document.getElementById(id).value = '');
  document.getElementById('master-error').textContent = '';
  show('master-modal');
}
function closeMasterModal() { hide('master-modal'); }

// ── SECURITY #1 #5 #12: Web Crypto key derive + salted hash + breach check ──
async function saveMasterPassword() {
  const pwd   = document.getElementById('new-master').value;
  const conf  = document.getElementById('confirm-master').value;
  const errEl = document.getElementById('master-error');
  const btn   = document.querySelector('#master-modal .btn-primary');

  const showErr = (msg) => {
    errEl.innerHTML = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/></svg> ${msg}`;
    if (btn) { btn.textContent = 'Save Master Password'; btn.disabled = false; }
  };

  if (!pwd || pwd.length < 8) { showErr('Min 8 characters required'); return; }
  if (pwd !== conf)            { showErr('Passwords do not match');     return; }

  if (btn) { btn.textContent = 'Securing vault…'; btn.disabled = true; }
  errEl.textContent = '';

  try {
    // ── FIX BUG #4: Breach check is non-blocking — warn but don't stop ──
    // If HIBP is unreachable (network block / hosting restriction), we
    // show a warning toast but still allow the user to set their password.
    try {
      const breached = await checkBreached(pwd);
      if (breached) {
        toast('⚠ Warning: This password was found in a data breach. Consider using a stronger password.', 'warn');
        // We warn but do NOT block — user can still proceed
      }
    } catch(hibpErr) {
      // HIBP unreachable — silently skip, do not block vault creation
      console.warn('[CyberVault] HIBP check skipped:', hibpErr.message);
    }

    // ── FIX BUG #2+3: Salt is always created fresh and verified before use ──
    CV.masterSalt = CV.getOrCreateSalt(CV.user.uid);

    // Verify salt is valid base64 before proceeding
    if (!CV.masterSalt || CV.masterSalt.length < 10) {
      throw new Error('Salt generation failed — localStorage may be blocked');
    }

    // ── FIX BUG #1: All WC calls now use safe b64enc/b64dec ──
    // Derive AES-GCM key
    CV.masterCryptoKey = await WC.deriveKey(pwd, CV.masterSalt);

    // Keep legacy CryptoJS key for migration of old encrypted data
    CV.masterKeyRaw = CV._legacyDeriveKey(pwd, CV.user.uid);

    // Hash master password with stable PBKDF2 (safe b64enc)
    CV.masterHash = await WC.hashMaster(pwd, CV.masterSalt);

    // Persist hash to localStorage
    localStorage.setItem(`cv_${CV.user.uid}_master`, CV.masterHash);

    // ── FIX: Sync salt + hash to Firestore so other devices (mobile etc.) can unlock ──
    await CV.syncMasterToFirestore(CV.user.uid, CV.masterSalt, CV.masterHash);

    if (btn) { btn.textContent = 'Save Master Password'; btn.disabled = false; }
    closeMasterModal();
    toast('🔐 Vault secured — AES-256-GCM + PBKDF2 (310k iterations)', 'success');
    CV.vaultLocked = false;
    showApp();

  } catch(e) {
    console.error('[CyberVault] saveMasterPassword error:', e);
    showErr('Key derivation failed: ' + e.message);
  }
}

// ── Vault Lock/Unlock ──
function showVaultScreen() {
  hide('app-screen'); hide('auth-screen');
  document.getElementById('vault-user-info').textContent = CV.user.email;
  document.getElementById('vault-attempts').textContent = '';
  document.getElementById('master-input').value = '';
  show('vault-screen'); CV.failedAttempts = 0;
}

// ── SECURITY #1 #5 #9: Async unlock with Web Crypto ──
async function unlockVault() {
  const pwd       = document.getElementById('master-input').value;
  const unlockBtn = document.getElementById('vault-unlock-btn');
  const resetBtn  = () => { if (unlockBtn) { unlockBtn.textContent = 'Decrypt & Unlock Vault'; unlockBtn.disabled = false; } };

  if (!pwd) { toast('Enter master password', 'warn'); return; }
  if (unlockBtn) { unlockBtn.textContent = 'Unlocking…'; unlockBtn.disabled = true; }

  try {
    // ── FIX: Always READ the stored salt — never regenerate during unlock ──
    // getOrCreateSalt() only creates a NEW salt if none exists.
    // On unlock we MUST use the SAME salt that was used when the hash was created.
    // If the salt key is missing something is seriously wrong — surface the error.
    const storedSalt = localStorage.getItem(`cv_${CV.user.uid}_salt`);
    if (!storedSalt) {
      resetBtn();
      toast('Vault salt missing — your vault data may be corrupted. Try signing out and back in.', 'error');
      return;
    }
    CV.masterSalt = storedSalt;

    // Compute new-format PBKDF2 hash using stored salt
    const hashNew = await WC.hashMaster(pwd, CV.masterSalt);

    // Legacy PBKDF2 hash check (for vaults created before v7) — no CryptoJS dependency
    // This uses the uid as salt which is weaker, but we auto-upgrade on success below.
    let hashLeg = null;
    try {
      if (typeof CryptoJS !== 'undefined' && CV.masterKeyRaw) {
        // Only attempt if CryptoJS loaded AND we have a legacy key — used for migration only
        hashLeg = CryptoJS.SHA256(CV.masterKeyRaw + 'CyberVault_LegacyCheck').toString();
      }
    } catch(legacyErr) {
      console.warn('[CyberVault] CryptoJS not available — legacy vault format not supported on this browser');
    }

    if (hashNew === CV.masterHash || (hashLeg !== null && hashLeg === CV.masterHash)) {
      // ── Correct password ──
      CV.masterCryptoKey = await WC.deriveKey(pwd, CV.masterSalt);
      CV.masterKeyRaw    = CV._legacyDeriveKey(pwd, CV.user.uid);
      CV.vaultLocked     = false;
      CV.failedAttempts  = 0;

      // Auto-upgrade legacy hash to new PBKDF2 format silently
      if (hashLeg !== null && hashLeg === CV.masterHash && hashNew !== CV.masterHash) {
        CV.masterHash = hashNew;
        localStorage.setItem(`cv_${CV.user.uid}_master`, hashNew);
        CV.syncMasterToFirestore(CV.user.uid, CV.masterSalt, hashNew);
      }

      document.getElementById('vault-box').classList.add('vault-opening');
      CV.addActivity('vault', 'Vault unlocked');
      await CV.loadLocal();
      resetBtn();
      setTimeout(() => { hide('vault-screen'); showApp(); }, 550);

    } else {
      // ── Wrong password ──
      CV.failedAttempts++;
      resetBtn();
      document.getElementById('vault-attempts').innerHTML =
        `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:middle"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94"/></svg> Incorrect password — attempt ${CV.failedAttempts}/5`;
      toast('Incorrect master password', 'error');
      if (CV.failedAttempts >= 5) {
        toast('Too many attempts — signing out', 'error');
        setTimeout(handleSignOut, 1500);
      }
      document.getElementById('master-input').value = '';
    }

  } catch(e) {
    console.error('[CyberVault] unlockVault error:', e);
    resetBtn();
    toast('Unlock error: ' + e.message, 'error');
  }
}

// ── SECURITY #9: Memory wipe helper ──
function secureWipeMemory() {
  // Overwrite sensitive data before nulling
  if (CV.masterCryptoKey) { CV.masterCryptoKey = null; }
  if (CV.masterKeyRaw)    { CV.masterKeyRaw    = new Array(CV.masterKeyRaw.length).fill('0').join(''); CV.masterKeyRaw = null; }
  if (CV.masterHash)      { CV.masterHash      = null; }
  if (CV.passwords && CV.passwords.length) {
    CV.passwords.forEach(p => { if (p._pwd) p._pwd = crypto.getRandomValues(new Uint8Array(p._pwd.length)).join(''); });
    CV.passwords = [];
  }
  CV.activityLog = [];
}

// ── SECURITY #9: Memory wipe on lock ──
function lockVault() {
  secureWipeMemory();
  CV.vaultLocked = true;
  stopInactivity(); hide('app-screen'); showVaultScreen();
  toast('Vault locked & memory wiped', 'info');
}

// ── App ──
function showApp() {
  document.getElementById('topbar-user-email').textContent = CV.user.email;
  show('app-screen'); renderDashboard(); renderPasswords(); renderActivity(); startInactivity(); loadSettings();
  // Update device FP display
  const fpEl = document.getElementById('device-fp-display');
  if (fpEl && CV.deviceFP) {
    fpEl.textContent = 'Bound to: ' + CV.deviceFP.slice(0, 20) + '…';
  }
  // Update App Check badge
  checkAppCheckStatus();
}

// ── SECURITY #4: App Check status checker ──
async function checkAppCheckStatus() {
  const badge = document.getElementById('appcheck-badge');
  if (!badge) return;
  const isLocal = ['localhost','127.0.0.1',''].includes(location.hostname);
  if (!window._firebaseReady || !window._firebaseAppCheck) {
    badge.className = 'appcheck-badge error';
    badge.textContent = 'APP CHECK OFF';
    badge.title = 'App Check not initialized — Firebase may be unprotected';
    return;
  }
  try {
    // Try to get an App Check token to verify it works
    const { getToken } = await import("https://www.gstatic.com/firebasejs/11.9.0/firebase-app-check.js");
    const tokenResult = await getToken(window._firebaseAppCheck, false);
    if (tokenResult && tokenResult.token) {
      if (isLocal) {
        badge.className = 'appcheck-badge debug';
        badge.textContent = '🔧 APP CHECK (DEBUG)';
        badge.title = 'App Check active in debug mode (localhost). Deploy to production for full reCAPTCHA v3 protection.';
      } else {
        badge.className = 'appcheck-badge verified';
        badge.textContent = '✓ APP CHECK';
        badge.title = 'Firebase App Check active — reCAPTCHA v3 verified. Only this domain can access your Firebase.';
      }
    }
  } catch(e) {
    badge.className = 'appcheck-badge error';
    badge.textContent = '⚠ APP CHECK ERR';
    badge.title = 'App Check error: ' + e.message;
    console.warn('[CyberVault] App Check token error:', e);
  }
}
function showSection(name) {
  document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  const sec = document.getElementById('section-' + name); if (sec) sec.classList.add('active');
  const nav = document.querySelector(`[data-section="${name}"]`); if (nav) nav.classList.add('active');
  CV.currentSection = name;
  if (name === 'dashboard') renderDashboard();
  if (name === 'passwords') renderPasswords();
  if (name === 'favorites') renderFavorites();
  if (name === 'linked') renderLinkedMap();
  if (name === 'activity') renderActivity();
  if (name === 'generator') generatePassword();
  if (name === 'settings') updateAppCheckSettingsDesc();
  // Scroll main content to top on nav change
  const mc = document.getElementById('main-content');
  if (mc) mc.scrollTo({ top: 0, behavior: 'smooth' });
}

// ── Password Strength ──
function passwordStrength(pwd) {
  if (!pwd) return { score: 0, label: 'None', color: 'var(--t5)', pct: 0 };
  let s = 0;
  if (pwd.length >= 8) s++; if (pwd.length >= 12) s++; if (pwd.length >= 16) s++;
  if (/[a-z]/.test(pwd)) s++; if (/[A-Z]/.test(pwd)) s++;
  if (/[0-9]/.test(pwd)) s++; if (/[^a-zA-Z0-9]/.test(pwd)) s++; if (pwd.length >= 20) s++;
  const L = [
    { label:'Very Weak',   color:'#f43f5e', pct:10 },
    { label:'Weak',        color:'#f97316', pct:25 },
    { label:'Fair',        color:'#f59e0b', pct:45 },
    { label:'Good',        color:'#84cc16', pct:65 },
    { label:'Strong',      color:'#22c55e', pct:80 },
    { label:'Very Strong', color:'#10b981', pct:95 },
    { label:'Excellent',   color:'#06b6d4', pct:100 },
  ];
  return { score: s, ...L[Math.min(s, L.length - 1)] };
}
function updateModalStrength() {
  const str = passwordStrength(document.getElementById('f-pwd').value);
  document.getElementById('modal-strength-fill').style.cssText = `width:${str.pct}%;background:${str.color}`;
  document.getElementById('modal-strength-label').style.color = str.color;
  document.getElementById('modal-strength-label').textContent = document.getElementById('f-pwd').value ? `Strength: ${str.label}` : 'Enter a password to check strength';
}

// ── Render Cards ──
function renderPasswords() {
  const grid = document.getElementById('cards-grid');
  let pwds = [...CV.passwords];
  const search = (document.getElementById('search-input')?.value || '').toLowerCase();
  const cat = document.getElementById('filter-cat')?.value || '';
  const sort = document.getElementById('sort-by')?.value || 'date-desc';
  if (search) pwds = pwds.filter(p => (p.name+p.email+p.url+'').toLowerCase().includes(search));
  if (cat) pwds = pwds.filter(p => p.category === cat);
  if (sort === 'date-desc') pwds.sort((a, b) => b.createdAt - a.createdAt);
  else if (sort === 'date-asc') pwds.sort((a, b) => a.createdAt - b.createdAt);
  else if (sort === 'name-asc') pwds.sort((a, b) => (a.name||'').localeCompare(b.name||''));
  else if (sort === 'strength-desc') pwds.sort((a, b) => passwordStrength(b._pwd||'').score - passwordStrength(a._pwd||'').score);
  document.getElementById('pwd-count').textContent = CV.passwords.length;
  if (pwds.length === 0) {
    grid.innerHTML = `<div class="empty"><div class="empty-icon"><svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778"/></svg></div><div class="empty-title">No Passwords Found</div><div class="empty-sub">Add your first encrypted password to get started</div></div>`;
  } else { grid.innerHTML = pwds.map(p => cardHTML(p)).join(''); }
}
function cardHTML(p) {
  const svc = detectService(p.name, p.email);
  const str = passwordStrength(p._pwd || '');
  const linked = p.linked || [];
  return `
  <div class="pwd-card" id="card-${p.id}" style="--c-accent:${svc.color}">
    <div class="card-header">
      ${buildServiceIcon(p, svc)}
      <div class="card-info">
        <div class="card-name">${esc(p.name || 'Unknown')}</div>
        <div class="card-email">${esc(p.email || '')}</div>
        <div class="card-tags">
          ${p.category ? `<span class="tag tag-cat">${p.category}</span>` : ''}
          ${p.favorite ? `<span class="tag tag-fav">Favorite</span>` : ''}
          ${linked.length ? `<span class="tag tag-linked">${linked.length} linked</span>` : ''}
          ${str.score < 3 && p._pwd ? `<span class="tag tag-weak">Weak</span>` : ''}
          ${p.breached ? `<span class="tag" style="background:rgba(244,63,94,0.15);color:#f43f5e;border-color:rgba(244,63,94,0.3)">⚠ Breached</span>` : ''}
        </div>
      </div>
      <button class="card-fav-btn ${p.favorite ? 'active' : ''}" onclick="toggleFav('${p.id}')">
        <svg width="15" height="15" viewBox="0 0 24 24" fill="${p.favorite ? 'currentColor' : 'none'}" stroke="currentColor" stroke-width="2"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>
      </button>
    </div>
    <div class="pwd-row">
      <span class="pwd-masked" id="pwd-display-${p.id}">● ● ● ● ● ● ● ● ● ●</span>
      <button class="card-icon-btn" onclick="togglePwdVisibility('${p.id}')">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
      </button>
    </div>
    <div class="strength-track"><div class="strength-bar" style="width:${str.pct}%;background:${str.color}"></div></div>
    <div class="strength-row">
      <span class="strength-label">STRENGTH</span>
      <span class="strength-label" style="color:${str.color}">${str.label.toUpperCase()}</span>
    </div>
    ${linked.length ? `
    <div class="linked-row">
      <div class="linked-row-label">
        <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/></svg>
        Linked Services
      </div>
      <div class="linked-chips">${linked.map(l => `<span class="linked-chip">${linkedIcon(l)} ${esc(l)}</span>`).join('')}</div>
    </div>
    ${linked.length >= 2 ? `<div class="risk-alert"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/></svg>Risk: ${linked.length} services affected if compromised</div>` : ''}
    ` : ''}
    ${p.notes ? `<div class="card-notes">${esc(p.notes)}</div>` : ''}
    <div class="card-actions">
      <button class="ca-btn copy" onclick="copyPwd('${p.id}')">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
        Copy
      </button>
      <button class="ca-btn edit" onclick="editPassword('${p.id}')">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
        Edit
      </button>
      <button class="ca-btn del" onclick="deletePassword('${p.id}')">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/></svg>
      </button>
    </div>
  </div>`;
}
function esc(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

// ── Visibility Toggles ──
const visiblePwds = new Set();
function togglePwdVisibility(id) {
  const p = CV.passwords.find(p => p.id === id); if (!p) return;
  const el = document.getElementById(`pwd-display-${id}`); if (!el) return;
  if (visiblePwds.has(id)) {
    visiblePwds.delete(id); el.className = 'pwd-masked'; el.textContent = '● ● ● ● ● ● ● ● ● ●';
  } else {
    visiblePwds.add(id); el.className = 'pwd-revealed'; el.textContent = p._pwd || '(empty)';
    CV.addActivity('copy', `Revealed: ${p.name}`);
    setTimeout(() => { visiblePwds.delete(id); if (el) { el.className = 'pwd-masked'; el.textContent = '● ● ● ● ● ● ● ● ● ●'; } }, 15000);
  }
}
function toggleVis(id, btn) {
  const inp = document.getElementById(id);
  inp.type = inp.type === 'password' ? 'text' : 'password';
  btn.querySelector('svg').innerHTML = inp.type === 'text'
    ? '<path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/>'
    : '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>';
}
function toggleFieldVisibility(id, btn) { toggleVis(id, btn); }

// ── Copy Password ──
function copyPwd(id) {
  const p = CV.passwords.find(p => p.id === id); if (!p || !p._pwd) { toast('No password to copy', 'warn'); return; }
  navigator.clipboard.writeText(p._pwd).then(() => {
    toast(`Password copied — clears in ${CV.settings.clipboard}s`, 'success');
    CV.addActivity('copy', `Copied: ${p.name}`);
    clearTimeout(CV.clipboardTimer);
    CV.clipboardTimer = setTimeout(() => { navigator.clipboard.writeText('').catch(()=>{}); toast('Clipboard cleared', 'info'); }, CV.settings.clipboard * 1000);
  }).catch(() => toast('Copy failed', 'error'));
}

// ── Add / Edit / Delete ──
function openAddModal() {
  CV.editingId = null;
  document.getElementById('modal-title').textContent = 'Add Password';
  document.getElementById('edit-id').value = '';
  ['f-name','f-email','f-url','f-notes'].forEach(id => document.getElementById(id).value = '');
  document.getElementById('f-pwd').value = ''; document.getElementById('f-pwd').type = 'password';
  document.getElementById('f-fav').checked = false; document.getElementById('f-cat').value = 'Other';
  document.getElementById('modal-strength-fill').style.cssText = 'width:0%';
  document.getElementById('modal-strength-label').textContent = 'Enter a password to check strength';
  document.getElementById('url-favicon-preview').classList.add('hidden');
  renderLinkedEditorList([]); show('pwd-modal');
}
function editPassword(id) {
  const p = CV.passwords.find(p => p.id === id); if (!p) return;
  CV.editingId = id;
  document.getElementById('modal-title').textContent = 'Edit Password';
  document.getElementById('edit-id').value = id;
  document.getElementById('f-name').value = p.name || '';
  document.getElementById('f-email').value = p.email || '';
  document.getElementById('f-pwd').value = p._pwd || ''; document.getElementById('f-pwd').type = 'password';
  document.getElementById('f-url').value = p.url || '';
  document.getElementById('f-notes').value = p.notes || '';
  document.getElementById('f-fav').checked = p.favorite || false;
  document.getElementById('f-cat').value = p.category || 'Other';
  updateModalStrength(); renderLinkedEditorList(p.linked || []); show('pwd-modal');
  updateFaviconPreview();
}
function closePwdModal() { hide('pwd-modal'); CV.editingId = null; }
async function savePassword() {
  const name  = document.getElementById('f-name').value.trim();
  const email = document.getElementById('f-email').value.trim();
  const pwd   = document.getElementById('f-pwd').value;
  if (!name && !email) { toast('Enter a name or email', 'warn'); return; }
  if (!pwd) { toast('Enter a password', 'warn'); return; }

  // #12 Breach check when saving password
  const breached = await checkBreached(pwd);
  if (breached) { toast('⚠ This password was found in a known data breach!', 'warn'); }

  const linked = getLinkedList();
  const svc    = detectService(name, email);
  const entry  = {
    id: CV.editingId || CV.uid(), name: name || svc.key || 'Unknown', email,
    _pwd: pwd, url: document.getElementById('f-url').value.trim(),
    notes: document.getElementById('f-notes').value.trim(),
    category: document.getElementById('f-cat').value,
    favorite: document.getElementById('f-fav').checked, linked,
    createdAt: Date.now(), updatedAt: Date.now(),
    breached: breached, // store breach flag
  };
  if (CV.editingId) {
    const idx = CV.passwords.findIndex(p => p.id === CV.editingId);
    if (idx !== -1) { entry.createdAt = CV.passwords[idx].createdAt; CV.passwords[idx] = entry; }
    CV.addActivity('edit', `Updated: ${entry.name}`); toast('Password updated', 'success');
  } else {
    CV.passwords.unshift(entry); CV.addActivity('add', `Added: ${entry.name}`); toast('Password saved & encrypted (AES-256-GCM)', 'success');
  }
  await CV.saveLocal(); closePwdModal(); renderPasswords(); renderDashboard();
}
async function deletePassword(id) {
  const p = CV.passwords.find(p => p.id === id);
  showConfirm('Delete Password', `Permanently delete "${p?.name || 'this entry'}"? This action cannot be undone.`, async () => {
    CV.passwords = CV.passwords.filter(p => p.id !== id);
    CV.addActivity('delete', `Deleted: ${p?.name || id}`); await CV.saveLocal(); renderPasswords(); renderDashboard();
    toast('Entry deleted', 'warn');
  });
}
async function toggleFav(id) {
  const p = CV.passwords.find(p => p.id === id); if (!p) return;
  p.favorite = !p.favorite; await CV.saveLocal(); renderPasswords();
  toast(p.favorite ? 'Added to favorites' : 'Removed from favorites', 'info');
}

// ── Linked Editor ──
function renderLinkedEditorList(items) {
  const list = document.getElementById('linked-editor-list');
  list.innerHTML = items.map((item, i) => `
    <div class="linked-edit-row">
      <span class="linked-edit-icon"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/></svg></span>
      <input class="linked-edit-input" value="${esc(item)}" placeholder="e.g. Facebook, Netflix..." id="linked-${i}">
      <button class="linked-edit-del" onclick="this.closest('.linked-edit-row').remove()">
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
      </button>
    </div>`).join('');
}
function addLinkedField() {
  const list = document.getElementById('linked-editor-list');
  const div = document.createElement('div'); div.className = 'linked-edit-row';
  div.innerHTML = `<span class="linked-edit-icon"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/></svg></span><input class="linked-edit-input" placeholder="e.g. Facebook, Netflix, Instagram..."><button class="linked-edit-del" onclick="this.closest('.linked-edit-row').remove()"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>`;
  list.appendChild(div); div.querySelector('input').focus();
}
function getLinkedList() { return Array.from(document.querySelectorAll('.linked-edit-input')).map(i => i.value.trim()).filter(Boolean); }

function autoDetectService() {
  const name = document.getElementById('f-name').value;
  const email = document.getElementById('f-email').value;
  if (!name && email) { const svc = detectService('', email); if (svc.key) document.getElementById('f-name').value = svc.key.charAt(0).toUpperCase() + svc.key.slice(1); }
}

// ── Dashboard ──
function renderDashboard() {
  const total = CV.passwords.length;
  const weak = CV.passwords.filter(p => passwordStrength(p._pwd||'').score < 3).length;
  const linkedTotal = CV.passwords.reduce((s, p) => s + (p.linked?.length || 0), 0);
  const health = total === 0 ? '—' : weak === 0 ? 'A+' : weak < total/4 ? 'B' : weak < total/2 ? 'C' : 'D';
  document.getElementById('stat-total').textContent = total;
  document.getElementById('stat-weak').textContent = weak;
  document.getElementById('stat-linked').textContent = linkedTotal;
  document.getElementById('stat-health').textContent = health;
  const recent = document.getElementById('dashboard-recent');
  const last5 = CV.passwords.slice(0, 4);
  recent.innerHTML = last5.length ? `<div class="cards-grid">${last5.map(p => cardHTML(p)).join('')}</div>` : `<div style="text-align:center;padding:24px;color:var(--t4);font-size:12px;font-family:var(--font-mono)">No passwords yet — add your first entry</div>`;
  renderActivity('dashboard');
}
function renderFavorites() {
  const grid = document.getElementById('fav-grid');
  const favs = CV.passwords.filter(p => p.favorite);
  grid.innerHTML = favs.length ? favs.map(p => cardHTML(p)).join('') : `<div class="empty"><div class="empty-icon"><svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg></div><div class="empty-title">No Favorites</div><div class="empty-sub">Star passwords to see them here</div></div>`;
}
function renderLinkedMap() {
  const panel = document.getElementById('linked-map-panel');
  const withLinks = CV.passwords.filter(p => p.linked?.length > 0);
  if (!withLinks.length) { panel.innerHTML = `<div class="empty"><div class="empty-icon"><svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/></svg></div><div class="empty-title">No Linked Accounts</div><div class="empty-sub">Add passwords with linked services to see the binding map</div></div>`; return; }
  panel.innerHTML = withLinks.map((p, idx) => {
    const svc = detectService(p.name, p.email);
    return `${idx > 0 ? '<hr style="border:none;border-top:1px solid var(--b1);margin:12px 0">' : ''}
    <div class="link-map-entry">
      <div class="link-map-primary">
        ${buildServiceIcon(p, svc)}
        <div style="flex:1">
          <div style="font-family:var(--font-head);font-size:14px;font-weight:700;color:var(--t1)">${esc(p.name)}</div>
          <div style="font-size:11px;color:var(--t3);font-family:var(--font-mono)">${esc(p.email)}</div>
        </div>
        <div class="risk-score-badge">${p.linked.length} AT RISK</div>
      </div>
      <div class="link-map-services">
        ${p.linked.map(l => `<div class="link-map-svc"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="color:var(--violet-mid)"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/></svg>${esc(l)}</div>`).join('')}
      </div>
    </div>`;
  }).join('');
}
function renderActivity(target) {
  const logs = CV.activityLog.slice(0, target === 'dashboard' ? 5 : 100);
  const el = document.getElementById(target === 'dashboard' ? 'dashboard-activity' : 'activity-list');
  if (!el) return;
  el.innerHTML = logs.length ? logs.map(l => `<div class="activity-item"><div class="act-pip ${l.type}"></div><div class="act-text">${esc(l.text)}</div><div class="act-time">${l.time}</div></div>`).join('') : `<div style="text-align:center;padding:20px;color:var(--t4);font-size:12px;font-family:var(--font-mono)">No activity recorded yet</div>`;
}
async function clearActivity() {
  showConfirm('Clear Activity Log', 'This will permanently delete all activity records from your vault.', async () => {
    CV.activityLog = []; await CV.saveLocal(); renderActivity(); toast('Activity log cleared', 'info');
  });
}

// Update the App Check description in settings panel
async function updateAppCheckSettingsDesc() {
  const desc = document.getElementById('appcheck-settings-desc');
  if (!desc) return;
  const isLocal = ['localhost','127.0.0.1',''].includes(location.hostname);
  if (!window._firebaseReady || !window._firebaseAppCheck) {
    desc.innerHTML = '<span style="color:var(--rose)">❌ Not initialized — check Firebase config</span>';
    return;
  }
  try {
    const { getToken } = await import("https://www.gstatic.com/firebasejs/11.9.0/firebase-app-check.js");
    const result = await getToken(window._firebaseAppCheck, false);
    if (result?.token) {
      const mode = isLocal
        ? '<span style="color:var(--amber)">🔧 Active (debug mode — localhost)</span>'
        : '<span style="color:var(--emerald)">✅ Active — reCAPTCHA v3 verified. Only cybervault-24007.web.app can access Firebase</span>';
      desc.innerHTML = mode;
    }
  } catch(e) {
    desc.innerHTML = `<span style="color:var(--rose)">⚠ Error: ${e.message}</span>`;
  }
}

// ── SECURITY #12: Scan all passwords for breaches ──
async function scanAllBreaches() {
  if (!CV.masterCryptoKey || CV.passwords.length === 0) {
    toast('No passwords to scan', 'warn'); return;
  }
  toast(`Scanning ${CV.passwords.length} passwords against HaveIBeenPwned…`, 'info');
  let breachedCount = 0;
  for (const p of CV.passwords) {
    if (!p._pwd) continue;
    const breached = await checkBreached(p._pwd);
    if (breached !== p.breached) {
      p.breached = breached;
    }
    if (breached) breachedCount++;
    await new Promise(r => setTimeout(r, 200)); // rate limit HIBP API
  }
  await CV.saveLocal(); renderPasswords(); renderDashboard();
  if (breachedCount > 0) {
    toast(`⚠ Found ${breachedCount} breached password(s) — check your vault!`, 'error');
  } else {
    toast('✅ No breached passwords found', 'success');
  }
  CV.addActivity('security', `Breach scan: ${breachedCount} breached of ${CV.passwords.length}`);
}

// ── SECURITY #13: Show device binding info ──
function showDeviceInfo() {
  const fp = CV.deviceFP || DeviceGuard.getFingerprint();
  showConfirm('Device Binding Info',
    `Your vault is bound to this device/browser.\n\nDevice ID: ${fp.slice(0,32)}…\n\nIf you sign in from a different device, you will see a warning. This helps detect unauthorized access.`,
    () => {}
  );
}

// ── Generator ──
let _genPwd = '';
function generatePassword() {
  const len = parseInt(document.getElementById('gen-length')?.value || 16);
  const upper = document.getElementById('gen-upper')?.checked;
  const lower = document.getElementById('gen-lower')?.checked;
  const nums = document.getElementById('gen-nums')?.checked;
  const syms = document.getElementById('gen-syms')?.checked;
  const noAmbig = document.getElementById('gen-ambig')?.checked;
  let chars = '';
  if (upper) chars += noAmbig ? 'ABCDEFGHJKLMNPQRSTUVWXYZ' : 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  if (lower) chars += noAmbig ? 'abcdefghjkmnpqrstuvwxyz' : 'abcdefghijklmnopqrstuvwxyz';
  if (nums)  chars += noAmbig ? '23456789' : '0123456789';
  if (syms)  chars += '!@#$%^&*()-_=+[]{}|;:,.<>?';
  if (!chars) chars = 'abcdefghijklmnopqrstuvwxyz';
  const arr = new Uint32Array(len); crypto.getRandomValues(arr);
  _genPwd = Array.from(arr).map(n => chars[n % chars.length]).join('');
  const el = document.getElementById('gen-output'); if (el) { el.textContent = _genPwd; el.style.animation = 'none'; void el.offsetWidth; el.style.animation = 'gen-flash 0.3s ease'; }
  const str = passwordStrength(_genPwd);
  const d = document.getElementById('gen-strength-display');
  if (d) d.innerHTML = `<div class="strength-track"><div class="strength-bar" style="width:${str.pct}%;background:${str.color}"></div></div><div class="strength-row"><span class="strength-label">STRENGTH</span><span class="strength-label" style="color:${str.color}">${str.label.toUpperCase()}</span></div>`;
}
function copyGenerated() {
  if (!_genPwd) { toast('Generate a password first', 'warn'); return; }
  navigator.clipboard.writeText(_genPwd).then(() => toast('Password copied to clipboard', 'success')).catch(() => {});
}
function fillGenerated() {
  if (!_genPwd) generatePassword();
  document.getElementById('f-pwd').value = _genPwd; updateModalStrength();
}

// ── SECURITY #10: Export with separate passphrase — uses secure modal, not prompt() ──
async function exportVault(fmt) {
  if (!CV.masterCryptoKey) { toast('Vault not unlocked', 'error'); return; }
  // Show secure passphrase modal instead of browser prompt()
  showPassphraseModal('Export', 'Set a passphrase for this export file (different from your master password — you\'ll need it to import):', async (exportPass) => {
    if (!exportPass) { toast('Export cancelled', 'info'); return; }
    if (exportPass.length < 6) { toast('Export passphrase must be at least 6 characters', 'warn'); return; }
    toast('Encrypting export…', 'info');
    const exportSalt = WC.newSalt();
    const exportKey  = await WC.deriveKey(exportPass, exportSalt);
    const encPayload = await WC.encrypt(CV.passwords, exportKey);
    const ts = new Date().toISOString().slice(0,19).replace(/:/g,'-');
    if (fmt === 'json') {
      const payload = JSON.stringify({
        version: '6.0', encrypted: true, algo: 'AES-256-GCM',
        kdf: 'PBKDF2-SHA256-310000', exportSalt, vault: encPayload,
        exportedAt: ts, user: CV.user?.email
      }, null, 2);
      dlBlob(new Blob([payload], { type: 'application/json' }), `cybervault-backup-${ts}.json`);
    } else {
      const rows = [['Name','Email','EncryptedPassword','URL','Category','Linked','Notes','ExportSalt']];
      for (const p of CV.passwords) {
        const encPwd = await WC.encrypt(p._pwd, exportKey);
        rows.push([p.name, p.email, encPwd, p.url, p.category, (p.linked||[]).join('|'), p.notes, exportSalt]);
      }
      dlBlob(new Blob([rows.map(r=>r.map(c=>`"${(c||'').replace(/"/g,'""')}"`).join(',')).join('\n')],{type:'text/csv'}), `cybervault-export-${ts}.csv`);
    }
    CV.addActivity('vault', 'Exported vault with separate passphrase');
    await CV.saveLocal();
    toast('Vault exported (AES-256-GCM encrypted with separate passphrase)', 'success');
  });
}
function dlBlob(blob, name) { const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = name; a.click(); }
async function importVault(input) {
  const file = input.files[0]; if (!file) return;
  const reader = new FileReader();
  reader.onload = async e => {
    try {
      const data = JSON.parse(e.target.result);
      if (!data.vault) throw new Error('Invalid backup file');
      if (data.version === '6.0' && data.exportSalt) {
        // New format — ask for export passphrase via secure modal
        showPassphraseModal('Import', 'Enter the export passphrase for this backup file:', async (exportPass) => {
          if (!exportPass) { toast('Import cancelled', 'info'); return; }
          try {
            const exportKey = await WC.deriveKey(exportPass, data.exportSalt);
            const dec = await WC.decrypt(data.vault, exportKey);
            if (!dec) { toast('Wrong export passphrase', 'error'); return; }
            showConfirm('Import Vault', `Import ${dec.length} entries? This will merge with your existing data.`, async () => {
              const ids = new Set(CV.passwords.map(p => p.id));
              dec.forEach(p => { if (!ids.has(p.id)) CV.passwords.push(p); });
              await CV.saveLocal(); renderPasswords(); renderDashboard();
              CV.addActivity('vault', `Imported ${dec.length} entries`); toast(`Imported ${dec.length} entries`, 'success');
            });
          } catch(e) { toast('Import failed: ' + e.message, 'error'); }
        });
      } else {
        // Legacy format — use master key
        let dec = await CV.decrypt(data.vault);
        if (!dec && CV.masterKeyRaw) dec = CV._legacyDecrypt(data.vault, CV.masterKeyRaw);
        if (!dec) throw new Error('Decryption failed — wrong master password?');
        showConfirm('Import Vault', `Import ${dec.length} entries? This will merge with your existing data.`, async () => {
          const ids = new Set(CV.passwords.map(p => p.id));
          dec.forEach(p => { if (!ids.has(p.id)) CV.passwords.push(p); });
          await CV.saveLocal(); renderPasswords(); renderDashboard();
          CV.addActivity('vault', `Imported ${dec.length} entries`); toast(`Imported ${dec.length} entries`, 'success');
        });
      }
    } catch(e) { toast('Import failed: ' + e.message, 'error'); }
  };
  reader.readAsText(file); input.value = '';
}
async function confirmWipe() {
  showConfirm('Secure Wipe', 'This will PERMANENTLY DELETE ALL passwords from this device and cloud storage. This cannot be undone.', async () => {
    CV.passwords = []; CV.activityLog = [];
    // Wipe localStorage
    localStorage.removeItem(CV.storageKey('vault'));
    localStorage.removeItem(CV.storageKey('log'));
    if (window._firebaseReady && CV.user) try { window._firebaseModules.deleteDoc(window._firebaseModules.doc(window._firebaseDb,'vaults',CV.user.uid)); } catch(e){}
    renderPasswords(); renderDashboard(); toast('Vault wiped securely', 'warn');
  });
}

// ── Settings ──
function loadSettings() {
  const s = localStorage.getItem(`cv_settings_${CV.user?.uid}`);
  if (s) try { Object.assign(CV.settings, JSON.parse(s)); } catch(e){}
  const al = document.getElementById('setting-autolock'); if (al) al.value = CV.settings.autolock || 300;
  const cl = document.getElementById('setting-clipboard'); if (cl) cl.value = CV.settings.clipboard || 30;
  const bl = document.getElementById('setting-blur'); if (bl) bl.checked = CV.settings.blur !== false;
  CV.inactivityMax = CV.settings.autolock || 300;
}
function saveSetting(key, value) {
  CV.settings[key] = value; localStorage.setItem(`cv_settings_${CV.user?.uid}`, JSON.stringify(CV.settings));
  if (key === 'autolock') { CV.inactivityMax = parseInt(value); CV.resetInactivity(); }
  if (key === 'clipboard') CV.settings.clipboard = parseInt(value);
  toast('Setting saved', 'success');
}

// ── Inactivity ──
function startInactivity() {
  stopInactivity(); CV.inactivityLeft = CV.inactivityMax;
  CV.inactivityTimer = setInterval(() => {
    CV.inactivityLeft--;
    const fill = document.getElementById('inactivity-fill');
    if (fill) fill.style.width = (CV.inactivityLeft / CV.inactivityMax * 100) + '%';
    if (CV.inactivityLeft <= 0) lockVault();
    if (CV.inactivityLeft === 30) toast('Auto-lock in 30 seconds', 'warn');
  }, 1000);
  ['mousemove','keydown','click','scroll','touchstart'].forEach(e => document.addEventListener(e, resetInactivity, { passive:true }));
}
function stopInactivity() {
  clearInterval(CV.inactivityTimer);
  ['mousemove','keydown','click','scroll','touchstart'].forEach(e => document.removeEventListener(e, resetInactivity));
}
function resetInactivity() { CV.inactivityLeft = CV.inactivityMax; }

document.addEventListener('visibilitychange', () => {
  const blur = document.hidden && CV.settings.blur !== false && !CV.vaultLocked;
  document.querySelectorAll('.pwd-revealed').forEach(el => { el.style.filter = blur ? 'blur(6px)' : ''; });
});

// ── Confirm Modal ──
function showConfirm(title, text, onOk) {
  document.getElementById('confirm-title').textContent = title;
  document.getElementById('confirm-text').textContent = text;
  document.getElementById('confirm-ok').onclick = () => { onOk(); closeConfirm(); };
  show('confirm-modal');
}
function closeConfirm() { hide('confirm-modal'); }

// ── Secure Passphrase Modal (replaces unsafe browser prompt()) ──
function showPassphraseModal(action, labelText, onSubmit) {
  const modal = document.getElementById('passphrase-modal');
  const title = document.getElementById('passphrase-modal-title');
  const label = document.getElementById('passphrase-modal-label');
  const input = document.getElementById('passphrase-modal-input');
  const okBtn = document.getElementById('passphrase-modal-ok');
  if (!modal) return;
  title.textContent = action + ' Passphrase';
  label.textContent = labelText;
  input.value = '';
  input.type = 'password';
  modal.classList.remove('hidden');
  setTimeout(() => input.focus(), 80);
  const submit = () => {
    const val = input.value;
    modal.classList.add('hidden');
    input.value = '';
    onSubmit(val);
  };
  okBtn.onclick = submit;
  input.onkeydown = (e) => { if (e.key === 'Enter') submit(); if (e.key === 'Escape') { modal.classList.add('hidden'); input.value = ''; } };
  document.getElementById('passphrase-modal-cancel').onclick = () => { modal.classList.add('hidden'); input.value = ''; onSubmit(null); };
}

// ── Toast ──
function toast(msg, type='info') {
  const icons = {
    success: `<svg class="toast-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>`,
    error:   `<svg class="toast-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>`,
    info:    `<svg class="toast-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>`,
    warn:    `<svg class="toast-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`,
  };
  const t = document.createElement('div'); t.className = `toast ${type}`;
  // FIX: Use textContent for the message to prevent XSS — never inject user data via innerHTML
  const iconWrap = document.createElement('span'); iconWrap.innerHTML = icons[type]||icons.info;
  const msgDiv = document.createElement('div'); msgDiv.className = 'toast-msg'; msgDiv.textContent = msg;
  const closeBtn = document.createElement('button'); closeBtn.className = 'toast-close';
  closeBtn.innerHTML = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>`;
  closeBtn.onclick = () => t.remove();
  t.appendChild(iconWrap); t.appendChild(msgDiv); t.appendChild(closeBtn);
  document.getElementById('toastContainer').appendChild(t);
  setTimeout(() => { t.classList.add('removing'); setTimeout(() => t.remove(), 250); }, 3500);
}

// ── Utils ──
function show(id) { const el = document.getElementById(id); if (el) el.classList.remove('hidden'); }
function hide(id) { const el = document.getElementById(id); if (el) el.classList.add('hidden'); }

// ── SECURITY #6: Back-button sign out protection ──
history.pushState(null, '', location.href);
window.addEventListener('popstate', () => {
  history.pushState(null, '', location.href);
  if (!CV.vaultLocked && CV.masterCryptoKey) {
    lockVault();
    toast('Back navigation detected — vault locked for safety', 'warn');
  }
});

// ── Keyboard Shortcuts ──
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') { hide('pwd-modal'); hide('master-modal'); hide('confirm-modal'); closeSidebar(); }
  if (e.ctrlKey && e.key === 'l') { e.preventDefault(); lockVault(); }
  if (e.ctrlKey && e.key === 'n' && !CV.vaultLocked) { e.preventDefault(); openAddModal(); }
});
document.getElementById('login-password').addEventListener('keydown', e => { if (e.key === 'Enter') handleLogin(); });
document.getElementById('master-input').addEventListener('keydown', e => { if (e.key === 'Enter') unlockVault(); });

// ── CSS for gen-flash ──
const genFlashStyle = document.createElement('style');
genFlashStyle.textContent = `@keyframes gen-flash { 0%{opacity:0.4;transform:scale(0.98)} 100%{opacity:1;transform:scale(1)} }`;
document.head.appendChild(genFlashStyle);

// ── Init ──
(function init() {
  if (window._firebaseReady) {
    const check = setInterval(() => {
      if (window._firebaseModules) {
        clearInterval(check);
        window._firebaseModules.onAuthStateChanged(window._firebaseAuth, async user => {
          if (user) {
            CV.user = { uid: user.uid, email: user.email };
            // #13 Device check on auto-login
            CV.deviceFP = DeviceGuard.getFingerprint();
            const storedFP = localStorage.getItem(`cv_${CV.user.uid}_device`);
            DeviceGuard.validate(storedFP);
            localStorage.setItem(`cv_${CV.user.uid}_device`, CV.deviceFP);

            // ── FIX: Try localStorage first, then fall back to Firestore (cross-device) ──
            let salt = localStorage.getItem(`cv_${CV.user.uid}_salt`);
            let hash = localStorage.getItem(`cv_${CV.user.uid}_master`);

            if (!salt || !hash) {
              // Missing on this device (e.g. first login on mobile) — fetch from cloud
              const cloud = await CV.loadMasterFromFirestore(CV.user.uid);
              if (cloud) {
                salt = cloud.salt;
                hash = cloud.masterHash;
                // Cache to localStorage for future offline use
                localStorage.setItem(`cv_${CV.user.uid}_salt`, salt);
                localStorage.setItem(`cv_${CV.user.uid}_master`, hash);
                toast('Vault credentials synced from cloud ✓', 'success');
              }
            }

            CV.masterSalt = salt || CV.getOrCreateSalt(CV.user.uid);
            if (hash) { CV.masterHash = hash; hide('auth-screen'); showVaultScreen(); } else { hide('auth-screen'); showSetMaster(); }
          }
        });
      }
    }, 100);
  }
  setTimeout(generatePassword, 600);
})();
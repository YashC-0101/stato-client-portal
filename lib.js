/**
 * stato-client-portal shared client lib.
 *
 * Three jobs:
 *   1. Page-level password gate (SHA-256 of typed password compared to a hash)
 *   2. AES-GCM encryption of submission data using the password as a key
 *   3. GitHub Contents API read/write of submissions.json in this same repo
 *
 * The password serves all three purposes, so the user enters it ONCE
 * per browser. localStorage remembers a "verified" flag for 7 days.
 *
 * Security model:
 *   - Anyone visiting the URL hits the password screen first.
 *   - The password is never stored — only a SHA-256 hash is in the page source.
 *   - Submission data is AES-GCM encrypted before being written to the repo,
 *     so even if someone fetches submissions.json directly, they see gibberish.
 *   - The GitHub PAT in CONFIG.token is fine-grained: write access to
 *     `submissions.json` only, in this single repo.
 */

const CONFIG = {
  // GitHub repo where submissions.json lives (this same repo).
  repo: 'YashC-0101/stato-client-portal',
  branch: 'main',
  file: 'submissions.json',

  // ⚠️ REPLACE with a fine-grained Personal Access Token before going live.
  // https://github.com/settings/personal-access-tokens/new
  //   - Repository access: Only `stato-client-portal`
  //   - Permissions → Repository → Contents → Read and write
  // Worst case if leaked: someone vandalises submissions.json. Easy to revert.
  token: 'PASTE_GITHUB_FINE_GRAINED_TOKEN_HERE',

  // SHA-256 hex of the access password.
  // Default password is "stato2026". To change it:
  //   echo -n "your-new-password" | shasum -a 256
  // Or in your browser console:
  //   crypto.subtle.digest('SHA-256', new TextEncoder().encode('your-new-password'))
  //     .then(h => console.log(Array.from(new Uint8Array(h)).map(b=>b.toString(16).padStart(2,'0')).join('')))
  passwordHash: '2d176fe23fb2781408fa4ac5517e08e6d9a40d797e12390855735013bb9043b1',

  // Localstorage TTL for "verified" flag. After this, the user re-enters the password.
  rememberMs: 7 * 24 * 60 * 60 * 1000, // 7 days
};

// ─── Helpers ────────────────────────────────────────────────────────────────

const enc = new TextEncoder();
const dec = new TextDecoder();

function bytesToHex(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}

function bytesToBase64(bytes) {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

function base64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function sha256Hex(str) {
  const buf = await crypto.subtle.digest('SHA-256', enc.encode(str));
  return bytesToHex(new Uint8Array(buf));
}

// PBKDF2 → AES-GCM key derivation. salt is per-submission so the same password
// produces different ciphertext each time (mitigates rainbow attacks).
async function deriveKey(password, salt) {
  const baseKey = await crypto.subtle.importKey(
    'raw',
    enc.encode(password),
    { name: 'PBKDF2' },
    false,
    ['deriveKey'],
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 200_000 },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

async function encryptJson(password, obj) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(password, salt);
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    enc.encode(JSON.stringify(obj)),
  );
  return {
    v: 1,
    salt: bytesToBase64(salt),
    iv: bytesToBase64(iv),
    ct: bytesToBase64(new Uint8Array(ct)),
  };
}

async function decryptJson(password, blob) {
  const salt = base64ToBytes(blob.salt);
  const iv = base64ToBytes(blob.iv);
  const ct = base64ToBytes(blob.ct);
  const key = await deriveKey(password, salt);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
  return JSON.parse(dec.decode(pt));
}

// ─── Password gate ──────────────────────────────────────────────────────────

const STORAGE_KEY = 'stato-portal-verified-v1';
const PASSWORD_KEY = 'stato-portal-password-v1';

function isVerified() {
  try {
    const v = JSON.parse(localStorage.getItem(STORAGE_KEY) || 'null');
    if (!v || !v.expiresAt) return false;
    return Date.now() < v.expiresAt;
  } catch {
    return false;
  }
}

function getStoredPassword() {
  try {
    return sessionStorage.getItem(PASSWORD_KEY);
  } catch {
    return null;
  }
}

function setVerified(password) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify({ expiresAt: Date.now() + CONFIG.rememberMs }));
  // Password held in sessionStorage (cleared when tab closes) — used for
  // encrypt/decrypt on this tab without re-prompting.
  sessionStorage.setItem(PASSWORD_KEY, password);
}

function clearVerified() {
  localStorage.removeItem(STORAGE_KEY);
  sessionStorage.removeItem(PASSWORD_KEY);
}

/**
 * Build and inject the password gate. Calls onUnlock(password) when the
 * password matches CONFIG.passwordHash.
 *
 * If the user has a valid "verified" flag and a stored session password,
 * onUnlock fires immediately without showing the modal.
 */
function mountPasswordGate(onUnlock) {
  // Auto-unlock if both flag and password are present + valid.
  if (isVerified() && getStoredPassword()) {
    onUnlock(getStoredPassword());
    return;
  }

  const wrap = document.createElement('div');
  wrap.id = 'stato-gate';
  wrap.innerHTML = `
    <style>
      #stato-gate {
        position: fixed; inset: 0;
        background: rgba(15, 17, 22, 0.96);
        backdrop-filter: blur(16px); -webkit-backdrop-filter: blur(16px);
        display: flex; align-items: center; justify-content: center;
        z-index: 9999; padding: 20px;
        font-family: -apple-system, BlinkMacSystemFont, 'SF Pro Text', 'Segoe UI', sans-serif;
      }
      #stato-gate .gate-card {
        background: white; border-radius: 18px; padding: 36px 32px;
        max-width: 380px; width: 100%;
        box-shadow: 0 24px 60px -20px rgba(0, 0, 0, 0.6);
        text-align: center;
      }
      #stato-gate .lock-ic {
        width: 56px; height: 56px; margin: 0 auto 18px;
        background: #f0f7ff; border-radius: 16px;
        display: flex; align-items: center; justify-content: center;
        font-size: 26px;
      }
      #stato-gate h2 {
        margin: 0 0 6px 0; font-size: 19px; font-weight: 700;
        letter-spacing: -0.015em; color: #1d1d1f;
      }
      #stato-gate p {
        margin: 0 0 22px 0; color: #6e6e73; font-size: 14px; line-height: 1.5;
      }
      #stato-gate input[type="password"] {
        width: 100%; padding: 12px 14px;
        border: 1px solid #e8e8ed; border-radius: 12px;
        font: inherit; font-size: 15px; text-align: center;
        outline: none; letter-spacing: 0.05em;
        transition: border-color 120ms ease, box-shadow 120ms ease;
      }
      #stato-gate input[type="password"]:focus {
        border-color: #0066cc; box-shadow: 0 0 0 3px rgba(0, 102, 204, 0.18);
      }
      #stato-gate button {
        width: 100%; margin-top: 12px;
        padding: 12px; border-radius: 12px; border: none;
        background: #0066cc; color: white;
        font: inherit; font-size: 15px; font-weight: 600;
        cursor: pointer; transition: background 120ms ease;
      }
      #stato-gate button:hover { background: #0058b3; }
      #stato-gate button:disabled { background: #c0c0c5; cursor: progress; }
      #stato-gate .err {
        color: #dc2626; font-size: 13px; margin-top: 12px; min-height: 18px;
      }
      #stato-gate .footer {
        margin-top: 22px; font-size: 12px; color: #86868b;
        border-top: 1px solid #e8e8ed; padding-top: 14px;
      }
    </style>
    <div class="gate-card">
      <div class="lock-ic">🔒</div>
      <h2>Access required</h2>
      <p>Enter the access code to continue.<br/>If you don't have one, please contact Yash.</p>
      <form id="gate-form">
        <input type="password" id="gate-input" placeholder="Access code" autocomplete="off" autofocus />
        <button type="submit" id="gate-btn">Continue</button>
        <div class="err" id="gate-err"></div>
      </form>
      <div class="footer">Stato · leadgeneration.io</div>
    </div>
  `;
  document.body.appendChild(wrap);
  document.body.style.overflow = 'hidden';

  const form = wrap.querySelector('#gate-form');
  const input = wrap.querySelector('#gate-input');
  const btn = wrap.querySelector('#gate-btn');
  const err = wrap.querySelector('#gate-err');

  form.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    err.textContent = '';
    btn.disabled = true;
    btn.textContent = 'Checking…';
    try {
      const typed = input.value.trim();
      const hash = await sha256Hex(typed);
      if (hash !== CONFIG.passwordHash) {
        err.textContent = 'Wrong code — please try again.';
        input.value = '';
        input.focus();
        return;
      }
      setVerified(typed);
      wrap.remove();
      document.body.style.overflow = '';
      onUnlock(typed);
    } finally {
      btn.disabled = false;
      btn.textContent = 'Continue';
    }
  });
}

// ─── GitHub Contents API ────────────────────────────────────────────────────

const GITHUB_API = 'https://api.github.com';

async function fetchSubmission() {
  const url = `${GITHUB_API}/repos/${CONFIG.repo}/contents/${CONFIG.file}?ref=${CONFIG.branch}`;
  const res = await fetch(url, {
    headers: {
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
    },
    cache: 'no-store',
  });
  if (res.status === 404) return { sha: null, blob: null };
  if (!res.ok) throw new Error(`GitHub fetch failed: ${res.status}`);
  const data = await res.json();
  // Decode base64 → JSON object (the encrypted blob)
  const jsonText = decodeURIComponent(escape(atob(data.content.replace(/\n/g, ''))));
  const blob = JSON.parse(jsonText);
  return { sha: data.sha, blob };
}

async function writeSubmission(blob, prevSha) {
  if (!CONFIG.token || CONFIG.token.startsWith('PASTE_')) {
    throw new Error('GitHub token not configured. Edit lib.js → CONFIG.token before going live.');
  }
  const url = `${GITHUB_API}/repos/${CONFIG.repo}/contents/${CONFIG.file}`;
  const content = btoa(unescape(encodeURIComponent(JSON.stringify(blob, null, 2))));
  const body = {
    message: prevSha ? 'Update submission' : 'Initial submission',
    content,
    branch: CONFIG.branch,
  };
  if (prevSha) body.sha = prevSha;

  const res = await fetch(url, {
    method: 'PUT',
    headers: {
      Authorization: `Bearer ${CONFIG.token}`,
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const err = await res.text();
    throw new Error(`GitHub write failed: ${res.status} — ${err}`);
  }
  return res.json();
}

// ─── High-level submit / load ───────────────────────────────────────────────

/**
 * Submit form data: encrypt with password, fetch existing file's SHA (if any),
 * write to GitHub. Returns the commit info on success.
 */
async function submitToGitHub(password, formData) {
  const payload = {
    submittedAt: new Date().toISOString(),
    submittedBy: 'sam',
    answers: formData,
  };
  const cipher = await encryptJson(password, payload);

  // Outer envelope: stays as plain JSON so anyone visiting the file can see
  // it's encrypted (and what version), but the actual answers are inside `data`.
  const envelope = {
    v: 1,
    encrypted: true,
    lastUpdated: payload.submittedAt,
    data: cipher,
  };

  const { sha } = await fetchSubmission();
  return writeSubmission(envelope, sha);
}

/**
 * Load and decrypt the latest submission. Returns null if no submission yet.
 */
async function loadLatest(password) {
  const { blob } = await fetchSubmission();
  if (!blob) return null;
  if (!blob.encrypted || !blob.data) {
    // Plaintext fallback (shouldn't happen, but be safe)
    return blob;
  }
  return decryptJson(password, blob.data);
}

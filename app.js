/**
 * VaultLock — app.js
 * AES-256-GCM browser-based file encryption/decryption
 * Uses: Web Crypto API, JSZip (DEFLATE compression)
 * Format: .vault = ASCII header + 96-bit IV + GCM ciphertext+tag
 */

'use strict';

/* ──────────────────────────────────────────────
   Constants & State
─────────────────────────────────────────────── */
const VAULT_HEADER = 'VAULTLOCK-AES256GCM-v1\n';
const IV_LENGTH = 12;      // 96-bit IV for AES-GCM
const KEY_LENGTH = 256;    // bits
const TAG_LENGTH = 128;    // GCM authentication tag bits

const state = {
  encryptFiles: [],
  generatedPassword: null,
  encryptBlobUrl: null,
  decryptFile: null,
};

/* ──────────────────────────────────────────────
   Utility helpers
─────────────────────────────────────────────── */
function hexFromBuffer(buf) {
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}

function bufferFromHex(hex) {
  if (hex.length % 2 !== 0) throw new Error('Invalid hex string');
  const buf = new Uint8Array(hex.length / 2);
  for (let i = 0; i < buf.length; i++) {
    buf[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return buf;
}

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1048576).toFixed(2)} MB`;
}

function compressionRatio(original, compressed) {
  if (original === 0) return '0%';
  const saved = ((1 - compressed / original) * 100).toFixed(1);
  return `${saved}%`;
}

function getFileIcon(name) {
  const ext = name.split('.').pop().toLowerCase();
  const map = {
    pdf: '📄', doc: '📝', docx: '📝', txt: '📃', jpg: '🖼️', jpeg: '🖼️',
    png: '🖼️', gif: '🖼️', mp4: '🎬', mp3: '🎵', zip: '📦', rar: '📦',
    xlsx: '📊', csv: '📊', pptx: '📊', js: '💻', py: '💻', html: '💻',
  };
  return map[ext] || '📎';
}

/* ──────────────────────────────────────────────
   Key generation — CSPRNG 256-bit key
─────────────────────────────────────────────── */
async function generateKey() {
  return crypto.subtle.generateKey(
    { name: 'AES-GCM', length: KEY_LENGTH },
    true,  // extractable to export as hex for user display
    ['encrypt', 'decrypt']
  );
}

async function keyToHex(cryptoKey) {
  const raw = await crypto.subtle.exportKey('raw', cryptoKey);
  return hexFromBuffer(raw);
}

async function hexToKey(hex, usage = ['decrypt']) {
  const raw = bufferFromHex(hex);
  if (raw.length !== 32) throw new Error('Password must be a 64-character hex string (256-bit key).');
  return crypto.subtle.importKey(
    'raw', raw,
    { name: 'AES-GCM', length: KEY_LENGTH },
    false,
    usage
  );
}

/* ──────────────────────────────────────────────
   Vault file format:
   [ASCII header]\n[hex IV (24 chars)]\n[hex ciphertext]
─────────────────────────────────────────────── */
function buildVaultBuffer(iv, ciphertext) {
  const ivHex = hexFromBuffer(iv);
  const ctHex = hexFromBuffer(ciphertext);
  const textPart = VAULT_HEADER + ivHex + '\n' + ctHex;
  return new TextEncoder().encode(textPart);
}

function parseVaultBuffer(bytes) {
  const text = new TextDecoder().decode(bytes);
  const lines = text.split('\n');
  if (lines[0] + '\n' !== VAULT_HEADER) {
    throw new Error('Not a valid .vault file. Ensure you have selected the correct file.');
  }
  const ivHex = lines[1];
  const ctHex = lines[2];
  if (!ivHex || ivHex.length !== IV_LENGTH * 2) {
    throw new Error('Vault file is corrupted: invalid IV.');
  }
  if (!ctHex || ctHex.length < 2) {
    throw new Error('Vault file is corrupted: missing ciphertext.');
  }
  return {
    iv: bufferFromHex(ivHex),
    ciphertext: bufferFromHex(ctHex),
  };
}

/* ──────────────────────────────────────────────
   Encrypt flow
─────────────────────────────────────────────── */
async function encryptFiles(files) {
  // 1. Compress all files into a single ZIP (DEFLATE)
  const zip = new JSZip();
  for (const file of files) {
    const data = await file.arrayBuffer();
    zip.file(file.name, data, { compression: 'DEFLATE', compressionOptions: { level: 6 } });
  }
  const zipBuffer = await zip.generateAsync({ type: 'arraybuffer' });

  // 2. Generate 256-bit key and 96-bit IV
  const cryptoKey = await generateKey();
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));

  // 3. AES-256-GCM encrypt
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, tagLength: TAG_LENGTH },
    cryptoKey,
    zipBuffer
  );

  // 4. Build .vault file
  const vaultBytes = buildVaultBuffer(iv, ciphertext);
  const blob = new Blob([vaultBytes], { type: 'application/octet-stream' });

  // 5. Export key as hex password
  const passwordHex = await keyToHex(cryptoKey);

  return {
    blob,
    passwordHex,
    originalSize: files.reduce((s, f) => s + f.size, 0),
    compressedSize: zipBuffer.byteLength,
    vaultSize: vaultBytes.byteLength,
  };
}

/* ──────────────────────────────────────────────
   Decrypt flow
─────────────────────────────────────────────── */
async function decryptVault(vaultFile, passwordHex) {
  const vaultBytes = await vaultFile.arrayBuffer();
  const { iv, ciphertext } = parseVaultBuffer(vaultBytes);

  const cryptoKey = await hexToKey(passwordHex.trim(), ['decrypt']);

  let zipBuffer;
  try {
    zipBuffer = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv, tagLength: TAG_LENGTH },
      cryptoKey,
      ciphertext
    );
  } catch {
    throw new Error('Decryption failed. The password is incorrect or the file has been tampered with.');
  }

  // Load the ZIP and extract all files
  const zip = await JSZip.loadAsync(zipBuffer);
  return zip;
}

/* ──────────────────────────────────────────────
   UI — Encrypt Tab
─────────────────────────────────────────────── */
const encDropzone = document.getElementById('enc-dropzone');
const encFileInput = document.getElementById('enc-file-input');
const encFileList = document.getElementById('enc-file-list');
const passwordPanel = document.getElementById('password-panel');
const passwordValue = document.getElementById('password-value');
const copyBtn = document.getElementById('copy-btn');
const encryptBtn = document.getElementById('encrypt-btn');
const encStatus = document.getElementById('enc-status');

// Drag counter tracks enter/leave across children
let encDragCounter = 0;

function renderFileList() {
  encFileList.innerHTML = '';
  state.encryptFiles.forEach((file, i) => {
    const item = document.createElement('div');
    item.className = 'file-item';
    item.innerHTML = `
      <div class="file-item-info">
        <div class="file-item-icon">${getFileIcon(file.name)}</div>
        <div>
          <div class="file-item-name" title="${file.name}">${file.name}</div>
          <div class="file-item-size">${formatBytes(file.size)}</div>
        </div>
      </div>
      <button class="file-item-remove" data-i="${i}" title="Remove">✕</button>
    `;
    encFileList.appendChild(item);
  });

  encFileList.querySelectorAll('.file-item-remove').forEach(btn => {
    btn.addEventListener('click', () => {
      state.encryptFiles.splice(Number(btn.dataset.i), 1);
      renderFileList();
      updateEncryptUI();
    });
  });

  updateEncryptUI();
}

function updateEncryptUI() {
  const hasFiles = state.encryptFiles.length > 0;
  encryptBtn.disabled = !hasFiles;

  if (hasFiles) {
    generateAndShowPassword();
  } else {
    passwordPanel.classList.remove('visible');
    state.generatedPassword = null;
  }

  // Reset status when files change
  encStatus.className = 'status-panel';
  encStatus.innerHTML = '';
  if (state.encryptBlobUrl) {
    URL.revokeObjectURL(state.encryptBlobUrl);
    state.encryptBlobUrl = null;
  }
}

async function generateAndShowPassword() {
  // Generate a preview password (will regenerate fresh on actual encrypt)
  try {
    const key = await generateKey();
    state.generatedPassword = await keyToHex(key);
    passwordValue.textContent = state.generatedPassword;
    passwordPanel.classList.add('visible');
    copyBtn.textContent = 'Copy';
    copyBtn.className = 'copy-btn';
  } catch (e) {
    console.error('Key gen failed:', e);
  }
}

encDropzone.addEventListener('click', () => encFileInput.click());

encDropzone.addEventListener('dragenter', (e) => {
  e.preventDefault();
  encDragCounter++;
  encDropzone.classList.add('drag-over');
});

encDropzone.addEventListener('dragover', (e) => { e.preventDefault(); });

encDropzone.addEventListener('dragleave', () => {
  encDragCounter--;
  if (encDragCounter <= 0) {
    encDragCounter = 0;
    encDropzone.classList.remove('drag-over');
  }
});

encDropzone.addEventListener('drop', (e) => {
  e.preventDefault();
  encDragCounter = 0;
  encDropzone.classList.remove('drag-over');
  const files = [...e.dataTransfer.files];
  if (files.length) {
    state.encryptFiles.push(...files);
    renderFileList();
  }
});

encFileInput.addEventListener('change', () => {
  const files = [...encFileInput.files];
  if (files.length) {
    state.encryptFiles.push(...files);
    renderFileList();
    encFileInput.value = '';
  }
});

copyBtn.addEventListener('click', () => {
  if (!state.generatedPassword) return;
  navigator.clipboard.writeText(state.generatedPassword).then(() => {
    copyBtn.textContent = '✓ Copied';
    copyBtn.classList.add('copied');
    setTimeout(() => {
      copyBtn.textContent = 'Copy';
      copyBtn.classList.remove('copied');
    }, 2000);
  });
});

encryptBtn.addEventListener('click', async () => {
  if (state.encryptFiles.length === 0) return;

  encryptBtn.disabled = true;
  encStatus.className = 'status-panel loading visible';
  encStatus.innerHTML = `
    <div class="status-header">
      <div class="spinner"></div>
      <span class="status-title">Encrypting…</span>
    </div>
    <p class="status-body">Compressing and encrypting your files in-browser. Nothing leaves your device.</p>
  `;

  try {
    const result = await encryptFiles(state.encryptFiles);

    // Update password panel with the actual key used
    state.generatedPassword = result.passwordHex;
    passwordValue.textContent = result.passwordHex;
    copyBtn.textContent = 'Copy';
    copyBtn.className = 'copy-btn';

    // Create download URL
    if (state.encryptBlobUrl) URL.revokeObjectURL(state.encryptBlobUrl);
    state.encryptBlobUrl = URL.createObjectURL(result.blob);

    const baseName = state.encryptFiles.length === 1
      ? state.encryptFiles[0].name.replace(/\.[^.]+$/, '')
      : 'vault_archive';

    const ratio = compressionRatio(result.originalSize, result.compressedSize);
    const saved = result.compressedSize < result.originalSize
      ? `Compression saved ${ratio}`
      : 'No size reduction';

    encStatus.className = 'status-panel success visible';
    encStatus.innerHTML = `
      <div class="status-header">
        <span class="status-icon">✅</span>
        <span class="status-title">Encryption complete</span>
      </div>
      <p class="status-body">Your file has been encrypted with AES-256-GCM. Download it and share your password through a separate, secure channel.</p>
      <div class="stats-row">
        <div class="stat-chip"><span class="label">Original</span><span class="value">${formatBytes(result.originalSize)}</span></div>
        <div class="stat-chip"><span class="label">Compressed</span><span class="value">${formatBytes(result.compressedSize)}</span></div>
        <div class="stat-chip"><span class="label">Vault size</span><span class="value">${formatBytes(result.vaultSize)}</span></div>
        <div class="stat-chip"><span class="label">Saved</span><span class="value">${ratio}</span></div>
      </div>
      <a class="download-btn" href="${state.encryptBlobUrl}" download="${baseName}.vault">
        ⬇ Download ${baseName}.vault
      </a>
    `;
  } catch (err) {
    encStatus.className = 'status-panel error visible';
    encStatus.innerHTML = `
      <div class="status-header">
        <span class="status-icon">❌</span>
        <span class="status-title">Encryption failed</span>
      </div>
      <p class="status-body">${err.message || 'An unexpected error occurred. Please try again.'}</p>
    `;
  } finally {
    encryptBtn.disabled = state.encryptFiles.length === 0;
  }
});

/* ──────────────────────────────────────────────
   UI — Decrypt Tab
─────────────────────────────────────────────── */
const decDropzone = document.getElementById('dec-dropzone');
const decFileInput = document.getElementById('dec-file-input');
const decFileName = document.getElementById('dec-file-name');
const decPassword = document.getElementById('dec-password');
const decryptBtn = document.getElementById('decrypt-btn');
const decStatus = document.getElementById('dec-status');

let decDragCounter = 0;

decDropzone.addEventListener('click', () => decFileInput.click());

decDropzone.addEventListener('dragenter', (e) => {
  e.preventDefault();
  decDragCounter++;
  decDropzone.classList.add('drag-over');
});

decDropzone.addEventListener('dragover', (e) => { e.preventDefault(); });

decDropzone.addEventListener('dragleave', () => {
  decDragCounter--;
  if (decDragCounter <= 0) {
    decDragCounter = 0;
    decDropzone.classList.remove('drag-over');
  }
});

decDropzone.addEventListener('drop', (e) => {
  e.preventDefault();
  decDragCounter = 0;
  decDropzone.classList.remove('drag-over');
  const file = e.dataTransfer.files[0];
  if (file) setDecryptFile(file);
});

decFileInput.addEventListener('change', () => {
  const file = decFileInput.files[0];
  if (file) {
    setDecryptFile(file);
    decFileInput.value = '';
  }
});

function setDecryptFile(file) {
  state.decryptFile = file;
  decFileName.textContent = file.name;
  decFileName.style.display = 'block';
  updateDecryptBtn();
}

decPassword.addEventListener('input', updateDecryptBtn);

function updateDecryptBtn() {
  const hasFile = !!state.decryptFile;
  const hasPass = decPassword.value.trim().length > 0;
  decryptBtn.disabled = !(hasFile && hasPass);
}

decryptBtn.addEventListener('click', async () => {
  if (!state.decryptFile || !decPassword.value.trim()) return;

  decryptBtn.disabled = true;
  decStatus.className = 'status-panel loading visible';
  decStatus.innerHTML = `
    <div class="status-header">
      <div class="spinner"></div>
      <span class="status-title">Decrypting…</span>
    </div>
    <p class="status-body">Verifying authentication tag and decrypting. Nothing leaves your device.</p>
  `;

  try {
    const zip = await decryptVault(state.decryptFile, decPassword.value.trim());
    const fileNames = Object.keys(zip.files).filter(n => !zip.files[n].dir);

    // Build download links for each file
    const fileLinks = await Promise.all(fileNames.map(async (name) => {
      const blob = await zip.files[name].async('blob');
      const url = URL.createObjectURL(blob);
      return { name, url, size: blob.size };
    }));

    const fileListHtml = fileLinks.map(f => `
      <a class="download-btn" href="${f.url}" download="${f.name}" style="margin-bottom:8px; font-size:13px; padding:12px 20px;">
        ⬇ ${f.name} <span style="font-weight:400;opacity:.7;">(${formatBytes(f.size)})</span>
      </a>
    `).join('');

    decStatus.className = 'status-panel success visible';
    decStatus.innerHTML = `
      <div class="status-header">
        <span class="status-icon">🔓</span>
        <span class="status-title">Decryption successful — ${fileLinks.length} file${fileLinks.length !== 1 ? 's' : ''} recovered</span>
      </div>
      <p class="status-body">Authentication tag verified. Your files are intact and untampered.</p>
      ${fileListHtml}
    `;
  } catch (err) {
    decStatus.className = 'status-panel error visible';
    decStatus.innerHTML = `
      <div class="status-header">
        <span class="status-icon">🔒</span>
        <span class="status-title">Decryption failed</span>
      </div>
      <p class="status-body">${err.message || 'An unexpected error occurred.'}</p>
    `;
  } finally {
    decryptBtn.disabled = false;
  }
});

/* ──────────────────────────────────────────────
   UI — Tabs
─────────────────────────────────────────────── */
document.querySelectorAll('.tool-tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.tool-tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tool-panel').forEach(p => p.classList.remove('active'));
    tab.classList.add('active');
    document.getElementById(tab.dataset.panel).classList.add('active');
  });
});

/* ──────────────────────────────────────────────
   UI — FAQ accordion
─────────────────────────────────────────────── */
document.querySelectorAll('.faq-item').forEach(item => {
  item.addEventListener('click', () => {
    const isOpen = item.classList.contains('open');
    document.querySelectorAll('.faq-item').forEach(i => i.classList.remove('open'));
    if (!isOpen) item.classList.add('open');
  });
});

/* ──────────────────────────────────────────────
   Smooth scroll for anchor links
─────────────────────────────────────────────── */
document.querySelectorAll('a[href^="#"]').forEach(a => {
  a.addEventListener('click', e => {
    const target = document.querySelector(a.getAttribute('href'));
    if (target) {
      e.preventDefault();
      target.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  });
});

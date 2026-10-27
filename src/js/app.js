// Vault Convert: controller. Wires events to state and session operations, and asks views.js to draw.
// All data stays in memory on this page. Only display preferences are saved to localStorage.

import { newItem, displayName, vaultOf, DEFAULT_VAULT, TYPE_LABEL, splitUrls, uniq } from './model.js';
import { parseFile, NeedsPassword } from './importers.js';
import { FORMATS, exportPlan, exportItems } from './exporters.js';
import { analyse, linkTotp, suggestTotpTargets, generatePassword, exactKey, newestId } from './analysis.js';
import { totpCode } from './totp.js';
import { KDF_PRESETS, KDF_TYPES } from './kdbx.js';
import {
  state, prefs, savePrefs, DEFAULT_PREFS, hooks, getItem, liveItems, trashedItems, allVaults,
  ensureVault, ensureFolder, snapshot, undo, refresh, editItem, bulkEdit, removeItems, mergeIds, visibleItems,
} from './state.js';
import {
  openDatabase, createDatabase, saveDatabase, downloadBackup, lockDatabase, unlockDatabase, closeDatabase,
  noteActivity, startBackgroundTimers, scheduleAutoSave, renameDatabase, changeMasterPassword, changeKdf, mergeFromFile,
} from './session.js';
import { addAttachmentBytes, getAttachmentBytes, pruneAttachments } from './attachments.js';
import { fieldText, fieldLabel, itemAsText } from './copyfields.js';
import {
  makePacket, bookmarkletHref, PACKET_TTL_MS, openAssistWindow, currentAssistWindow, assistSupport,
} from './autofill.js';
import { renderAll, renderDetail, updateTotp, assistHtml } from './views.js';
import { $, esc, toast } from './ui/dom.js';
import { copyText } from './ui/clipboard.js';
import { openModal, closeModal, promptText, confirmBox, chooseBox, credentialsDialog, isModalOpen } from './ui/modal.js';
import { pickKdbx, canUseFileHandles, downloadBytes } from './ui/fileio.js';
import { icon } from './ui/icons.js';

const render = () => renderAll();
hooks.render = render;
hooks.changed = scheduleAutoSave;

// ---------- copying ----------

async function copyValue(text, label) {
  if (!text) { toast(`${label} is empty`, 'warn'); return false; }
  const ok = await copyText(text, { clearSeconds: prefs.clipboardClear });
  if (ok) toast(`${label} copied${prefs.clipboardClear ? `. Clipboard clears in ${prefs.clipboardClear}s.` : '.'}`);
  else toast('Your browser blocked copying. Click the page and try again.', 'error');
  return ok;
}

function flash(el) {
  el.classList.add('copied');
  setTimeout(() => el.classList.remove('copied'), 700);
}

async function fillPacket(item) {
  const code = item.totp ? await totpCode(item.totp) : '';
  const ok = await copyText(makePacket(item, code), { clearSeconds: PACKET_TTL_MS / 1000 });
  if (ok) toast(`Fill data for “${displayName(item)}” copied. On the login page, click the Vault Fill bookmark within ${PACKET_TTL_MS / 1000} seconds.`, 'ok', 7000);
  else toast('Your browser blocked copying. Click the page and try again.', 'error');
}

// ---------- items ----------

function openDetail(id) {
  state.openId = id;
  state.editMode = false;
  state.revealDetail = !prefs.maskDetail;
  render();
}

function newItemAction() {
  if (state.locked) return;
  snapshot();
  const v = state.view;
  const vault = v.kind === 'vault' || v.kind === 'folder' ? v.vault : (state.kdbx ? (allVaults()[0] || DEFAULT_VAULT) : DEFAULT_VAULT);
  const folder = v.kind === 'folder' ? v.folder || '' : '';
  const it = newItem({ vault, folder });
  ensureVault(vault);
  ensureFolder(vault, folder);
  state.items.push(it);
  state.started = true;
  state.openId = it.id;
  state.editMode = true;
  state.revealDetail = true;
  if (state.view.kind === 'trash') state.view = { kind: 'all' };
  refresh();
  $('#detail input[data-field="name"]')?.focus();
}

/** In a KeePass database, deleting moves to the recycle bin. Elsewhere it removes the item. */
function deleteIds(ids) {
  if (state.kdbx) {
    for (const id of ids) {
      const it = getItem(id);
      if (it) it.trashed = true;
      state.selected.delete(id);
    }
    if (ids.includes(state.openId)) state.openId = null;
  } else {
    removeItems(ids);
  }
}

function linkAuthenticator(sourceId, targetId) {
  const src = getItem(sourceId);
  const tgt = getItem(targetId);
  if (!src || !tgt) return;
  snapshot();
  const linked = linkTotp(tgt, src);
  state.items = state.items.filter((i) => i.id !== src.id).map((i) => (i.id === tgt.id ? linked : i));
  state.selected.delete(src.id);
  state.openId = tgt.id;
  toast(`Linked the authenticator to ${displayName(tgt)}`);
  refresh();
}

function openLinkDialog(sourceId) {
  const src = getItem(sourceId);
  if (!src) return;
  const options = suggestTotpTargets(src, liveItems()).slice(0, 25);
  openModal(`
    <h2>Link authenticator</h2>
    <p class="lede">Choose the login that <strong>${esc(displayName(src))}</strong> belongs to. The code moves onto that login and the standalone item is removed.</p>
    <div class="suggest-list stacked">
      ${options.length ? options.map((s) => `<button class="btn" data-action="link" data-id="${s.item.id}" data-source="${sourceId}">${esc(displayName(s.item))} <small>${esc(s.item.username)}</small></button>`).join('') : '<p class="fine">Every login already has a one-time code.</p>'}
    </div>
    <div class="modal-actions"><button class="btn ghost" data-action="modal-close">Cancel</button></div>`);
}

// ---------- import ----------

function importVaultName(format) {
  if (/^(Generic|JSON|1Password \(1PIF\)|Vault Convert)/.test(format)) return 'Imported';
  return format.split(' ')[0];
}

function askImport(parsed) {
  const counts = parsed.items.reduce((acc, i) => ((acc[i.type] = (acc[i.type] || 0) + 1), acc), {});
  const preview = parsed.items.slice(0, 5).map((i) => `<li>${esc(displayName(i))} <small>${esc(TYPE_LABEL[i.type])}</small></li>`).join('');
  return openModal(`
    <h2>Import ${esc(parsed.fileName)}</h2>
    <p class="lede">Detected <strong>${esc(parsed.format)}</strong> with <strong>${parsed.count}</strong> item(s).</p>
    <div class="type-counts">${Object.entries(counts).map(([t, n]) => `<span class="chip info">${n} ${esc(TYPE_LABEL[t])}</span>`).join('')}</div>
    ${parsed.warnings.length ? `<ul class="warn-list">${parsed.warnings.map((w) => `<li>${esc(w)}</li>`).join('')}</ul>` : ''}
    <form id="import-form" class="stack">
      <label>Put imported items in vault<input id="imp-vault" value="${esc(importVaultName(parsed.format))}" required /></label>
      <p class="fine">If the file already has vault names, they are kept under this vault as "Name · Vault".</p>
      <label class="check"><input type="checkbox" id="imp-skip" checked /> Skip items that exactly match something already here</label>
      <details><summary>Preview the first items</summary><ul class="preview">${preview}</ul></details>
      <div class="modal-actions">
        <button type="button" class="btn ghost" data-action="modal-close">Cancel</button>
        <button class="btn primary" type="submit">Import ${parsed.count} item(s)</button>
      </div>
    </form>`, {
    onMount: (dlg) => {
      dlg.querySelector('#import-form').addEventListener('submit', (e) => {
        e.preventDefault();
        closeModal({
          vault: dlg.querySelector('#imp-vault').value.trim() || DEFAULT_VAULT,
          skipDupes: dlg.querySelector('#imp-skip').checked,
        });
      });
    },
  });
}

/** Parses a file, asking for a password first when it is encrypted. Returns the parsed result or null. */
async function parseWithPrompt(file) {
  const bytes = new Uint8Array(await file.arrayBuffer());
  try {
    return await parseFile(file.name, bytes);
  } catch (err) {
    if (!(err instanceof NeedsPassword)) throw err;
    return credentialsDialog({
      title: `Unlock ${file.name}`,
      intro: err.kind === 'kdbx'
        ? 'This is a KeePass database. Enter its password (and key file, if it uses one) to import its items.'
        : 'This Bitwarden export is password protected. Enter the password you chose when you exported it.',
      submitLabel: 'Decrypt',
      keyFile: err.kind === 'kdbx' ? 'optional' : 'none',
      run: (v) => parseFile(file.name, bytes, { password: v.password, keyFile: v.keyFile }),
    });
  }
}

async function importFiles(files) {
  for (const file of files) {
    try {
      const parsed = await parseWithPrompt(file);
      if (!parsed) continue;
      if (!parsed.items.length) { toast(`${file.name}: no items found`, 'error'); continue; }
      const choice = await askImport(parsed);
      if (!choice) continue;
      snapshot();
      const existing = new Set(liveItems().map(exactKey));
      const fileHasVaults = parsed.items.some((i) => i.vault && i.vault !== DEFAULT_VAULT);
      let added = 0;
      let skipped = 0;
      for (const it of parsed.items) {
        it.vault = fileHasVaults && it.vault !== DEFAULT_VAULT ? `${choice.vault} · ${it.vault}` : choice.vault;
        // Only items already present are skipped. Duplicates inside the file are kept so the duplicate tools can show them.
        if (choice.skipDupes && existing.has(exactKey(it))) { skipped++; continue; }
        ensureVault(it.vault);
        ensureFolder(it.vault, it.folder);
        for (const a of it.attachments || []) a.existing = false;
        state.items.push(it);
        added++;
      }
      state.started = true;
      toast(`Imported ${added} item(s) from ${file.name}${skipped ? `, skipped ${skipped} duplicate(s)` : ''}`);
      refresh();
    } catch (err) {
      toast(`${file.name}: ${err.message}`, 'error', 7000);
    }
  }
}

/** Route files: a .kdbx opens as the database when nothing is open yet, otherwise it is offered as an import. */
async function handleDroppedFiles(files, handle = null) {
  const kdbx = files.find((f) => /\.kdbx$/i.test(f.name));
  if (kdbx && !state.kdbx && !liveItems().length) {
    await openDatabase(kdbx, handle);
    return;
  }
  await importFiles(files);
}

// ---------- export ----------

function openExport(scope = 'all') {
  const scopes = () => ({
    all: liveItems(),
    selected: state.items.filter((i) => state.selected.has(i.id) && !i.trashed),
    view: visibleItems().filter((i) => !i.trashed),
  });
  const labels = { all: `All items (${liveItems().length})`, selected: `Selected (${state.selected.size})`, view: `Current view (${visibleItems().length})` };
  const kdfTypeOptions = Object.entries(KDF_TYPES).map(([k, l]) => `<option value="${k}">${esc(l)}</option>`).join('');
  const presetOptions = Object.entries(KDF_PRESETS).map(([k, p]) => `<option value="${k}" ${k === 'standard' ? 'selected' : ''}>${esc(p.label)}</option>`).join('');
  return openModal(`
    <h2>Export</h2>
    <div class="export-grid">
      <fieldset class="formats">
        <legend>Format</legend>
        ${FORMATS.map((f, i) => `
          <label class="fmt">
            <input type="radio" name="fmt" value="${f.id}" ${i === 0 ? 'checked' : ''}/>
            <div><strong>${esc(f.label)}</strong><small>${esc(f.desc)} <code>.${f.ext}</code></small></div>
          </label>`).join('')}
      </fieldset>
      <div class="export-side">
        <fieldset>
          <legend>What to export</legend>
          ${['all', 'selected', 'view'].map((s) => `
            <label class="check"><input type="radio" name="scope" value="${s}" ${s === scope ? 'checked' : ''} ${s === 'selected' && !state.selected.size ? 'disabled' : ''}/> ${labels[s]}</label>`).join('')}
        </fieldset>
        <fieldset id="enc-box" hidden>
          <legend>Encryption</legend>
          <label>Password<input id="enc-pw" type="password" autocomplete="off" /></label>
          <label>Repeat password<input id="enc-pw2" type="password" autocomplete="off" /></label>
          <label id="enc-key-row">Key file <small>(optional)</small><input id="enc-key" type="file" /></label>
          <div class="two" id="enc-kdf-kdbx">
            <label>Key derivation<select id="enc-kdf">${kdfTypeOptions}</select></label>
            <label>Strength<select id="enc-preset">${presetOptions}</select></label>
          </div>
          <label id="enc-kdf-bw-row">Key derivation<select id="enc-bwkdf"><option value="pbkdf2">PBKDF2 (Bitwarden default)</option><option value="argon2id">Argon2id</option></select></label>
          <p class="fine">Write the password down somewhere safe. There is no way to recover it.</p>
        </fieldset>
        <div id="exp-summary" class="summary"></div>
        <p class="warning" id="exp-warning">Exported files contain passwords in plain text. Keep them private, import them, then delete the file.</p>
        <p class="form-error" id="exp-error" role="alert" hidden></p>
        <div class="modal-actions">
          <button class="btn ghost" data-action="modal-close">Close</button>
          <button class="btn primary" id="exp-download">Download</button>
        </div>
      </div>
    </div>`, {
    wide: true,
    onMount: (dlg) => {
      const q = (s) => dlg.querySelector(s);
      const cur = () => ({ fmt: q('input[name="fmt"]:checked').value, sc: q('input[name="scope"]:checked').value });
      const err = q('#exp-error');
      const update = () => {
        const { fmt, sc } = cur();
        const f = FORMATS.find((x) => x.id === fmt);
        const items = scopes()[sc];
        const plan = exportPlan(fmt, items);
        q('#enc-box').hidden = !f.encrypted;
        q('#exp-warning').hidden = !!f.encrypted;
        q('#enc-key-row').hidden = fmt !== 'kdbx';
        q('#enc-kdf-kdbx').hidden = fmt !== 'kdbx';
        q('#enc-kdf-bw-row').hidden = fmt !== 'bitwarden-encrypted';
        const excluded = Object.entries(plan.excluded || {}).map(([t, n]) => `${n} ${TYPE_LABEL[t]}`).join(', ');
        q('#exp-summary').innerHTML = `
          <p><strong>${plan.exported}</strong> item(s) will be written to <code>${esc(plan.filename)}</code>.</p>
          ${excluded ? `<p class="fine">Left out (not supported by this format): ${esc(excluded)}.</p>` : ''}
          ${plan.notes.length ? `<ul class="warn-list">${plan.notes.map((n) => `<li>${esc(n)}</li>`).join('')}</ul>` : ''}`;
        q('#exp-download').disabled = plan.exported === 0;
        err.hidden = true;
      };
      dlg.querySelector('.modal-inner').addEventListener('change', update);
      q('#exp-download').addEventListener('click', async (e) => {
        const { fmt, sc } = cur();
        const f = FORMATS.find((x) => x.id === fmt);
        const btn = e.currentTarget;
        err.hidden = true;
        const options = {};
        if (f.encrypted) {
          const pw = q('#enc-pw').value;
          if (!pw) { err.textContent = 'Enter a password to encrypt the export.'; err.hidden = false; return; }
          if (pw !== q('#enc-pw2').value) { err.textContent = 'The two passwords do not match.'; err.hidden = false; return; }
          options.password = pw;
          if (fmt === 'kdbx') {
            const kf = q('#enc-key').files[0];
            options.keyFile = kf ? new Uint8Array(await kf.arrayBuffer()) : undefined;
            options.kdf = q('#enc-kdf').value;
            options.preset = q('#enc-preset').value;
            options.name = state.kdbx?.fileName?.replace(/\.kdbx$/i, '') || 'Vault Convert export';
          } else {
            options.kdf = q('#enc-bwkdf').value;
          }
        }
        const label = btn.textContent;
        btn.disabled = true;
        btn.textContent = 'Working…';
        try {
          const out = await exportItems(fmt, scopes()[sc], options);
          downloadBytes(out.filename, typeof out.content === 'string' ? new TextEncoder().encode(out.content) : out.content, out.mime);
          toast(f.encrypted ? 'Encrypted export downloaded.' : 'Export downloaded. Delete it once it has been imported.');
        } catch (ex) {
          err.textContent = ex.message || 'The export failed.';
          err.hidden = false;
        } finally {
          btn.disabled = false;
          btn.textContent = label;
        }
      });
      update();
    },
  });
}

// ---------- preferences ----------

function applyPrefs() {
  document.documentElement.dataset.theme = prefs.theme;
  $('#app').dataset.density = prefs.density;
}

function openPrefs() {
  return openModal(`
    <h2>Preferences</h2>
    <form id="prefs-form" class="stack">
      <div class="two">
        <label>Theme<select name="theme"><option value="system">Match system</option><option value="light">Light</option><option value="dark">Dark</option></select></label>
        <label>Density<select name="density"><option value="comfortable">Comfortable</option><option value="compact">Compact</option></select></label>
      </div>
      <label class="check"><input type="checkbox" name="maskDetail"/> Hide passwords when an item is opened</label>
      <div class="two">
        <label>Lock after inactivity (minutes, 0 = never)<input name="autoLockMinutes" type="number" min="0" max="240" /></label>
        <label>Clear clipboard after (seconds, 0 = never)<input name="clipboardClear" type="number" min="0" max="600" /></label>
      </div>
      <label class="check"><input type="checkbox" name="autoSave"/> Save automatically a few seconds after each change (needs a database opened with “Save in place”)</label>
      <fieldset>
        <legend>Table columns</legend>
        ${Object.keys(DEFAULT_PREFS.columns).map((c) => `<label class="check"><input type="checkbox" name="col-${c}" ${prefs.columns[c] ? 'checked' : ''}/> ${c === 'url' ? 'Website' : c === 'folder' ? 'Vault / folder' : c === 'quick' ? 'Quick copy buttons' : c[0].toUpperCase() + c.slice(1)}</label>`).join('')}
      </fieldset>
      <p class="fine">Only these display preferences are saved in this browser. Your items are never stored.</p>
      <div class="modal-actions"><button class="btn primary" type="button" data-action="modal-close">Done</button></div>
    </form>`, {
    onMount: (dlg) => {
      const form = dlg.querySelector('#prefs-form');
      form.elements.theme.value = prefs.theme;
      form.elements.density.value = prefs.density;
      form.elements.maskDetail.checked = prefs.maskDetail;
      form.elements.autoSave.checked = prefs.autoSave;
      form.elements.autoLockMinutes.value = prefs.autoLockMinutes;
      form.elements.clipboardClear.value = prefs.clipboardClear;
      form.addEventListener('change', () => {
        prefs.theme = form.elements.theme.value;
        prefs.density = form.elements.density.value;
        prefs.maskDetail = form.elements.maskDetail.checked;
        prefs.autoSave = form.elements.autoSave.checked;
        prefs.autoLockMinutes = Math.max(0, Math.min(240, Number(form.elements.autoLockMinutes.value) || 0));
        prefs.clipboardClear = Math.max(0, Math.min(600, Number(form.elements.clipboardClear.value) || 0));
        for (const c of Object.keys(DEFAULT_PREFS.columns)) prefs.columns[c] = form.elements[`col-${c}`].checked;
        savePrefs();
        applyPrefs();
        render();
        scheduleAutoSave();
      });
    },
  });
}

// ---------- database menu and autofill setup ----------

async function openDbMenu() {
  const s = state.kdbx;
  if (!s) return;
  const choice = await chooseBox(s.fileName, `${state.items.length ? liveItems().length : 0} item(s). Choose what to do with this database.`, [
    { value: 'saveas', label: canUseFileHandles() ? 'Save as…' : 'Download a copy' },
    { value: 'backup', label: 'Download backup' },
    { value: 'merge', label: 'Merge another .kdbx…' },
    { value: 'rename', label: 'Rename' },
    { value: 'password', label: 'Change master password' },
    { value: 'kdf', label: 'Encryption strength' },
    { value: 'close', label: 'Close database' },
  ]);
  const run = {
    saveas: () => saveDatabase({ saveAs: true }),
    backup: downloadBackup,
    merge: mergeFromFile,
    rename: renameDatabase,
    password: changeMasterPassword,
    kdf: changeKdf,
    close: closeDatabase,
  }[choice];
  if (run) await run();
}

function openAutofillSetup() {
  const sup = assistSupport();
  return openModal(`
    <h2>Fill logins without an extension</h2>
    <p class="lede">Two small tools work together. Neither installs anything in your browser.</p>
    <ol class="steps">
      <li><strong>Add the bookmark once.</strong> Drag this link to your bookmarks bar:
        <p><a class="bm-link" id="bm-link" data-action="bm-noop" href="${esc(bookmarkletHref())}">${icon('bolt', 14)} Vault Fill</a></p>
        <p class="fine">Can’t drag it? <button class="btn sm" data-action="bm-copy">Copy the bookmark code</button> and paste it as the URL of a new bookmark.</p></li>
      <li><strong>Copy the fill data.</strong> On a login in the list, click the <span class="ico-inline">${icon('bolt', 14)}</span> button (or “Fill” in the item). It expires after ${PACKET_TTL_MS / 1000} seconds.</li>
      <li><strong>Open the site’s login page and click the bookmark.</strong> It fills the username and password. On two-step logins, click it again on the password page. A site-name mismatch asks you first.</li>
    </ol>
    <p><button class="btn" data-action="assist">${icon('window', 14)} Open the floating fill assistant</button>
      <small class="fine">${sup.pip ? 'Stays on top of other windows.' : 'Opens a small window next to your browser.'}</small></p>
    <details><summary>How safe is this, and what are the limits?</summary>
      <ul class="warn-list">
        <li>The fill data sits on your clipboard (as one encoded line) for up to ${PACKET_TTL_MS / 1000} seconds, or until used. Other programs that read the clipboard could see it in that window.</li>
        <li>The bookmark only runs when you click it, only fills fields on the current page, and checks that the page’s site matches the login’s website.</li>
        <li>Your browser may ask permission for the bookmark to read the clipboard.</li>
        <li>Some sites block bookmarks with a strict security policy. Use the assistant’s copy buttons there.</li>
        <li>Browsers can’t type into other applications, so there’s no desktop “auto-type”.</li>
      </ul>
    </details>
    <div class="modal-actions"><button class="btn primary" data-action="modal-close">Done</button></div>`);
}

// ---------- fill assistant window ----------

let assistQuery = '';
let assistStatus = '';

function renderAssist() {
  const win = currentAssistWindow();
  if (!win) return;
  const host = win.document.getElementById('assist');
  if (!host) return;
  const q = assistQuery.trim().toLowerCase();
  const items = liveItems().filter((i) => i.type === 'login' && (!q
    || `${displayName(i)} ${i.username} ${i.urls.join(' ')}`.toLowerCase().includes(q))).slice(0, 60);
  host.innerHTML = assistHtml(items, assistQuery, assistStatus);
  const input = win.document.getElementById('assist-q');
  input.addEventListener('input', () => {
    assistQuery = input.value;
    const pos = input.selectionStart;
    renderAssist();
    const again = win.document.getElementById('assist-q');
    again.focus();
    again.setSelectionRange(pos, pos);
  });
}

async function assistClick(e) {
  const btn = e.target.closest('[data-assist]');
  if (!btn) return;
  const win = currentAssistWindow();
  const it = getItem(btn.dataset.id);
  if (!it || !win) return;
  const what = btn.dataset.assist;
  let text = '';
  let label = '';
  if (what === 'fill') {
    text = makePacket(it, it.totp ? await totpCode(it.totp) : '');
    label = 'Fill data';
  } else {
    text = await fieldText(it, what);
    label = fieldLabel(it, what);
  }
  const secs = what === 'fill' ? PACKET_TTL_MS / 1000 : prefs.clipboardClear;
  const ok = await copyText(text, { clearSeconds: secs, win });
  assistStatus = ok ? `${label} copied for “${displayName(it)}”.` : 'Copy was blocked. Click inside this window and try again.';
  renderAssist();
}

async function openAssistant() {
  if (state.locked) return;
  const win = await openAssistWindow();
  if (!win) {
    toast('Your browser blocked the assistant window. Allow pop-ups for this page and try again.', 'error', 7000);
    return;
  }
  assistStatus = '';
  if (!win.__vcWired) {
    win.__vcWired = true;
    win.document.addEventListener('click', assistClick);
  }
  renderAssist();
}

// ---------- actions ----------

const ACTIONS = {
  'pick-files': () => $('#file-input').click(),
  import: () => $('#file-input').click(),
  'new-item': newItemAction,
  undo,
  export: () => openExport('all'),
  prefs: openPrefs,
  autofill: openAutofillSetup,
  assist: openAssistant,
  'bm-noop': () => toast('Drag this link to your bookmarks bar instead of clicking it.', 'warn'),
  async 'bm-copy'() {
    if (await copyText(bookmarkletHref(), { clearSeconds: 0 })) toast('Bookmark code copied. Paste it as the URL of a new bookmark.');
  },
  'toggle-sidebar': () => document.body.classList.toggle('sidebar-open'),
  'modal-close': () => closeModal(null),
  'modal-ok': () => closeModal(true),
  'modal-choose': (el) => closeModal(el.dataset.value),

  // database
  async 'db-open'() {
    if (canUseFileHandles()) {
      try {
        const picked = await pickKdbx();
        if (picked) await openDatabase(picked.file, picked.handle);
      } catch (e) { toast(`Could not open the file: ${e.message}`, 'error'); }
    } else {
      $('#kdbx-input').click();
    }
  },
  'db-new': () => createDatabase(),
  'db-save': () => saveDatabase(),
  'db-lock': () => lockDatabase(),
  'db-unlock': () => unlockDatabase(),
  'db-close': () => closeDatabase(),
  'db-menu': openDbMenu,

  nav(el) {
    const d = el.dataset;
    state.view = { kind: d.kind, vault: d.vault, folder: d.folder, type: d.type };
    state.selected.clear();
    document.body.classList.remove('sidebar-open');
    render();
  },
  select(el) {
    const id = el.dataset.id;
    if (state.selected.has(id)) state.selected.delete(id); else state.selected.add(id);
    render();
  },
  'select-all'() {
    const list = visibleItems();
    const all = list.length && list.every((i) => state.selected.has(i.id));
    for (const i of list) (all ? state.selected.delete(i.id) : state.selected.add(i.id));
    render();
  },
  fav(el) { editItem(el.dataset.id, (it) => { it.favorite = !it.favorite; }); },
  'close-detail': () => { state.openId = null; state.editMode = false; render(); },
  'edit-start': () => { state.editMode = true; renderDetail(); },
  'edit-done': () => { state.editMode = false; render(); },
  reveal() { state.revealDetail = !state.revealDetail; renderDetail(); },

  async copy(el) {
    const it = getItem(el.dataset.id);
    if (!it) return;
    const what = el.dataset.what;
    const ok = await copyValue(await fieldText(it, what), fieldLabel(it, what));
    if (ok) flash(el);
  },
  async 'copy-field'(el) {
    const it = getItem(state.openId);
    if (!it) return;
    const field = el.dataset.field;
    const index = Number(el.dataset.index || 0);
    const ok = await copyValue(await fieldText(it, field, index), fieldLabel(it, field, index));
    if (ok) flash(el);
  },
  async 'copy-all'(el) {
    const it = getItem(el.dataset.id);
    if (it) await copyValue(await itemAsText(it), 'All fields');
  },
  async fill(el) {
    const it = getItem(el.dataset.id || state.openId);
    if (it) await fillPacket(it);
  },
  gen(el) {
    const pw = generatePassword({ length: 24 });
    editItem(el.dataset.id, (it) => { it.password = pw; });
    state.revealDetail = true;
    renderDetail();
  },
  'cf-add': (el) => editItem(el.dataset.id, (it) => it.customFields.push({ name: '', value: '', hidden: false })),
  'cf-hide': (el) => editItem(state.openId, (it) => { const f = it.customFields[+el.dataset.index]; if (f) f.hidden = !f.hidden; }),
  'cf-del': (el) => editItem(state.openId, (it) => it.customFields.splice(+el.dataset.index, 1)),

  'att-add': () => $('#att-input').click(),
  'att-del'(el) {
    editItem(state.openId, (it) => { it.attachments = (it.attachments || []).filter((a) => a.id !== el.dataset.id); });
    pruneAttachments(state.items);
  },
  'dl-att'(el) {
    const it = getItem(state.openId);
    const att = (it?.attachments || []).find((a) => a.id === el.dataset.id);
    const bytes = att && getAttachmentBytes(att.id);
    if (!bytes) { toast('That file’s contents are not available.', 'error'); return; }
    downloadBytes(att.name, bytes);
  },

  async 'delete-item'(el) {
    const it = getItem(el.dataset.id);
    if (!it) return;
    if (it.trashed) {
      if (!(await confirmBox('Delete permanently?', `“${esc(displayName(it))}” will be removed from the database for good.`, 'Delete permanently'))) return;
      snapshot();
      removeItems([it.id], true);
      refresh();
      return;
    }
    const msg = state.kdbx
      ? `“${esc(displayName(it))}” moves to the recycle bin. You can restore it from there.`
      : `“${esc(displayName(it))}” will be removed. You can undo this with the Undo button.`;
    if (!(await confirmBox(state.kdbx ? 'Move to recycle bin?' : 'Delete item?', msg, state.kdbx ? 'Move to bin' : 'Delete'))) return;
    snapshot();
    deleteIds([it.id]);
    refresh();
  },
  'restore-item'(el) { editItem(el.dataset.id, (it) => { it.trashed = false; }); },
  async 'empty-trash'() {
    const ids = trashedItems().map((i) => i.id);
    if (!ids.length) return;
    if (!(await confirmBox('Empty the recycle bin?', `${ids.length} item(s) will be deleted permanently.`, 'Empty bin'))) return;
    snapshot();
    removeItems(ids, true);
    refresh();
  },
  'dup-item'(el) {
    const src = getItem(el.dataset.id);
    if (!src) return;
    snapshot();
    const copy = structuredClone(src);
    copy.id = newItem().id;
    copy.name = `${src.name} (copy)`;
    copy.attachments = (src.attachments || []).map((a) => {
      const bytes = getAttachmentBytes(a.id);
      return { ...a, id: bytes ? addAttachmentBytes(new Uint8Array(bytes)) : a.id, existing: false };
    });
    copy.pwHistory = undefined;
    copy.historyCount = undefined;
    state.items.push(copy);
    state.openId = copy.id;
    refresh();
  },
  'show-dupes'() { state.view = { kind: 'dupes' }; render(); },
  link(el) { closeModal(null); linkAuthenticator(el.dataset.source, el.dataset.id); },

  async 'new-vault'() {
    const name = await promptText('New vault', '', 'Vault name');
    if (!name) return;
    snapshot();
    ensureVault(name);
    state.view = { kind: 'vault', vault: name };
    refresh();
  },
  async 'new-folder'(el) {
    const vault = el.dataset.vault || DEFAULT_VAULT;
    const name = await promptText(`New folder in “${vault}”`, '', 'Folder name');
    if (!name) return;
    snapshot();
    ensureVault(vault);
    ensureFolder(vault, name);
    state.view = { kind: 'folder', vault, folder: name };
    refresh();
  },
  async 'rename-vault'(el) {
    const vault = el.dataset.vault;
    const name = await promptText('Rename vault', vault, 'Vault name');
    if (!name || name === vault) return;
    snapshot();
    for (const i of state.items) if (vaultOf(i) === vault) i.vault = name;
    state.meta.vaults = uniq(state.meta.vaults.map((v) => (v === vault ? name : v)));
    state.meta.folders[name] = state.meta.folders[vault] || [];
    delete state.meta.folders[vault];
    if (state.view.vault === vault) state.view.vault = name;
    refresh();
  },
  async 'delete-vault'(el) {
    const vault = el.dataset.vault;
    const count = state.items.filter((i) => vaultOf(i) === vault).length;
    const ok = await confirmBox(`Delete vault “${vault}”?`,
      count ? `Its ${count} item(s) will move to “${DEFAULT_VAULT}”.` : 'The empty vault will be removed.', 'Delete vault');
    if (!ok) return;
    snapshot();
    for (const i of state.items) if (vaultOf(i) === vault) i.vault = DEFAULT_VAULT;
    state.meta.vaults = state.meta.vaults.filter((v) => v !== vault);
    delete state.meta.folders[vault];
    ensureVault(DEFAULT_VAULT);
    if (state.view.vault === vault) state.view = { kind: 'all' };
    refresh();
  },

  // bulk
  'bulk-clear': () => { state.selected.clear(); render(); },
  'bulk-fav': () => bulkEdit([...state.selected], (it) => { it.favorite = true; }),
  'bulk-restore': () => bulkEdit([...state.selected], (it) => { it.trashed = false; }),
  async 'bulk-move'() {
    const name = await promptText(`Move ${state.selected.size} item(s) to vault`, DEFAULT_VAULT, 'Vault name (existing or new)');
    if (!name) return;
    ensureVault(name);
    bulkEdit([...state.selected], (it) => { it.vault = name; it.folder = ''; });
  },
  'bulk-merge'() {
    const ids = state.items.filter((i) => state.selected.has(i.id)).map((i) => i.id);
    if (ids.length < 2) return;
    snapshot();
    mergeIds(ids);
    refresh();
    toast(`Merged ${ids.length} items into one`);
  },
  'bulk-link'() {
    const source = [...state.selected].find((id) => state.analysis.totpOnly.has(id));
    if (source) openLinkDialog(source);
  },
  'bulk-export': () => openExport('selected'),
  async 'bulk-delete'() {
    const ids = [...state.selected];
    const inBin = state.view.kind === 'trash';
    const title = inBin ? `Delete ${ids.length} item(s) permanently?` : state.kdbx ? `Move ${ids.length} item(s) to the recycle bin?` : `Delete ${ids.length} item(s)?`;
    const body = inBin ? 'They will be removed from the database for good.' : state.kdbx ? 'You can restore them from the recycle bin.' : 'You can undo this with the Undo button.';
    if (!(await confirmBox(title, body, inBin ? 'Delete permanently' : 'Delete'))) return;
    snapshot();
    if (inBin) removeItems(ids, true); else deleteIds(ids);
    refresh();
  },

  // duplicates
  'dupes-merge-exact'() {
    snapshot();
    for (const group of analyse(liveItems()).dupes.exact) mergeIds(group);
    refresh();
    toast('Exact duplicates merged');
  },
  async 'dupes-keep-newest'() {
    const groups = analyse(liveItems()).dupes.exact;
    const remove = groups.flatMap((g) => g.filter((id) => id !== newestId(g.map((x) => getItem(x)))));
    if (!(await confirmBox('Keep newest only?', `${remove.length} older duplicate(s) will be ${state.kdbx ? 'moved to the recycle bin' : 'deleted'}.`, 'Remove duplicates'))) return;
    snapshot();
    deleteIds(remove);
    refresh();
  },
  'dupes-merge-conflicts'() {
    snapshot();
    for (let guard = 0; guard < 500; guard++) {
      const group = analyse(liveItems()).dupes.conflicts[0];
      if (!group) break;
      mergeIds(group);
    }
    refresh();
    toast('Conflicting logins merged. Other passwords are kept as alternates.');
  },
};

// ---------- event wiring ----------

document.addEventListener('click', (e) => {
  noteActivity();
  if (e.target.closest('[data-stop]')) return;
  const el = e.target.closest('[data-action]');
  if (!el) {
    const row = e.target.closest('tr[data-row]');
    if (row && !e.target.closest('input,button,select,textarea,label,a')) openDetail(row.dataset.row);
    return;
  }
  const action = ACTIONS[el.dataset.action];
  if (!action) return;
  e.preventDefault();
  action(el, e);
});

document.addEventListener('keydown', (e) => {
  noteActivity();
  if ((e.key === 'Enter' || e.key === ' ') && e.target.matches?.('.vrow[data-action]')) {
    e.preventDefault();
    ACTIONS[e.target.dataset.action]?.(e.target, e);
    return;
  }
  if (e.key === 'Enter' && e.target.matches?.('.dropzone')) $('#file-input').click();
  const typing = /INPUT|TEXTAREA|SELECT/.test(document.activeElement?.tagName || '');
  const mod = e.ctrlKey || e.metaKey;
  if (mod && e.key.toLowerCase() === 's' && state.kdbx) {
    e.preventDefault();
    if (!state.locked) saveDatabase();
    return;
  }
  if (mod && e.key.toLowerCase() === 'l' && state.kdbx && !state.locked) {
    e.preventDefault();
    lockDatabase();
    return;
  }
  if (e.key === 'Escape' && !isModalOpen() && state.openId) {
    if (state.editMode) state.editMode = false; else state.openId = null;
    render();
    return;
  }
  if (typing || isModalOpen() || state.locked) return;
  if (e.key === '/') {
    e.preventDefault();
    $('#search').focus();
  } else if (!mod && e.key.toLowerCase() === 'n') {
    newItemAction();
  } else if (mod && e.key.toLowerCase() === 'z') {
    e.preventDefault();
    undo();
  } else if (mod && e.key.toLowerCase() === 'e') {
    e.preventDefault();
    openExport('all');
  } else if (!mod && state.openId && !state.editMode && ['u', 'p', 't'].includes(e.key.toLowerCase())) {
    const it = getItem(state.openId);
    const field = { u: 'username', p: 'password', t: 'totp' }[e.key.toLowerCase()];
    if (it) fieldText(it, field).then((text) => copyValue(text, fieldLabel(it, field)));
  }
});

document.addEventListener('input', noteActivity);
document.addEventListener('pointermove', noteActivity, { passive: true });

document.addEventListener('change', (e) => {
  const el = e.target;
  if (el.id === 'sort') {
    prefs.sort = el.value;
    savePrefs();
    render();
    return;
  }
  if (el.dataset.field && state.openId && el.closest('#detail')) applyFieldChange(el);
});

function applyFieldChange(el) {
  const f = el.dataset.field;
  const value = el.type === 'checkbox' ? el.checked : el.value;
  editItem(state.openId, (x) => {
    switch (f) {
      case 'type': x.type = value; break;
      case 'name': x.name = String(value).trim(); break;
      case 'vault': x.vault = String(value).trim() || DEFAULT_VAULT; ensureVault(x.vault); break;
      case 'folder': x.folder = String(value).trim(); ensureFolder(vaultOf(x), x.folder); break;
      case 'username': x.username = String(value).trim(); break;
      case 'password': x.password = value; break;
      case 'urls': x.urls = splitUrls(value); break;
      case 'totp': x.totp = String(value).trim(); break;
      case 'notes': x.notes = value; break;
      case 'tags': x.tags = String(value).split(',').map((s) => s.trim()).filter(Boolean); break;
      case 'favorite': x.favorite = value; break;
      case 'cf-name': if (x.customFields[+el.dataset.index]) x.customFields[+el.dataset.index].name = value; break;
      case 'cf-value': if (x.customFields[+el.dataset.index]) x.customFields[+el.dataset.index].value = value; break;
      default: break;
    }
  });
}

$('#search').addEventListener('input', (e) => {
  state.query = e.target.value;
  render();
});

$('#file-input').addEventListener('change', (e) => {
  const files = [...e.target.files];
  e.target.value = '';
  if (files.length) handleDroppedFiles(files);
});

$('#kdbx-input').addEventListener('change', (e) => {
  const file = e.target.files[0];
  e.target.value = '';
  if (file) openDatabase(file, null);
});

$('#att-input').addEventListener('change', async (e) => {
  const files = [...e.target.files];
  e.target.value = '';
  if (!files.length || !state.openId) return;
  const added = [];
  for (const f of files) {
    added.push({ id: addAttachmentBytes(new Uint8Array(await f.arrayBuffer())), name: f.name, size: f.size, existing: false });
  }
  editItem(state.openId, (it) => { it.attachments = [...(it.attachments || []), ...added]; });
});

// Drag and drop anywhere on the page.
let dragDepth = 0;
window.addEventListener('dragenter', (e) => { e.preventDefault(); dragDepth++; document.body.classList.add('dragging'); });
window.addEventListener('dragleave', () => { dragDepth = Math.max(0, dragDepth - 1); if (!dragDepth) document.body.classList.remove('dragging'); });
window.addEventListener('dragover', (e) => e.preventDefault());
window.addEventListener('drop', async (e) => {
  e.preventDefault();
  dragDepth = 0;
  document.body.classList.remove('dragging');
  const files = [...(e.dataTransfer?.files || [])];
  if (!files.length || state.locked) return;
  // Where the browser offers it, dropping a .kdbx also gives a handle so Save writes back to the same file.
  let handle = null;
  const first = e.dataTransfer.items?.[0];
  if (first?.getAsFileSystemHandle && /\.kdbx$/i.test(files[0].name)) {
    try { handle = await first.getAsFileSystemHandle(); } catch { handle = null; }
    if (handle && handle.kind !== 'file') handle = null;
  }
  handleDroppedFiles(files, handle);
});

window.addEventListener('beforeunload', (e) => {
  const dirty = state.kdbx ? state.kdbx.dirty || state.kdbx.pendingLocked : state.items.length > 0;
  if (dirty) {
    e.preventDefault();
    e.returnValue = '';
  }
});

applyPrefs();
render();
startBackgroundTimers();
setInterval(updateTotp, 1000);
updateTotp();

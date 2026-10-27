// KeePass database session: open, create, save, lock, unlock, merge and settings.
// The KDBX engine (kdbx.js) does the cryptography and format work; this module decides
// when to do it and handles the files and dialogs around it.

import { state, hooks, refresh, wipe, prefs, getItem } from './state.js';
import {
  openKdbx, createDb, syncToDb, saveDb, loadModel, mergeRemote, makeCredentials, changeCredentials,
  generateKeyFile, setKdfParams, KDF_PRESETS, KDF_TYPES,
} from './kdbx.js';
import { clearAttachments, pruneAttachments } from './attachments.js';
import { closeAssistWindow } from './autofill.js';
import { credentialsDialog, chooseBox, confirmBox, openModal, closeModal, promptText, isModalOpen } from './ui/modal.js';
import { toast, esc } from './ui/dom.js';
import { clearClipboardNow } from './ui/clipboard.js';
import {
  canUseFileHandles, pickSaveTarget, writeToHandle, readHandle, currentModified, downloadBytes, chooseFile,
} from './ui/fileio.js';

// ---------- attaching a loaded database to the app ----------

function attach(db, model, { fileName, handle = null, loadedMtime = null, lastBytes = null, dirty = false }) {
  wipe();
  state.items = model.items;
  state.meta = model.meta;
  state.kdbx = {
    db,
    kd: { baseline: model.baseline, baselineItems: model.baselineItems, idMap: model.idMap, rootName: model.rootName, permanent: model.permanent },
    fileName, handle, loadedMtime, lastBytes, dirty, pendingLocked: false,
  };
  state.started = true;
  state.locked = false;
  pruneAttachments(state.items);
  refresh();
}

/** Re-reads the whole model from the open database (after a merge). Keeps the UI position. */
function reloadFromDb() {
  const s = state.kdbx;
  const model = loadModel(s.db);
  state.items = model.items;
  state.meta = model.meta;
  s.kd = { baseline: model.baseline, baselineItems: model.baselineItems, idMap: model.idMap, rootName: model.rootName, permanent: model.permanent };
  state.history = [];
  state.selected = new Set([...state.selected].filter((id) => getItem(id)));
  if (state.openId && !getItem(state.openId)) state.openId = null;
  pruneAttachments(state.items);
}

export const databaseIsOpen = () => !!state.kdbx && !state.locked && !!state.kdbx.db;

// ---------- open and create ----------

export async function openDatabase(file, handle = null) {
  const bytes = new Uint8Array(await file.arrayBuffer());
  const res = await credentialsDialog({
    title: `Open ${file.name}`,
    intro: 'Enter the master password. If the database also uses a key file, choose it too. Everything is decrypted here in your browser.',
    submitLabel: 'Unlock',
    keyFile: 'optional',
    run: (v) => openKdbx(bytes, { password: v.password, keyFile: v.keyFile }),
  });
  if (!res) return false;
  attach(res.db, res, { fileName: file.name, handle, loadedMtime: file.lastModified, lastBytes: bytes, dirty: false });
  toast(`Opened ${file.name}: ${state.items.length} item(s)`);
  return true;
}

export async function createDatabase() {
  const res = await credentialsDialog({
    title: 'New KeePass database',
    intro: 'This creates a standard KDBX 4 file that KeePass, KeePassXC, KeePassDX and others can open. Choose a strong master password: if you forget it, nobody can recover your data.',
    submitLabel: 'Create',
    confirm: true,
    keyFile: 'create',
    kdf: true,
    nameLabel: 'Database name',
    nameValue: 'Passwords',
    run: async (v) => {
      const keyFile = v.createKeyFile ? await generateKeyFile() : null;
      const name = v.name || 'Passwords';
      const db = createDb({ name, password: v.password, keyFile, kdf: v.kdf, preset: v.preset });
      return { db, keyFile, name };
    },
  });
  if (!res) return false;
  if (res.keyFile) {
    downloadBytes(`${res.name}.keyx`, res.keyFile);
    toast('Key file downloaded. Store it somewhere safe and separate from the database.', 'ok', 8000);
  }
  const model = loadModel(res.db);
  attach(res.db, model, { fileName: `${res.name}.kdbx`, dirty: true });
  toast('Database created. Click Save to choose where to keep it.');
  return true;
}

// ---------- saving ----------

let saving = false;

async function mergeBytesIntoOpenDb(bytes, creds) {
  const s = state.kdbx;
  await mergeRemote(s.db, bytes, creds);
  reloadFromDb();
}

/**
 * Saves the database. In Chromium browsers this writes back to the same file, and checks that the file
 * has not been changed by someone else since it was opened (offering to merge). Elsewhere it downloads.
 * `silent` is used by auto-save: it never opens a picker or a dialog.
 */
export async function saveDatabase({ saveAs = false, silent = false } = {}) {
  const s = state.kdbx;
  if (!s || state.locked || saving) return false;
  saving = true;
  try {
    if (silent && s.handle) {
      if ((await s.handle.queryPermission({ mode: 'readwrite' })) !== 'granted') return false;
    }
    await syncToDb(s.db, s.kd, state.items, state.meta);
    let bytes = await saveDb(s.db);
    let handle = s.handle;

    if (saveAs || !handle) {
      if (canUseFileHandles()) {
        if (silent) return false;
        const picked = await pickSaveTarget(s.fileName || 'passwords.kdbx');
        if (!picked) return false;
        handle = picked;
      } else {
        handle = null;
      }
    }

    if (handle) {
      if (handle === s.handle && s.loadedMtime != null) {
        const mtime = await currentModified(handle);
        if (mtime !== s.loadedMtime) {
          if (silent) {
            toast('The file was changed elsewhere. Click Save to merge the changes.', 'error', 7000);
            return false;
          }
          const choice = await chooseBox(
            'The file changed since you opened it',
            'Another program or device saved this database after you opened it. <strong>Merge</strong> combines both sets of changes. <strong>Overwrite</strong> replaces the file with what you have here, discarding the other changes.',
            [{ value: 'merge', label: 'Merge and save', primary: true }, { value: 'overwrite', label: 'Overwrite it' }],
          );
          if (!choice) return false;
          if (choice === 'merge') {
            const remote = await readHandle(handle);
            try {
              await mergeBytesIntoOpenDb(remote.bytes);
            } catch (e) {
              toast(`Could not merge: ${e.message}. The file may use a different password.`, 'error', 9000);
              return false;
            }
            bytes = await saveDb(s.db);
          }
        }
      }
      s.loadedMtime = await writeToHandle(handle, bytes);
      s.handle = handle;
      s.fileName = handle.name || s.fileName;
    } else {
      s.fileName = /\.kdbx$/i.test(s.fileName) ? s.fileName : `${s.fileName}.kdbx`;
      downloadBytes(s.fileName, bytes);
    }

    s.lastBytes = bytes;
    s.dirty = false;
    s.pendingLocked = false;
    if (!silent) toast(handle ? `Saved to ${s.fileName}` : `Downloaded ${s.fileName}. Replace your old copy with it.`, 'ok', handle ? 4500 : 8000);
    hooks.render();
    return true;
  } catch (e) {
    if (e && e.name === 'NotAllowedError') toast('Saving was blocked. Allow write access to the file, or use Save as.', 'error', 8000);
    else toast(`Could not save: ${e && e.message ? e.message : e}`, 'error', 8000);
    return false;
  } finally {
    saving = false;
  }
}

/** Downloads an encrypted copy without touching the open file. */
export async function downloadBackup() {
  const s = state.kdbx;
  if (!s || state.locked) return;
  await syncToDb(s.db, s.kd, state.items, state.meta);
  const bytes = await saveDb(s.db);
  const stamp = new Date().toISOString().slice(0, 10);
  downloadBytes(s.fileName.replace(/\.kdbx$/i, '') + `-backup-${stamp}.kdbx`, bytes);
  toast('Encrypted backup copy downloaded.');
}

// ---------- lock, unlock, close ----------

/** Locks the database. Unsaved changes are kept, encrypted, so unlocking brings them back. */
export async function lockDatabase() {
  const s = state.kdbx;
  if (!s || state.locked || !s.db) return;
  try {
    if (s.dirty) {
      await syncToDb(s.db, s.kd, state.items, state.meta);
      s.lastBytes = await saveDb(s.db);
      s.pendingLocked = true;
    }
  } catch (e) {
    toast(`Locked, but unsaved changes could not be kept: ${e.message}`, 'error', 9000);
  }
  wipe();
  clearAttachments();
  closeAssistWindow();
  clearClipboardNow();
  s.db = null;
  s.kd = null;
  state.locked = true;
  hooks.render();
}

export async function unlockDatabase() {
  const s = state.kdbx;
  if (!s || !state.locked) return false;
  const res = await credentialsDialog({
    title: `Unlock ${s.fileName}`,
    submitLabel: 'Unlock',
    keyFile: 'optional',
    run: (v) => openKdbx(s.lastBytes, { password: v.password, keyFile: v.keyFile }),
  });
  if (!res) return false;
  attach(res.db, res, { fileName: s.fileName, handle: s.handle, loadedMtime: s.loadedMtime, lastBytes: s.lastBytes, dirty: s.pendingLocked });
  return true;
}

export async function closeDatabase() {
  const s = state.kdbx;
  if (!s) return false;
  if (s.dirty && !state.locked) {
    const ok = await confirmBox('Close without saving?', `You have unsaved changes in <strong>${esc(s.fileName)}</strong>. They will be lost.`, 'Close without saving');
    if (!ok) return false;
  } else if (state.locked && s.pendingLocked) {
    const ok = await confirmBox('Close without saving?', 'Unsaved changes made before the lock will be lost.', 'Close without saving');
    if (!ok) return false;
  }
  wipe();
  clearAttachments();
  closeAssistWindow();
  state.kdbx = null;
  state.locked = false;
  state.started = false;
  hooks.render();
  return true;
}

// ---------- auto-lock and auto-save ----------

let lastActive = Date.now();
export const noteActivity = () => { lastActive = Date.now(); };

export function startBackgroundTimers() {
  setInterval(() => {
    const s = state.kdbx;
    if (!s || state.locked || !prefs.autoLockMinutes || saving || isModalOpen()) return;
    if (Date.now() - lastActive > prefs.autoLockMinutes * 60000) {
      lockDatabase().then(() => toast('Locked after inactivity.'));
    }
  }, 5000);
}

let autoSaveTimer = null;
export function scheduleAutoSave() {
  clearTimeout(autoSaveTimer);
  const s = state.kdbx;
  if (!prefs.autoSave || !s || state.locked || !s.dirty || !s.handle) return;
  autoSaveTimer = setTimeout(() => saveDatabase({ silent: true }), 4000);
}

// ---------- database settings ----------

export async function renameDatabase() {
  const s = state.kdbx;
  const name = await promptText('Rename database', s.db.meta.name || '', 'Database name');
  if (!name) return;
  s.db.meta.name = name;
  s.dirty = true;
  hooks.render();
}

export async function changeMasterPassword() {
  const s = state.kdbx;
  const ok = await credentialsDialog({
    title: 'Change master password',
    intro: 'Set the new password (and key file, if you use one). Remember to save afterwards. Old copies of the file keep the old password.',
    submitLabel: 'Change password',
    confirm: true,
    keyFile: 'optional',
    run: async (v) => {
      await changeCredentials(s.db, { password: v.password, keyFile: v.keyFile });
      return true;
    },
  });
  if (ok) {
    s.dirty = true;
    toast('Master password changed. Click Save to apply it.');
    hooks.render();
  }
}

export function changeKdf() {
  const s = state.kdbx;
  const presets = Object.entries(KDF_PRESETS).map(([k, p]) => `<option value="${k}" ${k === 'standard' ? 'selected' : ''}>${esc(p.label)}</option>`).join('');
  const types = Object.entries(KDF_TYPES).map(([k, l]) => `<option value="${k}">${esc(l)}</option>`).join('');
  return openModal(`
    <h2>Encryption strength</h2>
    <p class="lede">Controls how slow it is to guess your master password. A stronger setting takes longer to open and save on every device you use, including phones.</p>
    <form id="kdf-form" class="stack">
      <label>Key derivation<select name="kdf">${types}</select></label>
      <label>Strength<select name="preset">${presets}</select></label>
      <p class="fine">Older apps may not support Argon2id. Argon2d and AES-KDF are the widest supported.</p>
      <div class="modal-actions">
        <button type="button" class="btn ghost" data-action="modal-close">Cancel</button>
        <button class="btn primary" type="submit">Apply</button>
      </div>
    </form>`, {
    onMount: (dlg) => {
      dlg.querySelector('#kdf-form').addEventListener('submit', (e) => {
        e.preventDefault();
        const f = e.currentTarget.elements;
        setKdfParams(s.db, { kdf: f.kdf.value, preset: f.preset.value });
        s.dirty = true;
        closeModal(true);
        toast('Updated. Click Save to apply it.');
        hooks.render();
      });
    },
  });
}

/** Merges another copy of a KeePass database into the open one. */
export async function mergeFromFile() {
  const s = state.kdbx;
  const file = await chooseFile('.kdbx');
  if (!file) return;
  const bytes = new Uint8Array(await file.arrayBuffer());
  const before = state.items.length;
  try {
    await syncToDb(s.db, s.kd, state.items, state.meta);
    try {
      await mergeBytesIntoOpenDb(bytes);
    } catch (e) {
      if (!/key|hmac|credential|password/i.test(String(e.message)) && e.code !== 'InvalidKey') throw e;
      const ok = await credentialsDialog({
        title: `Unlock ${file.name}`,
        intro: 'This file has a different password. Enter it to merge its entries.',
        submitLabel: 'Merge',
        keyFile: 'optional',
        run: async (v) => {
          await mergeBytesIntoOpenDb(bytes, makeCredentials({ password: v.password, keyFile: v.keyFile }));
          return true;
        },
      });
      if (!ok) return;
    }
    s.dirty = true;
    refresh();
    toast(`Merged ${file.name}. ${state.items.length - before >= 0 ? state.items.length - before : 0} new item(s). Click Save to keep the result.`, 'ok', 7000);
  } catch (e) {
    toast(`Could not merge: ${e.message}`, 'error', 8000);
  }
}

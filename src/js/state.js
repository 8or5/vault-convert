// Shared application state and the operations that change it. Everything lives in memory on
// this page. Only display preferences (never item data) are saved to localStorage.

import { vaultOf, DEFAULT_VAULT, uniq, displayName, folderPath } from './model.js';
import { analyse, mergeGroup } from './analysis.js';

// ---------- preferences ----------

const PREFS_KEY = 'vault-convert:prefs';

export const DEFAULT_PREFS = {
  theme: 'system',
  density: 'comfortable',
  sort: 'name',
  maskDetail: true,
  autoLockMinutes: 5,
  clipboardClear: 30,
  autoSave: false,
  columns: { username: true, url: true, folder: true, flags: true, updated: false, quick: true },
};

function loadPrefs() {
  try {
    const saved = JSON.parse(localStorage.getItem(PREFS_KEY) || '{}');
    return { ...DEFAULT_PREFS, ...saved, columns: { ...DEFAULT_PREFS.columns, ...(saved.columns || {}) } };
  } catch {
    return structuredClone(DEFAULT_PREFS);
  }
}

export const prefs = loadPrefs();
export const savePrefs = () => {
  try { localStorage.setItem(PREFS_KEY, JSON.stringify(prefs)); } catch { /* private mode or blocked storage */ }
};

// ---------- state ----------

export const state = {
  items: [],
  meta: { vaults: [DEFAULT_VAULT], folders: {} },
  view: { kind: 'all' },
  query: '',
  selected: new Set(),
  openId: null,
  revealDetail: false,
  editMode: false,
  started: false,
  history: [],
  analysis: analyse([]),
  /** Set while a KeePass database is open: { db, kd, fileName, handle, loadedMtime, dirty, lastBytes, pendingLocked } */
  kdbx: null,
  locked: false,
};

/** The UI registers its render function here, so state operations can trigger redraws without importing the UI. */
export const hooks = { render: () => {}, changed: () => {} };

export const liveItems = () => state.items.filter((i) => !i.trashed);
export const trashedItems = () => state.items.filter((i) => i.trashed);
export const getItem = (id) => state.items.find((i) => i.id === id);

export const allVaults = () =>
  uniq([...state.meta.vaults, ...liveItems().map(vaultOf)]).sort((a, b) => a.localeCompare(b));

export const foldersOf = (vault) =>
  uniq([
    ...(state.meta.folders[vault] || []),
    ...liveItems().filter((i) => vaultOf(i) === vault && i.folder).map((i) => i.folder),
  ]).sort();

export function ensureVault(name) {
  if (!state.meta.vaults.includes(name)) state.meta.vaults.push(name);
}

export function ensureFolder(vault, folder) {
  if (!folder) return;
  if (!state.meta.folders[vault]) state.meta.folders[vault] = [];
  if (!state.meta.folders[vault].includes(folder)) state.meta.folders[vault].push(folder);
}

// ---------- history (undo) ----------

/** Call before any change. Also marks an open KeePass database as having unsaved changes. */
export function snapshot() {
  state.history.push(structuredClone({ items: state.items, meta: state.meta }));
  if (state.history.length > 60) state.history.shift();
  if (state.kdbx) state.kdbx.dirty = true;
}

export function undo() {
  const prev = state.history.pop();
  if (!prev) return false;
  state.items = prev.items;
  state.meta = prev.meta;
  state.selected = new Set([...state.selected].filter((id) => getItem(id)));
  if (state.openId && !getItem(state.openId)) state.openId = null;
  if (state.kdbx) state.kdbx.dirty = true;
  refresh();
  return true;
}

export function refresh() {
  state.analysis = analyse(liveItems());
  const a = state.analysis;
  if (state.view.kind === 'dupes' && !a.dupeIds.size && !a.conflictIds.size) state.view = { kind: 'all' };
  hooks.render();
  hooks.changed();
}

// ---------- mutations ----------

/** Applies one change to one item, with undo support. */
export function editItem(id, fn) {
  const it = getItem(id);
  if (!it) return;
  snapshot();
  fn(it);
  it.updatedAt = new Date().toISOString();
  refresh();
}

export function bulkEdit(ids, fn) {
  snapshot();
  for (const id of ids) {
    const it = getItem(id);
    if (!it) continue;
    fn(it);
    it.updatedAt = new Date().toISOString();
  }
  refresh();
}

/** Removes items from the list. In a KeePass database, `permanent` also deletes them from the file (not the recycle bin). */
export function removeItems(ids, permanent = false) {
  const drop = new Set(ids);
  if (state.kdbx && permanent) for (const id of ids) state.kdbx.kd.permanent.add(id);
  state.items = state.items.filter((i) => !drop.has(i.id));
  for (const id of ids) state.selected.delete(id);
  if (drop.has(state.openId)) state.openId = null;
}

/** Merges the given item ids into one item, kept in the position of the first. */
export function mergeIds(ids) {
  const group = state.items.filter((i) => ids.includes(i.id));
  if (group.length < 2) return null;
  const merged = mergeGroup(group);
  merged.updatedAt = new Date().toISOString();
  const keep = group[0].id;
  state.items = state.items.filter((i) => i.id === keep || !ids.includes(i.id)).map((i) => (i.id === keep ? merged : i));
  for (const id of ids) if (id !== keep) state.selected.delete(id);
  if (state.openId && ids.includes(state.openId)) state.openId = keep;
  return merged;
}

/** Wipes everything from memory (used by lock and close). */
export function wipe() {
  state.items = [];
  state.meta = { vaults: [DEFAULT_VAULT], folders: {} };
  state.view = { kind: 'all' };
  state.query = '';
  state.selected = new Set();
  state.openId = null;
  state.revealDetail = false;
  state.editMode = false;
  state.history = [];
  state.analysis = analyse([]);
}

// ---------- selectors ----------

export function inView(it) {
  const v = state.view;
  const a = state.analysis;
  if (v.kind === 'trash') return !!it.trashed;
  if (it.trashed) return false;
  switch (v.kind) {
    case 'fav': return it.favorite;
    case 'attention': return (a.flags.get(it.id) || []).length > 0;
    case 'dupes': return a.dupeIds.has(it.id) || a.conflictIds.has(it.id);
    case 'totp': return a.totpOnly.has(it.id);
    case 'type': return it.type === v.type;
    case 'vault': return vaultOf(it) === v.vault;
    case 'folder': return vaultOf(it) === v.vault && (it.folder || '') === (v.folder || '');
    default: return true;
  }
}

export function matches(it, query) {
  if (!query) return true;
  const hay = [
    displayName(it), it.username, it.urls.join(' '), it.notes, it.folder, vaultOf(it), it.tags.join(' '),
    ...(it.attachments || []).map((a) => a.name),
    ...it.customFields.filter((f) => !f.hidden).map((f) => `${f.name} ${f.value}`),
  ].join(' ').toLowerCase();
  return query.toLowerCase().split(/\s+/).every((term) => hay.includes(term));
}

export const SORTERS = {
  name: (a, b) => displayName(a).localeCompare(displayName(b)),
  updated: (a, b) => (b.updatedAt || '').localeCompare(a.updatedAt || ''),
  vault: (a, b) => folderPath(a).localeCompare(folderPath(b)) || displayName(a).localeCompare(displayName(b)),
  username: (a, b) => (a.username || '').localeCompare(b.username || '') || displayName(a).localeCompare(displayName(b)),
};

export function visibleItems() {
  const q = state.query.trim();
  const sorter = SORTERS[prefs.sort] || SORTERS.name;
  return state.items.filter((it) => inView(it) && matches(it, q)).sort(sorter);
}

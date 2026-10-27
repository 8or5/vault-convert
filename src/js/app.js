// Vault Convert: UI controller. All state lives in memory on this page. Nothing is stored
// or sent anywhere. Only layout preferences (never passwords) are saved to localStorage.

import { newItem, displayName, folderPath, vaultOf, DEFAULT_VAULT, TYPE_LABEL, TYPE_GLYPH, hostOf, splitUrls, uniq } from './model.js';
import { parseFile } from './importers.js';
import { FORMATS, exportItems } from './exporters.js';
import { analyse, mergeGroup, linkTotp, suggestTotpTargets, generatePassword, passwordStrength, exactKey, newestId } from './analysis.js';
import { totpCode, secondsLeft, parseTotpInput, isValidTotp } from './totp.js';

// ---------- small helpers ----------

const $ = (sel, root = document) => root.querySelector(sel);
const esc = (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
const fmtDate = (iso) => (iso ? new Date(iso).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }) : '—');

const IMPORT_LABELS = [
  'Bitwarden (JSON, CSV)',
  '1Password (1PUX, 1PIF, CSV)',
  'Proton Pass (CSV)',
  'Dashlane (CSV, JSON)',
  'LastPass (CSV)',
  'KeePass 2 (XML, CSV)',
  'KeePassXC (CSV)',
  'Enpass (JSON, CSV)',
  'Monica (generic JSON or CSV)',
  'Apple Passwords (CSV)',
  'Chrome, Edge, Google (CSV)',
  'Firefox (CSV)',
  'Any CSV with a header row',
];

const PREFS_KEY = 'vault-convert:prefs';
const DEFAULT_PREFS = {
  theme: 'system',
  density: 'comfortable',
  sort: 'name',
  maskDetail: true,
  columns: { username: true, url: true, folder: true, flags: true, updated: false },
};

function loadPrefs() {
  try {
    const saved = JSON.parse(localStorage.getItem(PREFS_KEY) || '{}');
    return { ...DEFAULT_PREFS, ...saved, columns: { ...DEFAULT_PREFS.columns, ...(saved.columns || {}) } };
  } catch {
    return structuredClone(DEFAULT_PREFS);
  }
}
const prefs = loadPrefs();
const savePrefs = () => { try { localStorage.setItem(PREFS_KEY, JSON.stringify(prefs)); } catch { /* private mode */ } };

const SORTERS = {
  name: (a, b) => displayName(a).localeCompare(displayName(b)),
  updated: (a, b) => (b.updatedAt || '').localeCompare(a.updatedAt || ''),
  vault: (a, b) => folderPath(a).localeCompare(folderPath(b)) || displayName(a).localeCompare(displayName(b)),
  username: (a, b) => (a.username || '').localeCompare(b.username || '') || displayName(a).localeCompare(displayName(b)),
};

// ---------- state ----------

const state = {
  items: [],
  meta: { vaults: [DEFAULT_VAULT], folders: {} },
  view: { kind: 'all' },
  query: '',
  selected: new Set(),
  openId: null,
  revealDetail: false,
  started: false,
  history: [],
  analysis: analyse([]),
};

const getItem = (id) => state.items.find((i) => i.id === id);
const allVaults = () => uniq([...state.meta.vaults, ...state.items.map(vaultOf)]).sort((a, b) => a.localeCompare(b));
const foldersOf = (vault) =>
  uniq([...(state.meta.folders[vault] || []), ...state.items.filter((i) => vaultOf(i) === vault && i.folder).map((i) => i.folder)]).sort();
function ensureVault(name) {
  if (!state.meta.vaults.includes(name)) state.meta.vaults.push(name);
}
function ensureFolder(vault, folder) {
  if (!folder) return;
  if (!state.meta.folders[vault]) state.meta.folders[vault] = [];
  if (!state.meta.folders[vault].includes(folder)) state.meta.folders[vault].push(folder);
}

function snapshot() {
  state.history.push(structuredClone({ items: state.items, meta: state.meta }));
  if (state.history.length > 60) state.history.shift();
}

function undo() {
  const prev = state.history.pop();
  if (!prev) return toast('Nothing to undo');
  state.items = prev.items;
  state.meta = prev.meta;
  state.selected = new Set([...state.selected].filter((id) => getItem(id)));
  if (state.openId && !getItem(state.openId)) state.openId = null;
  refresh();
}

/** Applies one change to one item, with undo support. */
function editItem(id, fn) {
  const it = getItem(id);
  if (!it) return;
  snapshot();
  fn(it);
  it.updatedAt = new Date().toISOString();
  refresh();
}

function bulkEdit(ids, fn) {
  snapshot();
  for (const id of ids) {
    const it = getItem(id);
    if (!it) continue;
    fn(it);
    it.updatedAt = new Date().toISOString();
  }
  refresh();
}

function deleteIds(ids) {
  const drop = new Set(ids);
  state.items = state.items.filter((i) => !drop.has(i.id));
  for (const id of ids) state.selected.delete(id);
  if (drop.has(state.openId)) state.openId = null;
}

/** Merges the given item ids into one item in the position of the first. */
function mergeIds(ids) {
  const group = state.items.filter((i) => ids.includes(i.id));
  if (group.length < 2) return null;
  const merged = mergeGroup(group);
  merged.updatedAt = new Date().toISOString();
  const keep = group[0].id;
  state.items = state.items
    .filter((i) => i.id === keep || !ids.includes(i.id))
    .map((i) => (i.id === keep ? merged : i));
  for (const id of ids) if (id !== keep) state.selected.delete(id);
  if (state.openId && ids.includes(state.openId)) state.openId = keep;
  return merged;
}

function refresh() {
  state.analysis = analyse(state.items);
  if (state.view.kind === 'dupes' && !state.analysis.dupeIds.size && !state.analysis.conflictIds.size) state.view = { kind: 'all' };
  render();
}

// ---------- view filtering ----------

function inView(it) {
  const v = state.view;
  const a = state.analysis;
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

function matches(it, query) {
  if (!query) return true;
  const hay = [
    displayName(it), it.username, it.urls.join(' '), it.notes, it.folder, vaultOf(it), it.tags.join(' '),
    ...it.customFields.filter((f) => !f.hidden).map((f) => `${f.name} ${f.value}`),
  ].join(' ').toLowerCase();
  return query.toLowerCase().split(/\s+/).every((term) => hay.includes(term));
}

function visibleItems() {
  const q = state.query.trim();
  const sorter = SORTERS[prefs.sort] || SORTERS.name;
  return state.items.filter((it) => inView(it) && matches(it, q)).sort(sorter);
}

// ---------- rendering ----------

function render() {
  renderChrome();
  if (!(state.items.length || state.started)) return;
  renderSidebar();
  renderWorkspace();
  renderDetail();
}

function renderChrome() {
  const has = state.items.length > 0 || state.started;
  $('#welcome').hidden = has;
  $('#workspace').hidden = !has;
  $('#sidebar').hidden = !has;
  $('#layout').classList.toggle('has-detail', has && !!state.openId && !!getItem(state.openId));
  $('#btn-undo').disabled = state.history.length === 0;
  $('#sort').value = prefs.sort;
  if (!has) renderWelcome();
}

function renderWelcome() {
  $('#welcome').innerHTML = `
    <div class="hero">
      <p class="eyebrow">Offline password vault converter</p>
      <h1>Move your passwords between managers, privately.</h1>
      <p class="lede">Drop an export from any password manager. Everything is parsed, checked and edited in this page.
        Nothing is uploaded, and this app makes no network requests.</p>
      <div class="dropzone" data-action="pick-files" role="button" tabindex="0">
        <div class="dz-icon" aria-hidden="true">⬆</div>
        <strong>Drop files here, or click to choose</strong>
        <span>CSV, JSON, XML, 1PUX, 1PIF. You can load several files.</span>
      </div>
      <div class="hero-actions">
        <button class="btn ghost" data-action="start-empty">Start with an empty vault</button>
      </div>
      <h3>Recognised formats</h3>
      <ul class="format-chips">${IMPORT_LABELS.map((l) => `<li>${esc(l)}</li>`).join('')}</ul>
      <p class="fine">Encrypted backups (KeePass .kdbx, encrypted Bitwarden JSON, password-protected ZIP) can't be read here.
        Export them unencrypted first, then delete the unencrypted file after you're done.</p>
    </div>`;
}

function renderSidebar() {
  const a = state.analysis;
  const items = state.items;
  const isActive = (kind, extra = {}) => {
    const v = state.view;
    if (v.kind !== kind) return false;
    if (kind === 'vault') return v.vault === extra.vault;
    if (kind === 'folder') return v.vault === extra.vault && (v.folder || '') === (extra.folder || '');
    if (kind === 'type') return v.type === extra.type;
    return true;
  };
  const nav = (kind, label, count, extra = {}, depth = 0) => {
    const attrs = Object.entries(extra).map(([k, v]) => `data-${k}="${esc(v)}"`).join(' ');
    return `<button class="nav depth-${depth}${isActive(kind, extra) ? ' active' : ''}" data-action="nav" data-kind="${kind}" ${attrs}>
      <span class="nav-label">${esc(label)}</span><span class="count">${count}</span></button>`;
  };
  const types = ['login', 'note', 'card', 'identity'].filter((t) => items.some((i) => i.type === t));
  const vaults = allVaults();
  $('#sidebar').innerHTML = `
    <section>
      <h4>Library</h4>
      ${nav('all', 'All items', items.length)}
      ${nav('fav', 'Favourites', items.filter((i) => i.favorite).length)}
      ${nav('attention', 'Needs attention', items.filter((i) => (a.flags.get(i.id) || []).length).length)}
      ${nav('dupes', 'Duplicates & conflicts', a.dupeIds.size + a.conflictIds.size)}
      ${nav('totp', 'Authenticator only', a.totpOnly.size)}
    </section>
    ${types.length ? `<section><h4>Item types</h4>
      ${types.map((t) => nav('type', TYPE_LABEL[t] + 's', items.filter((i) => i.type === t).length, { type: t })).join('')}
    </section>` : ''}
    <section>
      <h4>Vaults</h4>
      ${vaults.map((v) => {
        const count = items.filter((i) => vaultOf(i) === v).length;
        const folders = foldersOf(v);
        return `<div class="nav-group">
          <div class="nav-row">
            ${nav('vault', v, count, { vault: v })}
            <span class="mini">
              <button data-action="new-folder" data-vault="${esc(v)}" title="New folder in ${esc(v)}" aria-label="New folder">+</button>
              <button data-action="rename-vault" data-vault="${esc(v)}" title="Rename vault" aria-label="Rename vault">✎</button>
              <button data-action="delete-vault" data-vault="${esc(v)}" title="Delete vault (items move to ${DEFAULT_VAULT})" aria-label="Delete vault">✕</button>
            </span>
          </div>
          ${folders.map((f) => nav('folder', f, items.filter((i) => vaultOf(i) === v && i.folder === f).length, { vault: v, folder: f }, 1)).join('')}
        </div>`;
      }).join('')}
      <div class="sidebar-add">
        <button class="btn sm ghost" data-action="new-vault">+ New vault</button>
      </div>
    </section>`;
}

function renderWorkspace() {
  const list = visibleItems();
  const a = state.analysis;
  const cols = prefs.columns;
  const colCount = 4 + ['username', 'url', 'folder', 'flags', 'updated'].filter((c) => cols[c]).length;

  $('#banner').innerHTML = state.view.kind === 'dupes' ? dupeBanner() : '';
  const counts = `<strong>${list.length}</strong> of ${state.items.length} items`;
  $('#counts').innerHTML = counts + (state.selected.size ? ` · <span class="sel">${state.selected.size} selected</span>` : '');
  const bulk = $('#bulk');
  bulk.hidden = state.selected.size === 0;
  bulk.innerHTML = state.selected.size ? bulkBar() : '';

  const head = [
    `<th class="c-check"><input type="checkbox" data-action="select-all" aria-label="Select all visible" ${list.length && list.every((i) => state.selected.has(i.id)) ? 'checked' : ''}/></th>`,
    '<th class="c-fav" aria-label="Favourite"></th>',
    '<th class="c-name">Name</th>',
    cols.username ? '<th>Username</th>' : '',
    cols.url ? '<th>Website</th>' : '',
    cols.folder ? '<th>Vault / folder</th>' : '',
    cols.flags ? '<th>Checks</th>' : '',
    cols.updated ? '<th>Updated</th>' : '',
  ];
  $('#thead').innerHTML = `<tr>${head.join('')}</tr>`;

  $('#rows').innerHTML = list.length
    ? list.map((it) => rowHtml(it, a, cols)).join('')
    : `<tr><td colspan="${colCount}" class="empty">Nothing matches this view. ${state.query ? 'Try a different search.' : ''}</td></tr>`;
}

function rowHtml(it, a, cols) {
  const flags = a.flags.get(it.id) || [];
  const sel = state.selected.has(it.id);
  const url = it.urls[0] || '';
  const shown = [
    `<td class="c-check"><input type="checkbox" data-action="select" data-id="${it.id}" ${sel ? 'checked' : ''} aria-label="Select ${esc(displayName(it))}"/></td>`,
    `<td class="c-fav"><button class="star${it.favorite ? ' on' : ''}" data-action="fav" data-id="${it.id}" aria-label="Toggle favourite">★</button></td>`,
    `<td class="c-name"><div class="name">
        <span class="glyph" title="${esc(TYPE_LABEL[it.type])}">${TYPE_GLYPH[it.type]}</span>
        <div><strong>${esc(displayName(it))}</strong>
          <small>${esc(TYPE_LABEL[it.type])}${it.tags.length ? ' · ' + esc(it.tags.join(', ')) : ''}</small></div>
      </div></td>`,
    cols.username ? `<td class="c-user">${esc(it.username)}</td>` : '',
    cols.url ? `<td class="c-url">${esc(hostOf(url) || url)}${it.urls.length > 1 ? ` <small>+${it.urls.length - 1}</small>` : ''}</td>` : '',
    cols.folder ? `<td class="c-folder">${esc(folderPath(it))}</td>` : '',
    cols.flags ? `<td class="c-flags">${flags.slice(0, 2).map((f) => `<span class="chip ${f.level}" title="${esc(f.hint)}">${esc(f.label)}</span>`).join('')}${flags.length > 2 ? `<span class="chip">+${flags.length - 2}</span>` : ''}</td>` : '',
    cols.updated ? `<td class="c-date">${esc(it.updatedAt ? new Date(it.updatedAt).toLocaleDateString() : '—')}</td>` : '',
  ];
  return `<tr data-row="${it.id}" class="${sel ? 'selected' : ''}${state.openId === it.id ? ' open' : ''}">${shown.join('')}</tr>`;
}

function bulkBar() {
  const ids = [...state.selected];
  const hasAuth = ids.some((id) => state.analysis.totpOnly.has(id));
  return `
    <button class="btn sm" data-action="bulk-fav">Favourite</button>
    <button class="btn sm" data-action="bulk-move">Move to vault…</button>
    <button class="btn sm" data-action="bulk-merge" ${ids.length < 2 ? 'disabled' : ''}>Merge</button>
    <button class="btn sm" data-action="bulk-link" ${hasAuth ? '' : 'disabled'}>Link authenticator…</button>
    <button class="btn sm" data-action="bulk-export">Export selection</button>
    <button class="btn sm danger" data-action="bulk-delete">Delete</button>
    <button class="btn sm ghost" data-action="bulk-clear">Clear</button>`;
}

function dupeBanner() {
  const d = state.analysis.dupes;
  if (!d.exact.length && !d.conflicts.length) return '<div class="banner ok">No duplicates or conflicting logins found.</div>';
  return `<div class="banner warn">
    <div>
      <strong>${d.exact.length} exact duplicate group(s)</strong> and <strong>${d.conflicts.length} conflicting login group(s)</strong>.
      Merging keeps every field. When two items disagree, the second value is saved as an alternate custom field, so nothing is lost.
    </div>
    <div class="banner-actions">
      <button class="btn sm" data-action="dupes-merge-exact" ${d.exact.length ? '' : 'disabled'}>Merge exact duplicates</button>
      <button class="btn sm" data-action="dupes-keep-newest" ${d.exact.length ? '' : 'disabled'}>Keep newest, delete rest</button>
      <button class="btn sm" data-action="dupes-merge-conflicts" ${d.conflicts.length ? '' : 'disabled'}>Merge conflicting logins</button>
    </div>
  </div>`;
}

function renderDetail() {
  const el = $('#detail');
  const it = state.openId ? getItem(state.openId) : null;
  el.hidden = !it;
  if (!it) {
    el.innerHTML = '';
    return;
  }
  const flags = state.analysis.flags.get(it.id) || [];
  const mask = !state.revealDetail;
  const isLogin = it.type === 'login';
  const suggestions = state.analysis.totpOnly.has(it.id) ? suggestTotpTargets(it, state.items).slice(0, 6) : [];

  el.innerHTML = `
    <header class="detail-head">
      <div class="detail-title">
        <span class="glyph big">${TYPE_GLYPH[it.type]}</span>
        <div><strong>${esc(displayName(it))}</strong><small>${esc(TYPE_LABEL[it.type])} · ${esc(folderPath(it))}</small></div>
      </div>
      <button class="btn sm ghost" data-action="close-detail" aria-label="Close editor">✕</button>
    </header>
    ${flags.length ? `<div class="flag-list">${flags.map((f) => `
      <div class="flag ${f.level}">
        <div><strong>${esc(f.label)}</strong><span>${esc(f.hint)}</span></div>
        ${flagAction(f, it)}
      </div>`).join('')}</div>` : ''}
    <form class="fields" autocomplete="off" onsubmit="return false">
      <div class="two">
        <label>Type<select data-field="type">${Object.keys(TYPE_LABEL).map((t) => `<option value="${t}" ${t === it.type ? 'selected' : ''}>${TYPE_LABEL[t]}</option>`).join('')}</select></label>
        <label class="check fav-check"><input type="checkbox" data-field="favorite" ${it.favorite ? 'checked' : ''}/> Favourite</label>
      </div>
      <label>Name<input data-field="name" value="${esc(it.name)}" /></label>
      <div class="two">
        <label>Vault<input list="vault-list" data-field="vault" value="${esc(vaultOf(it))}" /></label>
        <label>Folder<input list="folder-list" data-field="folder" value="${esc(it.folder)}" /></label>
      </div>
      <datalist id="vault-list">${allVaults().map((v) => `<option value="${esc(v)}"></option>`).join('')}</datalist>
      <datalist id="folder-list">${foldersOf(vaultOf(it)).map((f) => `<option value="${esc(f)}"></option>`).join('')}</datalist>

      ${isLogin ? `
        <label>Username<div class="with-btn"><input data-field="username" value="${esc(it.username)}" />
          <button type="button" class="btn sm" data-action="copy" data-what="username" data-id="${it.id}">Copy</button></div></label>
        <label>Password
          <div class="with-btn">
            <input data-field="password" type="${mask ? 'password' : 'text'}" value="${esc(it.password)}" />
            <button type="button" class="btn sm" data-action="reveal">${mask ? 'Show' : 'Hide'}</button>
            <button type="button" class="btn sm" data-action="copy" data-what="password" data-id="${it.id}">Copy</button>
            <button type="button" class="btn sm" data-action="gen" data-id="${it.id}">Generate</button>
          </div>
          <div class="strength s${passwordStrength(it.password)}" aria-label="Password strength"><span></span></div>
        </label>
        <label>Website(s), one per line<textarea data-field="urls" rows="2">${esc(it.urls.join('\n'))}</textarea></label>
        <label>One-time code<div class="with-btn"><input data-field="totp" value="${esc(it.totp)}" placeholder="Base32 secret or otpauth:// link" /></div></label>
        ${it.totp ? totpBlock(it) : ''}
      ` : ''}

      ${suggestions.length ? `<div class="suggest">
        <strong>Link this authenticator to a login</strong>
        <div class="suggest-list">${suggestions.map((s) => `<button type="button" class="btn sm" data-action="link" data-id="${s.item.id}" data-source="${it.id}">${esc(displayName(s.item))}${s.item.username ? ` <small>${esc(s.item.username)}</small>` : ''}</button>`).join('')}</div>
      </div>` : ''}

      <label>Notes<textarea data-field="notes" rows="4">${esc(it.notes)}</textarea></label>

      <div class="cf">
        <div class="cf-head"><strong>Custom fields</strong>
          <button type="button" class="btn sm" data-action="cf-add" data-id="${it.id}">+ Add field</button></div>
        ${it.customFields.map((f, i) => `
          <div class="cf-row">
            <input data-field="cf-name" data-index="${i}" value="${esc(f.name)}" aria-label="Field name" />
            <input data-field="cf-value" data-index="${i}" value="${esc(f.value)}" type="${f.hidden && mask ? 'password' : 'text'}" aria-label="Field value" />
            <button type="button" class="btn sm${f.hidden ? ' on' : ''}" data-action="cf-hide" data-index="${i}" title="Hide value">●</button>
            <button type="button" class="btn sm danger" data-action="cf-del" data-index="${i}" aria-label="Remove field">✕</button>
          </div>`).join('') || '<p class="fine">No custom fields.</p>'}
      </div>

      <label>Tags<input data-field="tags" value="${esc(it.tags.join(', '))}" placeholder="Comma separated" /></label>
      <p class="meta">Created ${fmtDate(it.createdAt)} · Updated ${fmtDate(it.updatedAt)}<br/>Source: ${esc(it.source)}</p>
    </form>
    <footer class="detail-foot">
      <button class="btn" data-action="dup-item" data-id="${it.id}">Duplicate</button>
      <button class="btn danger" data-action="delete-item" data-id="${it.id}">Delete</button>
    </footer>`;
}

function flagAction(f, it) {
  switch (f.code) {
    case 'no-password': return `<button class="btn sm" data-action="gen" data-id="${it.id}">Generate password</button>`;
    case 'duplicate':
    case 'conflict': return '<button class="btn sm" data-action="show-dupes">Review</button>';
    case 'weak':
    case 'reused': return `<button class="btn sm" data-action="gen" data-id="${it.id}">Replace with generated</button>`;
    default: return '';
  }
}

function totpBlock(it) {
  const valid = isValidTotp(it.totp);
  if (!valid) return `<div class="totp invalid">This secret is not valid base32. Re-copy it from the site's authenticator setup.</div>`;
  return `<div class="totp" id="totp-box">
      <div><span class="totp-code" id="totp-code" data-secret="${esc(it.totp)}">… …</span>
      <small id="totp-left"></small></div>
      <div class="totp-bar"><span id="totp-bar"></span></div>
      <button type="button" class="btn sm" data-action="copy" data-what="totp" data-id="${it.id}">Copy code</button>
    </div>`;
}

async function updateTotp() {
  const el = document.getElementById('totp-code');
  if (!el) return;
  const period = parseTotpInput(el.dataset.secret)?.period || 30;
  const code = await totpCode(el.dataset.secret);
  const left = secondsLeft(period);
  el.textContent = code ? `${code.slice(0, 3)} ${code.slice(3)}` : '—';
  document.getElementById('totp-left').textContent = `${left}s left`;
  document.getElementById('totp-bar').style.width = `${(left / period) * 100}%`;
}

// ---------- modals ----------

let modalResolve = null;

function openModal(html, { onMount, wide = false } = {}) {
  return new Promise((resolve) => {
    const dlg = $('#modal');
    dlg.className = `modal${wide ? ' wide' : ''}`;
    dlg.innerHTML = `<div class="modal-inner">${html}</div>`;
    modalResolve = resolve;
    dlg.onclose = () => {
      const r = modalResolve;
      modalResolve = null;
      r?.(null);
    };
    dlg.showModal();
    onMount?.(dlg);
  });
}

function closeModal(value) {
  const r = modalResolve;
  modalResolve = null;
  $('#modal').close();
  r?.(value);
}

async function promptText(title, value = '', label = 'Name') {
  return openModal(`
    <h2>${esc(title)}</h2>
    <form id="prompt-form" class="stack">
      <label>${esc(label)}<input id="prompt-input" value="${esc(value)}" /></label>
      <div class="modal-actions">
        <button type="button" class="btn ghost" data-action="modal-close">Cancel</button>
        <button class="btn primary" type="submit">OK</button>
      </div>
    </form>`, {
    onMount: (dlg) => {
      const input = dlg.querySelector('#prompt-input');
      input.focus();
      input.select();
      dlg.querySelector('#prompt-form').addEventListener('submit', (e) => {
        e.preventDefault();
        closeModal(input.value.trim() || null);
      });
    },
  });
}

async function confirmBox(title, body, okLabel = 'Confirm') {
  const r = await openModal(`
    <h2>${esc(title)}</h2>
    <p>${body}</p>
    <div class="modal-actions">
      <button class="btn ghost" data-action="modal-close">Cancel</button>
      <button class="btn danger" data-action="modal-ok">${esc(okLabel)}</button>
    </div>`);
  return r === true;
}

/** Suggested vault name for an import: the manager's name, or "Imported" for generic files. */
function importVaultName(format) {
  if (/^(Generic|JSON|1Password \(1PIF\))/.test(format)) return 'Imported';
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

function openExport(scope = 'all') {
  const scopes = () => ({
    all: state.items,
    selected: state.items.filter((i) => state.selected.has(i.id)),
    view: visibleItems(),
  });
  const labels = { all: `All items (${state.items.length})`, selected: `Selected (${state.selected.size})`, view: `Current view (${visibleItems().length})` };
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
        <div id="exp-summary" class="summary"></div>
        <p class="warning">Exported files contain passwords in plain text. Keep them private, import them, then delete the file.</p>
        <div class="modal-actions">
          <button class="btn ghost" data-action="modal-close">Close</button>
          <button class="btn primary" id="exp-download">Download</button>
        </div>
      </div>
    </div>`, {
    wide: true,
    onMount: (dlg) => {
      const summary = () => {
        const fmt = dlg.querySelector('input[name="fmt"]:checked').value;
        const sc = dlg.querySelector('input[name="scope"]:checked').value;
        const items = scopes()[sc];
        const out = exportItems(fmt, items);
        const excluded = Object.entries(out.excluded).map(([t, n]) => `${n} ${TYPE_LABEL[t]}`).join(', ');
        dlg.querySelector('#exp-summary').innerHTML = `
          <p><strong>${out.exported}</strong> item(s) will be written to <code>${esc(out.filename)}</code>.</p>
          ${excluded ? `<p class="fine">Left out (not supported by this format): ${esc(excluded)}.</p>` : ''}
          ${out.notes.length ? `<ul class="warn-list">${out.notes.map((n) => `<li>${esc(n)}</li>`).join('')}</ul>` : ''}`;
        dlg.querySelector('#exp-download').disabled = out.exported === 0;
      };
      dlg.addEventListener('change', summary);
      dlg.querySelector('#exp-download').addEventListener('click', () => {
        const fmt = dlg.querySelector('input[name="fmt"]:checked').value;
        const sc = dlg.querySelector('input[name="scope"]:checked').value;
        downloadResult(exportItems(fmt, scopes()[sc]));
        toast('Export downloaded. Delete it once it has been imported.');
      });
      summary();
    },
  });
}

function openPrefs() {
  return openModal(`
    <h2>Preferences</h2>
    <form id="prefs-form" class="stack">
      <div class="two">
        <label>Theme<select name="theme">
          <option value="system">Match system</option><option value="light">Light</option><option value="dark">Dark</option>
        </select></label>
        <label>Density<select name="density">
          <option value="comfortable">Comfortable</option><option value="compact">Compact</option>
        </select></label>
      </div>
      <label class="check"><input type="checkbox" name="maskDetail"/> Hide passwords in the editor by default</label>
      <fieldset>
        <legend>Table columns</legend>
        ${Object.keys(DEFAULT_PREFS.columns).map((c) => `<label class="check"><input type="checkbox" name="col-${c}" ${prefs.columns[c] ? 'checked' : ''}/> ${c === 'url' ? 'Website' : c === 'folder' ? 'Vault / folder' : c[0].toUpperCase() + c.slice(1)}</label>`).join('')}
      </fieldset>
      <p class="fine">Only these display preferences are saved in this browser. Your items are never stored.</p>
      <div class="modal-actions"><button class="btn primary" type="button" data-action="modal-close">Done</button></div>
    </form>`, {
    onMount: (dlg) => {
      const form = dlg.querySelector('#prefs-form');
      form.elements.theme.value = prefs.theme;
      form.elements.density.value = prefs.density;
      form.elements.maskDetail.checked = prefs.maskDetail;
      form.addEventListener('change', () => {
        prefs.theme = form.elements.theme.value;
        prefs.density = form.elements.density.value;
        prefs.maskDetail = form.elements.maskDetail.checked;
        for (const c of Object.keys(DEFAULT_PREFS.columns)) prefs.columns[c] = form.elements[`col-${c}`].checked;
        savePrefs();
        applyPrefs();
        render();
      });
    },
  });
}

function applyPrefs() {
  document.documentElement.dataset.theme = prefs.theme;
  $('#app').dataset.density = prefs.density;
}

// ---------- actions ----------

function toast(message, kind = 'ok') {
  const el = document.createElement('div');
  el.className = `toast ${kind}`;
  el.textContent = message;
  $('#toasts').appendChild(el);
  setTimeout(() => el.remove(), 4500);
}

function downloadResult(out) {
  const blob = new Blob([out.content], { type: out.mime });
  const url = URL.createObjectURL(blob);
  const a = Object.assign(document.createElement('a'), { href: url, download: out.filename });
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

async function copyText(text, label) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const ta = Object.assign(document.createElement('textarea'), { value: text });
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand('copy'); } catch { /* unsupported */ }
    ta.remove();
  }
  toast(`${label} copied. The clipboard is cleared after 30 seconds.`);
  setTimeout(() => navigator.clipboard?.writeText('').catch(() => {}), 30000);
}

function openDetail(id) {
  state.openId = id;
  state.revealDetail = !prefs.maskDetail;
  render();
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

async function importFiles(files) {
  for (const file of files) {
    try {
      const parsed = await parseFile(file.name, new Uint8Array(await file.arrayBuffer()));
      if (!parsed.items.length) {
        toast(`${file.name}: no items found`, 'error');
        continue;
      }
      const choice = await askImport(parsed);
      if (!choice) continue;
      snapshot();
      const existing = new Set(state.items.map(exactKey));
      const fileHasVaults = parsed.items.some((i) => i.vault && i.vault !== DEFAULT_VAULT);
      let added = 0;
      let skipped = 0;
      for (const it of parsed.items) {
        it.vault = fileHasVaults && it.vault !== DEFAULT_VAULT ? `${choice.vault} · ${it.vault}` : choice.vault;
        // Skip only items that already exist in the vault. Duplicates inside the file itself
        // are kept, so the duplicate tools can show and merge them.
        if (choice.skipDupes && existing.has(exactKey(it))) {
          skipped++;
          continue;
        }
        ensureVault(it.vault);
        ensureFolder(it.vault, it.folder);
        state.items.push(it);
        added++;
      }
      state.started = true;
      toast(`Imported ${added} item(s) from ${file.name}${skipped ? `, skipped ${skipped} duplicate(s)` : ''}`);
      refresh();
    } catch (err) {
      toast(`${file.name}: ${err.message}`, 'error');
    }
  }
}

function newItemAction() {
  snapshot();
  const v = state.view;
  const vault = v.kind === 'vault' || v.kind === 'folder' ? v.vault : DEFAULT_VAULT;
  const folder = v.kind === 'folder' ? v.folder || '' : '';
  const it = newItem({ vault, folder });
  ensureVault(vault);
  ensureFolder(vault, folder);
  state.items.push(it);
  state.started = true;
  state.openId = it.id;
  state.revealDetail = true;
  refresh();
  $('#detail input[data-field="name"]')?.focus();
}

const ACTIONS = {
  'pick-files': () => $('#file-input').click(),
  import: () => $('#file-input').click(),
  'start-empty': () => { state.started = true; render(); },
  'new-item': newItemAction,
  undo,
  export: () => openExport('all'),
  prefs: openPrefs,
  'toggle-sidebar': () => document.body.classList.toggle('sidebar-open'),
  'modal-close': () => closeModal(null),
  'modal-ok': () => closeModal(true),

  nav(el) {
    const d = el.dataset;
    state.view = { kind: d.kind, vault: d.vault, folder: d.folder, type: d.type };
    document.body.classList.remove('sidebar-open');
    render();
  },
  select(el) {
    const id = el.dataset.id;
    if (state.selected.has(id)) state.selected.delete(id);
    else state.selected.add(id);
    render();
  },
  'select-all'() {
    const list = visibleItems();
    const all = list.length && list.every((i) => state.selected.has(i.id));
    for (const i of list) (all ? state.selected.delete(i.id) : state.selected.add(i.id));
    render();
  },
  fav(el) {
    editItem(el.dataset.id, (it) => { it.favorite = !it.favorite; });
  },
  'close-detail': () => { state.openId = null; render(); },
  reveal() {
    state.revealDetail = !state.revealDetail;
    renderDetail();
  },
  async copy(el) {
    const it = getItem(el.dataset.id);
    if (!it) return;
    const what = el.dataset.what;
    if (what === 'username') return copyText(it.username, 'Username');
    if (what === 'password') return copyText(it.password, 'Password');
    if (what === 'totp') {
      const code = await totpCode(it.totp);
      if (code) copyText(code, 'One-time code');
    }
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
  async 'delete-item'(el) {
    const it = getItem(el.dataset.id);
    if (!it) return;
    if (!(await confirmBox('Delete item?', `“${esc(displayName(it))}” will be removed. You can undo this with the Undo button.`, 'Delete'))) return;
    snapshot();
    deleteIds([it.id]);
    refresh();
  },
  'dup-item'(el) {
    const src = getItem(el.dataset.id);
    if (!src) return;
    snapshot();
    const copy = structuredClone(src);
    copy.id = newItem().id;
    copy.name = `${src.name} (copy)`;
    state.items.push(copy);
    state.openId = copy.id;
    refresh();
  },
  'show-dupes'() {
    state.view = { kind: 'dupes' };
    render();
  },
  link(el) {
    closeModal(null);
    linkAuthenticator(el.dataset.source, el.dataset.id);
  },
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
    const ok = await confirmBox(
      `Delete vault “${vault}”?`,
      count ? `Its ${count} item(s) will move to “${DEFAULT_VAULT}”.` : 'The empty vault will be removed.',
      'Delete vault',
    );
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
    if (!(await confirmBox(`Delete ${ids.length} item(s)?`, 'You can undo this with the Undo button.', 'Delete'))) return;
    snapshot();
    deleteIds(ids);
    refresh();
  },

  // duplicates
  'dupes-merge-exact'() {
    snapshot();
    for (const group of analyse(state.items).dupes.exact) mergeIds(group);
    refresh();
    toast('Exact duplicates merged');
  },
  async 'dupes-keep-newest'() {
    const groups = analyse(state.items).dupes.exact;
    const remove = groups.flatMap((g) => g.filter((id) => id !== newestId(g.map((x) => getItem(x)))));
    if (!(await confirmBox('Keep newest only?', `${remove.length} older duplicate(s) will be deleted. Undo can bring them back.`, 'Delete duplicates'))) return;
    snapshot();
    deleteIds(remove);
    refresh();
  },
  'dupes-merge-conflicts'() {
    snapshot();
    for (let guard = 0; guard < 500; guard++) {
      const group = analyse(state.items).dupes.conflicts[0];
      if (!group) break;
      mergeIds(group);
    }
    refresh();
    toast('Conflicting logins merged. Other passwords are kept as alternates.');
  },
};

function openLinkDialog(sourceId) {
  const src = getItem(sourceId);
  if (!src) return;
  const options = suggestTotpTargets(src, state.items).slice(0, 25);
  openModal(`
    <h2>Link authenticator</h2>
    <p class="lede">Choose the login that <strong>${esc(displayName(src))}</strong> belongs to. The code moves onto that login and the standalone item is removed.</p>
    <div class="suggest-list stacked">
      ${options.length ? options.map((s) => `<button class="btn" data-action="link" data-id="${s.item.id}" data-source="${sourceId}">${esc(displayName(s.item))} <small>${esc(s.item.username)}</small></button>`).join('') : '<p class="fine">Every login already has a one-time code.</p>'}
    </div>
    <div class="modal-actions"><button class="btn ghost" data-action="modal-close">Cancel</button></div>`);
}

// ---------- event wiring ----------

document.addEventListener('click', (e) => {
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
  if (e.key === 'Enter' && e.target.matches?.('.dropzone')) $('#file-input').click();
  const typing = /INPUT|TEXTAREA|SELECT/.test(document.activeElement?.tagName || '');
  if (e.key === 'Escape' && !$('#modal').open && state.openId) {
    state.openId = null;
    render();
    return;
  }
  if (typing || $('#modal').open) return;
  const mod = e.ctrlKey || e.metaKey;
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
  }
});

document.addEventListener('change', (e) => {
  const el = e.target;
  if (el.id === 'sort') {
    prefs.sort = el.value;
    savePrefs();
    renderWorkspace();
    return;
  }
  if (el.dataset.field && state.openId) applyFieldChange(el);
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
  renderWorkspace();
});

$('#file-input').addEventListener('change', (e) => {
  const files = [...e.target.files];
  e.target.value = '';
  if (files.length) importFiles(files);
});

// Drag and drop anywhere on the page.
let dragDepth = 0;
window.addEventListener('dragenter', (e) => {
  e.preventDefault();
  dragDepth++;
  document.body.classList.add('dragging');
});
window.addEventListener('dragleave', () => {
  dragDepth = Math.max(0, dragDepth - 1);
  if (!dragDepth) document.body.classList.remove('dragging');
});
window.addEventListener('dragover', (e) => e.preventDefault());
window.addEventListener('drop', (e) => {
  e.preventDefault();
  dragDepth = 0;
  document.body.classList.remove('dragging');
  const files = [...(e.dataTransfer?.files || [])];
  if (files.length) importFiles(files);
});

// Warn before leaving when there is data that only exists in this page.
window.addEventListener('beforeunload', (e) => {
  if (state.items.length) {
    e.preventDefault();
    e.returnValue = '';
  }
});

applyPrefs();
render();
setInterval(updateTotp, 1000);
updateTotp();

// Rendering. Every function reads from shared state and writes HTML into the page.
// Event handling lives in app.js (data-action attributes), so this file has no listeners.

import { displayName, folderPath, vaultOf, DEFAULT_VAULT, TYPE_LABEL, TYPE_GLYPH, hostOf } from './model.js';
import { state, prefs, getItem, liveItems, trashedItems, allVaults, foldersOf, visibleItems } from './state.js';
import { suggestTotpTargets, passwordStrength } from './analysis.js';
import { totpCode, secondsLeft, parseTotpInput, isValidTotp } from './totp.js';
import { FORMATS } from './exporters.js';
import { $, esc, fmtDate, fmtSize } from './ui/dom.js';
import { icon } from './ui/icons.js';
import { canUseFileHandles } from './ui/fileio.js';

const IMPORT_LABELS = [
  'KeePass .kdbx (open directly)', 'Bitwarden (JSON, CSV, encrypted JSON)', '1Password (1PUX, 1PIF, CSV)', 'Proton Pass (CSV)',
  'Dashlane (CSV, JSON)', 'LastPass (CSV)', 'KeePass 2 (XML, CSV)', 'KeePassXC (CSV)', 'Enpass (JSON, CSV)',
  'Monica (generic JSON or CSV)', 'Apple Passwords (CSV)', 'Chrome, Edge, Google (CSV)', 'Firefox (CSV)', 'Any CSV with a header row',
];

export function renderAll() {
  renderChrome();
  if (state.locked || !(state.items.length || state.started)) {
    // Nothing sensitive may stay in the page while locked or empty.
    for (const id of ['#rows', '#thead', '#detail', '#sidebar', '#banner', '#counts', '#bulk']) { const el = $(id); if (el) el.innerHTML = ''; }
    const q = $('#search'); if (q) q.value = '';
    $('#detail').hidden = true;
  }
  if (state.locked) return;
  if (!(state.items.length || state.started)) return;
  renderSidebar();
  renderWorkspace();
  renderDetail();
}

// ---------- page chrome ----------

function renderChrome() {
  const has = state.items.length > 0 || state.started || !!state.kdbx;
  const locked = state.locked;
  $('#welcome').hidden = has;
  $('#lock').hidden = !locked;
  $('#workspace').hidden = !has || locked;
  $('#sidebar').hidden = !has || locked;
  $('#layout').classList.toggle('has-detail', has && !locked && !!state.openId && !!getItem(state.openId));
  $('#btn-undo').disabled = state.history.length === 0 || locked;
  $('#sort').value = prefs.sort;
  document.body.classList.toggle('is-locked', locked);
  renderDbBar();
  if (!has) renderWelcome();
  if (locked) renderLock();
}

function renderDbBar() {
  const el = $('#dbbar');
  const s = state.kdbx;
  if (!s) {
    el.hidden = true;
    el.innerHTML = '';
    return;
  }
  el.hidden = false;
  const dirty = !state.locked && s.dirty;
  el.innerHTML = `
    <button class="dbchip" data-action="${state.locked ? 'db-unlock' : 'db-menu'}" title="${state.locked ? 'Unlock' : 'Database settings'}">
      ${icon(state.locked ? 'lock' : 'unlock')}<span class="dbname">${esc(s.fileName)}</span>${dirty || s.pendingLocked ? '<span class="dirty" title="Unsaved changes">●</span>' : ''}
    </button>
    ${state.locked ? '' : `
      <button class="btn sm ${dirty ? 'primary' : ''}" data-action="db-save" title="Save (Ctrl+S)">Save</button>
      <button class="btn sm" data-action="db-lock" title="Lock now (Ctrl+L)">Lock</button>`}`;
}

function renderLock() {
  const s = state.kdbx;
  $('#lock').innerHTML = `
    <div class="lock-card">
      <div class="lock-icon">${icon('lock', 28)}</div>
      <h2>Database locked</h2>
      <p class="lede">${esc(s.fileName)}</p>
      ${s.pendingLocked ? '<p class="fine">Your unsaved changes are kept, encrypted, and come back when you unlock.</p>' : ''}
      <div class="modal-actions center">
        <button class="btn primary" data-action="db-unlock">Unlock</button>
        <button class="btn ghost" data-action="db-close">Close database</button>
      </div>
    </div>`;
}

function renderWelcome() {
  const inPlace = canUseFileHandles();
  $('#welcome').innerHTML = `
    <div class="hero">
      <p class="eyebrow">Private · offline · no account</p>
      <h1>Your KeePass vault in the browser, and a converter for everything else.</h1>
      <p class="lede">Open a KeePass database and use it like a password manager. Or load an export from any other manager,
        tidy it up, and convert it. Everything happens in this page. Nothing is uploaded, and the page makes no network requests.</p>
      <div class="cards">
        <button class="card primary" data-action="db-open">
          <span class="card-ico">${icon('db', 22)}</span>
          <strong>Open a KeePass database</strong>
          <span>.kdbx with a password and/or key file. ${inPlace ? 'Saves back to the same file.' : 'This browser can’t save in place, so Save downloads the file.'}</span>
        </button>
        <button class="card" data-action="db-new">
          <span class="card-ico">${icon('plus', 22)}</span>
          <strong>Create a new database</strong>
          <span>A standard KDBX 4 file that other KeePass apps can open.</span>
        </button>
        <button class="card" data-action="pick-files">
          <span class="card-ico">${icon('import', 22)}</span>
          <strong>Import or convert a file</strong>
          <span>Bitwarden, 1Password, Proton Pass, Dashlane, LastPass, Enpass and more.</span>
        </button>
      </div>
      <div class="dropzone" data-action="pick-files" role="button" tabindex="0">
        <strong>…or drop files here</strong>
        <span>CSV, JSON, XML, 1PUX, 1PIF, KDBX. You can load several files.</span>
      </div>
      <h3>Recognised formats</h3>
      <ul class="format-chips">${IMPORT_LABELS.map((l) => `<li>${esc(l)}</li>`).join('')}</ul>
      <p class="fine">Export formats: ${FORMATS.map((f) => esc(f.label)).join(', ')}.</p>
      <p class="fine">Account-restricted Bitwarden exports and KeePass databases without their password or key file can’t be opened here.
        Delete any unencrypted export file once you’re done with it.</p>
    </div>`;
}

// ---------- sidebar ----------

function renderSidebar() {
  const a = state.analysis;
  const live = liveItems();
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
  const types = ['login', 'note', 'card', 'identity'].filter((t) => live.some((i) => i.type === t));
  const trashed = trashedItems().length;
  $('#sidebar').innerHTML = `
    <section>
      <h4>Library</h4>
      ${nav('all', 'All items', live.length)}
      ${nav('fav', 'Favourites', live.filter((i) => i.favorite).length)}
      ${nav('attention', 'Needs attention', live.filter((i) => (a.flags.get(i.id) || []).length).length)}
      ${nav('dupes', 'Duplicates & conflicts', a.dupeIds.size + a.conflictIds.size)}
      ${nav('totp', 'Authenticator only', a.totpOnly.size)}
      ${state.kdbx || trashed ? nav('trash', 'Recycle bin', trashed) : ''}
    </section>
    ${types.length ? `<section><h4>Item types</h4>
      ${types.map((t) => nav('type', TYPE_LABEL[t] + 's', live.filter((i) => i.type === t).length, { type: t })).join('')}
    </section>` : ''}
    <section>
      <h4>Vaults</h4>
      ${allVaults().map((v) => {
        const count = live.filter((i) => vaultOf(i) === v).length;
        return `<div class="nav-group">
          <div class="nav-row">
            ${nav('vault', v, count, { vault: v })}
            <span class="mini">
              <button data-action="new-folder" data-vault="${esc(v)}" title="New folder in ${esc(v)}" aria-label="New folder">+</button>
              <button data-action="rename-vault" data-vault="${esc(v)}" title="Rename vault" aria-label="Rename vault">✎</button>
              <button data-action="delete-vault" data-vault="${esc(v)}" title="Delete vault (items move to ${DEFAULT_VAULT})" aria-label="Delete vault">✕</button>
            </span>
          </div>
          ${foldersOf(v).map((f) => nav('folder', f, live.filter((i) => vaultOf(i) === v && i.folder === f).length, { vault: v, folder: f }, 1)).join('')}
        </div>`;
      }).join('')}
      <div class="sidebar-add"><button class="btn sm ghost" data-action="new-vault">+ New vault</button></div>
    </section>`;
}

// ---------- item table ----------

function renderWorkspace() {
  const list = visibleItems();
  const a = state.analysis;
  const cols = prefs.columns;
  const colCount = 3 + ['username', 'url', 'folder', 'flags', 'updated', 'quick'].filter((c) => cols[c]).length;

  $('#banner').innerHTML = state.view.kind === 'dupes' ? dupeBanner() : state.view.kind === 'trash' ? trashBanner() : saveHint();
  $('#counts').innerHTML = `<strong>${list.length}</strong> of ${state.view.kind === 'trash' ? trashedItems().length : liveItems().length} items`
    + (state.selected.size ? ` · <span class="sel">${state.selected.size} selected</span>` : '');
  const bulk = $('#bulk');
  bulk.hidden = state.selected.size === 0;
  bulk.innerHTML = state.selected.size ? bulkBar() : '';

  $('#thead').innerHTML = `<tr>${[
    `<th class="c-check"><input type="checkbox" data-action="select-all" aria-label="Select all visible" ${list.length && list.every((i) => state.selected.has(i.id)) ? 'checked' : ''}/></th>`,
    '<th class="c-fav" aria-label="Favourite"></th>',
    '<th class="c-name">Name</th>',
    cols.username ? '<th>Username</th>' : '',
    cols.url ? '<th>Website</th>' : '',
    cols.folder ? '<th>Vault / folder</th>' : '',
    cols.flags ? '<th>Checks</th>' : '',
    cols.updated ? '<th>Updated</th>' : '',
    cols.quick ? '<th class="c-quick" aria-label="Quick copy"></th>' : '',
  ].join('')}</tr>`;

  $('#rows').innerHTML = list.length
    ? list.map((it) => rowHtml(it, a, cols)).join('')
    : `<tr><td colspan="${colCount}" class="empty">${state.query ? 'Nothing matches your search.' : state.view.kind === 'trash' ? 'The recycle bin is empty.' : 'Nothing here yet. Use Import, or add an item with + New.'}</td></tr>`;
}

function quickButtons(it) {
  const b = (action, what, ico, tip) => `<button class="qbtn" data-action="${action}" data-what="${what}" data-id="${it.id}" title="${tip}" aria-label="${tip}">${icon(ico, 15)}</button>`;
  return [
    it.username ? b('copy', 'username', 'user', 'Copy username') : '',
    it.password ? b('copy', 'password', 'key', 'Copy password') : '',
    it.totp ? b('copy', 'totp', 'clock', 'Copy one-time code') : '',
    it.type === 'login' && (it.password || it.username) ? b('fill', '', 'bolt', 'Copy fill data for the bookmark') : '',
  ].join('');
}

function rowHtml(it, a, cols) {
  const flags = a.flags.get(it.id) || [];
  const sel = state.selected.has(it.id);
  const url = it.urls[0] || '';
  return `<tr data-row="${it.id}" class="${sel ? 'selected' : ''}${state.openId === it.id ? ' open' : ''}">${[
    `<td class="c-check"><input type="checkbox" data-action="select" data-id="${it.id}" ${sel ? 'checked' : ''} aria-label="Select ${esc(displayName(it))}"/></td>`,
    `<td class="c-fav"><button class="star${it.favorite ? ' on' : ''}" data-action="fav" data-id="${it.id}" aria-label="Toggle favourite">★</button></td>`,
    `<td class="c-name"><div class="name">
        <span class="glyph" title="${esc(TYPE_LABEL[it.type])}">${TYPE_GLYPH[it.type]}</span>
        <div><strong>${esc(displayName(it))}</strong>
          <small>${esc(TYPE_LABEL[it.type])}${it.tags.length ? ' · ' + esc(it.tags.join(', ')) : ''}${(it.attachments || []).length ? ' · ' + (it.attachments.length) + ' file(s)' : ''}</small></div>
      </div></td>`,
    cols.username ? `<td class="c-user">${esc(it.username)}</td>` : '',
    cols.url ? `<td class="c-url">${esc(hostOf(url) || url)}${it.urls.length > 1 ? ` <small>+${it.urls.length - 1}</small>` : ''}</td>` : '',
    cols.folder ? `<td class="c-folder">${esc(folderPath(it))}</td>` : '',
    cols.flags ? `<td class="c-flags">${flags.slice(0, 2).map((f) => `<span class="chip ${f.level}" title="${esc(f.hint)}">${esc(f.label)}</span>`).join('')}${flags.length > 2 ? `<span class="chip">+${flags.length - 2}</span>` : ''}</td>` : '',
    cols.updated ? `<td class="c-date">${esc(it.updatedAt ? new Date(it.updatedAt).toLocaleDateString() : '—')}</td>` : '',
    cols.quick ? `<td class="c-quick"><div class="quick">${quickButtons(it)}</div></td>` : '',
  ].join('')}</tr>`;
}

function bulkBar() {
  const ids = [...state.selected];
  const hasAuth = ids.some((id) => state.analysis.totpOnly.has(id));
  const trashView = state.view.kind === 'trash';
  return trashView
    ? `<button class="btn sm" data-action="bulk-restore">Restore</button>
       <button class="btn sm danger" data-action="bulk-delete">Delete permanently</button>
       <button class="btn sm ghost" data-action="bulk-clear">Clear</button>`
    : `<button class="btn sm" data-action="bulk-fav">Favourite</button>
       <button class="btn sm" data-action="bulk-move">Move to vault…</button>
       <button class="btn sm" data-action="bulk-merge" ${ids.length < 2 ? 'disabled' : ''}>Merge</button>
       <button class="btn sm" data-action="bulk-link" ${hasAuth ? '' : 'disabled'}>Link authenticator…</button>
       <button class="btn sm" data-action="bulk-export">Export selection</button>
       <button class="btn sm danger" data-action="bulk-delete">${state.kdbx ? 'Move to recycle bin' : 'Delete'}</button>
       <button class="btn sm ghost" data-action="bulk-clear">Clear</button>`;
}

function saveHint() {
  const s = state.kdbx;
  if (!s || state.locked || s.handle || !s.dirty) return '';
  return `<div class="banner info"><div>This database isn’t saved yet. ${canUseFileHandles() ? 'Click <strong>Save</strong> to choose where to keep it.' : 'Click <strong>Save</strong> to download it. This browser can’t save in place.'}</div></div>`;
}

function trashBanner() {
  return `<div class="banner warn"><div>Items in the recycle bin stay in the database until you delete them permanently.</div>
    <div class="banner-actions"><button class="btn sm danger" data-action="empty-trash" ${trashedItems().length ? '' : 'disabled'}>Empty recycle bin</button></div></div>`;
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
    </div></div>`;
}

// ---------- detail panel ----------

export function renderDetail() {
  const el = $('#detail');
  const it = state.openId ? getItem(state.openId) : null;
  el.hidden = !it;
  if (!it) {
    el.innerHTML = '';
    return;
  }
  const editing = state.editMode && !it.trashed;
  el.innerHTML = `${detailHeader(it, editing)}${flagsBlock(it)}${editing ? detailEdit(it) : detailView(it)}${editing ? detailFooter(it) : ''}`;
  updateTotp();
}

function detailHeader(it, editing) {
  return `
    <header class="detail-head">
      <div class="detail-title">
        <span class="glyph big">${TYPE_GLYPH[it.type]}</span>
        <div><strong>${esc(displayName(it))}</strong><small>${esc(TYPE_LABEL[it.type])} · ${esc(folderPath(it))}</small></div>
      </div>
      <button class="btn sm ghost" data-action="close-detail" aria-label="Close">✕</button>
    </header>
    <div class="detail-actions">
      ${it.trashed ? `
        <button class="btn sm" data-action="restore-item" data-id="${it.id}">${icon('restore')} Restore</button>
        <button class="btn sm danger" data-action="delete-item" data-id="${it.id}">${icon('trash')} Delete permanently</button>`
    : editing ? `<button class="btn sm primary" data-action="edit-done">${icon('check')} Done</button>`
      : `<button class="btn sm" data-action="edit-start">${icon('edit')} Edit</button>
         ${it.type === 'login' && (it.password || it.username) ? `<button class="btn sm" data-action="fill" data-id="${it.id}" title="Copy fill data for the Vault Fill bookmark">${icon('bolt')} Fill</button>` : ''}
         <button class="btn sm" data-action="copy-all" data-id="${it.id}" title="Copy every field as text">${icon('copy')} Copy all</button>
         <button class="star${it.favorite ? ' on' : ''}" data-action="fav" data-id="${it.id}" aria-label="Toggle favourite">★</button>`}
    </div>`;
}

function flagsBlock(it) {
  const flags = state.analysis.flags.get(it.id) || [];
  if (!flags.length) return '';
  const action = (f) => {
    switch (f.code) {
      case 'no-password': return `<button class="btn sm" data-action="gen" data-id="${it.id}">Generate password</button>`;
      case 'duplicate':
      case 'conflict': return '<button class="btn sm" data-action="show-dupes">Review</button>';
      case 'weak':
      case 'reused':
      case 'old': return `<button class="btn sm" data-action="gen" data-id="${it.id}">Replace with generated</button>`;
      default: return '';
    }
  };
  return `<div class="flag-list">${flags.map((f) => `
    <div class="flag ${f.level}"><div><strong>${esc(f.label)}</strong><span>${esc(f.hint)}</span></div>${action(f)}</div>`).join('')}</div>`;
}

/** One clickable row. Clicking anywhere on it copies the value. */
function vrow({ label, field, index, text, secret = false, mono = false, multi = false, extra = '', live = '' }) {
  const shown = secret && !state.revealDetail ? '••••••••••' : text;
  return `<div class="vrow${multi ? ' multi' : ''}" role="button" tabindex="0" data-action="copy-field" data-field="${field}"${index !== undefined ? ` data-index="${index}"` : ''} title="Click to copy">
    <span class="vlabel">${esc(label)}</span>
    <span class="vvalue${mono ? ' mono' : ''}">${live || esc(shown)}</span>
    <span class="vactions">${extra}<span class="copy-ico">${icon('copy', 15)}</span></span>
  </div>`;
}

function detailView(it) {
  const rows = [];
  if (it.username) rows.push(vrow({ label: 'Username', field: 'username', text: it.username }));
  if (it.password) {
    rows.push(vrow({
      label: 'Password', field: 'password', text: it.password, secret: true, mono: true,
      extra: `<button class="ibtn" data-action="reveal" aria-label="${state.revealDetail ? 'Hide' : 'Show'} secrets" title="${state.revealDetail ? 'Hide' : 'Show'}">${icon(state.revealDetail ? 'eyeoff' : 'eye', 15)}</button>`,
    }));
  }
  if (it.totp) {
    rows.push(isValidTotp(it.totp)
      ? vrow({
        label: 'One-time code', field: 'totp', text: '', mono: true,
        live: '<span class="totp-code" id="totp-code" data-secret="' + esc(it.totp) + '">… …</span><small id="totp-left"></small><span class="totp-bar"><span id="totp-bar"></span></span>',
      })
      : '<div class="vrow bad"><span class="vlabel">One-time code</span><span class="vvalue">Invalid secret. Edit it to fix.</span></div>');
  }
  it.urls.forEach((u, i) => rows.push(vrow({
    label: it.urls.length > 1 ? `Website ${i + 1}` : 'Website', field: 'url', index: i, text: u,
    extra: /^https?:\/\//i.test(u) ? `<a class="ibtn" href="${esc(u)}" target="_blank" rel="noopener noreferrer" data-stop="1" aria-label="Open website" title="Open in a new tab">${icon('link', 15)}</a>` : '',
  })));
  if (it.notes) rows.push(vrow({ label: 'Notes', field: 'notes', text: it.notes, multi: true }));
  it.customFields.forEach((f, i) => rows.push(vrow({ label: f.name || 'Field', field: 'custom', index: i, text: f.value, secret: f.hidden, mono: f.hidden })));
  if (it.tags.length) rows.push(vrow({ label: 'Tags', field: 'tags', text: it.tags.join(', ') }));
  rows.push(vrow({ label: 'Location', field: 'location', text: folderPath(it) }));

  const files = (it.attachments || []).map((a) => `
    <div class="vrow" role="button" tabindex="0" data-action="dl-att" data-id="${esc(a.id)}" title="Click to download">
      <span class="vlabel">${icon('clip', 14)} File</span><span class="vvalue">${esc(a.name)} <small>${fmtSize(a.size)}</small></span>
      <span class="vactions">${icon('download', 15)}</span></div>`).join('');

  const hist = (it.pwHistory || []).length ? `
    <details class="hist"><summary>Password history (${it.pwHistory.length})</summary>
      ${it.pwHistory.map((h, i) => vrow({ label: h.time ? fmtDate(h.time) : 'Older', field: 'pwhist', index: i, text: h.password, secret: true, mono: true })).join('')}
    </details>` : '';

  const empty = !(it.username || it.password || it.totp || it.urls.length || it.notes || it.customFields.length);
  return `<div class="view">
    ${empty ? '<p class="fine pad">Nothing saved on this item yet. Click Edit to add details.</p>' : ''}
    ${rows.join('')}${files}${hist}
    <div class="view-meta">
      ${vrow({ label: 'Created', field: 'created', text: fmtDate(it.createdAt) })}
      ${vrow({ label: 'Updated', field: 'updated', text: fmtDate(it.updatedAt) })}
      <p class="meta">Source: ${esc(it.source)}</p>
    </div></div>`;
}

function detailEdit(it) {
  const mask = !state.revealDetail;
  const isLogin = it.type === 'login';
  const suggestions = state.analysis.totpOnly.has(it.id) ? suggestTotpTargets(it, state.items.filter((i) => !i.trashed)).slice(0, 6) : [];
  return `
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
        <label>Username<input data-field="username" value="${esc(it.username)}" /></label>
        <label>Password
          <div class="with-btn">
            <input data-field="password" type="${mask ? 'password' : 'text'}" value="${esc(it.password)}" />
            <button type="button" class="btn sm" data-action="reveal">${mask ? 'Show' : 'Hide'}</button>
            <button type="button" class="btn sm" data-action="gen" data-id="${it.id}">Generate</button>
          </div>
          <div class="strength s${passwordStrength(it.password)}" aria-label="Password strength"><span></span></div>
        </label>
        <label>Website(s), one per line<textarea data-field="urls" rows="2">${esc(it.urls.join('\n'))}</textarea></label>
        <label>One-time code<input data-field="totp" value="${esc(it.totp)}" placeholder="Base32 secret or otpauth:// link" /></label>
        ${it.totp ? totpBlock(it) : ''}` : ''}
      ${suggestions.length ? `<div class="suggest"><strong>Link this authenticator to a login</strong>
        <div class="suggest-list">${suggestions.map((s) => `<button type="button" class="btn sm" data-action="link" data-id="${s.item.id}" data-source="${it.id}">${esc(displayName(s.item))}${s.item.username ? ` <small>${esc(s.item.username)}</small>` : ''}</button>`).join('')}</div></div>` : ''}
      <label>Notes<textarea data-field="notes" rows="4">${esc(it.notes)}</textarea></label>
      <div class="cf">
        <div class="cf-head"><strong>Custom fields</strong><button type="button" class="btn sm" data-action="cf-add" data-id="${it.id}">+ Add field</button></div>
        ${it.customFields.map((f, i) => `
          <div class="cf-row">
            <input data-field="cf-name" data-index="${i}" value="${esc(f.name)}" aria-label="Field name" />
            <input data-field="cf-value" data-index="${i}" value="${esc(f.value)}" type="${f.hidden && mask ? 'password' : 'text'}" aria-label="Field value" />
            <button type="button" class="btn sm${f.hidden ? ' on' : ''}" data-action="cf-hide" data-index="${i}" title="Hide value" aria-pressed="${!!f.hidden}">●</button>
            <button type="button" class="btn sm danger" data-action="cf-del" data-index="${i}" aria-label="Remove field">✕</button>
          </div>`).join('') || '<p class="fine">No custom fields.</p>'}
      </div>
      <div class="cf">
        <div class="cf-head"><strong>Attachments</strong><button type="button" class="btn sm" data-action="att-add">+ Attach file</button></div>
        ${(it.attachments || []).map((a) => `
          <div class="att-row"><span>${icon('clip', 14)} ${esc(a.name)} <small>${fmtSize(a.size)}</small></span>
            <span><button type="button" class="btn sm" data-action="dl-att" data-id="${esc(a.id)}">Download</button>
            <button type="button" class="btn sm danger" data-action="att-del" data-id="${esc(a.id)}" aria-label="Remove attachment">✕</button></span></div>`).join('') || '<p class="fine">No attachments.</p>'}
      </div>
      <label>Tags<input data-field="tags" value="${esc(it.tags.join(', '))}" placeholder="Comma separated" /></label>
      <p class="meta">Created ${fmtDate(it.createdAt)} · Updated ${fmtDate(it.updatedAt)}<br/>Source: ${esc(it.source)}</p>
    </form>`;
}

function detailFooter(it) {
  return `<footer class="detail-foot">
      <button class="btn" data-action="dup-item" data-id="${it.id}">Duplicate</button>
      <button class="btn danger" data-action="delete-item" data-id="${it.id}">${state.kdbx ? 'Move to recycle bin' : 'Delete'}</button>
    </footer>`;
}

function totpBlock(it) {
  if (!isValidTotp(it.totp)) return '<div class="totp invalid">This secret is not valid base32. Re-copy it from the site’s authenticator setup.</div>';
  return `<div class="totp"><div><span class="totp-code" id="totp-code" data-secret="${esc(it.totp)}">… …</span><small id="totp-left"></small></div>
    <div class="totp-bar"><span id="totp-bar"></span></div></div>`;
}

/** Called every second to keep the live one-time code fresh. */
export async function updateTotp() {
  const el = document.getElementById('totp-code');
  if (!el) return;
  const period = parseTotpInput(el.dataset.secret)?.period || 30;
  const code = await totpCode(el.dataset.secret);
  const left = secondsLeft(period);
  el.textContent = code ? `${code.slice(0, code.length / 2)} ${code.slice(code.length / 2)}` : '—';
  const l = document.getElementById('totp-left');
  const b = document.getElementById('totp-bar');
  if (l) l.textContent = `${left}s`;
  if (b) b.style.width = `${(left / period) * 100}%`;
}

// ---------- fill assistant (rendered into a separate floating window) ----------

export function assistHtml(items, query, status = '') {
  const rows = items.map((it) => `
    <div class="arow">
      <div class="ainfo"><strong>${esc(displayName(it))}</strong><small>${esc(it.username || hostOf(it.urls[0]) || '')}</small></div>
      <div class="abtns">
        ${it.username ? `<button class="qbtn lbl" data-assist="username" data-id="${it.id}" title="Copy username">${icon('user', 14)} User</button>` : ''}
        ${it.password ? `<button class="qbtn lbl" data-assist="password" data-id="${it.id}" title="Copy password">${icon('key', 14)} Pass</button>` : ''}
        ${it.totp ? `<button class="qbtn lbl" data-assist="totp" data-id="${it.id}" title="Copy one-time code">${icon('clock', 14)} Code</button>` : ''}
        ${it.password || it.username ? `<button class="qbtn lbl" data-assist="fill" data-id="${it.id}" title="Copy fill data for the bookmark">${icon('bolt', 14)} Fill</button>` : ''}
      </div>
    </div>`).join('');
  return `
    <div class="assist-head"><strong>Vault Fill assistant</strong><small>Click a button, then paste into the page</small></div>
    <input id="assist-q" type="search" placeholder="Type a site or name…" value="${esc(query)}" autocomplete="off" />
    <div class="assist-status" role="status">${esc(status)}</div>
    <div class="assist-list">${rows || '<p class="fine pad">No matching logins.</p>'}</div>`;
}

export { hostOf };

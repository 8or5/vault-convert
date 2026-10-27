// Modal dialogs. One <dialog id="modal"> is reused; each helper returns a promise.

import { $, esc } from './dom.js';
import { KDF_PRESETS, KDF_TYPES } from '../kdbx.js';
import { passwordStrength } from '../analysis.js';

let resolver = null;

export function openModal(html, { onMount, wide = false } = {}) {
  return new Promise((resolve) => {
    const dlg = $('#modal');
    // A previous dialog may still be open or have a pending close event. Detach it first so
    // that event can never resolve this new dialog.
    dlg.onclose = null;
    if (dlg.open) dlg.close();
    dlg.className = `modal${wide ? ' wide' : ''}`;
    dlg.innerHTML = `<div class="modal-inner">${html}</div>`;
    resolver = resolve;
    dlg.onclose = () => {
      // The close event is dispatched asynchronously. If a newer dialog is already showing, this event belongs to the old one.
      if (dlg.open) return;
      const r = resolver;
      resolver = null;
      r?.(null);
    };
    dlg.showModal();
    onMount?.(dlg);
  });
}

export function closeModal(value) {
  const r = resolver;
  resolver = null;
  const dlg = $('#modal');
  dlg.onclose = null;
  if (dlg.open) dlg.close();
  r?.(value);
}

export const isModalOpen = () => $('#modal').open;

export function promptText(title, value = '', label = 'Name') {
  return openModal(`
    <h2>${esc(title)}</h2>
    <form id="prompt-form" class="stack">
      <label>${esc(label)}<input id="prompt-input" value="${esc(value)}" autocomplete="off" /></label>
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

export async function confirmBox(title, body, okLabel = 'Confirm', { danger = true } = {}) {
  const r = await openModal(`
    <h2>${esc(title)}</h2>
    <p>${body}</p>
    <div class="modal-actions">
      <button class="btn ghost" data-action="modal-close">Cancel</button>
      <button class="btn ${danger ? 'danger' : 'primary'}" data-action="modal-ok">${esc(okLabel)}</button>
    </div>`);
  return r === true;
}

/** Offers several buttons. Returns the chosen value, or null if dismissed. */
export function chooseBox(title, body, choices) {
  return openModal(`
    <h2>${esc(title)}</h2>
    <p>${body}</p>
    <div class="modal-actions">
      <button class="btn ghost" data-action="modal-close">Cancel</button>
      ${choices.map((c) => `<button class="btn ${c.primary ? 'primary' : ''}" data-action="modal-choose" data-value="${esc(c.value)}">${esc(c.label)}</button>`).join('')}
    </div>`);
}

const readBytes = async (file) => (file ? new Uint8Array(await file.arrayBuffer()) : null);

/**
 * Asks for a password (and optionally a key file or KDF settings), then runs `run(values)`
 * with the dialog still open. If `run` throws, the message is shown inline and the user can
 * retry, so a wrong password never loses the file they were opening.
 *
 * keyFile: 'none' | 'optional' (choose a file) | 'create' (checkbox: make and download a new one)
 * Resolves to run()'s result, or null if cancelled.
 */
export function credentialsDialog({
  title, intro = '', submitLabel = 'Continue', confirm = false, keyFile = 'none', kdf = false,
  nameLabel = '', nameValue = '', kdfTypes = true, allowEmptyPassword = false, run,
}) {
  const presetOptions = Object.entries(KDF_PRESETS).map(([k, p]) => `<option value="${k}" ${k === 'standard' ? 'selected' : ''}>${esc(p.label)}</option>`).join('');
  const typeOptions = Object.entries(KDF_TYPES).map(([k, l]) => `<option value="${k}">${esc(l)}</option>`).join('');
  return openModal(`
    <h2>${esc(title)}</h2>
    ${intro ? `<p class="lede">${intro}</p>` : ''}
    <form id="cred-form" class="stack" autocomplete="off">
      ${nameLabel ? `<label>${esc(nameLabel)}<input name="name" value="${esc(nameValue)}" autocomplete="off" /></label>` : ''}
      <label>Password
        <div class="with-btn">
          <input name="password" type="password" autocomplete="off" autocapitalize="off" spellcheck="false" />
          <button type="button" class="btn sm" data-action="cred-toggle">Show</button>
        </div>
        ${confirm ? '<div class="strength" id="cred-strength" aria-hidden="true"><span></span></div>' : ''}
      </label>
      ${confirm ? '<label>Repeat password<input name="confirm" type="password" autocomplete="off" autocapitalize="off" spellcheck="false" /></label>' : ''}
      ${keyFile === 'optional' ? '<label>Key file <small>(only if this database uses one)</small><input name="keyfile" type="file" /></label>' : ''}
      ${keyFile === 'create' ? '<label class="check"><input type="checkbox" name="makekey" /> Also require a key file. A new one is created and downloaded. Keep it safe: without it the database cannot be opened.</label>' : ''}
      ${kdf ? `
        <div class="two">
          ${kdfTypes ? `<label>Key derivation<select name="kdf">${typeOptions}</select></label>` : ''}
          <label>Strength<select name="preset">${presetOptions}</select></label>
        </div>
        <p class="fine">A stronger setting makes password guessing slower for an attacker. It also makes opening and saving take longer on your devices.</p>` : ''}
      <p class="form-error" role="alert" hidden></p>
      <div class="modal-actions">
        <button type="button" class="btn ghost" data-action="modal-close">Cancel</button>
        <button class="btn primary" type="submit">${esc(submitLabel)}</button>
      </div>
    </form>`, {
    onMount: (dlg) => {
      const form = dlg.querySelector('#cred-form');
      const err = dlg.querySelector('.form-error');
      const submit = form.querySelector('button[type=submit]');
      const pw = form.elements.password;
      pw.focus();
      form.elements.name?.select?.();
      if (confirm) {
        pw.addEventListener('input', () => {
          dlg.querySelector('#cred-strength').className = `strength s${passwordStrength(pw.value)}`;
        });
      }
      dlg.querySelector('[data-action=cred-toggle]').addEventListener('click', (e) => {
        const show = pw.type === 'password';
        for (const el of [pw, form.elements.confirm]) if (el) el.type = show ? 'text' : 'password';
        e.currentTarget.textContent = show ? 'Hide' : 'Show';
      });
      const fail = (msg) => {
        err.textContent = msg;
        err.hidden = false;
      };
      form.addEventListener('submit', async (e) => {
        e.preventDefault();
        err.hidden = true;
        if (!pw.value && !allowEmptyPassword && !(form.elements.keyfile && form.elements.keyfile.files[0])) {
          return fail(keyFile === 'optional' ? 'Enter the password, or choose a key file.' : 'Enter a password.');
        }
        if (confirm && pw.value !== form.elements.confirm.value) return fail('The two passwords do not match.');
        const label = submit.textContent;
        submit.disabled = true;
        submit.textContent = 'Working…';
        try {
          const values = {
            password: pw.value,
            keyFile: await readBytes(form.elements.keyfile?.files?.[0]),
            createKeyFile: !!form.elements.makekey?.checked,
            kdf: form.elements.kdf?.value || 'argon2d',
            preset: form.elements.preset?.value || 'standard',
            name: form.elements.name?.value.trim() || '',
          };
          const result = await run(values);
          closeModal(result ?? true);
        } catch (ex) {
          fail(ex && ex.message ? ex.message : 'That did not work.');
          submit.disabled = false;
          submit.textContent = label;
          pw.select();
        }
      });
    },
  });
}

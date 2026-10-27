// File access. Chromium browsers can open a file once and save back to the same file
// (File System Access API). Other browsers fall back to a file input and a download.

export const canUseFileHandles = () =>
  typeof window !== 'undefined' && 'showOpenFilePicker' in window && 'showSaveFilePicker' in window && window.isSecureContext;

const KDBX_TYPES = [{ description: 'KeePass database', accept: { 'application/octet-stream': ['.kdbx'] } }];

/** Opens the native picker. Returns { file, handle } or null if the user cancelled. */
export async function pickKdbx() {
  try {
    const [handle] = await window.showOpenFilePicker({ types: KDBX_TYPES, multiple: false, excludeAcceptAllOption: false });
    return { file: await handle.getFile(), handle };
  } catch (e) {
    if (e && e.name === 'AbortError') return null;
    throw e;
  }
}

export async function pickSaveTarget(suggestedName) {
  try {
    return await window.showSaveFilePicker({ suggestedName, types: KDBX_TYPES });
  } catch (e) {
    if (e && e.name === 'AbortError') return null;
    throw e;
  }
}

async function ensureWritable(handle) {
  const opts = { mode: 'readwrite' };
  if ((await handle.queryPermission(opts)) === 'granted') return true;
  return (await handle.requestPermission(opts)) === 'granted';
}

export async function writeToHandle(handle, bytes) {
  if (!(await ensureWritable(handle))) {
    const e = new Error('Permission to write to the file was not granted.');
    e.name = 'NotAllowedError';
    throw e;
  }
  const w = await handle.createWritable();
  await w.write(bytes);
  await w.close();
  return (await handle.getFile()).lastModified;
}

/** Reads the file's current bytes and modification time (for conflict checks). */
export async function readHandle(handle) {
  const f = await handle.getFile();
  return { bytes: new Uint8Array(await f.arrayBuffer()), lastModified: f.lastModified };
}

export async function currentModified(handle) {
  return (await handle.getFile()).lastModified;
}

/** A plain file chooser that works in every browser. Resolves to a File, or null if cancelled. */
export function chooseFile(accept = '') {
  return new Promise((resolve) => {
    const input = Object.assign(document.createElement('input'), { type: 'file', accept });
    input.style.display = 'none';
    input.addEventListener('change', () => { resolve(input.files[0] || null); input.remove(); });
    input.addEventListener('cancel', () => { resolve(null); input.remove(); });
    document.body.appendChild(input);
    input.click();
  });
}

export function downloadBytes(name, bytes, mime = 'application/octet-stream') {
  const blob = new Blob([bytes], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = Object.assign(document.createElement('a'), { href: url, download: name });
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

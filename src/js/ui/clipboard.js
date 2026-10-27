// Clipboard with automatic clearing. A newer copy cancels the pending clear of an older one,
// so copying a second value never gets wiped by the first value's timer.

let timer = null;

async function write(text, win) {
  try {
    await win.navigator.clipboard.writeText(text);
    return true;
  } catch {
    // Older browsers, or a window without clipboard permission: fall back to a hidden textarea.
    const doc = win.document;
    const ta = Object.assign(doc.createElement('textarea'), { value: text });
    ta.style.cssText = 'position:fixed;opacity:0;top:0;left:0';
    doc.body.appendChild(ta);
    ta.select();
    let ok = false;
    try { ok = doc.execCommand('copy'); } catch { /* unsupported */ }
    ta.remove();
    return ok;
  }
}

/**
 * Copies text. Returns true on success. `clearSeconds` of 0 keeps the value on the clipboard.
 * `win` lets a floating window use its own clipboard permission, which browsers tie to the focused window.
 */
export async function copyText(text, { clearSeconds = 30, win = window } = {}) {
  const ok = await write(String(text ?? ''), win);
  clearTimeout(timer);
  timer = null;
  if (ok && clearSeconds > 0) {
    timer = setTimeout(() => {
      timer = null;
      write('', win).then((cleared) => { if (!cleared && win !== window) write('', window); });
    }, clearSeconds * 1000);
  }
  return ok;
}

export function clearClipboardNow() {
  clearTimeout(timer);
  timer = null;
  return write('', window);
}

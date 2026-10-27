// Attachment bytes live here, outside the item objects, so that undo snapshots (which
// structured-clone items) never copy file contents. Items only hold { id, name, size }.

const store = new Map();
let seq = 0;

export function addAttachmentBytes(bytes) {
  const id = `att-${++seq}`;
  store.set(id, bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes));
  return id;
}

export const getAttachmentBytes = (id) => store.get(id);
export const clearAttachments = () => store.clear();

/** Drops stored bytes that no item references any more. */
export function pruneAttachments(items) {
  const keep = new Set(items.flatMap((i) => (i.attachments || []).map((a) => a.id)));
  for (const id of [...store.keys()]) if (!keep.has(id)) store.delete(id);
}

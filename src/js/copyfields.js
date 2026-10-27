// What each clickable field copies. Pure functions, so they can be tested without a browser.

import { displayName, folderPath, TYPE_LABEL } from './model.js';
import { totpCode } from './totp.js';

export const FIELD_LABEL = {
  name: 'Name', username: 'Username', password: 'Password', totp: 'One-time code', url: 'Website', notes: 'Notes',
  custom: 'Field', tags: 'Tags', location: 'Location', created: 'Created', updated: 'Updated', pwhist: 'Old password',
};

/** The text a field copies. `index` selects which website, custom field or history entry. */
export async function fieldText(item, field, index = 0) {
  switch (field) {
    case 'name': return displayName(item);
    case 'username': return item.username || '';
    case 'password': return item.password || '';
    case 'totp': return (await totpCode(item.totp)) || '';
    case 'url': return item.urls[index] || '';
    case 'notes': return item.notes || '';
    case 'custom': return item.customFields[index]?.value || '';
    case 'tags': return item.tags.join(', ');
    case 'location': return folderPath(item);
    case 'created': return item.createdAt || '';
    case 'updated': return item.updatedAt || '';
    case 'pwhist': return item.pwHistory?.[index]?.password || '';
    default: return '';
  }
}

/** Human label for the toast, e.g. "Password" or "Field “PIN”". */
export function fieldLabel(item, field, index = 0) {
  if (field === 'custom') return `“${item.customFields[index]?.name || 'Field'}”`;
  if (field === 'url') return item.urls.length > 1 ? `Website ${index + 1}` : 'Website';
  return FIELD_LABEL[field] || 'Value';
}

/** Every field of an item as plain "Label: value" lines, for the Copy all button. */
export async function itemAsText(item) {
  const lines = [displayName(item), `Type: ${TYPE_LABEL[item.type] || item.type}`];
  const add = (label, value) => { if (value) lines.push(`${label}: ${value}`); };
  add('Username', item.username);
  add('Password', item.password);
  add('One-time code', item.totp ? await totpCode(item.totp) : '');
  item.urls.forEach((u, i) => add(item.urls.length > 1 ? `Website ${i + 1}` : 'Website', u));
  for (const f of item.customFields) add(f.name || 'Field', f.value);
  if (item.tags.length) add('Tags', item.tags.join(', '));
  add('Location', folderPath(item));
  if (item.notes) lines.push('', 'Notes:', item.notes);
  return lines.join('\n');
}

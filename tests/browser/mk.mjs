import { createDb, saveDb, syncToDb, loadModel } from '../../src/js/kdbx.js';
import { newItem } from '../../src/js/model.js';
import { writeFileSync } from 'node:fs';
const db = createDb({ name: 'Test', password: 'hunter2 pw', preset: 'fast' });
const m = loadModel(db);
const a = newItem({ name: 'Example', username: 'alice@example.com', password: 'S3cret!pass', urls: ['https://login.example.com/'], totp: 'JBSWY3DPEHPK3PXP', vault: m.rootName, tags: ['work'] });
const b = newItem({ name: 'Other', username: 'bob', password: 'pw2', urls: ['https://other.test'], vault: m.rootName });
await syncToDb(db, m, [a, b], { vaults: [m.rootName], folders: {} });
writeFileSync(process.argv[2], await saveDb(db));

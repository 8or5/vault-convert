// Bundles src/js into one classic script and inlines it with the CSS into a single HTML file.
// The output opens straight from disk (file://) with no server and no network access.
import { build } from 'esbuild';
import { readFile, writeFile, mkdir } from 'node:fs/promises';

const result = await build({
  entryPoints: ['src/js/app.js'],
  bundle: true,
  format: 'iife',
  minify: true,
  write: false,
  target: ['es2020'],
  platform: 'browser',
  alias: { crypto: './src/js/empty-module.cjs', '@xmldom/xmldom': './src/js/empty-module.cjs' },
  legalComments: 'none',
});

const js = result.outputFiles[0].text.replace(/<\/script/gi, '<\\/script');
const css = await readFile('src/styles.css', 'utf8');
const template = await readFile('src/template.html', 'utf8');

const html = template
  .replace('/*__CSS__*/', () => css)
  .replace('/*__JS__*/', () => js);

await mkdir('dist', { recursive: true });
await writeFile('dist/vault-convert.html', html);
console.log(`Built dist/vault-convert.html (${(html.length / 1024).toFixed(1)} KB)`);

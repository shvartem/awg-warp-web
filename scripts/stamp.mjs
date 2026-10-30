// Cache busting for GitHub Pages: appends ?v=<version> to every local
// script/style reference so a browser never mixes fresh and cached files.
// Usage: node scripts/stamp.mjs <site dir> <version>
import { readFileSync, writeFileSync, readdirSync, statSync } from 'node:fs';
import { join, extname } from 'node:path';

const [dir, version] = process.argv.slice(2);
if (!dir || !version || !/^[\w.-]+$/.test(version)) {
  console.error('usage: node scripts/stamp.mjs <site dir> <version>');
  process.exit(1);
}

const files = [];
(function walk(d) {
  for (const name of readdirSync(d)) {
    const p = join(d, name);
    if (statSync(p).isDirectory()) walk(p);
    else if (['.html', '.js', '.mjs', '.css'].includes(extname(p))) files.push(p);
  }
})(dir);

const v = `?v=${version}`;
let count = 0;
for (const file of files) {
  const src = readFileSync(file, 'utf8');
  let out = src;
  if (file.endsWith('.html')) {
    // <script src="app.js">, <link href="style.css"> — relative paths only
    out = out.replace(/\b(src|href)="((?![a-z]+:|\/\/|#|data:)[^"?#]+\.(?:js|mjs|css))"/gi, (_, attr, path) => `${attr}="${path}${v}"`);
  } else if (/\.m?js$/.test(file)) {
    // import ... from './x.js'  /  import './x.js'
    out = out.replace(/(\bfrom\s*|\bimport\s*)(['"])(\.{1,2}\/[^'"?]+\.m?js)\2/g, (_, kw, q, path) => `${kw}${q}${path}${v}${q}`);
  }
  if (out !== src) {
    writeFileSync(file, out);
    count++;
  }
}
console.log(`stamped ${count} files with ${v}`);

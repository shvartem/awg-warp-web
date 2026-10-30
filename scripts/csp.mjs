// Adds a Content Security Policy to site/index.html at deploy time.
// The only server the page may talk to is the Worker from WORKER_URL, so even
// an injected script could not send a key anywhere else.
// Usage: node scripts/csp.mjs <site dir> <worker url>
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const [dir, workerUrl] = process.argv.slice(2);
let origin;
try {
  const u = new URL(workerUrl);
  if (u.protocol !== 'https:') throw new Error('not https');
  origin = u.origin;
} catch {
  console.error('usage: node scripts/csp.mjs <site dir> <https worker url>');
  process.exit(1);
}

export const policy = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "font-src 'self'",
  "img-src 'self' data:",
  `connect-src ${origin}`,
  "manifest-src 'self'",
  "base-uri 'none'",
  "form-action 'none'",
  "object-src 'none'",
].join('; ');

const file = join(dir, 'index.html');
const html = readFileSync(file, 'utf8');
if (html.includes('Content-Security-Policy')) {
  console.error('index.html already has a CSP');
  process.exit(1);
}
const meta = `<meta http-equiv="Content-Security-Policy" content="${policy}">`;
const out = html.replace(/(<meta charset="utf-8">)/i, `$1\n  ${meta}`);
if (out === html) {
  console.error('could not find <meta charset> in index.html');
  process.exit(1);
}
writeFileSync(file, out);
console.log(`CSP added, connect-src ${origin}`);

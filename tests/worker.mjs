// node tests/worker.mjs — runs the Worker with a mocked global fetch.
import assert from 'node:assert/strict';
import worker from '../worker/src/index.js';

const calls = [];
globalThis.fetch = async (url, init = {}) => {
  calls.push({ url: String(url), init });
  if (String(url).startsWith('https://santa.test/')) {
    return new Response(JSON.stringify({ result: { key: 'k', config: {} }, success: true }), { status: 200 });
  }
  if (String(url).startsWith('https://api.cloudflareclient.com/')) {
    const body = JSON.parse(init.body);
    return new Response(JSON.stringify({ result: { key: body.key, token: 'SECRET', account: { license: 'L' } }, success: true }), { status: 200 });
  }
  throw new Error('unexpected upstream ' + url);
};

const env = { ALLOWED_ORIGINS: 'https://me.github.io', SANTA_URL: 'https://santa.test/gen' };
const req = (path, init = {}, origin = 'https://me.github.io') =>
  new Request('https://warp-proxy.example.workers.dev' + path, { ...init, headers: { Origin: origin, ...(init.headers || {}) } });
let n = 0;
const test = async (name, fn) => { await fn(); n++; console.log('ok -', name); };

await test('preflight', async () => {
  const r = await worker.fetch(req('/reg', { method: 'OPTIONS' }), env);
  assert.equal(r.status, 204);
  assert.equal(r.headers.get('Access-Control-Allow-Origin'), 'https://me.github.io');
});

await test('foreign origin rejected', async () => {
  const r = await worker.fetch(req('/santa', {}, 'https://evil.example'), env);
  assert.equal(r.status, 403);
});

await test('/santa relays with CORS', async () => {
  const r = await worker.fetch(req('/santa'), env);
  assert.equal(r.status, 200);
  assert.equal(r.headers.get('Access-Control-Allow-Origin'), 'https://me.github.io');
  assert.equal((await r.json()).result.key, 'k');
});

await test('/santa without SANTA_URL', async () => {
  const r = await worker.fetch(req('/santa'), { ALLOWED_ORIGINS: 'https://me.github.io' });
  assert.equal(r.status, 500);
  assert.match((await r.json()).errors[0].message, /SANTA_URL/);
});

await test('/santa uses env.SANTA_URL', async () => {
  calls.length = 0;
  await worker.fetch(req('/santa'), env);
  assert.equal(calls[0].url, 'https://santa.test/gen');
});

await test('/reg validates key', async () => {
  const r = await worker.fetch(req('/reg', { method: 'POST', body: '{"key":"nope"}' }), env);
  assert.equal(r.status, 400);
});

await test('/reg sends wgcf payload and strips token', async () => {
  calls.length = 0;
  const key = 'bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=';
  const r = await worker.fetch(req('/reg', { method: 'POST', body: JSON.stringify({ key }) }), env);
  assert.equal(r.status, 200);
  const data = await r.json();
  assert.equal(data.result.token, undefined);
  assert.equal(data.result.account.license, 'L');
  const c = calls[0];
  assert.equal(c.url, 'https://api.cloudflareclient.com/v0a5641/reg');
  assert.equal(c.init.headers['CF-Client-Version'], 'a-6.38.9-5641');
  const sent = JSON.parse(c.init.body);
  assert.equal(sent.key, key);
  assert.equal(sent.tunnel_type, 'wireguard');
  assert.equal(sent.key_type, 'curve25519');
});

await test('no other paths proxied', async () => {
  const r = await worker.fetch(req('/https://example.com'), env);
  assert.equal(r.status, 404);
});

await test('wildcard origin', async () => {
  const r = await worker.fetch(req('/santa', {}, 'https://any.example'), { ALLOWED_ORIGINS: '*', SANTA_URL: 'https://santa.test/gen' });
  assert.equal(r.headers.get('Access-Control-Allow-Origin'), 'https://any.example');
});

await test('health without Origin', async () => {
  const r = await worker.fetch(new Request('https://w.example/'), env);
  assert.equal(r.status, 200);
  assert.deepEqual(await r.json(), { ok: true, santa: true });
});

await test('santa still requires allowed Origin', async () => {
  const r = await worker.fetch(new Request('https://w.example/santa'), env);
  assert.equal(r.status, 403);
});

console.log(`\n${n} worker tests passed`);

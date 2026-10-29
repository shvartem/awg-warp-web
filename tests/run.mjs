// node tests/run.mjs — no dependencies.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import crypto from 'node:crypto';
import { writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createZip, crc32 } from '../site/lib/zip.js';
import { scalarMult, publicKeyFromPrivate, generateKeyPair, toBase64, fromBase64 } from '../site/lib/x25519.js';
import { parseRegistration, buildConfig, DEFAULT_SETTINGS, validateSettings, isValidWgKey, DNS_GROUPS, DNS_PRESETS, resolveDns, presetForDns, configFileName, ENDPOINT_HOSTS, ENDPOINT_PORTS, batchConfigs, batchArchiveName } from '../site/lib/warp.js';

const hex = (h) => Uint8Array.from(h.match(/../g).map((x) => parseInt(x, 16)));
const toHex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
let passed = 0;
const test = (name, fn) => { fn(); passed++; console.log('ok -', name); };

// RFC 7748 §5.2
test('X25519 vector 1', () => {
  const out = scalarMult(
    hex('a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4'),
    hex('e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c'));
  assert.equal(toHex(out), 'c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552');
});
test('X25519 vector 2', () => {
  const out = scalarMult(
    hex('4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d'),
    hex('e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493'));
  assert.equal(toHex(out), '95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957');
});
test('X25519 matches node:crypto on 300 random inputs', () => {
  const b64u = (b) => Buffer.from(b).toString('base64url');
  for (let i = 0; i < 300; i++) {
    const k = crypto.randomBytes(32), u = crypto.randomBytes(32);
    u[31] &= 127;
    let ref;
    try {
      const priv = crypto.createPrivateKey({ key: { kty: 'OKP', crv: 'X25519', d: b64u(k), x: b64u(new Uint8Array(32)) }, format: 'jwk' });
      const pub = crypto.createPublicKey({ key: { kty: 'OKP', crv: 'X25519', x: b64u(u) }, format: 'jwk' });
      ref = Buffer.from(crypto.diffieHellman({ privateKey: priv, publicKey: pub })).toString('hex');
    } catch { continue; } // low-order points rejected by OpenSSL
    assert.equal(toHex(scalarMult(k, u)), ref);
  }
});
// RFC 7748 §6.1 Diffie-Hellman
test('X25519 public keys (Alice/Bob)', () => {
  assert.equal(toHex(publicKeyFromPrivate(hex('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a'))),
    '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a');
  assert.equal(toHex(publicKeyFromPrivate(hex('5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb'))),
    'de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f');
});

test('generated pair matches `wg pubkey` if available', () => {
  const kp = generateKeyPair();
  assert.ok(isValidWgKey(kp.privateKey) && isValidWgKey(kp.publicKey));
  assert.equal(toBase64(publicKeyFromPrivate(fromBase64(kp.privateKey))), kp.publicKey);
  try {
    const wg = execFileSync('wg', ['pubkey'], { input: kp.privateKey + '\n' }).toString().trim();
    assert.equal(wg, kp.publicKey);
  } catch (e) {
    if (e.code !== 'ENOENT') throw e;
  }
});

// Real response shape returned by the Santa generator
const santa = {
  result: {
    id: '936c9be4-3e20-4350-a490-f6cd98b7c755', type: 'i',
    key: 'IJzeNVFFuCqe0yq5Z59WvW21fy4dofTZixjZ3LJInkE=',
    account: { license: 'amOM8376-P20M3bS6-3y2h4a1M', warp_plus: true },
    config: {
      client_id: 'yk7i',
      peers: [{ public_key: 'bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=',
        endpoint: { v4: '162.159.192.6:0', host: 'engage.cloudflareclient.com:2408', ports: [2408, 500, 1701, 4500] } }],
      interface: { addresses: { v4: '172.16.0.2', v6: '2606:4700:110:838a:aca5:e9c5:cb06:c4f1' } },
    },
  },
  success: true, errors: [],
};

test('parse Santa response', () => {
  const r = parseRegistration(santa);
  assert.equal(r.privateKey, santa.result.key);
  assert.equal(r.peerPublicKey, 'bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=');
  assert.equal(r.v4, '172.16.0.2');
  assert.equal(r.source, 'santa');
});

test('parse Cloudflare response uses own private key', () => {
  const r = parseRegistration(santa, 'OWNPRIV');
  assert.equal(r.privateKey, 'OWNPRIV');
  assert.equal(r.source, 'local');
});

test('error response is reported', () => {
  assert.throws(() => parseRegistration({ success: false, errors: [{ message: 'Too many requests' }] }), /Too many requests/);
});

test('config layout with defaults', () => {
  const conf = buildConfig(parseRegistration(santa), DEFAULT_SETTINGS);
  assert.match(conf, /^\[Interface\]\nPrivateKey = IJzeNV/);
  assert.match(conf, /\nJc = 120\nJmin = 23\nJmax = 911\n/);
  assert.match(conf, /\nI1 = <b 0xc2000000011419fa/);
  assert.match(conf, /\nAddress = 172\.16\.0\.2\/32, 2606:4700:110:838a:aca5:e9c5:cb06:c4f1\/128\n/);
  assert.match(conf, /\nEndpoint = 162\.159\.192\.1:500\n/);
  assert.match(conf, /\nPersistentKeepalive = 25\n$/);
});

test('IPv4-only and no I1', () => {
  const conf = buildConfig(parseRegistration(santa), { ...DEFAULT_SETTINGS, ipv6: false, useI1: false, endpointHost: 'engage.cloudflareclient.com', endpointPort: 2408 });
  assert.ok(!conf.includes('I1 ='));
  assert.match(conf, /\nAddress = 172\.16\.0\.2\/32\n/);
  assert.match(conf, /\nDNS = 1\.1\.1\.1, 1\.0\.0\.1\n/);
  assert.match(conf, /\nAllowedIPs = 0\.0\.0\.0\/0\n/);
  assert.match(conf, /\nEndpoint = engage\.cloudflareclient\.com:2408\n/);
});

test('IPv6 endpoint is bracketed', () => {
  const conf = buildConfig(parseRegistration(santa), { ...DEFAULT_SETTINGS, endpointHost: '2606:4700:d0::a29f:c006' });
  assert.match(conf, /Endpoint = \[2606:4700:d0::a29f:c006\]:500/);
});

test('validation', () => {
  assert.deepEqual(validateSettings(DEFAULT_SETTINGS), []);
  assert.ok(validateSettings({ ...DEFAULT_SETTINGS, Jmin: 1000, Jmax: 10 }).length > 0);
  assert.ok(validateSettings({ ...DEFAULT_SETTINGS, I1: 'garbage' }).length > 0);
});

test('default DNS preset matches previous default', () => {
  assert.equal(resolveDns(DEFAULT_SETTINGS), DEFAULT_SETTINGS.dns);
  assert.equal(presetForDns(DEFAULT_SETTINGS.dns), 'cloudflare');
  assert.equal(presetForDns('1.1.1.1,  2606:4700:4700::1111,1.0.0.1, 2606:4700:4700::1001'), 'cloudflare');
  assert.equal(presetForDns('1.1.1.1'), 'custom');
});

test('every DNS preset: 2 IPv4 + 2 IPv6, all valid', () => {
  for (const p of DNS_PRESETS) {
    assert.equal(p.servers.filter((x) => !x.includes(':')).length, 2, p.id);
    assert.equal(p.servers.filter((x) => x.includes(':')).length, 2, p.id);
    assert.deepEqual(validateSettings({ ...DEFAULT_SETTINGS, dnsPreset: 'custom', dns: p.servers.join(', ') }), [], p.id);
  }
});

test('AdGuard preset in config, IPv6 dropped when off', () => {
  const reg = parseRegistration(santa);
  assert.match(buildConfig(reg, { ...DEFAULT_SETTINGS, dnsPreset: 'adguard' }),
    /\nDNS = 94\.140\.14\.14, 2a10:50c0::ad1:ff, 94\.140\.15\.15, 2a10:50c0::ad2:ff\n/);
  assert.match(buildConfig(reg, { ...DEFAULT_SETTINGS, dnsPreset: 'adguard', ipv6: false }),
    /\nDNS = 94\.140\.14\.14, 94\.140\.15\.15\n/);
});

test('custom DNS used and validated', () => {
  const reg = parseRegistration(santa);
  const s = { ...DEFAULT_SETTINGS, dnsPreset: 'custom', dns: '10.0.0.53' };
  assert.match(buildConfig(reg, s), /\nDNS = 10\.0\.0\.53\n/);
  assert.ok(validateSettings({ ...s, dns: '' }).some((e) => e.startsWith('DNS')));
  assert.ok(validateSettings({ ...s, dns: 'https://dns.example/dns-query' }).some((e) => e.startsWith('DNS')));
  assert.ok(validateSettings({ ...s, dns: '300.1.1.1' }).some((e) => e.startsWith('DNS')));
  assert.deepEqual(validateSettings({ ...DEFAULT_SETTINGS, dnsPreset: 'quad9', dns: 'junk' }), []);
});

test('every DNS preset belongs to a group, no duplicates', () => {
  const groups = new Set(DNS_GROUPS.map((g) => g.id));
  assert.equal(new Set(DNS_PRESETS.map((p) => p.id)).size, DNS_PRESETS.length);
  for (const p of DNS_PRESETS) assert.ok(groups.has(p.group) && p.note, p.id);
});

test('config file name', () => {
  const santaReg = parseRegistration(santa);
  const localReg = parseRegistration(santa, 'OWN');
  // default endpoint 162.159.192.1 is #2 in the list, port 500 is "a"
  assert.equal(configFileName(santaReg, DEFAULT_SETTINGS), 'warp_cf_2a_s.conf');
  assert.equal(configFileName(localReg, DEFAULT_SETTINGS), 'warp_cf_2a.conf');
  assert.equal(configFileName(localReg, { ...DEFAULT_SETTINGS, dnsPreset: 'custom' }), 'warp_own_2a.conf');
  assert.equal(configFileName(santaReg, { ...DEFAULT_SETTINGS, dnsPreset: 'adguard-family', endpointHost: '188.114.96.81', endpointPort: 4500 }), 'warp_adgf_10d_s.conf');
  assert.equal(configFileName(santaReg, { ...DEFAULT_SETTINGS, endpointHost: 'engage.cloudflareclient.com', endpointPort: 2408 }), 'warp_cf_1b_s.conf');
  assert.equal(configFileName(santaReg, { ...DEFAULT_SETTINGS, endpointHost: '162.159.193.5', endpointPort: '1701' }), 'warp_cf_0c_s.conf');
  assert.equal(new Set(DNS_PRESETS.map((p) => p.tag)).size, DNS_PRESETS.length);
  // every combination satisfies the WireGuard tunnel-name rule
  for (const dnsPreset of [...DNS_PRESETS.map((x) => x.id), 'custom'])
    for (const endpointHost of [...ENDPOINT_HOSTS, '10.0.0.1'])
      for (const endpointPort of ENDPOINT_PORTS) {
        const name = configFileName(santaReg, { ...DEFAULT_SETTINGS, dnsPreset, endpointHost, endpointPort }).replace(/\.conf$/, '');
        assert.match(name, /^[a-zA-Z0-9_=+.-]{1,15}$/, name);
      }
});

test('batch: one config per host × port, unique names', () => {
  const reg = parseRegistration(santa);
  const files = batchConfigs(reg, DEFAULT_SETTINGS, ENDPOINT_HOSTS, ENDPOINT_PORTS);
  assert.equal(files.length, 40);
  assert.equal(new Set(files.map((f) => f.name)).size, 40);
  const f = files.find((x) => x.name === 'warp_cf_3b_s.conf');
  assert.match(f.text, /\nEndpoint = 162\.159\.192\.2:2408\n/);
  assert.ok(files.every((x) => x.text.includes('PrivateKey = ' + reg.privateKey)));
});

test('batch archive name', () => {
  assert.equal(batchArchiveName(parseRegistration(santa), DEFAULT_SETTINGS), 'warp_cf_s.zip');
  assert.equal(batchArchiveName(parseRegistration(santa, 'OWN'), { ...DEFAULT_SETTINGS, dnsPreset: 'adguard-family', endpointHost: '188.114.96.81' }), 'warp_adgf.zip');
});

test('crc32 known value', () => {
  assert.equal(crc32(new TextEncoder().encode('123456789')), 0xcbf43926);
});

test('zip is readable by Python zipfile', () => {
  const files = batchConfigs(parseRegistration(santa), DEFAULT_SETTINGS, ENDPOINT_HOSTS.slice(0, 3), [500, 2408]);
  const path = join(mkdtempSync(join(tmpdir(), 'zip-')), 'a.zip');
  writeFileSync(path, createZip(files.map((f) => ({ name: f.name, data: f.text }))));
  const py = `import zipfile,sys,json
z=zipfile.ZipFile(sys.argv[1]); assert z.testzip() is None
print(json.dumps({n: z.read(n).decode() for n in z.namelist()}))`;
  let out;
  try {
    out = JSON.parse(execFileSync('python3', ['-I', '-c', py, path]).toString());
  } catch (e) {
    if (e.code === 'ENOENT') return; // no python: skip
    throw e;
  }
  assert.deepEqual(Object.keys(out), files.map((f) => f.name));
  for (const f of files) assert.equal(out[f.name], f.text);
});

console.log(`\n${passed} tests passed`);

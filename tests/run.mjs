// node tests/run.mjs — no dependencies.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import crypto from 'node:crypto';
import { writeFileSync, mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createZip, crc32 } from '../site/lib/zip.js';
import { parseCidr, formatCidr, subtractCidrs, LAN_V4, LAN_V6 } from '../site/lib/cidr.js';
import { buildUci, isValidIfaceName } from '../site/lib/openwrt.js';
import { scalarMult, publicKeyFromPrivate, generateKeyPair, toBase64, fromBase64 } from '../site/lib/x25519.js';
import { parseRegistration, buildConfig, DEFAULT_SETTINGS, validateSettings, isValidWgKey, DNS_GROUPS, DNS_PRESETS, resolveDns, presetForDns, configFileName, ENDPOINT_HOSTS, ENDPOINT_PORTS, batchConfigs, batchArchiveName, parseConfigText } from '../site/lib/warp.js';

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

test('import: round trip of our own config', () => {
  const reg = parseRegistration(santa);
  const s = { ...DEFAULT_SETTINGS, dnsPreset: 'adguard', endpointHost: '188.114.96.23', endpointPort: 2408, Jc: 7, keepalive: 15 };
  const { reg: r2, settings, notes } = parseConfigText(buildConfig(reg, s));
  assert.equal(r2.privateKey, reg.privateKey);
  assert.equal(r2.peerPublicKey, reg.peerPublicKey);
  assert.equal(r2.v4, '172.16.0.2');
  assert.equal(r2.v6, reg.v6);
  assert.equal(r2.source, 'import');
  assert.deepEqual(notes, []);
  assert.equal(settings.dnsPreset, 'adguard');
  assert.equal(settings.endpointHost, '188.114.96.23');
  assert.equal(settings.endpointPort, 2408);
  assert.equal(settings.Jc, 7);
  assert.equal(settings.keepalive, 15);
  assert.equal(settings.useI1, true);
  // rebuilding with imported settings gives the same text
  assert.equal(buildConfig(r2, { ...DEFAULT_SETTINGS, ...settings }), buildConfig(reg, s));
});

test('import: plain WireGuard config, comments, CRLF, IPv4 only', () => {
  const text = [
    '# WARP from somewhere', '[Interface]', 'PrivateKey = IJzeNVFFuCqe0yq5Z59WvW21fy4dofTZixjZ3LJInkE=',
    'Address = 172.16.0.2/32', 'DNS = 1.1.1.1, 1.0.0.1  # cloudflare', 'MTU = 1280', '',
    '[Peer]', 'PublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=', 'AllowedIPs = 0.0.0.0/0',
    'Endpoint = engage.cloudflareclient.com:2408',
  ].join('\r\n');
  const { reg, settings, notes } = parseConfigText(text);
  assert.equal(reg.v6, '');
  assert.equal(settings.ipv6, false);
  assert.equal(settings.dnsPreset, 'cloudflare'); // IPv4 half of the preset
  assert.equal(settings.endpointHost, 'engage.cloudflareclient.com');
  assert.equal(settings.endpointPort, 2408);
  assert.equal(settings.useI1, undefined);
  assert.equal(settings.Jc, undefined);
  assert.equal(notes.length, 1);
});

test('import: custom DNS, unknown port, IPv6 endpoint', () => {
  const text = `[Interface]
PrivateKey = IJzeNVFFuCqe0yq5Z59WvW21fy4dofTZixjZ3LJInkE=
Address = 172.16.0.2/32, 2606:4700::1/128
DNS = 10.0.0.53
Jc = 4
[Peer]
PublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=
Endpoint = [2606:4700:d0::a29f:c001]:854`;
  const { settings, notes } = parseConfigText(text);
  assert.equal(settings.dnsPreset, 'custom');
  assert.equal(settings.dns, '10.0.0.53');
  assert.equal(settings.endpointHost, '2606:4700:d0::a29f:c001');
  assert.equal(settings.endpointPort, 500);
  assert.equal(settings.useI1, false); // AWG config without I1
  assert.ok(notes.some((n) => n.includes('854')));
});

test('import: errors are explained', () => {
  assert.throws(() => parseConfigText(''), /PrivateKey/);
  assert.throws(() => parseConfigText('[Interface]\nPrivateKey = abc\n'), /повреждён/);
  assert.throws(() => parseConfigText('[Interface]\nPrivateKey = IJzeNVFFuCqe0yq5Z59WvW21fy4dofTZixjZ3LJInkE=\n'), /PublicKey/);
  assert.throws(() => parseConfigText('[Interface]\nPrivateKey = IJzeNVFFuCqe0yq5Z59WvW21fy4dofTZixjZ3LJInkE=\n[Peer]\nPublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=\n'), /IPv4/);
});

test('cidr parse/format', () => {
  for (const c of ['0.0.0.0/0', '10.0.0.0/8', '192.168.1.0/24', '::/0', 'fc00::/7', '2606:4700::1111/128', '2001:db8:0:1::/64'])
    assert.equal(formatCidr(parseCidr(c)), c);
  assert.equal(formatCidr(parseCidr('10.1.2.3/8')), '10.0.0.0/8');   // host bits cleared
  assert.equal(formatCidr(parseCidr('1.2.3.4')), '1.2.3.4/32');
  for (const bad of ['300.1.1.1/8', '1.2.3/8', '10.0.0.0/33', '::1::2/64', 'fz::/7', 'abc'])
    assert.equal(parseCidr(bad), null, bad);
});

test('cidr subtract: no LAN left, nothing else lost (checked by Python ipaddress)', () => {
  const v4 = subtractCidrs(['0.0.0.0/0'], LAN_V4);
  const v6 = subtractCidrs(['::/0'], LAN_V6);
  assert.ok(v4.length <= 48 && v6.length <= 16, `${v4.length} / ${v6.length}`);
  const py = `import ipaddress,sys,json
d=json.loads(sys.argv[1])
for fam,full,lan,res in (('4','0.0.0.0/0',d['lan4'],d['v4']),('6','::/0',d['lan6'],d['v6'])):
    nets=[ipaddress.ip_network(x) for x in res]
    lan=[ipaddress.ip_network(x) for x in lan]
    total=sum(n.num_addresses for n in nets)+sum(n.num_addresses for n in lan)
    assert total==ipaddress.ip_network(full).num_addresses, (fam,'coverage')
    assert not any(a.overlaps(b) for i,a in enumerate(nets) for b in nets[i+1:]), (fam,'overlap')
    assert not any(a.overlaps(b) for a in nets for b in lan), (fam,'lan leak')
print('ok')`;
  let out;
  try {
    out = execFileSync('python3', ['-I', '-c', py, JSON.stringify({ v4, v6, lan4: LAN_V4, lan6: LAN_V6 })]).toString().trim();
  } catch (e) {
    if (e.code === 'ENOENT') return;
    throw e;
  }
  assert.equal(out, 'ok');
});

test('cidr subtract: partial overlap and unrelated', () => {
  assert.deepEqual(subtractCidrs(['192.168.0.0/16'], ['192.168.1.0/24']).length, 8);
  assert.deepEqual(subtractCidrs(['8.8.8.0/24'], LAN_V4), ['8.8.8.0/24']);
  assert.deepEqual(subtractCidrs(['10.1.0.0/16'], LAN_V4), []);
  assert.throws(() => subtractCidrs(['nonsense'], LAN_V4), /неверный диапазон/);
});

test('exclude LAN in config', () => {
  const reg = parseRegistration(santa);
  const line = (conf) => conf.split('\n').find((l) => l.startsWith('AllowedIPs = ')).slice(13).split(', ');
  const on = line(buildConfig(reg, { ...DEFAULT_SETTINGS, excludeLan: true }));
  assert.ok(on.includes('8.0.0.0/7') && on.includes('11.0.0.0/8') && !on.includes('0.0.0.0/0'));
  assert.ok(!on.some((x) => x.startsWith('10.') || x.startsWith('192.168.')));
  assert.ok(on.some((x) => x.includes(':')));
  const v4only = line(buildConfig(reg, { ...DEFAULT_SETTINGS, excludeLan: true, ipv6: false }));
  assert.ok(v4only.length > 10 && !v4only.some((x) => x.includes(':')));
  assert.deepEqual(line(buildConfig(reg, DEFAULT_SETTINGS)), ['0.0.0.0/0', '::/0']);
});

test('import recognises LAN-excluded AllowedIPs', () => {
  const reg = parseRegistration(santa);
  for (const ipv6 of [true, false]) {
    const { settings } = parseConfigText(buildConfig(reg, { ...DEFAULT_SETTINGS, excludeLan: true, ipv6 }));
    assert.equal(settings.excludeLan, true);
    assert.equal(settings.allowedIPs, '0.0.0.0/0, ::/0');
  }
  const { settings } = parseConfigText(buildConfig(reg, { ...DEFAULT_SETTINGS, allowedIPs: '8.8.8.8/32, 1.1.1.0/24' }));
  assert.equal(settings.excludeLan, false);
  assert.equal(settings.allowedIPs, '8.8.8.8/32, 1.1.1.0/24');
});

test('AllowedIPs validation', () => {
  assert.ok(validateSettings({ ...DEFAULT_SETTINGS, allowedIPs: '' }).some((e) => e.includes('Через туннель')));
  assert.ok(validateSettings({ ...DEFAULT_SETTINGS, allowedIPs: '0.0.0.0/0, oops' }).some((e) => e.includes('oops')));
  assert.deepEqual(validateSettings({ ...DEFAULT_SETTINGS, allowedIPs: '1.1.1.1, 10.0.0.0/8, ::/0' }), []);
});

// Runs generated uci commands in a real sh with a fake `uci` that logs its args.
function runUci(script) {
  const stub = `uci() { printf '%s\\n' "$*" >> "$LOG"; }\n` + script.replace(/^\/etc\/init\.d\/(\w+) reload$/gm, 'echo "reload $1" >> "$LOG"');
  const dir = mkdtempSync(join(tmpdir(), 'uci-'));
  const log = join(dir, 'log');
  writeFileSync(join(dir, 's.sh'), stub);
  execFileSync('sh', ['-eu', join(dir, 's.sh')], { env: { ...process.env, LOG: log } });
  return readFileSync(log, 'utf8').trim().split('\n');
}

test('openwrt: uci commands produce the right values', () => {
  const reg = parseRegistration(santa);
  const calls = runUci(buildUci(reg, { ...DEFAULT_SETTINGS, endpointHost: '188.114.96.23', endpointPort: 2408 }, { iface: 'awg10', routeAll: false }));
  const has = (c) => assert.ok(calls.includes(c), c);
  has('set network.awg10=interface');
  has("set network.awg10.proto=amneziawg");
  has('set network.awg10.private_key=' + reg.privateKey);
  has('add_list network.awg10.addresses=172.16.0.2/32');
  has('set network.awg10.awg_jc=120');
  has('set network.awg10.awg_h4=4');
  assert.ok(calls.find((c) => c.startsWith('set network.awg10.awg_i1=<b 0xc2000000011419fa')), 'I1 passed intact with spaces');
  has('set network.awg10.nohostroute=1');
  has('set network.awg10_peer=amneziawg_awg10');
  has('set network.awg10_peer.public_key=' + reg.peerPublicKey);
  has('set network.awg10_peer.endpoint_host=188.114.96.23');
  has('set network.awg10_peer.endpoint_port=2408');
  has('add_list network.awg10_peer.allowed_ips=0.0.0.0/0');
  has('set network.awg10_peer.route_allowed_ips=0');
  has('set firewall.awg10_fwd.dest=awg10');
  assert.ok(!calls.some((c) => c.includes('family')), 'IPv6 on -> no family=ipv4');
  assert.deepEqual(calls.slice(-4), ['commit network', 'commit firewall', 'reload network', 'reload firewall']);
});

test('openwrt: routeAll, no I1, IPv4 only, LAN excluded, IPv6 endpoint', () => {
  const reg = parseRegistration(santa);
  const s = { ...DEFAULT_SETTINGS, useI1: false, ipv6: false, excludeLan: true, endpointHost: '2606:4700:d0::a29f:c001', endpointPort: 500 };
  const calls = runUci(buildUci(reg, s, { iface: 'warp', routeAll: true }));
  assert.ok(!calls.some((c) => c.includes('awg_i1') || c.includes('nohostroute')));
  assert.ok(calls.includes('set network.warp_peer.route_allowed_ips=1'));
  assert.ok(calls.includes('set firewall.warp_zone.family=ipv4'));
  assert.ok(calls.includes('set network.warp_peer.endpoint_host=2606:4700:d0::a29f:c001'));
  assert.equal(calls.filter((c) => c.startsWith('add_list network.warp_peer.allowed_ips=')).length, 40);
  assert.ok(!calls.some((c) => c.includes('addresses=2606')));
});

test('openwrt: quotes are escaped, bad names rejected', () => {
  const reg = parseRegistration(santa);
  const calls = runUci(buildUci(reg, { ...DEFAULT_SETTINGS, I1: "<b 0x01'; touch /tmp/pwned; '>" }, { iface: 'awg10', routeAll: false }));
  assert.ok(calls.includes("set network.awg10.awg_i1=<b 0x01'; touch /tmp/pwned; '>"));
  for (const bad of ['', 'Awg', '1awg', 'awg-10', 'abcdefghijkl', "a'b"]) assert.equal(isValidIfaceName(bad), false, bad);
  assert.equal(isValidIfaceName('awg10'), true);
  assert.throws(() => buildUci(reg, DEFAULT_SETTINGS, { iface: 'bad name', routeAll: false }), /имя интерфейса/);
});

console.log(`\n${passed} tests passed`);

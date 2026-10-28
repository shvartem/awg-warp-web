// Pure functions: AmneziaWG defaults for Cloudflare WARP,
// parsing of registration responses and building the AmneziaWG config text.

// AmneziaWG obfuscation values known to work with Cloudflare WARP.
export const DEFAULT_AWG = {
  Jc: 120,
  Jmin: 23,
  Jmax: 911,
  S1: 0,
  S2: 0,
  H1: 1,
  H2: 2,
  H3: 3,
  H4: 4,
};

// QUIC-Initial-like signature packet from the same function (AmneziaWG 1.5+).
export const DEFAULT_I1 = '<b 0xc2000000011419fa4bb3599f336777de79f81ca9a8d80d91eeec000044c635cef024a885dcb66d1420a91a8c427e87d6cf8e08b563932f449412cddf77d3e2594ea1c7a183c238a89e9adb7ffa57c133e55c59bec101634db90afb83f75b19fe703179e26a31902324c73f82d9354e1ed8da39af610afcb27e6590a44341a0828e5a3d2f0e0f7b0945d7bf3402feea0ee6332e19bdf48ffc387a97227aa97b205a485d282cd66d1c384bafd63dc42f822c4df2109db5b5646c458236ddcc01ae1c493482128bc0830c9e1233f0027a0d262f92b49d9d8abd9a9e0341f6e1214761043c021d7aa8c464b9d865f5fbe234e49626e00712031703a3e23ef82975f014ee1e1dc428521dc23ce7c6c13663b19906240b3efe403cf30559d798871557e4e60e86c29ea4504ed4d9bb8b549d0e8acd6c334c39bb8fb42ede68fb2aadf00cfc8bcc12df03602bbd4fe701d64a39f7ced112951a83b1dbbe6cd696dd3f15985c1b9fef72fa8d0319708b633cc4681910843ce753fac596ed9945d8b839aeff8d3bf0449197bd0bb22ab8efd5d63eb4a95db8d3ffc796ed5bcf2f4a136a8a36c7a0c65270d511aebac733e61d414050088a1c3d868fb52bc7e57d3d9fd132d78b740a6ecdc6c24936e92c28672dbe00928d89b891865f885aeb4c4996d50c2bbbb7a99ab5de02ac89b3308e57bcecf13f2da0333d1420e18b66b4c23d625d836b538fc0c221d6bd7f566a31fa292b85be96041d8e0bfe655d5dc1afed23eb8f2b3446561bbee7644325cc98d31cea38b865bdcc507e48c6ebdc7553be7bd6ab963d5a14615c4b81da7081c127c791224853e2d19bafdc0d9f3f3a6de898d14abb0e2bc849917e0a599ed4a541268ad0e60ea4d147dc33d17fa82f22aa505ccb53803a31d10a7ca2fea0b290a52ee92c7bf4aab7cea4e3c07b1989364eed87a3c6ba65188cd349d37ce4eefde9ec43bab4b4dc79e03469c2ad6b902e28e0bbbbf696781ad4edf424ffb35ce0236d373629008f142d04b5e08a124237e03e3149f4cdde92d7fae581a1ac332e26b2c9c1a6bdec5b3a9c7a2a870f7a0c25fc6ce245e029b686e346c6d862ad8df6d9b62474fbc31dbb914711f78074d4441f4e6e9edca3c52315a5c0653856e23f681558d669f4a4e6915bcf42b56ce36cb7dd3983b0b1d6fdf0f8efddb68e7ca0ae9dd4570fe6978fbb524109f6ec957ca61f1767ef74eb803b0f16abd0087cf2d01bc1db1c01d97ac81b3196c934586963fe7cf2d310e0739621e8bd00dc23fded18576d8c8f285d7bb5f43b547af3c76235de8b6f757f817683b2151600b11721219212bf27558edd439e73fce951f61d582320e5f4d6c315c71129b719277fc144bbe8ded25ab6d29b6e189c9bd9b16538faf60cc2aab3c3bb81fc2213657f2dd0ceb9b3b871e1423d8d3e8cc008721ef03b28e0ee7bb66b8f2a2ac01ef88df1f21ed49bf1ce435df31ac34485936172567488812429c269b49ee9e3d99652b51a7a614b7c460bf0d2d64d8349ded7345bedab1ea0a766a8470b1242f38d09f7855a32db39516c2bd4bcc538c52fa3a90c8714d4b006a15d9c7a7d04919a1cab48da7cce0d5de1f9e5f8936cffe469132991c6eb84c5191d1bcf69f70c58d9a7b66846440a9f0eef25ee6ab62715b50ca7bef0bc3013d4b62e1639b5028bdf757454356e9326a4c76dabfb497d451a3a1d2dbd46ec283d255799f72dfe878ae25892e25a2542d3ca9018394d8ca35b53ccd94947a8>';

export const DEFAULT_SETTINGS = {
  ...DEFAULT_AWG,
  mtu: 1280,
  dnsPreset: 'cloudflare',
  dns: '1.1.1.1, 2606:4700:4700::1111, 1.0.0.1, 2606:4700:4700::1001', // used when dnsPreset = 'custom'
  allowedIPs: '0.0.0.0/0, ::/0',
  endpointHost: '162.159.192.1',
  endpointPort: 500,
  keepalive: 25,
  useI1: true,
  I1: DEFAULT_I1,
  ipv6: true,
};

// Public DNS resolvers offered in the UI. Order: primary v4, primary v6,
// secondary v4, secondary v6 (IPv6 entries are dropped when IPv6 is off).
export const DNS_PRESETS = [
  { id: 'cloudflare', name: 'Cloudflare', note: 'Без фильтрации. Быстрее всего внутри WARP.',
    servers: ['1.1.1.1', '2606:4700:4700::1111', '1.0.0.1', '2606:4700:4700::1001'] },
  { id: 'cloudflare-security', name: 'Cloudflare Security', note: 'Блокирует вредоносные и фишинговые сайты.',
    servers: ['1.1.1.2', '2606:4700:4700::1112', '1.0.0.2', '2606:4700:4700::1002'] },
  { id: 'cloudflare-family', name: 'Cloudflare Family', note: 'Блокирует вредоносные сайты и контент 18+.',
    servers: ['1.1.1.3', '2606:4700:4700::1113', '1.0.0.3', '2606:4700:4700::1003'] },
  { id: 'adguard', name: 'AdGuard', note: 'Блокирует рекламу и трекеры.',
    servers: ['94.140.14.14', '2a10:50c0::ad1:ff', '94.140.15.15', '2a10:50c0::ad2:ff'] },
  { id: 'adguard-family', name: 'AdGuard Family', note: 'Блокирует рекламу, трекеры и контент 18+, включает безопасный поиск.',
    servers: ['94.140.14.15', '2a10:50c0::bad1:ff', '94.140.15.16', '2a10:50c0::bad2:ff'] },
  { id: 'google', name: 'Google', note: 'Без фильтрации.',
    servers: ['8.8.8.8', '2001:4860:4860::8888', '8.8.4.4', '2001:4860:4860::8844'] },
  { id: 'quad9', name: 'Quad9', note: 'Блокирует вредоносные сайты. Некоммерческий.',
    servers: ['9.9.9.9', '2620:fe::fe', '149.112.112.112', '2620:fe::9'] },
];

// The DNS list actually written to the config.
export function resolveDns(s) {
  const preset = DNS_PRESETS.find((p) => p.id === s.dnsPreset);
  return preset ? preset.servers.join(', ') : String(s.dns || '');
}

// Maps a stored DNS string back to a preset id (for settings saved before presets existed).
export function presetForDns(dns) {
  const norm = splitList(dns).join(',');
  const p = DNS_PRESETS.find((x) => x.servers.join(',') === norm);
  return p ? p.id : 'custom';
}

// Known Cloudflare WARP endpoints and the ports Cloudflare advertises.
export const ENDPOINT_HOSTS = [
  'engage.cloudflareclient.com',
  '162.159.192.1',
  '162.159.192.2',
  '162.159.192.4',
  '162.159.195.1',
  '162.159.195.4',
  '188.114.96.1',
  '188.114.96.23',
  '188.114.96.50',
  '188.114.96.81',
];
export const ENDPOINT_PORTS = [500, 2408, 1701, 4500];


/**
 * Normalises a registration response (Santa or Cloudflare) into
 * { privateKey, peerPublicKey, v4, v6, license, ports }.
 * Santa puts the private key it generated into result.key. For a Cloudflare response result.key is OUR public
 * key, so the caller passes the private key it generated.
 */
export function parseRegistration(json, ownPrivateKey = null) {
  const r = json && json.result ? json.result : json;
  if (!r || !r.config) {
    const msg = (json && json.errors && json.errors[0] && json.errors[0].message) || 'неожиданный формат ответа';
    throw new Error(msg);
  }
  const peer = r.config.peers && r.config.peers[0];
  const addrs = r.config.interface && r.config.interface.addresses;
  const privateKey = ownPrivateKey || r.key;
  if (!peer || !peer.public_key || !addrs || !addrs.v4 || !privateKey) {
    throw new Error('в ответе нет ключей или адресов');
  }
  return {
    privateKey,
    peerPublicKey: peer.public_key,
    v4: stripMask(addrs.v4),
    v6: addrs.v6 ? stripMask(addrs.v6) : '',
    license: (r.account && r.account.license) || '',
    ports: (peer.endpoint && peer.endpoint.ports) || [],
    source: ownPrivateKey ? 'local' : 'santa',
  };
}

function stripMask(a) {
  return String(a).split('/')[0].trim();
}

function formatHost(host) {
  return host.includes(':') && !host.startsWith('[') ? `[${host}]` : host;
}

export function buildConfig(reg, s) {
  const address = [`${reg.v4}/32`];
  if (s.ipv6 && reg.v6) address.push(`${reg.v6}/128`);

  let allowed = s.allowedIPs;
  let dns = resolveDns(s);
  if (!s.ipv6) {
    allowed = splitList(allowed).filter((x) => !x.includes(':')).join(', ') || '0.0.0.0/0';
    dns = splitList(dns).filter((x) => !x.includes(':')).join(', ') || '1.1.1.1';
  }

  const lines = [
    '[Interface]',
    `PrivateKey = ${reg.privateKey}`,
    `S1 = ${s.S1}`,
    `S2 = ${s.S2}`,
    `Jc = ${s.Jc}`,
    `Jmin = ${s.Jmin}`,
    `Jmax = ${s.Jmax}`,
    `H1 = ${s.H1}`,
    `H2 = ${s.H2}`,
    `H3 = ${s.H3}`,
    `H4 = ${s.H4}`,
    `MTU = ${s.mtu}`,
  ];
  if (s.useI1 && s.I1 && s.I1.trim()) lines.push(`I1 = ${s.I1.trim()}`);
  lines.push(
    `Address = ${address.join(', ')}`,
    `DNS = ${dns}`,
    '',
    '[Peer]',
    `PublicKey = ${reg.peerPublicKey}`,
    `AllowedIPs = ${allowed}`,
    `Endpoint = ${formatHost(s.endpointHost)}:${s.endpointPort}`,
  );
  if (Number(s.keepalive) > 0) lines.push(`PersistentKeepalive = ${s.keepalive}`);
  return lines.join('\n') + '\n';
}

function splitList(v) {
  return String(v).split(',').map((x) => x.trim()).filter(Boolean);
}

// Basic validation; returns a list of problems in Russian.
export function validateSettings(s) {
  const errs = [];
  const int = (k, min, max) => {
    const n = Number(s[k]);
    if (!Number.isInteger(n) || n < min || n > max) errs.push(`${k}: целое от ${min} до ${max}`);
  };
  int('Jc', 0, 128);
  int('Jmin', 0, 1280);
  int('Jmax', 0, 1280);
  int('S1', 0, 1132);
  int('S2', 0, 1188);
  for (const h of ['H1', 'H2', 'H3', 'H4']) int(h, 0, 4294967295);
  int('mtu', 1280, 1500);
  int('endpointPort', 1, 65535);
  int('keepalive', 0, 65535);
  if (Number(s.Jmin) > Number(s.Jmax)) errs.push('Jmin не может быть больше Jmax');
  if (!String(s.endpointHost || '').trim()) errs.push('не указан адрес endpoint');
  if (s.dnsPreset === 'custom' || !DNS_PRESETS.some((p) => p.id === s.dnsPreset)) {
    const list = splitList(s.dns);
    if (!list.length) errs.push('DNS: укажите хотя бы один адрес');
    else if (list.some((x) => !isIp(x))) errs.push('DNS: только IP-адреса через запятую');
  }
  if (s.useI1 && s.I1 && !/^<[^>]+>(\s*<[^>]+>)*$/.test(s.I1.trim())) errs.push('I1: ожидается формат вида <b 0x…>');
  return errs;
}

function isIp(x) {
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(x)) return x.split('.').every((o) => Number(o) <= 255);
  return /^[0-9a-f:]+$/i.test(x) && x.includes(':') && (x.match(/::/g) || []).length <= 1;
}

export function isValidWgKey(b64) {
  return /^[A-Za-z0-9+/]{43}=$/.test(String(b64 || ''));
}

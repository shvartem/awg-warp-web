// CIDR arithmetic on BigInt for IPv4 and IPv6: parse, format, subtract.
// Used to turn "0.0.0.0/0, ::/0" into the same space minus local networks.

export const LAN_V4 = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '169.254.0.0/16', '224.0.0.0/4'];
export const LAN_V6 = ['fc00::/7', 'fe80::/10', 'ff00::/8'];

function parseV4(s) {
  const parts = s.split('.');
  if (parts.length !== 4) return null;
  let n = 0n;
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p) || Number(p) > 255) return null;
    n = (n << 8n) | BigInt(p);
  }
  return n;
}

function parseV6(s) {
  if (!/^[0-9a-f:]+$/i.test(s) || (s.match(/::/g) || []).length > 1) return null;
  const [head, tail] = s.includes('::') ? s.split('::') : [s, null];
  const h = head ? head.split(':') : [];
  const t = tail ? tail.split(':') : [];
  if (tail === null && h.length !== 8) return null;
  if (tail !== null && h.length + t.length > 7) return null;
  const groups = tail === null ? h : [...h, ...Array(8 - h.length - t.length).fill('0'), ...t];
  let n = 0n;
  for (const g of groups) {
    if (!/^[0-9a-f]{1,4}$/i.test(g)) return null;
    n = (n << 16n) | BigInt(parseInt(g, 16));
  }
  return n;
}

/** "10.0.0.0/8" or "::/0" or a bare address → { v: 4|6, addr: BigInt, len } (host bits cleared), or null. */
export function parseCidr(str) {
  const m = String(str).trim().match(/^([^/\s]+)(?:\/(\d{1,3}))?$/);
  if (!m) return null;
  const v = m[1].includes(':') ? 6 : 4;
  const bits = v === 4 ? 32 : 128;
  const addr = v === 4 ? parseV4(m[1]) : parseV6(m[1]);
  const len = m[2] === undefined ? bits : Number(m[2]);
  if (addr === null || len > bits) return null;
  const mask = len === 0 ? 0n : ((1n << BigInt(len)) - 1n) << BigInt(bits - len);
  return { v, addr: addr & mask, len };
}

function formatV6(n) {
  const groups = [];
  for (let i = 7; i >= 0; i--) groups.push(Number((n >> BigInt(i * 16)) & 0xffffn).toString(16));
  // compress the longest run of zero groups (length ≥ 2)
  let best = -1, bestLen = 0;
  for (let i = 0; i < 8; ) {
    if (groups[i] !== '0') { i++; continue; }
    let j = i;
    while (j < 8 && groups[j] === '0') j++;
    if (j - i > bestLen && j - i >= 2) { best = i; bestLen = j - i; }
    i = j;
  }
  if (best < 0) return groups.join(':');
  return `${groups.slice(0, best).join(':')}::${groups.slice(best + bestLen).join(':')}`;
}

export function formatCidr({ v, addr, len }) {
  if (v === 4) {
    const o = [24n, 16n, 8n, 0n].map((s) => Number((addr >> s) & 0xffn));
    return `${o.join('.')}/${len}`;
  }
  return `${formatV6(addr)}/${len}`;
}

function contains(a, b) {
  // does a contain b (same family)?
  if (a.len > b.len) return false;
  const bits = a.v === 4 ? 32 : 128;
  return (b.addr >> BigInt(bits - a.len)) === (a.addr >> BigInt(bits - a.len)) || a.len === 0;
}

function subtractOne(net, ex) {
  if (net.v !== ex.v) return [net];
  if (contains(ex, net)) return [];
  if (!contains(net, ex)) return [net];
  // ex is strictly inside net: split net in halves and recurse
  const bits = net.v === 4 ? 32 : 128;
  const len = net.len + 1;
  const lo = { v: net.v, addr: net.addr, len };
  const hi = { v: net.v, addr: net.addr | (1n << BigInt(bits - len)), len };
  return [...subtractOne(lo, ex), ...subtractOne(hi, ex)];
}

/** Subtracts CIDR strings `excludes` from CIDR strings `nets`; returns CIDR strings. */
export function subtractCidrs(nets, excludes) {
  let list = nets.map((n) => {
    const p = parseCidr(n);
    if (!p) throw new Error(`неверный диапазон: ${n}`);
    return p;
  });
  for (const e of excludes) {
    const ex = parseCidr(e);
    list = list.flatMap((n) => subtractOne(n, ex));
  }
  return list.map(formatCidr);
}

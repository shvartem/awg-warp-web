// X25519 (RFC 7748) on BigInt. Used to generate a WireGuard key pair in the
// browser so the private key never leaves the device. Works in every modern
// browser, no WebCrypto X25519 support required.

const P = (1n << 255n) - 19n;
const A24 = 121665n;

const mod = (a) => {
  const r = a % P;
  return r >= 0n ? r : r + P;
};

function pow(base, exp) {
  let result = 1n;
  let b = mod(base);
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = mod(result * b);
    b = mod(b * b);
    e >>= 1n;
  }
  return result;
}

function bytesToBigLE(bytes) {
  let n = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(bytes[i]);
  return n;
}

function bigToBytesLE(n) {
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return out;
}

export function clampScalar(bytes) {
  const k = Uint8Array.from(bytes);
  k[0] &= 248;
  k[31] &= 127;
  k[31] |= 64;
  return k;
}

export function scalarMult(scalarBytes, uBytes) {
  const k = bytesToBigLE(clampScalar(scalarBytes));
  const uCopy = Uint8Array.from(uBytes);
  uCopy[31] &= 127;
  const x1 = mod(bytesToBigLE(uCopy));

  let x2 = 1n, z2 = 0n, x3 = x1, z3 = 1n;
  let swap = 0n;

  for (let t = 254n; t >= 0n; t--) {
    const kt = (k >> t) & 1n;
    swap ^= kt;
    if (swap) { [x2, x3] = [x3, x2]; [z2, z3] = [z3, z2]; }
    swap = kt;

    const A = mod(x2 + z2);
    const AA = mod(A * A);
    const B = mod(x2 - z2);
    const BB = mod(B * B);
    const E = mod(AA - BB);
    const C = mod(x3 + z3);
    const D = mod(x3 - z3);
    const DA = mod(D * A);
    const CB = mod(C * B);
    x3 = mod((DA + CB) ** 2n);
    z3 = mod(x1 * mod((DA - CB) ** 2n));
    x2 = mod(AA * BB);
    z2 = mod(E * (AA + A24 * E));
  }
  if (swap) { [x2, x3] = [x3, x2]; [z2, z3] = [z3, z2]; }

  return bigToBytesLE(mod(x2 * pow(z2, P - 2n)));
}

const BASE = (() => { const b = new Uint8Array(32); b[0] = 9; return b; })();

export function publicKeyFromPrivate(privateBytes) {
  return scalarMult(privateBytes, BASE);
}

export function toBase64(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

export function fromBase64(str) {
  const bin = atob(str.trim());
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// Same as `wg genkey` + `wg pubkey`.
export function generateKeyPair(randomBytes = (n) => crypto.getRandomValues(new Uint8Array(n))) {
  const priv = clampScalar(randomBytes(32));
  const pub = publicKeyFromPrivate(priv);
  return { privateKey: toBase64(priv), publicKey: toBase64(pub) };
}

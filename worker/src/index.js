// Cloudflare Worker: CORS proxy for the static page.
//   GET  /santa  -> env.SANTA_URL (the key generator; the key is created there)
//   POST /reg    -> official Cloudflare WARP API, registers a PUBLIC key
//                   generated in the browser (private key never reaches here)
// Only these two upstreams are reachable, so this is not an open proxy.
//
// Environment (Worker → Settings → Variables and Secrets):
//   SANTA_URL        secret, required for /santa
//   ALLOWED_ORIGINS  comma-separated page origins allowed to call the proxy; "*" or unset = any
// Binding (wrangler.toml): RATE_LIMITER — per-IP limit for /santa and /reg.

// Same values as wgcf (github.com/ViRb3/wgcf, cloudflare/api.go).
const CF_API = 'https://api.cloudflareclient.com/v0a5641/reg';
const CF_HEADERS = {
  'User-Agent': '1.1.1.1/6.38.9-5641 (Android 16.0.0)',
  'CF-Client-Version': 'a-6.38.9-5641',
  'Content-Type': 'application/json; charset=UTF-8',
  Accept: 'application/json',
};

const KEY_RE = /^[A-Za-z0-9+/]{43}=$/;

function allowedOrigin(request, env) {
  const origin = request.headers.get('Origin');
  const list = String(env.ALLOWED_ORIGINS || '*').split(',').map((s) => s.trim()).filter(Boolean);
  if (list.includes('*')) return origin || '*';
  return origin && list.includes(origin) ? origin : null;
}

function corsHeaders(origin) {
  return {
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Max-Age': '86400',
    Vary: 'Origin',
  };
}

function json(body, status, origin) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...corsHeaders(origin) },
  });
}

async function relay(upstream, origin, transform) {
  const text = await upstream.text();
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    return json({ success: false, errors: [{ message: `upstream returned non-JSON (HTTP ${upstream.status})` }] }, 502, origin);
  }
  if (transform) data = transform(data);
  return json(data, upstream.ok ? 200 : upstream.status, origin);
}

// The access token lets anyone manage the device; the page does not need it.
function stripSecrets(data) {
  if (data && data.result) delete data.result.token;
  return data;
}

// Approximate per-IP, per-route limit (Cloudflare Rate Limiting binding).
// Returns true when the request may proceed. Without the binding, no limit.
async function withinLimit(request, env, route) {
  if (!env.RATE_LIMITER) return true;
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  try {
    const { success } = await env.RATE_LIMITER.limit({ key: `${route}:${ip}` });
    return success;
  } catch {
    return true; // never block users because the limiter itself failed
  }
}

function tooMany(origin) {
  const res = json({ success: false, errors: [{ message: 'rate limited' }] }, 429, origin);
  res.headers.set('Retry-After', '60');
  return res;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // Health check works when the address is opened directly in a browser tab
    // (no Origin header). It reveals nothing but whether config is present.
    if (request.method === 'GET' && (url.pathname === '/' || url.pathname === '/health')) {
      return new Response(JSON.stringify({ ok: true, santa: Boolean(env.SANTA_URL), ratelimit: Boolean(env.RATE_LIMITER) }), {
        headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' },
      });
    }

    const origin = allowedOrigin(request, env);
    if (!origin) return new Response('Origin not allowed', { status: 403 });

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(origin) });
    }

    try {
      if (url.pathname === '/santa' && request.method === 'GET') {
        if (!env.SANTA_URL) {
          return json({ success: false, errors: [{ message: 'SANTA_URL is not configured on the Worker' }] }, 500, origin);
        }
        if (!(await withinLimit(request, env, 'santa'))) return tooMany(origin);
        const upstream = await fetch(env.SANTA_URL, {
          headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36', Accept: 'application/json' },
          cf: { cacheTtl: 0 },
        });
        return relay(upstream, origin);
      }

      if (url.pathname === '/reg' && request.method === 'POST') {
        let body;
        try { body = await request.json(); } catch { body = null; }
        const key = body && body.key;
        if (!KEY_RE.test(String(key || ''))) {
          return json({ success: false, errors: [{ message: 'invalid public key' }] }, 400, origin);
        }
        if (!(await withinLimit(request, env, 'reg'))) return tooMany(origin);
        const payload = {
          key,
          install_id: '',
          fcm_token: '',
          tos: new Date().toISOString(),
          model: 'PC',
          serial_number: '',
          os_version: '16.0.0',
          key_type: 'curve25519',
          tunnel_type: 'wireguard',
          locale: 'en_US',
        };
        const upstream = await fetch(CF_API, { method: 'POST', headers: CF_HEADERS, body: JSON.stringify(payload) });
        return relay(upstream, origin, stripSecrets);
      }

      return json({ success: false, errors: [{ message: 'not found' }] }, 404, origin);
    } catch (e) {
      return json({ success: false, errors: [{ message: `upstream unreachable: ${e.message}` }] }, 502, origin);
    }
  },
};

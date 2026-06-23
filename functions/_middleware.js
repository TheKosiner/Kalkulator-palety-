// Auth guard for /app.html — runs on every request via Cloudflare Pages middleware

const _enc = new TextEncoder();

function _fromB64url(s) {
  return atob(s.replace(/-/g, '+').replace(/_/g, '/'));
}

async function verifyJWT(token, secret) {
  try {
    const [header, body, sig] = token.split('.');
    if (!header || !body || !sig) return null;
    const key = await crypto.subtle.importKey(
      'raw', _enc.encode(secret),
      { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']
    );
    const sigBytes = Uint8Array.from(_fromB64url(sig), c => c.charCodeAt(0));
    const valid = await crypto.subtle.verify('HMAC', key, sigBytes, _enc.encode(`${header}.${body}`));
    if (!valid) return null;
    const payload = JSON.parse(_fromB64url(body));
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch {
    return null;
  }
}

function isActive(user) {
  const now = Math.floor(Date.now() / 1000);
  if (user.subscription_status === 'active' &&
      (!user.subscription_ends_at || user.subscription_ends_at > now)) return true;
  if (user.subscription_status === 'trial' && user.trial_ends_at > now) return true;
  return false;
}

export async function onRequest(context) {
  const { request, next, env } = context;
  const url = new URL(request.url);
  const path = url.pathname;

  // Only protect the calculator page
  if (path === '/app.html' || path === '/app') {
    // Skip if bindings not configured (local dev without D1 / secrets)
    if (!env.JWT_SECRET || !env.DB) return next();

    const cookie = request.headers.get('Cookie') || '';
    const m = cookie.match(/token=([^;]+)/);
    if (!m) return Response.redirect(`${url.origin}/?login=1`, 302);

    const payload = await verifyJWT(m[1], env.JWT_SECRET);
    if (!payload) return Response.redirect(`${url.origin}/?login=1`, 302);

    const user = await env.DB
      .prepare('SELECT * FROM users WHERE id = ?')
      .bind(payload.sub)
      .first();

    if (!user) return Response.redirect(`${url.origin}/?login=1`, 302);
    if (!isActive(user)) return Response.redirect(`${url.origin}/account.html?expired=1`, 302);
  }

  return next();
}

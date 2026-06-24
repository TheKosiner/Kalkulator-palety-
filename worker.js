// ─── UTILITIES ───────────────────────────────────────────────────────────────

const _enc = new TextEncoder();

function jsonRes(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...extra }
  });
}

function setCookie(name, value, maxAge) {
  return `${name}=${value}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${maxAge}`;
}

function b64url(s) { return btoa(s).replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_'); }
function b64urlArr(buf) { return btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_'); }
function fromB64url(s) { return atob(s.replace(/-/g,'+').replace(/_/g,'/')); }

async function hashPassword(password, salt) {
  const key = await crypto.subtle.importKey('raw', _enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: _enc.encode(salt), iterations: 100000 }, key, 256
  );
  return Array.from(new Uint8Array(bits)).map(b => b.toString(16).padStart(2,'0')).join('');
}

function randomStr(len = 32) {
  const buf = new Uint8Array(len);
  crypto.getRandomValues(buf);
  return Array.from(buf).map(b => b.toString(16).padStart(2,'0')).join('').slice(0, len);
}

async function signJWT(payload, secret) {
  const h = b64url(JSON.stringify({ alg:'HS256', typ:'JWT' }));
  const b = b64url(JSON.stringify(payload));
  const key = await crypto.subtle.importKey('raw', _enc.encode(secret), { name:'HMAC', hash:'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, _enc.encode(`${h}.${b}`));
  return `${h}.${b}.${b64urlArr(sig)}`;
}

async function verifyJWT(token, secret) {
  try {
    const [h, b, sig] = token.split('.');
    if (!h || !b || !sig) return null;
    const key = await crypto.subtle.importKey('raw', _enc.encode(secret), { name:'HMAC', hash:'SHA-256' }, false, ['verify']);
    const sigBytes = Uint8Array.from(fromB64url(sig), c => c.charCodeAt(0));
    const valid = await crypto.subtle.verify('HMAC', key, sigBytes, _enc.encode(`${h}.${b}`));
    if (!valid) return null;
    const payload = JSON.parse(fromB64url(b));
    if (payload.exp && payload.exp < Math.floor(Date.now()/1000)) return null;
    return payload;
  } catch { return null; }
}

async function getUser(request, env) {
  const cookie = request.headers.get('Cookie') || '';
  const m = cookie.match(/token=([^;]+)/);
  if (!m) return null;
  const payload = await verifyJWT(m[1], env.JWT_SECRET);
  if (!payload) return null;
  return env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(payload.sub).first();
}

function isActive(user) {
  const now = Math.floor(Date.now()/1000);
  if (user.subscription_status === 'active' && (!user.subscription_ends_at || user.subscription_ends_at > now)) return true;
  if (user.subscription_status === 'trial' && user.trial_ends_at > now) return true;
  return false;
}

function subInfo(user) {
  const now = Math.floor(Date.now()/1000);
  if (user.subscription_status === 'trial') {
    const daysLeft = Math.max(0, Math.ceil((user.trial_ends_at - now) / 86400));
    return { status:'trial', active: daysLeft > 0, daysLeft };
  }
  if (user.subscription_status === 'active') {
    return { status:'active', active:true, endsAt: user.subscription_ends_at };
  }
  return { status: user.subscription_status || 'expired', active:false };
}

// ─── EMAIL ───────────────────────────────────────────────────────────────────

async function sendEmail(env, to, subject, html) {
  if (!env.RESEND_API_KEY) return false;
  try {
    const res = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ from: 'Pallet3D <noreply@pallet3d.com>', to: [to], subject, html })
    });
    return res.ok;
  } catch { return false; }
}

// ─── STRIPE ──────────────────────────────────────────────────────────────────

async function stripePost(env, path, body) {
  const res = await fetch(`https://api.stripe.com/v1${path}`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${env.STRIPE_SECRET_KEY}`, 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(body).toString()
  });
  return res.json();
}

async function verifyStripeWebhook(body, sigHeader, secret) {
  const parts = sigHeader.split(',');
  const ts = parts.find(p => p.startsWith('t='))?.split('=')[1];
  const v1s = parts.filter(p => p.startsWith('v1=')).map(p => p.split('=')[1]);
  if (!ts || !v1s.length) throw new Error('Missing signature parts');
  const key = await crypto.subtle.importKey('raw', _enc.encode(secret), { name:'HMAC', hash:'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, _enc.encode(`${ts}.${body}`));
  const hex = Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2,'0')).join('');
  if (!v1s.includes(hex)) throw new Error('Signature mismatch');
  if (Math.abs(Date.now()/1000 - parseInt(ts)) > 300) throw new Error('Timestamp too old');
  return JSON.parse(body);
}

// ─── API HANDLERS ─────────────────────────────────────────────────────────────

async function apiRegister(request, env) {
  const body = await request.json().catch(() => null);
  if (!body?.email || !body?.password || !body?.name) return jsonRes({ error:'Uzupełnij wszystkie pola.' }, 400);
  const email = body.email.trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return jsonRes({ error:'Nieprawidłowy adres e-mail.' }, 400);
  if (body.password.length < 8) return jsonRes({ error:'Hasło musi mieć co najmniej 8 znaków.' }, 400);
  const existing = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email).first();
  if (existing) return jsonRes({ error:'Konto z tym adresem już istnieje.' }, 409);
  const id = randomStr(20), salt = randomStr(32);
  const hash = await hashPassword(body.password, salt);
  const now = Math.floor(Date.now()/1000);
  const trialDays = parseInt(env.TRIAL_DAYS || '14');
  const needsVerification = !!env.RESEND_API_KEY;
  const verifyToken = needsVerification ? randomStr(32) : null;

  await env.DB.prepare(
    'INSERT INTO users (id,email,name,password_hash,salt,created_at,trial_ends_at,subscription_status,email_verified,email_verify_token) VALUES (?,?,?,?,?,?,?,?,?,?)'
  ).bind(id, email, body.name.trim(), hash, salt, now, now + trialDays * 86400, 'trial', needsVerification ? 0 : 1, verifyToken).run();

  if (needsVerification) {
    const firstName = body.name.trim().split(' ')[0];
    await sendEmail(env, email, 'Potwierdź adres e-mail — Pallet3D', `
      <div style="font-family:sans-serif;max-width:520px;margin:0 auto;padding:24px">
        <h2 style="color:#1e293b">Cześć ${firstName}!</h2>
        <p>Kliknij przycisk poniżej, aby potwierdzić adres e-mail i aktywować 14-dniowy okres próbny Pallet3D.</p>
        <p><a href="${env.APP_URL}/api/auth/verify-email?token=${verifyToken}"
          style="display:inline-block;background:#3b82f6;color:#fff;padding:12px 28px;border-radius:8px;text-decoration:none;font-weight:700;font-size:1rem">
          Potwierdź adres e-mail
        </a></p>
        <p style="color:#94a3b8;font-size:.82rem">Link jest ważny 24 godziny. Jeśli nie zakładałeś konta na Pallet3D, zignoruj tę wiadomość.</p>
      </div>
    `);
    return jsonRes({ ok: true, needsVerification: true }, 201);
  }

  const token = await signJWT({ sub:id, exp: now + 7*86400 }, env.JWT_SECRET);
  return new Response(JSON.stringify({ ok:true }), { status:201, headers:{ 'Content-Type':'application/json', 'Set-Cookie': setCookie('token', token, 7*86400) }});
}

async function apiLogin(request, env) {
  const body = await request.json().catch(() => null);
  if (!body?.email || !body?.password) return jsonRes({ error:'Uzupełnij wszystkie pola.' }, 400);
  const email = body.email.trim().toLowerCase();
  const user = await env.DB.prepare('SELECT * FROM users WHERE email = ?').bind(email).first();
  if (!user) return jsonRes({ error:'Nieprawidłowy e-mail lub hasło.' }, 401);
  if (!user.password_hash) return jsonRes({ error:'To konto używa logowania przez Google. Kliknij „Zaloguj się przez Google".' }, 401);
  const hash = await hashPassword(body.password, user.salt);
  if (hash !== user.password_hash) return jsonRes({ error:'Nieprawidłowy e-mail lub hasło.' }, 401);
  if (user.email_verified === 0) {
    return jsonRes({ error:'Potwierdź adres e-mail — sprawdź skrzynkę odbiorczą.', needsVerification: true, email }, 403);
  }
  const now = Math.floor(Date.now()/1000);
  const token = await signJWT({ sub:user.id, exp: now + 7*86400 }, env.JWT_SECRET);
  return new Response(JSON.stringify({ ok:true }), { headers:{ 'Content-Type':'application/json', 'Set-Cookie': setCookie('token', token, 7*86400) }});
}

function apiLogout() {
  return new Response(JSON.stringify({ ok:true }), { headers:{ 'Content-Type':'application/json', 'Set-Cookie':'token=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0' }});
}

async function apiMe(request, env) {
  const user = await getUser(request, env);
  if (!user) return jsonRes({ error:'Niezalogowany.' }, 401);
  return jsonRes({ name:user.name, email:user.email, emailVerified: user.email_verified !== 0, subscription: subInfo(user) });
}

async function apiVerifyEmail(request, env) {
  const url = new URL(request.url);
  const token = url.searchParams.get('token');
  const appUrl = env.APP_URL || 'https://pallet3d.com';
  if (!token) return Response.redirect(`${appUrl}/?login=1`, 302);
  const user = await env.DB.prepare('SELECT id FROM users WHERE email_verify_token = ?').bind(token).first();
  if (!user) return Response.redirect(`${appUrl}/?login=1&verifyErr=1`, 302);
  await env.DB.prepare('UPDATE users SET email_verified = 1, email_verify_token = NULL WHERE id = ?').bind(user.id).run();
  const now = Math.floor(Date.now()/1000);
  const jwt = await signJWT({ sub: user.id, exp: now + 7*86400 }, env.JWT_SECRET);
  return new Response(null, { status: 302, headers: { 'Location': `${appUrl}/app.html`, 'Set-Cookie': setCookie('token', jwt, 7*86400) }});
}

async function apiResendVerification(request, env) {
  const body = await request.json().catch(() => null);
  if (!body?.email) return jsonRes({ error: 'Podaj adres e-mail.' }, 400);
  const email = body.email.trim().toLowerCase();
  const user = await env.DB.prepare('SELECT * FROM users WHERE email = ?').bind(email).first();
  if (!user || user.email_verified !== 0) return jsonRes({ ok: true });
  const verifyToken = randomStr(32);
  await env.DB.prepare('UPDATE users SET email_verify_token = ? WHERE id = ?').bind(verifyToken, user.id).run();
  const firstName = user.name.split(' ')[0];
  await sendEmail(env, email, 'Potwierdź adres e-mail — Pallet3D', `
    <div style="font-family:sans-serif;max-width:520px;margin:0 auto;padding:24px">
      <h2 style="color:#1e293b">Cześć ${firstName}!</h2>
      <p>Kliknij poniższy przycisk, aby potwierdzić adres e-mail:</p>
      <p><a href="${env.APP_URL}/api/auth/verify-email?token=${verifyToken}"
        style="display:inline-block;background:#3b82f6;color:#fff;padding:12px 28px;border-radius:8px;text-decoration:none;font-weight:700">
        Potwierdź adres e-mail
      </a></p>
    </div>
  `);
  return jsonRes({ ok: true });
}

async function apiChangePassword(request, env) {
  const user = await getUser(request, env);
  if (!user) return jsonRes({ error: 'Niezalogowany.' }, 401);
  const body = await request.json().catch(() => null);
  if (!body?.newPassword) return jsonRes({ error: 'Uzupełnij wszystkie pola.' }, 400);
  if (body.newPassword.length < 8) return jsonRes({ error: 'Nowe hasło musi mieć co najmniej 8 znaków.' }, 400);
  if (user.password_hash) {
    if (!body.currentPassword) return jsonRes({ error: 'Podaj aktualne hasło.' }, 400);
    const hash = await hashPassword(body.currentPassword, user.salt);
    if (hash !== user.password_hash) return jsonRes({ error: 'Nieprawidłowe aktualne hasło.' }, 401);
  }
  const newSalt = randomStr(32);
  const newHash = await hashPassword(body.newPassword, newSalt);
  await env.DB.prepare('UPDATE users SET password_hash = ?, salt = ? WHERE id = ?').bind(newHash, newSalt, user.id).run();
  return jsonRes({ ok: true });
}

async function apiGoogleAuth(request, env) {
  if (!env.GOOGLE_CLIENT_ID) return jsonRes({ error: 'Google OAuth nie jest skonfigurowane.' }, 503);
  const appUrl = env.APP_URL || 'https://pallet3d.com';
  const params = new URLSearchParams({
    client_id: env.GOOGLE_CLIENT_ID,
    redirect_uri: `${appUrl}/api/auth/google/callback`,
    response_type: 'code',
    scope: 'openid email profile',
    prompt: 'select_account'
  });
  return Response.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params}`, 302);
}

async function apiGoogleCallback(request, env) {
  const url = new URL(request.url);
  const code = url.searchParams.get('code');
  const appUrl = env.APP_URL || 'https://pallet3d.com';
  if (!code) return Response.redirect(`${appUrl}/?login=1`, 302);

  const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      code, client_id: env.GOOGLE_CLIENT_ID, client_secret: env.GOOGLE_CLIENT_SECRET,
      redirect_uri: `${appUrl}/api/auth/google/callback`, grant_type: 'authorization_code'
    }).toString()
  });
  const tokens = await tokenRes.json();
  if (!tokens.access_token) return Response.redirect(`${appUrl}/?login=1`, 302);

  const infoRes = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
    headers: { Authorization: `Bearer ${tokens.access_token}` }
  });
  const gUser = await infoRes.json();
  if (!gUser.email) return Response.redirect(`${appUrl}/?login=1`, 302);

  let user = await env.DB.prepare('SELECT * FROM users WHERE google_id = ? OR email = ?').bind(gUser.id, gUser.email).first();
  const now = Math.floor(Date.now()/1000);

  if (!user) {
    const id = randomStr(20);
    const trialDays = parseInt(env.TRIAL_DAYS || '14');
    await env.DB.prepare(
      'INSERT INTO users (id,email,name,password_hash,salt,created_at,trial_ends_at,subscription_status,email_verified,google_id) VALUES (?,?,?,?,?,?,?,?,1,?)'
    ).bind(id, gUser.email, gUser.name || gUser.email, '', '', now, now + trialDays * 86400, 'trial', gUser.id).run();
    user = { id };
  } else if (!user.google_id) {
    await env.DB.prepare('UPDATE users SET google_id = ?, email_verified = 1 WHERE id = ?').bind(gUser.id, user.id).run();
  }

  const jwt = await signJWT({ sub: user.id, exp: now + 7*86400 }, env.JWT_SECRET);
  return new Response(null, { status: 302, headers: { 'Location': `${appUrl}/app.html`, 'Set-Cookie': setCookie('token', jwt, 7*86400) }});
}

async function apiCheckout(request, env) {
  const user = await getUser(request, env);
  if (!user) return jsonRes({ error:'Niezalogowany.' }, 401);
  const appUrl = env.APP_URL || 'https://pallet3d.com';
  let customerId = user.stripe_customer_id;
  if (!customerId) {
    const customer = await stripePost(env, '/customers', { email:user.email, name:user.name, 'metadata[userId]':user.id });
    if (!customer.id) return jsonRes({ error:'Błąd Stripe.' }, 502);
    customerId = customer.id;
    await env.DB.prepare('UPDATE users SET stripe_customer_id = ? WHERE id = ?').bind(customerId, user.id).run();
  }
  const session = await stripePost(env, '/checkout/sessions', {
    customer: customerId, mode:'subscription',
    'line_items[0][price]': env.STRIPE_PRICE_ID, 'line_items[0][quantity]':'1',
    success_url:`${appUrl}/account.html?success=1`, cancel_url:`${appUrl}/account.html`,
    'subscription_data[metadata][userId]':user.id, allow_promotion_codes:'true'
  });
  if (!session.url) return jsonRes({ error:'Błąd sesji płatności.' }, 502);
  return jsonRes({ url:session.url });
}

async function apiWebhook(request, env) {
  const body = await request.text();
  const sig = request.headers.get('Stripe-Signature') || '';
  let event;
  try { event = await verifyStripeWebhook(body, sig, env.STRIPE_WEBHOOK_SECRET); }
  catch (e) { return new Response(`Webhook error: ${e.message}`, { status:400 }); }
  const obj = event.data?.object;
  if (event.type === 'customer.subscription.created' || event.type === 'customer.subscription.updated') {
    const userId = obj.metadata?.userId;
    if (userId) {
      const active = obj.status === 'active' || obj.status === 'trialing';
      await env.DB.prepare('UPDATE users SET subscription_status=?,stripe_subscription_id=?,subscription_ends_at=? WHERE id=?')
        .bind(active ? 'active' : obj.status, obj.id, obj.current_period_end, userId).run();
    }
  }
  if (event.type === 'customer.subscription.deleted') {
    const userId = obj.metadata?.userId;
    if (userId) await env.DB.prepare('UPDATE users SET subscription_status=? WHERE id=?').bind('cancelled', userId).run();
  }
  if (event.type === 'invoice.payment_failed') {
    const subId = obj.subscription;
    if (subId) await env.DB.prepare('UPDATE users SET subscription_status=? WHERE stripe_subscription_id=?').bind('past_due', subId).run();
  }
  return jsonRes({ received:true });
}

async function apiBillingPortal(request, env) {
  const user = await getUser(request, env);
  if (!user) return jsonRes({ error:'Niezalogowany.' }, 401);
  if (!user.stripe_customer_id) return jsonRes({ error:'Brak subskrypcji.' }, 400);
  const appUrl = env.APP_URL || 'https://pallet3d.com';
  const session = await stripePost(env, '/billing_portal/sessions', { customer:user.stripe_customer_id, return_url:`${appUrl}/account.html` });
  if (!session.url) return jsonRes({ error:'Błąd portalu.' }, 502);
  return jsonRes({ url:session.url });
}

// ─── MAIN FETCH HANDLER ───────────────────────────────────────────────────────

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    // ── Auth guard for /app.html ──
    if (path === '/app.html' || path === '/app') {
      if (env.JWT_SECRET && env.DB) {
        const cookie = request.headers.get('Cookie') || '';
        const m = cookie.match(/token=([^;]+)/);
        if (!m) return Response.redirect(`${url.origin}/?login=1`, 302);
        const payload = await verifyJWT(m[1], env.JWT_SECRET);
        if (!payload) return Response.redirect(`${url.origin}/?login=1`, 302);
        const user = await env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(payload.sub).first();
        if (!user) return Response.redirect(`${url.origin}/?login=1`, 302);
        if (user.email_verified === 0) return Response.redirect(`${url.origin}/?login=1&verify=1`, 302);
        if (!isActive(user)) return Response.redirect(`${url.origin}/account.html?expired=1`, 302);
      }
      return env.ASSETS.fetch(request);
    }

    // ── API routes ──
    if (path.startsWith('/api/')) {
      const apiPath = path.replace('/api', '');
      if (method === 'OPTIONS') return new Response(null, { status:204, headers:{ 'Access-Control-Allow-Origin':'*', 'Access-Control-Allow-Methods':'GET,POST,OPTIONS', 'Access-Control-Allow-Headers':'Content-Type', 'Access-Control-Allow-Credentials':'true' }});
      try {
        if (method==='POST' && apiPath==='/auth/register')          return await apiRegister(request, env);
        if (method==='POST' && apiPath==='/auth/login')             return await apiLogin(request, env);
        if (method==='POST' && apiPath==='/auth/logout')            return await apiLogout();
        if (method==='GET'  && apiPath==='/auth/me')                return await apiMe(request, env);
        if (method==='GET'  && apiPath==='/auth/verify-email')      return await apiVerifyEmail(request, env);
        if (method==='POST' && apiPath==='/auth/resend-verification') return await apiResendVerification(request, env);
        if (method==='POST' && apiPath==='/auth/change-password')   return await apiChangePassword(request, env);
        if (method==='GET'  && apiPath==='/auth/google')            return await apiGoogleAuth(request, env);
        if (method==='GET'  && apiPath==='/auth/google/callback')   return await apiGoogleCallback(request, env);
        if (method==='POST' && apiPath==='/stripe/checkout')        return await apiCheckout(request, env);
        if (method==='POST' && apiPath==='/stripe/webhook')         return await apiWebhook(request, env);
        if (method==='GET'  && apiPath==='/billing/portal')         return await apiBillingPortal(request, env);
        return new Response('Not found', { status:404 });
      } catch(e) {
        return jsonRes({ error: e?.message || 'Internal server error' }, 500);
      }
    }

    // ── Static assets ──
    return env.ASSETS.fetch(request);
  }
};

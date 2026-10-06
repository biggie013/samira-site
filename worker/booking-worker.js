/**
 * Booking form → Telegram relay for the SAMIRA MAGERAMOVA site (Cloudflare Worker).
 *
 * The site posts { client_name, client_phone, consent_pd, consent_policy, website, startedAt }.
 * This function checks the request, forwards a short message to the owner's Telegram chat
 * and forgets it — nothing is written to any storage. The bot token never appears in the
 * repository: it lives only in the Worker's settings.
 *
 * Settings → Variables and Secrets:
 *   TELEGRAM_BOT_TOKEN  (Secret) — token from @BotFather
 *   TELEGRAM_CHAT_ID    (Secret) — the owner's chat id
 *   ALLOWED_ORIGIN      (Text)   — https://biggie013.github.io  (comma-separate to add more)
 * Optional binding RATE_LIMITER (Workers Rate Limiting) — used instead of the in-memory limit.
 */

const MAX_PER_WINDOW = 3;            // requests per visitor…
const WINDOW_MS = 10 * 60 * 1000;    // …per 10 minutes
const MIN_FILL_MS = 2000;            // a person needs at least this long to fill the form
const MAX_BODY_BYTES = 2048;

// Best-effort limit kept only in this instance's memory: salted hashes of IP addresses and
// timestamps, dropped after the window. No names, phones or raw IPs are kept.
const recent = new Map();
const SALT = crypto.randomUUID();

export default {
  async fetch(request, env) {
    const origin = request.headers.get('Origin') || '';
    const allowed = (env.ALLOWED_ORIGIN || '').split(',').map(s => s.trim()).filter(Boolean);
    const originOk = allowed.includes(origin);
    const cors = originOk ? {
      'Access-Control-Allow-Origin': origin,
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
      'Access-Control-Max-Age': '86400',
      'Vary': 'Origin',
    } : { 'Vary': 'Origin' };

    if (request.method === 'OPTIONS') return new Response(null, { status: originOk ? 204 : 403, headers: cors });
    if (request.method !== 'POST') return reply({ ok: false, error: 'method' }, 405, cors);
    if (!originOk) return reply({ ok: false, error: 'origin' }, 403, cors);
    if (!env.TELEGRAM_BOT_TOKEN || !env.TELEGRAM_CHAT_ID) return reply({ ok: false, error: 'not_configured' }, 500, cors);

    // --- body ---
    const raw = await request.text();
    if (raw.length > MAX_BODY_BYTES) return reply({ ok: false, error: 'too_large' }, 413, cors);
    let data;
    try { data = JSON.parse(raw); } catch { return reply({ ok: false, error: 'bad_json' }, 400, cors); }
    if (!data || typeof data !== 'object') return reply({ ok: false, error: 'bad_json' }, 400, cors);

    // --- spam traps ---
    // the hidden "website" field is invisible to people; anything in it means a bot.
    // Answer as if it worked, so the bot learns nothing, and send nothing.
    if (typeof data.website === 'string' && data.website.trim() !== '') return reply({ ok: true }, 200, cors);
    const started = Number(data.startedAt);
    if (!Number.isFinite(started) || Date.now() - started < MIN_FILL_MS) {
      return reply({ ok: false, error: 'too_fast' }, 400, cors);
    }

    // --- both consent ticks are required ---
    if (data.consent_pd !== true || data.consent_policy !== true) {
      return reply({ ok: false, error: 'consent' }, 400, cors);
    }

    // --- fields ---
    const name = clean(data.client_name);
    const phone = clean(data.client_phone);
    const digits = phone.replace(/\D/g, '');
    if (name.length < 1 || name.length > 80 || /https?:|www\.|<|>/i.test(name)) {
      return reply({ ok: false, error: 'name' }, 400, cors);
    }
    if (phone.length > 30 || !/^[\d\s()+\-]+$/.test(phone) || digits.length < 10 || digits.length > 15) {
      return reply({ ok: false, error: 'phone' }, 400, cors);
    }

    // --- rate limit ---
    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
    const key = await sha256(SALT + ip);
    if (env.RATE_LIMITER) {
      const { success } = await env.RATE_LIMITER.limit({ key });
      if (!success) return reply({ ok: false, error: 'rate' }, 429, cors);
    } else if (!allowHit(key)) {
      return reply({ ok: false, error: 'rate' }, 429, cors);
    }

    // --- send ---
    const time = new Date().toLocaleString('ru-RU', {
      timeZone: 'Europe/Moscow', day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit',
    });
    const text = `Новая заявка с сайта\nИмя: ${name}\nТелефон: ${phone}\nВремя: ${time} (МСК)`;
    const tg = await fetch(`https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: env.TELEGRAM_CHAT_ID, text, disable_web_page_preview: true }),
    }).catch(() => null);
    if (!tg || !tg.ok) {
      // status only — never the request body, so no personal data lands in logs
      console.log('telegram send failed', tg ? tg.status : 'network');
      return reply({ ok: false, error: 'telegram' }, 502, cors);
    }
    return reply({ ok: true }, 200, cors);
  },
};

function clean(value) {
  return typeof value === 'string' ? value.replace(/\s+/g, ' ').trim() : '';
}

function allowHit(key) {
  const now = Date.now();
  for (const [k, times] of recent) {
    const fresh = times.filter(t => now - t < WINDOW_MS);
    if (fresh.length) recent.set(k, fresh); else recent.delete(k);
  }
  const times = recent.get(key) || [];
  if (times.length >= MAX_PER_WINDOW) return false;
  times.push(now);
  recent.set(key, times);
  return true;
}

async function sha256(text) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}

function reply(body, status, headers) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...headers, 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' },
  });
}

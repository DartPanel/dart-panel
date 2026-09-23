// Dart Panel - Cloudflare Worker entry point.
import { appHtml } from './ui.generated.js';
import { connect } from 'cloudflare:sockets';
import * as Auth from './auth.js';
import { SUB_FORMATS, buildLinks, buildSubscription } from './configs.js';
import * as Settings from './settings.js';
import { handleWebsocket } from './websocket.js';
import * as TG from './telegram.js';

const headers = {
  'Cache-Control': 'no-store',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  'Content-Security-Policy':
    "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
};

const json = (data, status = 200, extra = {}) => Response.json(data, { status, headers: { ...headers, ...extra } });
const notFound = () => new Response('Not found', { status: 404 });

async function readBody(request) {
  try { return (await request.json()) ?? {}; } catch { return {}; }
}

// Settings are read on every tunnel connection, so keep a short in-memory copy.
let cached = { at: 0, value: null };
const invalidateSettingsCache = () => { cached = { at: 0, value: null }; };
async function cachedSettings(env) {
  if (cached.value && Date.now() - cached.at < 30000) return cached.value;
  cached = { at: Date.now(), value: await Settings.loadSettings(env) };
  return cached.value;
}

function redact(settings) {
  // Never send the bot token or webhook secret to the browser; /api/telegram covers what the UI needs.
  const { telegram, ...rest } = settings;
  return { ...rest, telegram: { chatId: telegram.chatId, botUsername: telegram.botUsername, connected: !!telegram.token } };
}

async function settingsView(env, url) {
  // env.SECURE_PATH is the tunnel path used inside generated configs
  const settings = await Settings.loadSettings(env);
  const subs = Object.entries(SUB_FORMATS).map(([id, f]) => ({ id, label: f.label, apps: f.apps, url: `${url.origin}/${settings.subToken}/${id}` }));
  const links = buildLinks(settings, url.host, env.SECURE_PATH).map((l) => ({ name: decodeURIComponent(l.split('#')[1]), url: l }));
  return { settings: redact(settings), subs, links, limits: { tlsPorts: Settings.TLS_PORTS, fragmentPackets: Settings.FRAGMENT_PACKETS, fingerprints: Settings.FINGERPRINTS } };
}

async function subscription(env, url, token, format) {
  const settings = await cachedSettings(env);
  if (token !== settings.subToken || !SUB_FORMATS[format]) return notFound();
  const body = buildSubscription(format, settings, url.host, env.SECURE_PATH);
  return new Response(body, { headers: { 'Content-Type': `${SUB_FORMATS[format].type}; charset=utf-8`, 'Cache-Control': 'no-store', 'Profile-Update-Interval': '6', 'Content-Disposition': `inline; filename="dart-${format}"` } });
}


// ---- Telegram bot ----
function telegramView(settings) {
  const t = settings.telegram;
  return { connected: !!t.token, botUsername: t.botUsername, linked: !!t.chatId };
}

async function saveTelegramToken(env, token) {
  token = String(token || '').trim();
  const me = await TG.getMe(token); // throws if the token is invalid
  const s = await Settings.loadSettings(env);
  const webhookSecret = crypto.randomUUID();
  s.telegram = { token, botUsername: me.username, chatId: '', webhookSecret };
  await env.kv.put('settings', JSON.stringify(s));
  return s;
}

async function disconnectTelegram(env) {
  const s = await Settings.loadSettings(env);
  if (s.telegram.token) await TG.deleteWebhook(s.telegram.token).catch(() => {});
  s.telegram = { token: '', chatId: '', botUsername: '', webhookSecret: '' };
  await env.kv.put('settings', JSON.stringify(s));
  return s;
}

async function unlinkTelegramChat(env) {
  const s = await Settings.loadSettings(env);
  s.telegram.chatId = '';
  await env.kv.put('settings', JSON.stringify(s));
  return s;
}

async function telegramLinkCode(env, settings) {
  if (!settings.telegram.token) throw new Error('Connect a bot first.');
  const code = crypto.randomUUID().slice(0, 8);
  await env.kv.put(`tg-link:${code}`, '1', { expirationTtl: 600 });
  return { deepLink: `https://t.me/${settings.telegram.botUsername}?start=${code}` };
}

async function telegramWebhook(request, env, url) {
  const settings = await Settings.loadSettings(env);
  if (!settings.telegram.token) return notFound();
  const sig = request.headers.get('X-Telegram-Bot-Api-Secret-Token');
  if (!sig || sig !== settings.telegram.webhookSecret) return new Response('Forbidden', { status: 403 });
  const update = await readBody(request);
  const subs = Object.entries(SUB_FORMATS).map(([id, f]) => ({ id, label: f.label, url: `${url.origin}/${settings.subToken}/${id}` }));
  await TG.handleUpdate(update, env, settings, {
    subs,
    saveTelegram: async (next) => { const s = await Settings.loadSettings(env); s.telegram = next; await env.kv.put('settings', JSON.stringify(s)); invalidateSettingsCache(); },
    regenerateSub: async () => (await Settings.regenerate(env, 'sub')).subToken,
  });
  return json({ ok: true });
}

async function state(request, env) {
  const auth = await Auth.getAuth(env);
  if (!auth) return { auth, state: 'setup' };
  return { auth, state: (await Auth.hasValidSession(request, env, auth)) ? 'app' : 'login' };
}

async function api(request, env, base, route) {
  const url = new URL(request.url);
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';

  if (request.method === 'GET' && route === 'session') {
    return json({ state: (await state(request, env)).state });
  }
  if (request.method === 'GET' && route === 'settings') {
    if ((await state(request, env)).state !== 'app') return json({ error: 'Sign in again.' }, 401);
    return json(await settingsView(env, url));
  }
  if (request.method === 'GET' && route === 'telegram') {
    if ((await state(request, env)).state !== 'app') return json({ error: 'Sign in again.' }, 401);
    return json(telegramView(await Settings.loadSettings(env)));
  }

  // Everything below changes something: require same-origin.
  if (request.method !== 'POST') return notFound();
  if (request.headers.get('Origin') !== url.origin) return json({ error: 'Blocked request.' }, 403);
  const body = await readBody(request);
  const cookiePath = base;

  switch (route) {
    case 'setup': {
      if (await Auth.getAuth(env)) return json({ error: 'A password already exists. Sign in instead.' }, 409);
      const bad = Auth.validatePassword(body.password);
      if (bad) return json({ error: bad }, 400);
      await Auth.savePassword(env, body.password);
      const auth = await Auth.getAuth(env);
      return json({ ok: true }, 200, { 'Set-Cookie': await Auth.makeSessionCookie(env, auth, cookiePath) });
    }
    case 'login': {
      const auth = await Auth.getAuth(env);
      if (!auth) return json({ error: 'Create a password first.' }, 409);
      if (await Auth.isLocked(env, ip)) return json({ error: 'Too many attempts. Try again in 15 minutes.' }, 429);
      if (!(await Auth.checkPassword(auth, body.password))) {
        await Auth.recordFailure(env, ip);
        return json({ error: 'That password is not correct.' }, 401);
      }
      await Auth.clearFailures(env, ip);
      return json({ ok: true }, 200, { 'Set-Cookie': await Auth.makeSessionCookie(env, auth, cookiePath) });
    }
    case 'logout':
      return json({ ok: true }, 200, { 'Set-Cookie': Auth.clearSessionCookie(cookiePath) });
    case 'settings':
    case 'regenerate': {
      if ((await state(request, env)).state !== 'app') return json({ error: 'Sign in again.' }, 401);
      try {
        if (route === 'settings') await Settings.saveSettings(env, body);
        else await Settings.regenerate(env, body.what);
      } catch (e) { return json({ error: e.message }, 400); }
      invalidateSettingsCache();
      return json(await settingsView(env, url));
    }
    case 'telegram/token': {
      if ((await state(request, env)).state !== 'app') return json({ error: 'Sign in again.' }, 401);
      try {
        const s = await saveTelegramToken(env, body.token);
        await TG.setWebhook(s.telegram.token, `${url.origin}${base}/tg`, s.telegram.webhookSecret);
        invalidateSettingsCache();
        return json(telegramView(s));
      } catch (e) { return json({ error: e.message || 'Could not connect to that bot. Check the token.' }, 400); }
    }
    case 'telegram/disconnect': {
      if ((await state(request, env)).state !== 'app') return json({ error: 'Sign in again.' }, 401);
      const s = await disconnectTelegram(env); invalidateSettingsCache();
      return json(telegramView(s));
    }
    case 'telegram/unlink': {
      if ((await state(request, env)).state !== 'app') return json({ error: 'Sign in again.' }, 401);
      const s = await unlinkTelegramChat(env); invalidateSettingsCache();
      return json(telegramView(s));
    }
    case 'telegram/link': {
      if ((await state(request, env)).state !== 'app') return json({ error: 'Sign in again.' }, 401);
      try { return json(await telegramLinkCode(env, await Settings.loadSettings(env))); }
      catch (e) { return json({ error: e.message }, 400); }
    }
    case 'password': {
      const s = await state(request, env);
      if (s.state !== 'app') return json({ error: 'Sign in again.' }, 401);
      if (!(await Auth.checkPassword(s.auth, body.current))) return json({ error: 'Your current password is not correct.' }, 401);
      const bad = Auth.validatePassword(body.password);
      if (bad) return json({ error: bad }, 400);
      await Auth.savePassword(env, body.password);
      const auth = await Auth.getAuth(env);
      return json({ ok: true }, 200, { 'Set-Cookie': await Auth.makeSessionCookie(env, auth, cookiePath) });
    }
    default:
      return notFound();
  }
}

export default {
  async fetch(request, env) {
    try {
      const url = new URL(request.url);
      const [, sp, section, ...rest] = url.pathname.split('/');
      if (!env.SECURE_PATH) return notFound();

      // Tunnel traffic: only accepted on /<secure path>/ws
      if (request.headers.get('Upgrade') === 'websocket') {
        if (sp !== env.SECURE_PATH || section !== 'ws') return notFound();
        return handleWebsocket(request, await cachedSettings(env), connect);
      }

      // Subscription links use their own token so they can be shared without exposing the panel path.
      if (sp !== env.SECURE_PATH) {
        if (request.method === 'GET' && sp && section && rest.length === 0) return await subscription(env, url, sp, section);
        return notFound();
      }
      const base = `/${sp}`;

      if (!section) return Response.redirect(`${url.origin}${base}/panel`, 302);
      if (section === 'panel' && request.method === 'GET') {
        return new Response(appHtml, { headers: { 'Content-Type': 'text/html; charset=utf-8', ...headers } });
      }
      if (section === 'api') return await api(request, env, base, rest.join('/'));
      if (section === 'tg' && request.method === 'POST') return await telegramWebhook(request, env, url);
      return notFound();
    } catch (err) {
      return new Response('Something went wrong.', { status: 500 });
    }
  },
};

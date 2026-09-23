import test from 'node:test';
import assert from 'node:assert/strict';
import worker from '../panel/src/worker.js';
import { makeEnv, req, cookieOf } from './helpers.mjs';

const P = '/abc123';
const realFetch = globalThis.fetch;
function mockTelegram({ username = 'dart_test_bot' } = {}) {
  const calls = [];
  globalThis.fetch = async (url, init) => {
    calls.push({ url: String(url), body: init?.body ? JSON.parse(init.body) : null });
    const m = /\/bot([^/]+)\/(\w+)/.exec(String(url));
    const [, token, method] = m;
    if (token === 'bad-token') return Response.json({ ok: false, description: 'Unauthorized' });
    if (method === 'getMe') return Response.json({ ok: true, result: { id: 1, username } });
    if (method === 'setWebhook' || method === 'deleteWebhook' || method === 'sendMessage') return Response.json({ ok: true, result: true });
    return Response.json({ ok: false, description: 'unmocked ' + method });
  };
  return calls;
}

async function signedIn() {
  const env = makeEnv();
  const res = await worker.fetch(req(P + '/api/setup', { method: 'POST', body: { password: 'correct horse' } }), env);
  return { env, cookie: cookieOf(res) };
}
const api = (env, cookie, path, opts = {}) => worker.fetch(req(P + path, { cookie, ...opts }), env);

test.after(() => { globalThis.fetch = realFetch; });

test('connecting a bad token fails without saving anything', async () => {
  mockTelegram(); const { env, cookie } = await signedIn();
  const res = await api(env, cookie, '/api/telegram/token', { method: 'POST', body: { token: 'bad-token' } });
  assert.equal(res.status, 400);
  const v = await (await api(env, cookie, '/api/telegram')).json();
  assert.equal(v.connected, false);
});

test('connecting a bot registers the webhook and reports the username', async () => {
  const calls = mockTelegram({ username: 'dart_test_bot' });
  const { env, cookie } = await signedIn();
  const res = await api(env, cookie, '/api/telegram/token', { method: 'POST', body: { token: 'good-token' } });
  const v = await res.json();
  assert.equal(v.connected, true); assert.equal(v.botUsername, 'dart_test_bot'); assert.equal(v.linked, false);
  const hook = calls.find((c) => c.url.includes('/setWebhook'));
  assert.ok(hook.body.url.endsWith('/abc123/tg'));
  assert.ok(hook.body.secret_token);
});

test('link code flow: /start links the chat, unlinked chats are ignored', async () => {
  mockTelegram({ username: 'dart_test_bot' });
  const { env, cookie } = await signedIn();
  await api(env, cookie, '/api/telegram/token', { method: 'POST', body: { token: 'good-token' } });
  const link = await (await api(env, cookie, '/api/telegram/link', { method: 'POST' })).json();
  const code = new URL(link.deepLink).searchParams.get('start');

  const webhook = (update, secret) => worker.fetch(new Request('https://dart.example.workers.dev' + P + '/tg', {
    method: 'POST', headers: { 'X-Telegram-Bot-Api-Secret-Token': secret ?? 'guess', 'Content-Type': 'application/json' }, body: JSON.stringify(update),
  }), env);

  const settingsBefore = await (await api(env, cookie, '/api/settings')).json();
  const realSecret = settingsBefore.settings.telegram?.webhookSecret; // not exposed on purpose
  assert.equal(realSecret, undefined, 'webhook secret must not be exposed to the browser');

  // wrong secret token is rejected
  assert.equal((await webhook({ message: { chat: { id: 555 }, text: `/start ${code}` } })).status, 403);

  // we don't have the real secret from the API on purpose, so fetch it straight from KV for the test
  const stored = await env.kv.get('settings', 'json');
  const ok = await webhook({ message: { chat: { id: 555 }, text: `/start ${code}` } }, stored.telegram.webhookSecret);
  assert.equal(ok.status, 200);
  const v = await (await api(env, cookie, '/api/telegram')).json();
  assert.equal(v.linked, true);

  // an unrelated chat is ignored (no crash, no state change)
  await webhook({ message: { chat: { id: 999 }, text: '/status' } }, stored.telegram.webhookSecret);
  const v2 = await (await api(env, cookie, '/api/telegram')).json();
  assert.equal(v2.linked, true);
});

test('disconnect clears the bot and unlink clears only the chat', async () => {
  mockTelegram({ username: 'dart_test_bot' });
  const { env, cookie } = await signedIn();
  await api(env, cookie, '/api/telegram/token', { method: 'POST', body: { token: 'good-token' } });
  const link = await (await api(env, cookie, '/api/telegram/link', { method: 'POST' })).json();
  const code = new URL(link.deepLink).searchParams.get('start');
  const stored = await env.kv.get('settings', 'json');
  await worker.fetch(new Request('https://dart.example.workers.dev' + P + '/tg', { method: 'POST', headers: { 'X-Telegram-Bot-Api-Secret-Token': stored.telegram.webhookSecret, 'Content-Type': 'application/json' }, body: JSON.stringify({ message: { chat: { id: 555 }, text: `/start ${code}` } }) }), env);

  const unlinked = await (await api(env, cookie, '/api/telegram/unlink', { method: 'POST' })).json();
  assert.equal(unlinked.connected, true); assert.equal(unlinked.linked, false);

  const disconnected = await (await api(env, cookie, '/api/telegram/disconnect', { method: 'POST' })).json();
  assert.equal(disconnected.connected, false);
});

test('telegram routes require a session', async () => {
  mockTelegram(); const { env } = await signedIn();
  assert.equal((await api(env, undefined, '/api/telegram')).status, 401);
  assert.equal((await api(env, undefined, '/api/telegram/token', { method: 'POST', body: { token: 'x' } })).status, 401);
});

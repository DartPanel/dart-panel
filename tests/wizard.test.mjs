import test from 'node:test';
import assert from 'node:assert/strict';
import worker from '../wizard/src/worker.js';

const ORIGIN = 'https://wizard-dart-panel.me.workers.dev';
const PANEL_URL = 'https://example.com/worker.js';
const env = { PANEL_RELEASE_URL: PANEL_URL };
const cfOk = (result) => Response.json({ success: true, result });
const cfErr = (status, message) => Response.json({ success: false, errors: [{ message }] }, { status });

function mockFetch(handlers) {
  const calls = [];
  globalThis.fetch = async (url, init = {}) => {
    const u = String(url); const method = init.method || 'GET';
    calls.push({ url: u, method, init });
    for (const [match, fn] of handlers) if (match(u, method)) return fn(u, init);
    throw new Error(`unmocked ${method} ${u}`);
  };
  return calls;
}
const at = (m, s) => (u, method) => method === m && u.includes(s);
const deployReq = (body, origin = ORIGIN) => new Request(ORIGIN + '/api/deploy', { method: 'POST', headers: { 'Content-Type': 'application/json', Origin: origin }, body: JSON.stringify(body) });
async function events(res) { return (await res.text()).trim().split('\n').map((l) => JSON.parse(l)); }
const realFetch = globalThis.fetch;

const happy = () => [
  [at('GET', '/accounts?'), () => cfOk([{ id: 'acc1' }])],
  [at('GET', '/scripts/mypanel/settings'), () => cfErr(404, 'not found')],
  [at('GET', '/workers/subdomain'), () => cfOk({ subdomain: 'me' })],
  [(u) => u === PANEL_URL, () => new Response('x'.repeat(2000))],
  [at('POST', '/storage/kv/namespaces'), () => cfOk({ id: 'kv1' })],
  [at('PUT', '/workers/scripts/mypanel'), () => cfOk({})],
  [at('POST', '/scripts/mypanel/subdomain'), () => cfOk({})],
];

test('serves the wizard page', async () => {
  const res = await worker.fetch(new Request(ORIGIN + '/'), env);
  assert.equal(res.status, 200);
  assert.match(await res.text(), /Set up your Dart Panel/);
});

test('rejects bad input and cross-origin calls', async () => {
  assert.equal((await worker.fetch(deployReq({ token: 'short', name: 'mypanel' }), env)).status, 400);
  assert.equal((await worker.fetch(deployReq({ token: 't'.repeat(30), name: 'Bad Name!' }), env)).status, 400);
  assert.equal((await worker.fetch(deployReq({ token: 't'.repeat(30), name: 'mypanel' }, 'https://evil.example'), env)).status, 403);
});

test('deploys: creates KV, uploads worker with bindings, enables workers.dev, returns secure URL', async () => {
  const calls = mockFetch(happy());
  const res = await worker.fetch(deployReq({ token: 't'.repeat(30), name: 'mypanel' }), env);
  const ev = await events(res);
  globalThis.fetch = realFetch;
  const done = ev.at(-1);
  assert.equal(done.type, 'done');
  assert.match(done.panelUrl, /^https:\/\/mypanel\.me\.workers\.dev\/[a-z0-9]{14}\/panel$/);
  const put = calls.find((c) => c.method === 'PUT' && c.url.includes('/workers/scripts/mypanel'));
  const meta = JSON.parse(await put.init.body.get('metadata').text());
  assert.equal(meta.main_module, 'worker.js');
  const names = meta.bindings.map((b) => `${b.type}:${b.name}`).sort();
  assert.deepEqual(names, ['kv_namespace:kv', 'plain_text:SECURE_PATH', 'secret_text:SESSION_SECRET']);
  const secure = meta.bindings.find((b) => b.name === 'SECURE_PATH').text;
  assert.ok(done.panelUrl.includes(`/${secure}/`));
  assert.ok(ev.filter((e) => e.type === 'step' && e.status === 'ok').length >= 5);
  assert.ok(calls.every((c) => !c.url.includes('api.cloudflare.com') || c.init.headers.Authorization === 'Bearer ' + 't'.repeat(30)));
});

test('refuses to overwrite an existing Worker', async () => {
  const h = happy(); h[1] = [at('GET', '/scripts/mypanel/settings'), () => cfOk({})];
  const calls = mockFetch(h);
  const ev = await events(await worker.fetch(deployReq({ token: 't'.repeat(30), name: 'mypanel' }), env));
  globalThis.fetch = realFetch;
  assert.equal(ev.at(-1).type, 'error');
  assert.match(ev.at(-1).message, /already exists/);
  assert.ok(!calls.some((c) => c.method === 'PUT'));
});

test('cleans up storage and script when a later step fails', async () => {
  const h = happy(); h[6] = [at('POST', '/scripts/mypanel/subdomain'), () => cfErr(500, 'boom')];
  h.push([at('DELETE', '/workers/scripts/mypanel'), () => cfOk({})], [at('DELETE', '/storage/kv/namespaces/kv1'), () => cfOk({})]);
  const calls = mockFetch(h);
  const ev = await events(await worker.fetch(deployReq({ token: 't'.repeat(30), name: 'mypanel' }), env));
  globalThis.fetch = realFetch;
  assert.equal(ev.at(-1).type, 'error');
  assert.ok(calls.some((c) => c.method === 'DELETE' && c.url.includes('/workers/scripts/mypanel')));
  assert.ok(calls.some((c) => c.method === 'DELETE' && c.url.includes('/kv/namespaces/kv1')));
});

test('explains token permission problems', async () => {
  mockFetch([[at('GET', '/accounts?'), () => cfErr(403, 'Authentication error')]]);
  const ev = await events(await worker.fetch(deployReq({ token: 't'.repeat(30), name: 'mypanel' }), env));
  globalThis.fetch = realFetch;
  assert.match(ev.at(-1).message, /Workers Scripts: Edit/);
});

test('tells you when the release URL is not configured', async () => {
  mockFetch(happy().filter((h) => h[0] !== undefined));
  const ev = await events(await worker.fetch(deployReq({ token: 't'.repeat(30), name: 'mypanel' }), { PANEL_RELEASE_URL: 'https://github.com/OWNER/dart-panel/releases/latest/download/worker.js' }));
  globalThis.fetch = realFetch;
  assert.match(ev.at(-1).message, /PANEL_RELEASE_URL/);
});

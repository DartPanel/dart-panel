// Confirms dist/worker.js (what the wizard actually deploys) behaves the same
// as the unbundled module graph the other test files exercise directly.
import test from 'node:test';
import assert from 'node:assert/strict';
import { execSync } from 'node:child_process';
import worker from '../dist/worker.js';
import { makeEnv, req, cookieOf } from './helpers.mjs';

test.before(() => { execSync('node scripts/bundle-worker.mjs', { cwd: new URL('..', import.meta.url) }); });

test('bundle: full setup -> login -> settings -> subscription flow', async () => {
  const env = makeEnv();
  const setup = await worker.fetch(req('/abc123/api/setup', { method: 'POST', body: { password: 'correct horse' } }), env);
  assert.equal(setup.status, 200);
  const cookie = cookieOf(setup);

  const settingsRes = await worker.fetch(req('/abc123/api/settings', { cookie }), env);
  const { settings, subs } = await settingsRes.json();
  assert.match(settings.uuid, /^[0-9a-f-]{36}$/);
  assert.equal(settings.telegram.token, undefined, 'bundle must also redact the bot token');

  const raw = await worker.fetch(req(`/${settings.subToken}/raw`), env);
  assert.equal(raw.status, 200);
  assert.match(atob(await raw.text()), /^vless:\/\//);

  const panel = await worker.fetch(req('/abc123/panel'), env);
  assert.match(await panel.text(), /Dart Panel/);
});

test('bundle: websocket upgrade path is reachable (rejects outside secure path)', async () => {
  const env = makeEnv();
  const res = await worker.fetch(new Request('https://x.workers.dev/wrong/ws', { headers: { Upgrade: 'websocket' } }), env);
  assert.equal(res.status, 404);
});

import test from 'node:test';
import assert from 'node:assert/strict';
import worker from '../panel/src/worker.js';
import { makeEnv, req, cookieOf } from './helpers.mjs';

const P = '/abc123';
const call = (env, path, opts) => worker.fetch(req(P + path, opts), env);

test('wrong or missing secure path returns 404', async () => {
  const env = makeEnv();
  assert.equal((await worker.fetch(req('/panel'), env)).status, 404);
  assert.equal((await worker.fetch(req('/wrong/panel'), env)).status, 404);
  assert.equal((await worker.fetch(req('/'), env)).status, 404);
});

test('panel page is served with security headers', async () => {
  const res = await call(makeEnv(), '/panel');
  assert.equal(res.status, 200);
  assert.match(res.headers.get('Content-Type'), /text\/html/);
  assert.match(res.headers.get('Content-Security-Policy'), /frame-ancestors 'none'/);
  assert.match(await res.text(), /Dart Panel/);
});

test('first visit is in setup state, then setup logs you in', async () => {
  const env = makeEnv();
  assert.deepEqual(await (await call(env, '/api/session')).json(), { state: 'setup' });
  const short = await call(env, '/api/setup', { method: 'POST', body: { password: 'short' } });
  assert.equal(short.status, 400);
  const ok = await call(env, '/api/setup', { method: 'POST', body: { password: 'correct horse' } });
  assert.equal(ok.status, 200);
  const cookie = cookieOf(ok);
  assert.match(ok.headers.get('Set-Cookie'), /HttpOnly; Secure; SameSite=Strict/);
  assert.deepEqual(await (await call(env, '/api/session', { cookie })).json(), { state: 'app' });
  assert.deepEqual(await (await call(env, '/api/session')).json(), { state: 'login' });
});

test('setup cannot be run twice', async () => {
  const env = makeEnv();
  await call(env, '/api/setup', { method: 'POST', body: { password: 'correct horse' } });
  const again = await call(env, '/api/setup', { method: 'POST', body: { password: 'attacker pass' } });
  assert.equal(again.status, 409);
});

test('login accepts the right password and rejects the wrong one', async () => {
  const env = makeEnv();
  await call(env, '/api/setup', { method: 'POST', body: { password: 'correct horse' } });
  assert.equal((await call(env, '/api/login', { method: 'POST', body: { password: 'nope nope nope' } })).status, 401);
  const ok = await call(env, '/api/login', { method: 'POST', body: { password: 'correct horse' } });
  assert.equal(ok.status, 200);
  assert.ok(cookieOf(ok).startsWith('dp_session='));
});

test('locks out after repeated failures', async () => {
  const env = makeEnv();
  await call(env, '/api/setup', { method: 'POST', body: { password: 'correct horse' } });
  for (let i = 0; i < 8; i++) await call(env, '/api/login', { method: 'POST', body: { password: 'bad bad bad' } });
  const locked = await call(env, '/api/login', { method: 'POST', body: { password: 'correct horse' } });
  assert.equal(locked.status, 429);
  // a different IP is not affected
  const other = await call(env, '/api/login', { method: 'POST', body: { password: 'correct horse' }, ip: '9.9.9.9' });
  assert.equal(other.status, 200);
});

test('tampered or expired session cookies are rejected', async () => {
  const env = makeEnv();
  const ok = await call(env, '/api/setup', { method: 'POST', body: { password: 'correct horse' } });
  const cookie = cookieOf(ok);
  const [name, value] = cookie.split('=');
  const [exp, ver, sig] = value.split('.');
  assert.deepEqual(await (await call(env, '/api/session', { cookie: `${name}=${Number(exp) + 999}.${ver}.${sig}` })).json(), { state: 'login' });
  assert.deepEqual(await (await call(env, '/api/session', { cookie: `${name}=${exp}.${ver}.${sig.slice(0, -2)}xx` })).json(), { state: 'login' });
  const past = Math.floor(Date.now() / 1000) - 10;
  assert.deepEqual(await (await call(env, '/api/session', { cookie: `${name}=${past}.${ver}.${sig}` })).json(), { state: 'login' });
});

test('cross-origin POSTs are blocked', async () => {
  const env = makeEnv();
  const res = await call(env, '/api/setup', { method: 'POST', body: { password: 'correct horse' }, origin: 'https://evil.example' });
  assert.equal(res.status, 403);
  assert.deepEqual(await (await call(env, '/api/session')).json(), { state: 'setup' });
});

test('changing password needs the current one and signs out old sessions', async () => {
  const env = makeEnv();
  const first = cookieOf(await call(env, '/api/setup', { method: 'POST', body: { password: 'correct horse' } }));
  const wrong = await call(env, '/api/password', { method: 'POST', cookie: first, body: { current: 'wrong wrong', password: 'brand new pass' } });
  assert.equal(wrong.status, 401);
  const changed = await call(env, '/api/password', { method: 'POST', cookie: first, body: { current: 'correct horse', password: 'brand new pass' } });
  assert.equal(changed.status, 200);
  const fresh = cookieOf(changed);
  assert.deepEqual(await (await call(env, '/api/session', { cookie: first })).json(), { state: 'login' });
  assert.deepEqual(await (await call(env, '/api/session', { cookie: fresh })).json(), { state: 'app' });
  assert.equal((await call(env, '/api/login', { method: 'POST', body: { password: 'brand new pass' } })).status, 200);
});

test('password change requires being signed in', async () => {
  const env = makeEnv();
  await call(env, '/api/setup', { method: 'POST', body: { password: 'correct horse' } });
  const res = await call(env, '/api/password', { method: 'POST', body: { current: 'correct horse', password: 'brand new pass' } });
  assert.equal(res.status, 401);
});

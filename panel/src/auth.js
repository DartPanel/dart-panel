// Single-user password auth with stateless signed sessions.
import { b64u, hashPassword, hmac, randomToken, safeEqual } from './crypto.js';

const SESSION_DAYS = 7;
const MAX_ATTEMPTS = 8;
const LOCK_SECONDS = 15 * 60;
export const MIN_PASSWORD = 8;
export const MAX_PASSWORD = 200;

export const getAuth = (env) => env.kv.get('auth', 'json');

export function validatePassword(pw) {
  if (typeof pw !== 'string' || pw.length < MIN_PASSWORD) return `Use at least ${MIN_PASSWORD} characters.`;
  if (pw.length > MAX_PASSWORD) return `Use at most ${MAX_PASSWORD} characters.`;
  return null;
}

export async function savePassword(env, password) {
  const h = await hashPassword(password);
  // `ver` is part of every session signature, so changing the password signs out all devices.
  await env.kv.put('auth', JSON.stringify({ ...h, ver: randomToken(6) }));
}

export async function checkPassword(auth, password) {
  if (!auth || typeof password !== 'string' || password.length > MAX_PASSWORD) return false;
  const h = await hashPassword(password, b64u.dec(auth.salt), auth.iter);
  return safeEqual(h.hash, auth.hash);
}

export async function makeSessionCookie(env, auth, path) {
  const exp = Math.floor(Date.now() / 1000) + SESSION_DAYS * 86400;
  const body = `${exp}.${auth.ver}`;
  const value = `${body}.${await hmac(env.SESSION_SECRET, body)}`;
  return `dp_session=${value}; Path=${path}; Max-Age=${SESSION_DAYS * 86400}; HttpOnly; Secure; SameSite=Strict`;
}

export const clearSessionCookie = (path) => `dp_session=; Path=${path}; Max-Age=0; HttpOnly; Secure; SameSite=Strict`;

export async function hasValidSession(request, env, auth) {
  if (!auth) return false;
  const m = /(?:^|;\s*)dp_session=([^;]+)/.exec(request.headers.get('Cookie') || '');
  if (!m) return false;
  const parts = m[1].split('.');
  if (parts.length !== 3) return false;
  const [exp, ver, sig] = parts;
  if (!(Number(exp) > Date.now() / 1000) || !safeEqual(ver, auth.ver)) return false;
  return safeEqual(sig, await hmac(env.SESSION_SECRET, `${exp}.${ver}`));
}

// Best-effort brute-force guard (KV is eventually consistent, so this slows attackers rather than stopping them exactly).
export async function isLocked(env, ip) {
  return Number(await env.kv.get(`rl:${ip}`)) >= MAX_ATTEMPTS;
}
export async function recordFailure(env, ip) {
  const n = Number(await env.kv.get(`rl:${ip}`)) + 1;
  await env.kv.put(`rl:${ip}`, String(n), { expirationTtl: LOCK_SECONDS });
}
export const clearFailures = (env, ip) => env.kv.delete(`rl:${ip}`);

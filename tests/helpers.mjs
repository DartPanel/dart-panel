import { sha224Hex } from '../panel/src/protocol.js';
export class FakeKV {
  constructor() { this.m = new Map(); }
  async get(k, type) { const v = this.m.get(k); if (v === undefined) return null; return type === 'json' ? JSON.parse(v) : v; }
  async put(k, v) { this.m.set(k, String(v)); }
  async delete(k) { this.m.delete(k); }
}
export const ORIGIN = 'https://dart.example.workers.dev';
export const makeEnv = () => ({ kv: new FakeKV(), SECURE_PATH: 'abc123', SESSION_SECRET: 'test-secret-value' });
export const req = (path, { method = 'GET', body, cookie, origin = ORIGIN, ip = '1.2.3.4' } = {}) =>
  new Request(ORIGIN + path, {
    method,
    headers: { ...(body ? { 'Content-Type': 'application/json' } : {}), ...(cookie ? { Cookie: cookie } : {}), ...(method === 'POST' ? { Origin: origin } : {}), 'CF-Connecting-IP': ip },
    body: body ? JSON.stringify(body) : undefined,
  });
export const cookieOf = (res) => (res.headers.get('Set-Cookie') || '').split(';')[0];

export const UUID = '11111111-2222-4333-8444-555555555555';
export const uuidBytes = Uint8Array.from(UUID.replace(/-/g, '').match(/../g), (h) => parseInt(h, 16));
export const cat = (...p) => Uint8Array.from(p.flatMap((x) => [...x]));

export const vlessDomain = (host, port, payload = [1, 2, 3], id = uuidBytes) =>
  cat([0], id, [0], [1], [port >> 8, port & 255], [2, host.length], new TextEncoder().encode(host), payload);
export const trojanIPv4 = (pass, ip, port, payload = [9, 8]) =>
  cat(new TextEncoder().encode(sha224Hex(pass)), [13, 10], [1], [1], ip.split('.').map(Number), [port >> 8, port & 255], [13, 10], payload);


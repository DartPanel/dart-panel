import test from 'node:test';
import assert from 'node:assert/strict';
import { handleWebsocket } from '../panel/src/websocket.js';
import { DEFAULTS } from '../panel/src/settings.js';
import { UUID, vlessDomain, trojanIPv4 } from './helpers.mjs';

const settings = (over = {}) => ({ ...structuredClone(DEFAULTS), uuid: UUID, trojanPass: 'secret-pass', ...over });
const tick = (ms = 20) => new Promise((r) => setTimeout(r, ms));

function fakeEnvironment() {
  const sent = []; const listeners = {}; let closed = false;
  const server = { readyState: 1, accept() {}, send: (d) => sent.push(Uint8Array.from(d)), close() { closed = true; }, addEventListener: (t, f) => (listeners[t] = f) };
  globalThis.WebSocketPair = class { constructor() { this[0] = {}; this[1] = server; } };
  const RealResponse = globalThis.Response;
  globalThis.Response = class extends RealResponse {
    constructor(b, init) { if (init?.status === 101) { super(null, { status: 200 }); } else super(b, init); }
  };
  return { sent, send: (d) => listeners.message({ data: d }), isClosed: () => closed, restore: () => { globalThis.Response = RealResponse; delete globalThis.WebSocketPair; delete globalThis.__connect; } };
}
const socketReplying = (reply, log, tag) => ({
  readable: new ReadableStream({ start(c) { if (reply) c.enqueue(Uint8Array.from(reply)); c.close(); } }),
  writable: new WritableStream({ write(ch) { log.push({ tag, data: [...ch] }); } }),
  close() {},
});
const req = () => new Request('https://x.workers.dev/sp/ws', { headers: { Upgrade: 'websocket' } });

test('VLESS: connects to the requested host, forwards payload, prefixes the reply header', async () => {
  const env = fakeEnvironment(); const log = []; const connects = [];
  globalThis.__connect = (o) => { connects.push(o); return socketReplying([7, 7], log, 'direct'); };
  try {
    handleWebsocket(req(), settings(), globalThis.__connect);
    env.send(vlessDomain('example.com', 443, [1, 2, 3]));
    await tick();
    assert.deepEqual(connects, [{ hostname: 'example.com', port: 443 }]);
    assert.deepEqual(log, [{ tag: 'direct', data: [1, 2, 3] }]);
    assert.deepEqual([...env.sent[0]], [0, 0, 7, 7]);
  } finally { env.restore(); }
});

test('Trojan: authenticates by SHA-224 and relays', async () => {
  const env = fakeEnvironment(); const log = []; const connects = [];
  const connect = (o) => { connects.push(o); return socketReplying([5], log, 'd'); };
  try {
    handleWebsocket(req(), settings(), connect);
    env.send(trojanIPv4('secret-pass', '1.2.3.4', 8080));
    await tick();
    assert.deepEqual(connects, [{ hostname: '1.2.3.4', port: 8080 }]);
    assert.deepEqual([...env.sent[0]], [5]);
  } finally { env.restore(); }
});

test('unknown users are dropped without opening any connection', async () => {
  const env = fakeEnvironment(); const connects = [];
  try {
    handleWebsocket(req(), settings(), (o) => { connects.push(o); return socketReplying([1], [], 'x'); });
    env.send(trojanIPv4('wrong-pass', '1.2.3.4', 80));
    await tick();
    assert.equal(connects.length, 0); assert.ok(env.isClosed());
  } finally { env.restore(); }
});

test('disabled protocols are refused', async () => {
  const env = fakeEnvironment(); const connects = [];
  try {
    handleWebsocket(req(), settings({ protocols: { vless: false, trojan: true } }), (o) => { connects.push(o); return socketReplying([1], [], 'x'); });
    env.send(vlessDomain('example.com', 443));
    await tick();
    assert.equal(connects.length, 0);
  } finally { env.restore(); }
});

test('falls back to a proxy IP when the direct connection returns nothing', async () => {
  const env = fakeEnvironment(); const log = []; const connects = [];
  const connect = (o) => { connects.push(o); return connects.length === 1 ? socketReplying(null, log, 'direct') : socketReplying([9], log, 'proxy'); };
  try {
    handleWebsocket(req(), settings({ proxyIPs: ['5.6.7.8'] }), connect);
    env.send(vlessDomain('blocked.example', 443, [4, 4]));
    await tick(50);
    assert.deepEqual(connects.map((c) => c.hostname), ['blocked.example', '5.6.7.8']);
    assert.deepEqual(log.filter((l) => l.tag === 'proxy'), [{ tag: 'proxy', data: [4, 4] }]);
    assert.deepEqual([...env.sent[0]], [0, 0, 9]);
  } finally { env.restore(); }
});

test('later messages are streamed to the open connection', async () => {
  const env = fakeEnvironment(); const log = [];
  const connect = () => ({ readable: new ReadableStream({ start() {} }), writable: new WritableStream({ write(ch) { log.push([...ch]); } }), close() {} });
  try {
    handleWebsocket(req(), settings(), connect);
    env.send(vlessDomain('example.com', 443, [1]));
    await tick();
    env.send(Uint8Array.from([2, 2]).buffer);
    await tick();
    assert.deepEqual(log, [[1], [2, 2]]);
  } finally { env.restore(); }
});

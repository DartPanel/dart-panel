import test from 'node:test';
import assert from 'node:assert/strict';
import worker from '../panel/src/worker.js';
import { DEFAULTS, mergeSettings } from '../panel/src/settings.js';
import { buildLinks, buildXray, buildSingbox, buildClash, endpoints } from '../panel/src/configs.js';
import { makeEnv, req, cookieOf } from './helpers.mjs';

const HOST = 'dart.me.workers.dev';
const S = (over = {}) => ({ ...structuredClone(DEFAULTS), uuid: '11111111-2222-4333-8444-555555555555', trojanPass: 'pw-123456', ...over });

test('settings validation gives readable errors', () => {
  const bad = (input, re) => assert.throws(() => mergeSettings(DEFAULTS, input), re);
  bad({ ports: [80] }, /Ports must be/);
  bad({ cleanIPs: ['not a host!'] }, /not a valid/);
  bad({ remoteDNS: 'http://1.1.1.1/dns-query' }, /https/);
  bad({ fragment: { enabled: true, packets: 'tlshello', length: '200-100', interval: '1-1' } }, /small to large/);
  bad({ protocols: { vless: false, trojan: false } }, /at least one/);
  bad({ uuid: 'nope' }, /UUID/);
  const ok = mergeSettings(DEFAULTS, { cleanIPs: '1.1.1.1, cdn.example.com', proxyIPs: ['5.6.7.8:8443'], ports: [443, 8443] });
  assert.deepEqual(ok.cleanIPs, ['1.1.1.1', 'cdn.example.com']);
  assert.deepEqual(ok.ports, [443, 8443]);
});

test('endpoints multiply addresses, ports and protocols', () => {
  const eps = endpoints(S({ cleanIPs: ['1.1.1.1'], ports: [443, 8443] }), HOST);
  assert.equal(eps.length, 2 * 2 * 2);
  assert.equal(new Set(eps.map((e) => e.name)).size, eps.length);
});

test('share links carry credentials, SNI, host and the secure ws path', () => {
  const links = buildLinks(S(), HOST, 'sp1');
  assert.equal(links.length, 2);
  const v = new URL(links[0]);
  assert.equal(v.protocol, 'vless:'); assert.equal(v.username, '11111111-2222-4333-8444-555555555555');
  assert.equal(v.searchParams.get('sni'), HOST); assert.equal(v.searchParams.get('type'), 'ws');
  assert.equal(v.searchParams.get('path'), '/sp1/ws?ed=2560');
  const t = new URL(links[1]);
  assert.equal(t.protocol, 'trojan:'); assert.equal(t.username, 'pw-123456');
});

test('xray: outbound per endpoint, fragment dialer only when enabled', () => {
  const on = buildXray(S({ cleanIPs: ['1.1.1.1'] }), HOST, 'sp1');
  assert.equal(on.length, 4);
  for (const c of on) {
    const tags = c.outbounds.map((o) => o.tag);
    assert.ok(tags.includes('fragment') && tags.includes('direct') && tags.includes('block'));
    const proxy = c.outbounds.find((o) => o.tag === 'proxy');
    assert.equal(proxy.streamSettings.sockopt.dialerProxy, 'fragment');
    assert.equal(proxy.streamSettings.wsSettings.path, '/sp1/ws?ed=2560');
    assert.equal(c.routing.rules.at(-1).outboundTag, 'proxy');
    for (const r of c.routing.rules) assert.ok(tags.includes(r.outboundTag), `rule targets missing outbound ${r.outboundTag}`);
  }
  const off = buildXray(S({ fragment: { ...DEFAULTS.fragment, enabled: false } }), HOST, 'sp1')[0];
  assert.ok(!off.outbounds.some((o) => o.tag === 'fragment'));
  assert.equal(off.outbounds[0].streamSettings.sockopt, undefined);
});

test('xray: server domain is resolved by the local DNS to avoid a proxy loop', () => {
  const c = buildXray(S(), HOST, 'sp1')[0];
  assert.ok(c.dns.servers.some((d) => d.domains?.includes(`full:${HOST}`)));
});

test('sing-box: every reference points at an existing outbound or DNS server', () => {
  const c = buildSingbox(S({ cleanIPs: ['1.1.1.1'] }), HOST, 'sp1');
  const tags = c.outbounds.map((o) => o.tag);
  assert.equal(new Set(tags).size, tags.length);
  for (const o of c.outbounds.filter((o) => o.outbounds)) for (const t of o.outbounds) assert.ok(tags.includes(t), `missing ${t}`);
  assert.ok(tags.includes(c.route.final));
  for (const r of c.route.rules) if (r.outbound) assert.ok(tags.includes(r.outbound));
  const dnsTags = c.dns.servers.map((d) => d.tag);
  assert.ok(dnsTags.includes(c.dns.final));
  for (const r of c.dns.rules) assert.ok(dnsTags.includes(r.server));
  assert.ok(dnsTags.includes(c.route.default_domain_resolver.server));
  const p = c.outbounds.find((o) => o.type === 'vless');
  assert.equal(p.transport.path, '/sp1/ws'); assert.equal(p.tls.fragment, true);
});

test('clash: groups and rules reference real proxies and groups', () => {
  const c = buildClash(S(), HOST, 'sp1');
  const names = c.proxies.map((p) => p.name);
  for (const g of c['proxy-groups']) for (const n of g.proxies) assert.ok(names.includes(n) || c['proxy-groups'].some((x) => x.name === n));
  assert.equal(c.rules.at(-1), 'MATCH,Select');
  assert.equal(c.proxies[0]['ws-opts'].path, '/sp1/ws');
});

// ---- API ----
const P = '/abc123';
async function signedIn() {
  const env = makeEnv();
  const res = await worker.fetch(req(P + '/api/setup', { method: 'POST', body: { password: 'correct horse' } }), env);
  return { env, cookie: cookieOf(res) };
}
const api = (env, cookie, path, opts = {}) => worker.fetch(req(P + path, { cookie, ...opts }), env);

test('settings API needs a session', async () => {
  const { env } = await signedIn();
  assert.equal((await api(env, undefined, '/api/settings')).status, 401);
  assert.equal((await api(env, undefined, '/api/settings', { method: 'POST', body: { ports: [443] } })).status, 401);
});

test('first settings read creates credentials and subscription links', async () => {
  const { env, cookie } = await signedIn();
  const v = await (await api(env, cookie, '/api/settings')).json();
  assert.match(v.settings.uuid, /^[0-9a-f-]{36}$/);
  assert.ok(v.settings.trojanPass.length >= 8);
  assert.deepEqual(v.subs.map((s) => s.id), ['raw', 'xray', 'singbox', 'clash']);
  assert.ok(v.subs[0].url.endsWith(`/${v.settings.subToken}/raw`));
});

test('saving settings validates and persists', async () => {
  const { env, cookie } = await signedIn();
  const bad = await api(env, cookie, '/api/settings', { method: 'POST', body: { ports: [1234] } });
  assert.equal(bad.status, 400); assert.match((await bad.json()).error, /Ports must be/);
  const ok = await api(env, cookie, '/api/settings', { method: 'POST', body: { ports: [443, 8443], cleanIPs: ['1.1.1.1'] } });
  assert.equal(ok.status, 200);
  const v = await (await api(env, cookie, '/api/settings')).json();
  assert.deepEqual(v.settings.ports, [443, 8443]); assert.deepEqual(v.settings.cleanIPs, ['1.1.1.1']);
});

test('subscription URLs work without a session, only with the right token and format', async () => {
  const { env, cookie } = await signedIn();
  const v = await (await api(env, cookie, '/api/settings')).json();
  const path = (id, tok = v.settings.subToken) => `/${tok}/${id}`;
  const raw = await worker.fetch(req(path('raw')), env);
  assert.equal(raw.status, 200);
  assert.match(atob(await raw.text()), /^vless:\/\//);
  for (const f of ['xray', 'singbox', 'clash']) {
    const r = await worker.fetch(req(path(f)), env);
    assert.equal(r.status, 200); assert.ok(JSON.parse(await r.text()));
  }
  assert.equal((await worker.fetch(req(path('raw', 'wrongtoken')), env)).status, 404);
  assert.equal((await worker.fetch(req(path('nope')), env)).status, 404);
});

test('regenerating the subscription token kills the old link', async () => {
  const { env, cookie } = await signedIn();
  const before = (await (await api(env, cookie, '/api/settings')).json()).settings.subToken;
  const res = await api(env, cookie, '/api/regenerate', { method: 'POST', body: { what: 'sub' } });
  const after = (await res.json()).settings.subToken;
  assert.notEqual(before, after);
  assert.equal((await worker.fetch(req(`/${before}/raw`), env)).status, 404);
  assert.equal((await worker.fetch(req(`/${after}/raw`), env)).status, 200);
});

test('websocket upgrades are only accepted on the secret path', async () => {
  const { env } = await signedIn();
  const r = new Request('https://dart.example.workers.dev/other/ws', { headers: { Upgrade: 'websocket' } });
  assert.equal((await worker.fetch(r, env)).status, 404);
});

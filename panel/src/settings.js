// Panel settings: defaults, validation and KV persistence.
import { randomToken } from './crypto.js';

// Ports Cloudflare proxies over HTTPS for Workers.
export const TLS_PORTS = [443, 2053, 2083, 2087, 2096, 8443];
export const FRAGMENT_PACKETS = ['tlshello', '1-1', '1-2', '1-3'];
export const FINGERPRINTS = ['chrome', 'firefox', 'safari', 'ios', 'android', 'edge', 'randomized'];

export const DEFAULTS = Object.freeze({
  uuid: '',
  trojanPass: '',
  subToken: '',
  protocols: { vless: true, trojan: true },
  ports: [443],
  cleanIPs: [],
  proxyIPs: [],
  remoteDNS: 'https://8.8.8.8/dns-query',
  localDNS: '8.8.8.8',
  fingerprint: 'chrome',
  fragment: { enabled: true, packets: 'tlshello', length: '100-200', interval: '1-1' },
  routing: { bypassIran: true, bypassLAN: true, blockAds: false, blockQUIC: true },
  configName: 'Dart',
  telegram: { token: '', chatId: '', botUsername: '', webhookSecret: '' },
});

const IPV4 = /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/;
const IPV6 = /^[0-9a-fA-F:]+$/;
const DOMAIN = /^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$/;
const RANGE = /^\d{1,5}-\d{1,5}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export const isHost = (s) => IPV4.test(s) || (s.includes(':') && IPV6.test(s) && s.length <= 45) || DOMAIN.test(s);

function hostList(value, label, max) {
  const items = (Array.isArray(value) ? value : String(value ?? '').split(/[\s,]+/)).map((s) => String(s).trim()).filter(Boolean);
  if (items.length > max) throw new Error(`${label}: at most ${max} entries.`);
  for (const it of items) {
    // proxy IPs may carry a port: host:port
    const m = /^(.*):(\d{1,5})$/.exec(it);
    const host = m && !IPV6.test(it) ? m[1] : it;
    if (!isHost(host) || (m && !IPV6.test(it) && Number(m[2]) > 65535)) throw new Error(`${label}: "${it}" is not a valid IP or domain.`);
  }
  return [...new Set(items)];
}

function range(value, label) {
  const v = String(value ?? '').trim();
  if (!RANGE.test(v)) throw new Error(`${label} must look like 100-200.`);
  const [a, b] = v.split('-').map(Number);
  if (a > b || b > 65535) throw new Error(`${label} must be a range from small to large.`);
  return v;
}

const bool = (v) => v === true || v === 'true';

// Validates a (possibly partial) settings object and returns the merged, clean result.
export function mergeSettings(current, input) {
  const out = structuredClone(current);
  const i = input || {};

  if ('protocols' in i) {
    out.protocols = { vless: bool(i.protocols?.vless), trojan: bool(i.protocols?.trojan) };
    if (!out.protocols.vless && !out.protocols.trojan) throw new Error('Turn on at least one protocol.');
  }
  if ('ports' in i) {
    const ports = [...new Set((Array.isArray(i.ports) ? i.ports : []).map(Number))];
    if (!ports.length || ports.some((p) => !TLS_PORTS.includes(p))) throw new Error(`Ports must be chosen from ${TLS_PORTS.join(', ')}.`);
    out.ports = ports.sort((a, b) => a - b);
  }
  if ('cleanIPs' in i) out.cleanIPs = hostList(i.cleanIPs, 'Clean IPs', 50);
  if ('proxyIPs' in i) out.proxyIPs = hostList(i.proxyIPs, 'Proxy IPs', 20);
  if ('remoteDNS' in i) {
    let u;
    try { u = new URL(String(i.remoteDNS).trim()); } catch { throw new Error('Remote DNS must be a DNS-over-HTTPS URL like https://8.8.8.8/dns-query.'); }
    if (u.protocol !== 'https:') throw new Error('Remote DNS must start with https://.');
    out.remoteDNS = u.href;
  }
  if ('localDNS' in i) {
    const v = String(i.localDNS).trim();
    if (!isHost(v)) throw new Error('Local DNS must be an IP address or domain.');
    out.localDNS = v;
  }
  if ('fingerprint' in i) {
    if (!FINGERPRINTS.includes(i.fingerprint)) throw new Error('Unknown TLS fingerprint.');
    out.fingerprint = i.fingerprint;
  }
  if ('fragment' in i) {
    const f = i.fragment || {};
    if (!FRAGMENT_PACKETS.includes(f.packets)) throw new Error('Unknown fragment packets mode.');
    out.fragment = { enabled: bool(f.enabled), packets: f.packets, length: range(f.length, 'Fragment length'), interval: range(f.interval, 'Fragment interval') };
  }
  if ('routing' in i) {
    const r = i.routing || {};
    out.routing = { bypassIran: bool(r.bypassIran), bypassLAN: bool(r.bypassLAN), blockAds: bool(r.blockAds), blockQUIC: bool(r.blockQUIC) };
  }
  if ('configName' in i) {
    const n = String(i.configName).trim();
    if (!/^[\w .-]{1,24}$/.test(n)) throw new Error('Config name: 1-24 letters, numbers, spaces, dots or dashes.');
    out.configName = n;
  }
  if ('uuid' in i) {
    if (!UUID.test(String(i.uuid))) throw new Error('UUID is not valid.');
    out.uuid = String(i.uuid).toLowerCase();
  }
  if ('trojanPass' in i) {
    const p = String(i.trojanPass);
    if (p.length < 8 || p.length > 64 || /\s/.test(p)) throw new Error('Trojan password: 8-64 characters, no spaces.');
    out.trojanPass = p;
  }
  return out;
}

const fresh = () => ({
  ...structuredClone(DEFAULTS),
  uuid: crypto.randomUUID(),
  trojanPass: randomToken(12),
  subToken: randomToken(9).replace(/[-_]/g, 'x'),
});

export async function loadSettings(env) {
  const stored = await env.kv.get('settings', 'json');
  if (!stored) {
    const s = fresh();
    await env.kv.put('settings', JSON.stringify(s));
    return s;
  }
  // Fill any keys added in newer versions.
  return { ...structuredClone(DEFAULTS), ...stored, fragment: { ...DEFAULTS.fragment, ...stored.fragment }, routing: { ...DEFAULTS.routing, ...stored.routing }, protocols: { ...DEFAULTS.protocols, ...stored.protocols } };
}

export async function saveSettings(env, input) {
  const next = mergeSettings(await loadSettings(env), input);
  await env.kv.put('settings', JSON.stringify(next));
  return next;
}

export async function regenerate(env, what) {
  const s = await loadSettings(env);
  if (what === 'uuid') s.uuid = crypto.randomUUID();
  else if (what === 'trojan') s.trojanPass = randomToken(12);
  else if (what === 'sub') s.subToken = randomToken(9).replace(/[-_]/g, 'x');
  else throw new Error('Unknown item.');
  await env.kv.put('settings', JSON.stringify(s));
  return s;
}

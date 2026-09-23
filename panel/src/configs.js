// Subscription builders: share links, Xray, Sing-box and Clash/Mihomo.
export const wsPath = (securePath) => `/${securePath}/ws`;
const EARLY = 2560;

// One entry per address x port x protocol.
export function endpoints(settings, host) {
  const addrs = [{ address: host, label: 'D' }, ...settings.cleanIPs.map((a, i) => ({ address: a, label: `C${i + 1}` }))];
  const protos = ['vless', 'trojan'].filter((p) => settings.protocols[p]);
  const out = [];
  for (const proto of protos) {
    for (const a of addrs) {
      for (const port of settings.ports) {
        out.push({ proto, address: a.address, port, name: `${settings.configName} ${proto === 'vless' ? 'VLESS' : 'Trojan'} ${a.label}:${port}` });
      }
    }
  }
  return out;
}

const secret = (s, proto) => (proto === 'vless' ? s.uuid : s.trojanPass);
const hostForUrl = (a) => (a.includes(':') ? `[${a}]` : a);

// ---- share links (v2rayNG, v2rayN, Streisand, Husi...) ----
export function buildLinks(s, host, sp) {
  const path = encodeURIComponent(`${wsPath(sp)}?ed=${EARLY}`);
  return endpoints(s, host).map((e) => {
    const q = `security=tls&sni=${host}&fp=${s.fingerprint}&alpn=http%2F1.1&type=ws&host=${host}&path=${path}`;
    const extra = e.proto === 'vless' ? 'encryption=none&' : '';
    return `${e.proto}://${encodeURIComponent(secret(s, e.proto))}@${hostForUrl(e.address)}:${e.port}?${extra}${q}#${encodeURIComponent(e.name)}`;
  });
}
export const buildRaw = (s, host, sp) => btoa(buildLinks(s, host, sp).join('\n'));

// ---- Xray ----
function xrayOutbound(s, e, host, sp) {
  const stream = {
    network: 'ws',
    security: 'tls',
    tlsSettings: { serverName: host, fingerprint: s.fingerprint, alpn: ['http/1.1'], allowInsecure: false },
    wsSettings: { path: `${wsPath(sp)}?ed=${EARLY}`, headers: { Host: host } },
  };
  if (s.fragment.enabled) stream.sockopt = { dialerProxy: 'fragment' };
  const base = { tag: 'proxy', streamSettings: stream, mux: { enabled: false } };
  return e.proto === 'vless'
    ? { ...base, protocol: 'vless', settings: { vnext: [{ address: e.address, port: e.port, users: [{ id: s.uuid, encryption: 'none', level: 8 }] }] } }
    : { ...base, protocol: 'trojan', settings: { servers: [{ address: e.address, port: e.port, password: s.trojanPass, level: 8 }] } };
}

export function buildXray(s, host, sp) {
  const r = s.routing;
  const rules = [{ type: 'field', ip: [s.localDNS], port: '53', outboundTag: 'direct' }];
  if (r.blockQUIC) rules.push({ type: 'field', network: 'udp', port: '443', outboundTag: 'block' });
  if (r.blockAds) rules.push({ type: 'field', domain: ['geosite:category-ads-all'], outboundTag: 'block' });
  if (r.bypassLAN) rules.push({ type: 'field', ip: ['geoip:private'], outboundTag: 'direct' });
  if (r.bypassIran) rules.push({ type: 'field', domain: ['regexp:.*\\.ir$'], outboundTag: 'direct' }, { type: 'field', ip: ['geoip:ir'], outboundTag: 'direct' });
  rules.push({ type: 'field', network: 'tcp,udp', outboundTag: 'proxy' });

  const dnsServers = [
    { address: s.localDNS, domains: [`full:${host}`], skipFallback: true },
    s.remoteDNS,
  ];
  if (r.bypassIran) dnsServers.splice(1, 0, { address: s.localDNS, domains: ['regexp:.*\\.ir$'], skipFallback: true });

  return endpoints(s, host).map((e) => ({
    remarks: e.name,
    log: { loglevel: 'warning' },
    dns: { servers: dnsServers, queryStrategy: 'UseIPv4', tag: 'dns' },
    inbounds: [
      { tag: 'socks-in', port: 10808, listen: '127.0.0.1', protocol: 'socks', settings: { auth: 'noauth', udp: true }, sniffing: { enabled: true, destOverride: ['http', 'tls'], routeOnly: true } },
      { tag: 'http-in', port: 10809, listen: '127.0.0.1', protocol: 'http', sniffing: { enabled: true, destOverride: ['http', 'tls'], routeOnly: true } },
    ],
    outbounds: [
      xrayOutbound(s, e, host, sp),
      ...(s.fragment.enabled ? [{ tag: 'fragment', protocol: 'freedom', settings: { fragment: { packets: s.fragment.packets, length: s.fragment.length, interval: s.fragment.interval } }, streamSettings: { sockopt: { tcpNoDelay: true } } }] : []),
      { tag: 'direct', protocol: 'freedom', settings: { domainStrategy: 'UseIP' } },
      { tag: 'block', protocol: 'blackhole', settings: { response: { type: 'http' } } },
    ],
    routing: { domainStrategy: 'IPIfNonMatch', rules },
  }));
}

// ---- Sing-box (1.12+) ----
function singboxOutbound(s, e, host, sp) {
  const tls = { enabled: true, server_name: host, alpn: ['http/1.1'], utls: { enabled: true, fingerprint: s.fingerprint } };
  if (s.fragment.enabled) { tls.fragment = true; tls.record_fragment = true; }
  const transport = { type: 'ws', path: wsPath(sp), headers: { Host: host }, max_early_data: EARLY, early_data_header_name: 'Sec-WebSocket-Protocol' };
  const base = { tag: e.name, server: e.address, server_port: e.port, tls, transport, domain_resolver: 'dns-local' };
  return e.proto === 'vless' ? { type: 'vless', ...base, uuid: s.uuid } : { type: 'trojan', ...base, password: s.trojanPass };
}

export function buildSingbox(s, host, sp) {
  const r = s.routing;
  const eps = endpoints(s, host);
  const names = eps.map((e) => e.name);
  const dnsRules = [];
  if (r.bypassIran) dnsRules.push({ domain_suffix: ['.ir'], action: 'route', server: 'dns-local' });
  dnsRules.push({ domain: [host], action: 'route', server: 'dns-local' });
  const rules = [{ action: 'sniff' }, { protocol: 'dns', action: 'hijack-dns' }];
  if (r.blockQUIC) rules.push({ protocol: 'quic', action: 'reject' });
  if (r.bypassLAN) rules.push({ ip_is_private: true, action: 'route', outbound: 'direct' });
  if (r.bypassIran) rules.push({ domain_suffix: ['.ir'], action: 'route', outbound: 'direct' });
  return {
    log: { level: 'warn', timestamp: true },
    dns: {
      servers: [
        { tag: 'dns-remote', type: 'https', server: new URL(s.remoteDNS).hostname, path: new URL(s.remoteDNS).pathname, detour: 'Select', domain_resolver: 'dns-local' },
        { tag: 'dns-local', type: 'udp', server: s.localDNS },
      ],
      rules: dnsRules,
      final: 'dns-remote',
      strategy: 'ipv4_only',
    },
    inbounds: [
      { type: 'tun', tag: 'tun-in', address: ['172.19.0.1/28'], auto_route: true, strict_route: true, stack: 'mixed' },
      { type: 'mixed', tag: 'mixed-in', listen: '127.0.0.1', listen_port: 2080 },
    ],
    outbounds: [
      { type: 'selector', tag: 'Select', outbounds: ['Auto', ...names], default: 'Auto' },
      { type: 'urltest', tag: 'Auto', outbounds: names, url: 'https://www.gstatic.com/generate_204', interval: '5m', tolerance: 50 },
      ...eps.map((e) => singboxOutbound(s, e, host, sp)),
      { type: 'direct', tag: 'direct' },
    ],
    route: { rules, final: 'Select', auto_detect_interface: true, default_domain_resolver: { server: 'dns-local' } },
  };
}

// ---- Clash / Mihomo (JSON is valid YAML, so we emit JSON) ----
export function buildClash(s, host, sp) {
  const r = s.routing;
  const eps = endpoints(s, host);
  const names = eps.map((e) => e.name);
  const ws = { path: wsPath(sp), headers: { Host: host }, 'max-early-data': EARLY, 'early-data-header-name': 'Sec-WebSocket-Protocol' };
  const proxies = eps.map((e) => e.proto === 'vless'
    ? { name: e.name, type: 'vless', server: e.address, port: e.port, uuid: s.uuid, network: 'ws', tls: true, udp: false, servername: host, 'client-fingerprint': s.fingerprint, alpn: ['http/1.1'], 'ws-opts': ws }
    : { name: e.name, type: 'trojan', server: e.address, port: e.port, password: s.trojanPass, network: 'ws', udp: false, sni: host, 'client-fingerprint': s.fingerprint, alpn: ['http/1.1'], 'ws-opts': ws });
  const rules = [];
  if (r.blockQUIC) rules.push('AND,((NETWORK,UDP),(DST-PORT,443)),REJECT');
  if (r.bypassLAN) rules.push('GEOIP,LAN,DIRECT,no-resolve');
  if (r.bypassIran) rules.push('DOMAIN-SUFFIX,ir,DIRECT', 'GEOIP,IR,DIRECT,no-resolve');
  rules.push('MATCH,Select');
  return {
    'mixed-port': 7890,
    'allow-lan': false,
    mode: 'rule',
    'log-level': 'warning',
    ipv6: false,
    dns: {
      enable: true,
      ipv6: false,
      'enhanced-mode': 'fake-ip',
      'fake-ip-range': '198.18.0.1/16',
      'default-nameserver': [s.localDNS],
      'proxy-server-nameserver': [s.localDNS],
      nameserver: [s.remoteDNS],
      ...(r.bypassIran ? { 'nameserver-policy': { '+.ir': [s.localDNS] } } : {}),
    },
    tun: { enable: true, stack: 'mixed', 'auto-route': true, 'auto-detect-interface': true, 'dns-hijack': ['any:53'] },
    proxies,
    'proxy-groups': [
      { name: 'Select', type: 'select', proxies: ['Auto', ...names] },
      { name: 'Auto', type: 'url-test', url: 'https://www.gstatic.com/generate_204', interval: 300, tolerance: 50, proxies: names },
    ],
    rules,
  };
}

export const SUB_FORMATS = {
  raw: { label: 'Universal links', apps: 'v2rayNG, v2rayN, Streisand, Husi', type: 'text/plain' },
  xray: { label: 'Xray JSON', apps: 'v2rayNG, v2rayN, Streisand (fragment support)', type: 'application/json' },
  singbox: { label: 'Sing-box', apps: 'Sing-box 1.12+, Husi', type: 'application/json' },
  clash: { label: 'Clash / Mihomo', apps: 'Clash Verge Rev, Clash Meta, FLClash', type: 'application/yaml' },
};

export function buildSubscription(format, s, host, sp) {
  switch (format) {
    case 'raw': return buildRaw(s, host, sp);
    case 'xray': return JSON.stringify(buildXray(s, host, sp));
    case 'singbox': return JSON.stringify(buildSingbox(s, host, sp));
    case 'clash': return JSON.stringify(buildClash(s, host, sp));
    default: return null;
  }
}

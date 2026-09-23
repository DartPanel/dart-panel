// VLESS / Trojan over WebSocket, relayed to the destination with cloudflare:sockets.
import { b64u } from './crypto.js';
import { looksLikeTrojan, parseTrojan, parseVless, sha224Hex } from './protocol.js';

const OPEN = 1;
const concat = (a, b) => { const o = new Uint8Array(a.length + b.length); o.set(a); o.set(b, a.length); return o; };
const toBytes = (d) => (d instanceof ArrayBuffer ? new Uint8Array(d) : ArrayBuffer.isView(d) ? new Uint8Array(d.buffer, d.byteOffset, d.byteLength) : new TextEncoder().encode(String(d)));

function splitProxyIP(entry) {
  const m = /^(.*):(\d{1,5})$/.exec(entry);
  return m && !entry.includes('::') && (entry.match(/:/g) || []).length === 1 ? { hostname: m[1], port: Number(m[2]) } : { hostname: entry, port: null };
}

export function handleWebsocket(request, settings, connect) {
  const [client, server] = Object.values(new WebSocketPair());
  server.accept();

  let remote = null;      // { socket, writer }
  let ready = Promise.resolve();
  let closed = false;

  const closeAll = () => {
    if (closed) return;
    closed = true;
    try { remote?.writer.releaseLock(); } catch {}
    try { remote?.socket.close(); } catch {}
    try { server.close(1000); } catch {}
  };

  async function open(hostname, port, first) {
    const socket = connect({ hostname, port });
    const writer = socket.writable.getWriter();
    await writer.write(first);
    return { socket, writer };
  }

  function pipe(r, respHeader, onEmptyClose) {
    let sentHeader = !respHeader;
    let gotData = false;
    r.socket.readable.pipeTo(new WritableStream({
      write(chunk) {
        if (server.readyState !== OPEN) return;
        gotData = true;
        if (!sentHeader) { server.send(concat(respHeader, chunk)); sentHeader = true; } else server.send(chunk);
      },
      close() { if (!gotData && onEmptyClose) onEmptyClose(); else closeAll(); },
      abort() { if (!gotData && onEmptyClose) onEmptyClose(); else closeAll(); },
    })).catch(() => { if (!gotData && onEmptyClose) onEmptyClose(); else closeAll(); });
  }

  async function firstPacket(bytes) {
    const parsed = looksLikeTrojan(bytes) && settings.protocols.trojan
      ? parseTrojan(bytes, sha224Hex(settings.trojanPass))
      : settings.protocols.vless ? parseVless(bytes, settings.uuid) : { error: 'protocol disabled' };
    if (parsed.error) return closeAll();
    if (parsed.protocol === 'vless' && !settings.protocols.vless) return closeAll();

    const { address, port, payload, response } = parsed;
    const tryDirect = async () => {
      remote = await open(address, port, payload);
      let retried = false;
      const retry = async () => {
        if (retried || closed) return closeAll();
        retried = true;
        const list = settings.proxyIPs;
        if (!list.length) return closeAll();
        const pick = splitProxyIP(list[Math.floor(Math.random() * list.length)]);
        try {
          try { remote.writer.releaseLock(); remote.socket.close(); } catch {}
          remote = await open(pick.hostname, pick.port || port, payload);
          pipe(remote, response, closeAll);
        } catch { closeAll(); }
      };
      pipe(remote, response, retry);
    };
    try { await tryDirect(); } catch { closeAll(); }
  }

  const onData = (bytes) => {
    ready = ready.then(async () => {
      if (closed) return;
      if (remote) { try { await remote.writer.write(bytes); } catch { closeAll(); } return; }
      await firstPacket(bytes);
    });
  };

  // 0-RTT early data arrives base64url-encoded in Sec-WebSocket-Protocol.
  const early = request.headers.get('Sec-WebSocket-Protocol');
  if (early) { try { onData(b64u.dec(early)); } catch {} }

  server.addEventListener('message', (e) => onData(toBytes(e.data)));
  server.addEventListener('close', closeAll);
  server.addEventListener('error', closeAll);

  const init = { status: 101, webSocket: client };
  if (early) init.headers = { 'Sec-WebSocket-Protocol': early };
  return new Response(null, init);
}

// VLESS and Trojan request-header parsing, plus a small SHA-224 (WebCrypto has none).
const dec = new TextDecoder();

// ---- SHA-224 (FIPS 180-4) ----
const K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

export function sha224Hex(text) {
  const msg = new TextEncoder().encode(text);
  const bitLen = msg.length * 8;
  const total = (((msg.length + 8) >> 6) + 1) << 6;
  const buf = new Uint8Array(total);
  buf.set(msg); buf[msg.length] = 0x80;
  const dv = new DataView(buf.buffer);
  dv.setUint32(total - 8, Math.floor(bitLen / 2 ** 32)); dv.setUint32(total - 4, bitLen >>> 0);
  const H = new Uint32Array([0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4]);
  const w = new Uint32Array(64);
  const rotr = (x, n) => (x >>> n) | (x << (32 - n));
  for (let off = 0; off < total; off += 64) {
    for (let t = 0; t < 16; t++) w[t] = dv.getUint32(off + t * 4);
    for (let t = 16; t < 64; t++) {
      const s0 = rotr(w[t - 15], 7) ^ rotr(w[t - 15], 18) ^ (w[t - 15] >>> 3);
      const s1 = rotr(w[t - 2], 17) ^ rotr(w[t - 2], 19) ^ (w[t - 2] >>> 10);
      w[t] = (w[t - 16] + s0 + w[t - 7] + s1) >>> 0;
    }
    let [a, b, c, d, e, f, g, h] = H;
    for (let t = 0; t < 64; t++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (h + S1 + ch + K[t] + w[t]) >>> 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) >>> 0;
      h = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    H[0] += a; H[1] += b; H[2] += c; H[3] += d; H[4] += e; H[5] += f; H[6] += g; H[7] += h;
  }
  return Array.from(H.slice(0, 7), (x) => x.toString(16).padStart(8, '0')).join('');
}

// ---- helpers ----
export function uuidBytes(uuid) {
  const hex = uuid.replace(/-/g, '');
  return Uint8Array.from({ length: 16 }, (_, i) => parseInt(hex.slice(i * 2, i * 2 + 2), 16));
}

function readAddress(view, bytes, offset, type, names) {
  // type ids differ between VLESS (1 v4, 2 domain, 3 v6) and Trojan (1 v4, 3 domain, 4 v6); callers pass a map.
  const kind = names[type];
  if (kind === 'ipv4') return { address: Array.from(bytes.subarray(offset, offset + 4)).join('.'), next: offset + 4 };
  if (kind === 'domain') {
    const len = bytes[offset];
    return { address: dec.decode(bytes.subarray(offset + 1, offset + 1 + len)), next: offset + 1 + len };
  }
  if (kind === 'ipv6') {
    const parts = [];
    for (let i = 0; i < 8; i++) parts.push(view.getUint16(offset + i * 2).toString(16));
    return { address: parts.join(':'), next: offset + 16 };
  }
  return null;
}

// VLESS header: ver(1) uuid(16) addonLen(1) addon cmd(1) port(2) atype(1) addr payload
export function parseVless(bytes, expectedUuid) {
  if (bytes.length < 24) return { error: 'header too short' };
  const version = bytes[0];
  const id = bytes.subarray(1, 17);
  const want = uuidBytes(expectedUuid);
  let diff = 0;
  for (let i = 0; i < 16; i++) diff |= id[i] ^ want[i];
  if (diff !== 0) return { error: 'invalid user' };
  const addonLen = bytes[17];
  let p = 18 + addonLen;
  const cmd = bytes[p++];
  if (cmd !== 1) return { error: cmd === 2 ? 'udp not supported' : 'unsupported command' };
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (p + 3 > bytes.length) return { error: 'header too short' };
  const port = view.getUint16(p); p += 2;
  const type = bytes[p++];
  const addr = readAddress(view, bytes, p, type, { 1: 'ipv4', 2: 'domain', 3: 'ipv6' });
  if (!addr || addr.next > bytes.length) return { error: 'bad address' };
  return { protocol: 'vless', address: addr.address, port, payload: bytes.subarray(addr.next), response: new Uint8Array([version, 0]) };
}

// Trojan header: hex(sha224(pass))(56) CRLF cmd(1) atype(1) addr port(2) CRLF payload
export function parseTrojan(bytes, expectedHash) {
  if (bytes.length < 62) return { error: 'header too short' };
  if (dec.decode(bytes.subarray(0, 56)) !== expectedHash) return { error: 'invalid user' };
  if (bytes[56] !== 0x0d || bytes[57] !== 0x0a) return { error: 'bad header' };
  if (bytes[58] !== 1) return { error: 'unsupported command' };
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const type = bytes[59];
  const addr = readAddress(view, bytes, 60, type, { 1: 'ipv4', 3: 'domain', 4: 'ipv6' });
  if (!addr || addr.next + 4 > bytes.length) return { error: 'bad address' };
  const port = view.getUint16(addr.next);
  if (bytes[addr.next + 2] !== 0x0d || bytes[addr.next + 3] !== 0x0a) return { error: 'bad header' };
  return { protocol: 'trojan', address: addr.address, port, payload: bytes.subarray(addr.next + 4), response: null };
}

// Trojan first packets carry CRLF at bytes 56-57; VLESS starts with a version byte and a UUID.
export const looksLikeTrojan = (bytes) => bytes.length >= 58 && bytes[56] === 0x0d && bytes[57] === 0x0a;

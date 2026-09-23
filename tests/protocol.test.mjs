import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { parseTrojan, parseVless, sha224Hex, looksLikeTrojan } from '../panel/src/protocol.js';

import { UUID, uuidBytes, cat, vlessDomain, trojanIPv4 } from './helpers.mjs';

test('sha224 matches Node crypto', () => {
  for (const s of ['', 'abc', 'x'.repeat(55), 'x'.repeat(56), 'x'.repeat(64), 'pässwörd']) {
    assert.equal(sha224Hex(s), createHash('sha224').update(s).digest('hex'));
  }
});

test('parses a VLESS domain request', () => {
  const r = parseVless(vlessDomain('example.com', 443), UUID);
  assert.equal(r.address, 'example.com'); assert.equal(r.port, 443);
  assert.deepEqual([...r.payload], [1, 2, 3]); assert.deepEqual([...r.response], [0, 0]);
});

test('parses VLESS IPv4 and IPv6 addresses', () => {
  const v4 = cat([0], uuidBytes, [0, 1, 0, 80, 1, 8, 8, 4, 4]);
  assert.equal(parseVless(v4, UUID).address, '8.8.4.4');
  const v6 = cat([0], uuidBytes, [0, 1, 1, 187, 3], [0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
  assert.equal(parseVless(v6, UUID).address, '2001:db8:0:0:0:0:0:1');
});

test('rejects wrong user, UDP and truncated VLESS headers', () => {
  assert.ok(parseVless(vlessDomain('a.com', 80, [], uuidBytes.map((b) => b ^ 1)), UUID).error);
  const udp = vlessDomain('a.com', 53); udp[18] = 2;
  assert.match(parseVless(udp, UUID).error, /udp/);
  assert.ok(parseVless(vlessDomain('a.com', 80).subarray(0, 20), UUID).error);
});

test('parses Trojan and detects it by CRLF', () => {
  const b = trojanIPv4('secret-pass', '1.2.3.4', 8080);
  assert.ok(looksLikeTrojan(b));
  const r = parseTrojan(b, sha224Hex('secret-pass'));
  assert.equal(r.address, '1.2.3.4'); assert.equal(r.port, 8080); assert.deepEqual([...r.payload], [9, 8]);
  assert.ok(parseTrojan(b, sha224Hex('other-pass')).error);
  assert.ok(!looksLikeTrojan(vlessDomain('a.com', 80)));
});

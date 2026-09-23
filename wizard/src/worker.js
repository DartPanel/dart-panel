// Dart Panel Wizard - deploys a Dart Panel Worker into the visitor's own Cloudflare account.
// The API token is used for this single request and is never stored or logged.
import { wizardHtml } from './ui.generated.js';
import * as CF from './cloudflare.js';

const NAME_RE = /^[a-z0-9](?:[a-z0-9-]{0,38}[a-z0-9])$/;
const enc = new TextEncoder();

function randomId(len) {
  const alphabet = 'abcdefghijklmnopqrstuvwxyz0123456789';
  const bytes = crypto.getRandomValues(new Uint8Array(len * 2));
  let out = '';
  for (const b of bytes) if (b < 252 && out.length < len) out += alphabet[b % 36];
  return out;
}

const securityHeaders = {
  'Cache-Control': 'no-store',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  'Content-Security-Policy':
    "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
};

const page = () => new Response(wizardHtml, { headers: { 'Content-Type': 'text/html; charset=utf-8', ...securityHeaders } });

async function fetchPanelCode(env) {
  const url = env.PANEL_RELEASE_URL;
  if (!url || url.includes('OWNER')) {
    throw new Error('The wizard is not configured yet: set PANEL_RELEASE_URL in wizard/wrangler.toml to your release URL.');
  }
  const res = await fetch(url);
  if (!res.ok) throw new Error(`Could not download the panel (HTTP ${res.status}). Check that a release with worker.js exists.`);
  const code = await res.text();
  if (code.length < 1000) throw new Error('The downloaded panel file looks empty.');
  return code;
}

async function deploy(token, name, env, emit) {
  const step = async (id, label, fn) => {
    emit({ type: 'step', id, label, status: 'run' });
    const result = await fn();
    emit({ type: 'step', id, label, status: 'ok' });
    return result;
  };

  let kvId = null;
  let scriptCreated = false;
  let accountId = null;
  try {
    const account = await step('account', 'Checking your Cloudflare account', () => CF.getAccount(token));
    accountId = account.id;

    if (await CF.scriptExists(token, accountId, name)) {
      throw new Error(`A Worker named "${name}" already exists in this account. Choose another name.`);
    }

    const sub = await step('subdomain', 'Preparing your workers.dev address', async () => {
      let s = await CF.getWorkersSubdomain(token, accountId);
      if (!s) {
        s = `dart-${randomId(8)}`;
        await CF.createWorkersSubdomain(token, accountId, s);
      }
      return s;
    });

    const code = await step('download', 'Downloading Dart Panel', () => fetchPanelCode(env));

    kvId = (await step('storage', 'Creating storage', () => CF.createKV(token, accountId, `dart-panel-${name}`))).id;

    const securePath = randomId(14);
    const sessionSecret = Array.from(crypto.getRandomValues(new Uint8Array(32)), (b) => b.toString(16).padStart(2, '0')).join('');
    await step('upload', 'Uploading Dart Panel', async () => {
      await CF.uploadWorker(token, accountId, name, code, [
        { type: 'kv_namespace', name: 'kv', namespace_id: kvId },
        { type: 'plain_text', name: 'SECURE_PATH', text: securePath },
        { type: 'secret_text', name: 'SESSION_SECRET', text: sessionSecret },
      ]);
      scriptCreated = true;
    });

    await step('address', 'Turning on your address', () => CF.enableWorkersDev(token, accountId, name));

    return `https://${name}.${sub}.workers.dev/${securePath}/panel`;
  } catch (err) {
    // Best-effort cleanup so a failed attempt leaves nothing behind.
    if (scriptCreated) await CF.deleteScript(token, accountId, name).catch(() => {});
    if (kvId) await CF.deleteKV(token, accountId, kvId).catch(() => {});
    throw err;
  }
}

function handleDeploy(request, env) {
  return request.json().then((body) => {
    const token = String(body?.token || '').trim();
    const name = String(body?.name || '').trim().toLowerCase();
    if (token.length < 20) return Response.json({ error: 'Paste a valid Cloudflare API token.' }, { status: 400 });
    if (!NAME_RE.test(name)) return Response.json({ error: 'Use 2-40 lowercase letters, numbers or dashes for the name.' }, { status: 400 });

    const { readable, writable } = new TransformStream();
    const writer = writable.getWriter();
    const emit = (obj) => writer.write(enc.encode(JSON.stringify(obj) + '\n'));

    (async () => {
      try {
        const panelUrl = await deploy(token, name, env, emit);
        await emit({ type: 'done', panelUrl });
      } catch (e) {
        await emit({ type: 'error', message: friendly(e) });
      } finally {
        await writer.close();
      }
    })();

    return new Response(readable, { headers: { 'Content-Type': 'application/x-ndjson', ...securityHeaders } });
  }, () => Response.json({ error: 'Invalid request.' }, { status: 400 }));
}

function friendly(e) {
  if (e instanceof CF.CFError && (e.status === 401 || e.status === 403)) {
    return `Cloudflare rejected the token (${e.message}). Check that it has Workers Scripts: Edit, Workers KV Storage: Edit and Account Settings: Read.`;
  }
  return e.message || 'Something went wrong.';
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === 'GET' && url.pathname === '/') return page();
    if (request.method === 'POST' && url.pathname === '/api/deploy') {
      if (request.headers.get('Origin') !== url.origin) return new Response('Forbidden', { status: 403 });
      return handleDeploy(request, env);
    }
    return new Response('Not found', { status: 404 });
  },
};

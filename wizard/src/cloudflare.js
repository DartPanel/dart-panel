// Minimal Cloudflare REST client used by the wizard. No dependencies.
const API = 'https://api.cloudflare.com/client/v4';

export class CFError extends Error {
  constructor(message, status) {
    super(message);
    this.name = 'CFError';
    this.status = status;
  }
}

async function cf(token, path, init = {}) {
  const res = await fetch(API + path, {
    ...init,
    headers: { Authorization: `Bearer ${token}`, ...(init.headers || {}) },
  });
  let body = null;
  try { body = await res.json(); } catch { /* non-JSON error page */ }
  if (!res.ok || !body || body.success === false) {
    const detail = body?.errors?.map((e) => e.message).join('; ');
    throw new CFError(detail || `Cloudflare returned HTTP ${res.status}`, res.status);
  }
  return body.result;
}

const json = (method, data) => ({
  method,
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(data),
});

export async function getAccount(token) {
  const accounts = await cf(token, '/accounts?per_page=50');
  if (!accounts.length) throw new CFError('This token cannot see any Cloudflare account.', 403);
  return accounts[0];
}

export async function getWorkersSubdomain(token, accountId) {
  try {
    return (await cf(token, `/accounts/${accountId}/workers/subdomain`)).subdomain || null;
  } catch (e) {
    if (e.status === 404) return null;
    throw e;
  }
}

export const createWorkersSubdomain = (token, accountId, subdomain) =>
  cf(token, `/accounts/${accountId}/workers/subdomain`, json('PUT', { subdomain }));

export async function scriptExists(token, accountId, name) {
  try {
    await cf(token, `/accounts/${accountId}/workers/scripts/${name}/settings`);
    return true;
  } catch (e) {
    if (e.status === 404) return false;
    throw e;
  }
}

export const createKV = (token, accountId, title) =>
  cf(token, `/accounts/${accountId}/storage/kv/namespaces`, json('POST', { title }));

export const deleteKV = (token, accountId, id) =>
  cf(token, `/accounts/${accountId}/storage/kv/namespaces/${id}`, { method: 'DELETE' });

export const deleteScript = (token, accountId, name) =>
  cf(token, `/accounts/${accountId}/workers/scripts/${name}`, { method: 'DELETE' });

export function uploadWorker(token, accountId, name, code, bindings) {
  const metadata = {
    main_module: 'worker.js',
    compatibility_date: '2025-09-01',
    bindings,
  };
  const form = new FormData();
  form.append('metadata', new Blob([JSON.stringify(metadata)], { type: 'application/json' }));
  form.append('worker.js', new Blob([code], { type: 'application/javascript+module' }), 'worker.js');
  return cf(token, `/accounts/${accountId}/workers/scripts/${name}`, { method: 'PUT', body: form });
}

export const enableWorkersDev = (token, accountId, name) =>
  cf(token, `/accounts/${accountId}/workers/scripts/${name}/subdomain`, json('POST', { enabled: true, previews_enabled: false }));

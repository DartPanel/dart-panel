// Custom loader hook (the module.register() API, stable since Node 18.19/20.6)
// that lets tests import modules using Cloudflare's runtime-only "cloudflare:sockets".
export async function resolve(specifier, context, nextResolve) {
  if (specifier === 'cloudflare:sockets') {
    return { url: 'data:text/javascript,export const connect = (...a) => globalThis.__connect(...a);', shortCircuit: true };
  }
  return nextResolve(specifier, context);
}

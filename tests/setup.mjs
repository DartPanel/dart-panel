// Lets Node import modules that use Cloudflare's runtime-only "cloudflare:sockets".
// Uses module.register() (stable since Node 18.19/20.6) rather than the newer
// module.registerHooks() (Node 22.15+), so this also works on older CI runners.
import { register } from 'node:module';
register('./loader.mjs', import.meta.url);

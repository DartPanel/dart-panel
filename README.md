# Dart Panel

Dart Panel is a self-hosted VLESS/Trojan panel that runs entirely on
Cloudflare Workers. A one-page setup wizard deploys it into your own
Cloudflare account in a couple of minutes — no server to rent or maintain.

## Features

- **One-click deploy.** The wizard creates the storage, uploads the panel,
  and turns on its address for you.
- **VLESS and Trojan** over WebSocket, with TLS fragmentation and
  configurable routing (bypass local sites, block ads, block QUIC, etc).
- **Subscription links** in four formats: universal share links, Xray,
  Sing-box, and Clash/Mihomo — so it works with most popular client apps.
- **Password-protected panel** with brute-force lockout and signed
  sessions; no separate database needed.
- **Telegram bot** for status checks and getting your links without
  opening the panel.
- **Mobile-friendly UI** for both the wizard and the panel itself.

## Quick start

Visit [Wizard Page](https://wizard-dart-panel.dartpanel.workers.dev) to setup your Dart Panel!

## How it works

- The **wizard** (`wizard/`) is a Worker you deploy once. It takes a
  Cloudflare API token from whoever is setting up a panel, then creates a
  KV namespace and uploads the panel Worker into *their* account — with a
  random, unguessable path and a fresh set of credentials.
- The **panel** (`panel/`) is the Worker that actually gets deployed. It
  serves the dashboard, the JSON API, the VLESS/Trojan tunnel, subscription
  links, and the Telegram webhook.
- The wizard downloads the panel's code from this repository's latest
  GitHub Release (`worker.js`), which the release workflow builds
  automatically — see [Development](#development).

## Project layout

```
assets/    logo and icons
shared/    CSS design tokens shared by the wizard and the panel
wizard/    the setup wizard (source + UI)
panel/     the panel Worker (source + UI)
scripts/   build and bundling scripts
docs/      setup guide and Telegram bot guide
```

## Development

```
npm run build:ui               # inline panel/wizard HTML+CSS into ui.generated.js
node scripts/bundle-worker.mjs # bundle panel/src into a single dist/worker.js
npm run build                  # both of the above
npm test                       # runs the test suite (no external dependencies)
```

Pushing a version tag (`git tag v1.0.0 && git push --tags`), or running the
**Release panel worker** GitHub Action manually, builds and tests the panel
and attaches `worker.js` to a GitHub Release. The wizard always downloads
the latest one.

## Credits and license

Dart Panel is free software under the **GPL-3.0** license (see `LICENSE`).
It's based on [BPB Worker Panel](https://github.com/bia-pain-bache/BPB-Worker-Panel)
and [BPB Wizard](https://github.com/bia-pain-bache/BPB-Wizard) (also
GPL-3.0) — see `NOTICE` for details. The interface and branding are
original to Dart Panel.

## Author

- [DartPanel](https://github.com/DartPanel)
- [TahaFathalizadeh](https://github.com/TahaFathalizadeh)

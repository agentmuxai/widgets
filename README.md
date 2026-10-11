# AgentMux widget catalog

Sandboxed widgets for [AgentMux](https://github.com/agentmuxai/agentmux), browsable in **Settings → Widgets → Browse the catalog**.

A widget from the catalog is installed like any other: it runs only after you approve it in AgentMux, and the prompt lists exactly what it may do. The catalog is a second check, never an approval.

## How it works

- Each widget is a folder in [`widgets/`](widgets/), named as its id (`publisher.name`), holding its package exactly as AgentMux installs it, with its `widget.sig`.
- [`publishers.json`](publishers.json) lists each publisher's signing key.
- On every change to `main`, CI checks every widget (`scripts/build.mjs`), writes `index.json` and a zip per widget, signs `index.json` with the catalog key, and publishes them at `https://agentmuxai.github.io/widgets/`.
- AgentMux checks the index's signature against the catalog key it has built in, downloads widgets only from this site, and checks each download's hash, its files and its author's signature against the index before it asks you to approve it.

## Add your widget

1. Build a **sandboxed** widget ([Build a widget](https://docs.agentmux.ai/build-a-widget/)). Trusted widgets aren't listed.
2. Sign it with your key:
   ```bash
   npx -p @agentmuxai/widget-sdk agentmux-widget keygen ~/.agentmux-widget-key.json   # once
   npx -p @agentmuxai/widget-sdk agentmux-widget sign ./acme.board --key ~/.agentmux-widget-key.json
   ```
3. Open a pull request that adds `widgets/acme.board/` and, the first time, your publisher's key to `publishers.json` (`"acme": "<publicKey from your key file>"`).

CI checks it:
- the manifest;
- that it's sandboxed and signed by the key `publishers.json` lists;
- the size limits;
- that it loads no script or stylesheet from another origin.

A maintainer reads it before it's merged; a new network origin or `agents:send` gets a closer look. To update it, change its files, bump its `version` and sign it again.

## Build it locally

```bash
node scripts/build.mjs --out dist
```

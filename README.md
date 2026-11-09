# Trace: bug bounty repository review

Trace is a local website for reviewing public GitHub repositories. Paste a link, see candidate security findings, ask follow-up questions in chat, and download a PR-ready report.

Built by [kvianAR](https://github.com/kvianAR).

## Start

Requirements: Python 3.9+, Git, and the [Codex CLI](https://developers.openai.com/codex/cli) signed in on this machine. No Python packages or API key are required.

```bash
python3 server.py
```

Open [http://127.0.0.1:8791](http://127.0.0.1:8791). Paste a public GitHub repository URL. A review may take several minutes. Scans and chat are saved under `data/`, which Git ignores. Set `BUGBOUNTY_PORT` to change the port.

## How it works

1. The app validates a public GitHub URL and clones a shallow checkout into `data/`.
2. Codex runs in read-only mode against that checkout and returns structured findings.
3. The app checks each finding's path and line, then renders evidence, impact, safe reproduction, suggested fix, and PR checklist.
4. Chat uses the same checkout and report as context. Report download produces Markdown.

The agent does **source review**, not live exploitation. Findings are candidates until you reproduce them in an allowed environment. It cannot guarantee finding every bug. Check the bug-bounty program's scope, exclusions, duplicate policy, and disclosure rules before testing or submitting. Never paste private credentials into chat.

## CLI

For a terminal-only review:

```bash
python3 bugbounty_agent.py https://github.com/owner/repository --output report
```

Local checkout paths also work with the CLI. The website accepts public GitHub URLs only.

## Development checks

```bash
python3 -m py_compile server.py bugbounty_agent.py
node --check public/app.js
```

The website binds to `127.0.0.1` by default. It has no account system or remote hosting. A public deployment needs a separate authenticated server that can run Git and Codex safely.

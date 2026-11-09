# Trace: bug bounty repository review

Trace is a local website for reviewing public GitHub repositories. Paste a link, see candidate security findings, ask follow-up questions in chat, and download a PR-ready report.

Built by [kvianAR](https://github.com/kvianAR).

## Start

Requirements: Python 3.9+, Git, and the [Codex CLI](https://developers.openai.com/codex/cli) signed in on this machine. No Python packages or API key are required.

```bash
python3 server.py
```

Open the private access link printed by the server. Paste a public GitHub repository URL. A review may take several minutes. Scans and chat are saved under `data/`, which Git ignores. Set `BUGBOUNTY_PORT` to change the port. A new access link is generated on each restart; keep it private.

## How it works

1. The app validates a public GitHub URL and clones a shallow checkout into `data/`.
2. Codex runs in read-only mode against that checkout and returns structured findings.
3. The app checks each finding's path and line, then renders evidence, impact, safe reproduction, suggested fix, and PR checklist.
4. Chat uses the same checkout and report as context. Report download produces Markdown.
5. Add or delete Codex, OpenRouter, or direct provider models in **Models +**. Choose a scan model in the scan form and a chat model beside the chat box. Add multiple API keys by name and choose one for each action. On macOS, keys are saved in Keychain; on other systems, they stay in server memory until restart. Deleting a model removes it from future choices; past reports remain. Delete keys in the same dialog. The **Test** button sends a small paid or free request and reports success or the provider error.

OpenRouter model IDs use `provider/model` format. Paste an exact ID such as `nvidia/nemotron-3-ultra-550b-a55b:free` or search the live catalog in the app. The `:free` suffix stays unchanged. Check **Use :floor** only when you want the cheapest provider for a paid model. This can be less reliable than normal routing. OpenRouter usage is billed to your selected key, subject to the model's free or paid terms. See [OpenRouter's routing guide](https://openrouter.ai/blog/tutorials/how-to-get-the-lowest-cost-llm-inference-on-openrouter/).

For a direct provider, save its full HTTPS OpenAI-compatible Chat Completions endpoint, then add that provider's model ID and API key. The form has [DeepSeek](https://api-docs.deepseek.com/guides/codex) and [MiMo](https://mimo.mi.com/docs/en-US/api/chat/openai-api) endpoint presets; other compatible providers can be entered manually. The app rejects local/private provider endpoints. A model test verifies a basic response; a model may still fail to produce a structured security report.

Codex models use the signed-in Codex CLI and can inspect the checkout with read-only tools. OpenRouter and direct provider scans use a selected source excerpt capped at 65,000 characters, because Chat Completions models do not receive local filesystem tools in this app. Their report lists that coverage limit. Chat with those models gets a shorter source excerpt and the report. Using any outside provider sends this source and chat context to that provider. Check the repository's disclosure rules before using a third-party model.

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
python3 -m unittest discover -s tests
```

The website binds to `127.0.0.1` by default and requires a random access token for API requests. It has no remote hosting. A public deployment needs a separate authenticated server that can run Git and Codex safely.

# Trace

A local bug bounty source-review website by [kvianAR](https://github.com/kvianAR).

Paste a public or authorized private GitHub repository or pull-request link. Review candidate findings, inspect source evidence, chat with your selected model, prepare a repair, and export a complete PR bundle.

## Start

Requires Python 3.9+, Git, and either a signed-in [Codex CLI](https://developers.openai.com/codex/cli) or an OpenAI-compatible model provider. No Python packages are required. Private repository access requires a GitHub account signed in through `gh auth login`.

```bash
python3 server.py
```

Open the private access link printed by the server. Data stays under the ignored `data/` directory. `BUGBOUNTY_PORT` changes the default port of 8791. The server binds to `127.0.0.1` and requires a random access token. Keep the access link private. Public hosting requires a separately secured deployment.

## Review workflow

1. **Choose scope.** Paste a repository or `/pull/N` link. Select the authorized GitHub account for private source. PR scans compare the head against its actual merge base. Choose an earlier scan of the same repository for incremental review.
2. **Choose models and budget.** Select a model and key, input/output token limits, an optional estimated USD ceiling, and up to three explicit fallback routes. Workspace usage includes review, chat, and repair preparation.
3. **Inspect evidence.** Each candidate includes a redacted source excerpt, location, best-effort enclosing function, trigger, impact, and stable fingerprint. Coverage lists submitted, partial, and skipped files with reasons. Submitted context does not prove that a model understood every line.
4. **Triage findings.** Save a decision and note. Matching fingerprints retain triage across scans. Repeated findings show prior occurrences. A finding absent from a later response is not automatically marked fixed. Deleting a scan retains its triage history.
5. **Prepare a fix.** Choose a model/key and prepare a draft. The model reassesses the security boundary first. It may reject intended behavior or request deployment evidence. Accepted drafts include a source patch, regression test, command, and expected markers. Edit the plan if needed. Patch validation happens in disposable snapshots.
6. **Verify in Docker.** Run the regression against original and patched source. A reproduced result requires the expected failure on original source and success after the fix. Review the test's meaning and security impact before disclosure.
7. **Export the PR.** Copy the title and complete body. Download the bundle containing `PR.md`, `APPLY.txt`, `fix.patch`, `regression.patch`, `evidence.json`, and `coverage.json`. Follow the pinned-commit branch/apply commands to review and submit your PR.

The website labels a PR ready only after a validated patch and successful regression verification, with an eligible assessment and triage decision. Submission remains manual.

## Models and keys

Use **Models +** to add, delete, or test models and keys. Select models separately for scans, chat, and repair drafts. Model testing makes a small provider request and reports whether it responds.

- OpenRouter accepts exact model IDs, including `nvidia/nemotron-3-ultra-550b-a55b:free`. The suffix is preserved. Enable `:floor` routing for the cheapest supported provider. [OpenRouter routing guide](https://openrouter.ai/blog/tutorials/how-to-get-the-lowest-cost-llm-inference-on-openrouter/)
- Direct providers accept an HTTPS OpenAI-compatible base URL, model ID, and your own key. DeepSeek and MiMo presets are included. Local/private provider endpoints are rejected.
- Codex uses the local signed-in CLI. It retains read-only tools. Precise total tool-context token enforcement and USD caps are unavailable for this route.

Keys use macOS Keychain where available. On other systems they remain in server memory until restart. Deleting keys or models removes future choices while historical reports remain.

OpenRouter pricing comes from its catalog, with zero pricing for `:free` routes. Direct-provider estimates require configured input/output rates. The app checks estimated reservations before dispatch and records reported usage/cost. Provider billing and tokenization can differ, so the USD ceiling is an application estimate. Unknown failed-request charges retain conservative reservations. Review the provider's own billing controls.

## Isolated verification

Start Docker Desktop and cache the runtime images you need before verification.

```bash
docker pull python:3.12-alpine
docker pull node:22-alpine
```

Verification uses cached image IDs, disabled network, a read-only root filesystem, a non-root user, dropped capabilities, and temporary writable storage. Each run has a 40-second deadline, 512 MB RAM, one CPU, 64 processes, a 128 MB workspace, and capped output. Source is mounted read-only. Keys, Git credentials, and the Docker socket are excluded from the container.

Snapshots allow 64 MB total and 8 MB per file. Tests requiring uncached dependencies, external services, larger source snapshots, or another runtime may be blocked. A blocked result includes its reason. Automated tests demonstrate the selected regression behavior and still require a human review of exploitability.

## Source and disclosure boundaries

Repository source and chat context are sent to the selected model provider. Use only authorized repositories and follow their disclosure rules. Private GitHub credentials are passed to Git through a child environment and excluded from clone URLs and model requests. Source excerpts are bounded and coverage records omissions. Existing historical scans cannot reconstruct precise past coverage.

Model findings remain candidates until reproduced in an authorized environment. Source review cannot guarantee every bug will be found. Never paste credentials into chat. The Codex read-only tool boundary has not received full filesystem-containment verification.

Delete completed, failed, or interrupted scans from the workspace. Active work and baselines used by running comparisons must finish first. Failed scans offer repository editing and retry.

## CLI

```bash
python3 bugbounty_agent.py https://github.com/owner/repository --output report
```

Local checkout paths also work. Use `--github-account LOGIN` for private repositories and `--pull-request NUMBER` for PR review.

## Development checks

```bash
python3 -m py_compile server.py bugbounty_agent.py review_workflow.py
node --check public/app.js
node --check public/workflow-ui.js
python3 -m unittest discover -s tests
node --test tests/frontend.test.js
```

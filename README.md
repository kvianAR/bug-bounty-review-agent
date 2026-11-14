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

## Investigative reviews and evidence gates

New scans build a repository map of declarations, imports and route hints. The model can request bounded source ranges anywhere in supported files and literal searches for helpers and callers. Discovery and candidate investigation each allow up to three rounds of six actions. Reads are capped at 160 lines, files at 250 KB, and searches at 8 MB of source and 35 hits per action. The manifest is bounded and marks its limits. Source access stays inside the checkout and never executes repository code.

The reviewer traces auth, ownership, helper validation, storage and deployment assumptions. Every accepted or rejected source verdict requires an exact citation to source that was supplied. A supported candidate also requires an attacker, entry point, violated control and unauthorized effect. Missing evidence becomes `needs_validation`. Hardening and rejected findings are retained and hidden by default. Enable their checkbox to inspect them.

Choose **Independent reviewer** and its key in the advanced scan settings to use another saved model. The default uses the scan model with a fresh context. Both review routes share workspace cost limits and their calls appear in usage. A fresh context from the same model is not independent empirical confirmation. At most eight discovered candidates receive review per run.

PR readiness now requires all three gates.

1. Source review supports the claimed security boundary.
2. A separate regression review checks that the test exercises the real entry point, relevant auth/ownership controls and security assertion. Toy reimplementations and tests that bypass the control need validation.
3. Isolated execution fails on original source and passes with the patch using expected markers.

Older scans need a fresh investigative review before they can pass these gates. A model's semantic review and an automated regression still require a human assessment of disclosure impact.

## Static tools and application test runtimes

Enable **Run isolated Semgrep leads** to run the app-owned rules offline in a restricted container. Cache the official tool image first.

```bash
docker pull semgrep/semgrep:1.143.0
```

The runner ignores repository-provided Semgrep configurations and treats all alerts as unverified leads. An unavailable tool or exceeded limit is shown in coverage. The small bundled rules cover shell execution, dynamic evaluation and disabled TLS checks. They do not provide comprehensive language or vulnerability coverage.

Upload **SARIF 2.1.0** from Semgrep or CodeQL in the scan form to add external analyzer leads. Relative paths must match the scanned checkout. Use output from the same commit. Imports are capped at 600 KB in the browser and 100 retained leads. Trace does not execute CodeQL's project build scripts. Generate its database and SARIF in an environment authorized for that repository. See the [CodeQL CLI documentation](https://docs.github.com/en/code-security/codeql-cli) and [Semgrep documentation](https://semgrep.dev/docs/).

Two optional runtimes support tests that import real web application libraries or drive a browser.

```bash
docker build -f tools/python-review.Dockerfile -t trace-python-review:latest tools
docker build -f tools/browser-review.Dockerfile -t trace-browser-review:latest tools
```

Select `python-app` or `browser` in an editable regression plan. Python app includes pinned FastAPI, HTTPX, pytest, SQLAlchemy and Redis packages. Browser includes pinned Playwright and Chromium. These dependencies may differ from a target's requirements. All test runs keep the same offline container restrictions. Browser runs allow 1 GB RAM, 128 processes, 128 MB temporary storage and a 64 MB per-file write ceiling so Chromium can start. Other runtimes retain their smaller limits. Browser tests may start a local fixture service inside that container and must use its own loopback address. Required remote services or missing target dependencies lead to a blocked result. Burp Suite remains an external manual tool for authorized request inspection.

## Accuracy benchmark

`accuracy_benchmark.py` provides eight small synthetic cases, including vulnerable/fixed authorization, SQL injection and HTML rendering pairs, plus self-only input and admin-output negatives. Ground truth stays outside the repository shown to the model. Tests verify the fixtures' behavior separately from model predictions.

Run a live evaluation with an explicit model, key alias and total estimated cost ceiling.

```bash
python3 accuracy_benchmark.py --model 'openrouter|provider/model:free' --key-alias 'Your saved key name' --max-cost-usd 0 --output benchmark-results.json
```

Add `--publish` to display the live benchmark summary in the website. Use `TRACE_BENCHMARK_KEY` for a temporary key, `--case case_07` for one case, or `--predictions predictions.json` to score existing decisions. Output includes precision, recall, false-positive rate, abstentions, decision coverage, raw reviewed findings and usage. Positive abstentions count as recall misses. False-positive rate is calculated among decided negative cases. Undefined metrics remain null. This benchmark measures a small synthetic source-review task and cannot establish real-world bounty accuracy.

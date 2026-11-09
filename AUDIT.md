# Source audit and repairs

Reviewed on 9 November 2026 against `aaeb935`, followed by repairs in this checkout.

## Scope

Reviewed the HTTP API, browser state, model routing, key lifecycle, repository checkout, source selection, report parsing, exports, and Codex subprocess configuration. Two source reviewers examined frontend and backend independently. A separate reviewer checked the repairs.

## Repairs

- Preserved the repository URL in exported reports. Source excerpts use a separate value.
- Validated report field types, source paths, line numbers, and limitations. Malformed findings are discarded with a coverage note. Worker failures reach a terminal state.
- Included bounded source from a large first file instead of silently reviewing zero files.
- Pinned provider connections to validated public IPs while retaining TLS certificate and hostname verification. Provider redirects and environment proxies cannot change that connection.
- Added HTTPS request deadlines, including responses that transfer socket ownership on `Connection: close`. Truncated and malformed responses produce controlled errors.
- Replaced host-wide authentication cookies with a port-scoped browser session token sent in the Authorization header. Report downloads send the same header.
- Redacted the request's captured API key from successful provider output and errors, including after a key is changed or removed.
- Serialized Keychain mutations and verified actual Keychain state. Uncertain failures reconcile runtime state before another use.
- Persisted model/provider changes before updating runtime state, so failed saves can be retried consistently.
- Serialized chat per scan and bounded concurrent work. Active keys cannot be deleted or replaced.
- Guarded browser state against late scan, history, chat, and catalog responses. A reply preserves its original model/key choice.
- Required the expected model-test response instead of accepting arbitrary nonempty text.
- Added a Git clone deadline and isolated Git from inherited credential helpers, configuration overrides, hooks, and filters.
- Cleaned up subprocess groups after completion and timeout on POSIX systems.
- Started Codex outside the target checkout with user configuration ignored, ephemeral sessions, and a restricted inherited environment.
- Restricted local data-directory and saved-record permissions to the owner.

## Verification

All 22 regression fixtures passed. They run in a disposable source copy with external networking and user-home content access denied. They use dummy keys and mocked providers, Git, Codex, and Keychain. API fixtures use in-memory HTTP streams. Browser-state fixtures exercise the normal event handlers with delayed responses. CPU, file-size, open-file, process-count, and wall-clock limits were applied. Node's heap was capped at 128 MB.

These checks verify deterministic behavior. Provider credentials, paid model execution, and live third-party targets are outside this run.

## Remaining validation

Codex read-only tools can inspect accessible filesystem paths. Clean startup and environment filtering reduce inherited authority, but this audit did not establish filesystem containment of those tools against malicious repository instructions. Use a separately isolated environment for untrusted Codex tool reviews until that boundary is verified. OpenRouter and direct-provider source-excerpt reviews do not launch local model tools.

The HTTPS connection/response deadline starts after DNS resolution. Real provider success, provider-specific structured-output quality, OS Keychain failure behavior, and public deployment configuration require environment-specific validation. This report makes no exhaustive vulnerability or bounty-eligibility claim.

"""Evidence, incremental coverage, patch review, and isolated regression verification."""

import hashlib
import difflib
import io
import json
import math
import os
import re
import shlex
import shutil
import subprocess
import tempfile
import threading
import time
import uuid
import zipfile
from pathlib import Path, PurePosixPath
from urllib.parse import urlparse

from bugbounty_agent import bounded_process, git_environment


SOURCE_SUFFIXES = {".py", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx", ".go", ".rs", ".java",
                   ".rb", ".php", ".sh", ".json", ".yaml", ".yml", ".toml", ".c", ".cpp", ".h", ".hpp",
                   ".swift", ".cs", ".kt", ".sql", ".html", ".vue", ".svelte", ".tf", ".xml", ".proto", ".ini", ".cfg"}
EXCLUDED_PARTS = {"node_modules", "vendor", "dist", "build", ".git", "__pycache__", ".venv", "venv", ".next", "coverage", "test-results"}
RUNTIME_IMAGES = {"python": "python:3.12-alpine", "node": "node:22-alpine"}
MAX_PATCH_BYTES = 200_000
MAX_SNAPSHOT_BYTES = 64 * 1024 * 1024


def repository_key(url):
    parts = urlparse(url).path.strip("/").removesuffix(".git").split("/")
    return "/".join(parts[:2]).lower()


def git(repo, arguments, timeout=15, input_text=None):
    command = ["git", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=" + os.devnull,
               "-C", str(repo)] + list(arguments)
    if input_text is None:
        return bounded_process(command, git_environment(repo.parent), timeout)
    return subprocess.run(command, input=input_text, env=git_environment(repo.parent),
                          capture_output=True, text=True, timeout=timeout)


def tracked_files(repo):
    result = git(repo, ["ls-files", "-z"])
    if result.returncode:
        raise RuntimeError("Could not inventory repository files")
    return [name for name in result.stdout.split("\0") if name]


def safe_file(repo, name):
    relative = PurePosixPath(name)
    if relative.is_absolute() or ".." in relative.parts or ".git" in relative.parts:
        raise ValueError("Repository path escapes the checkout")
    path = repo / name
    if path.is_symlink() or not path.resolve().is_relative_to(repo.resolve()) or not path.is_file():
        raise ValueError("Source path is unavailable or links outside the checkout")
    return path


def redact_source(text):
    text = re.sub(r"(?i)((?:api[_-]?key|secret|password|token)\s*[:=]\s*)[^,\s]+", r"\1[REDACTED]", text)
    return re.sub(r"(?:sk-or-v1-|sk-proj-|ghp_|gho_)[A-Za-z0-9_-]{20,}", "[REDACTED]", text)


def evidence_for(repo, item):
    try:
        path = safe_file(repo, item["path"])
        if path.stat().st_size > 2_000_000:
            raise ValueError("File exceeds evidence limit")
        lines = path.read_text(errors="replace").splitlines()
        line = item["line"]
        first, last = max(1, line - 4), min(len(lines), line + 4)
        snippet = "\n".join("{}: {}".format(number, redact_source(lines[number - 1][:500]))
                            for number in range(first, last + 1))
        anchor = hashlib.sha256(re.sub(r"\s+", "", lines[line - 1]).encode()).hexdigest()
        function_name = None
        for previous in reversed(lines[max(0, line - 80):line]):
            match = re.search(r"(?:\bdef\s+|\bfunction\s+|\bfunc\s+)([A-Za-z_$][\w$]*)", previous)
            if match:
                function_name = match.group(1)
                break
        return {"path": item["path"], "line": line, "first_line": first, "last_line": last,
                "snippet": snippet, "anchor": anchor, "function": function_name,
                "flow": [{"label": "Trigger", "text": item["reproduction"]},
                         {"label": "Source evidence", "text": item["evidence"]},
                         {"label": "Impact", "text": item["impact"]}]}
    except (OSError, ValueError, IndexError, RuntimeError):
        return {"path": item["path"], "line": item["line"], "snippet": "Source evidence unavailable", "anchor": "", "flow": []}


def attach_findings(repo, url, findings):
    unique = {}
    for item in findings:
        finding = dict(item)
        evidence = evidence_for(repo, finding)
        identity = "\n".join([repository_key(url), finding["path"], finding["cwe"], evidence["anchor"] or finding["title"].lower()])
        fingerprint = hashlib.sha256(identity.encode()).hexdigest()[:20]
        if fingerprint in unique:
            unique[fingerprint]["duplicates"] += 1
            continue
        finding.update(id=fingerprint, fingerprint=fingerprint, duplicates=0,
                       evidence_view=evidence, verification={"status": "not_run"})
        unique[fingerprint] = finding
    return list(unique.values())


def coverage_context(repo, limit=65000, changed_paths=None):
    paths = tracked_files(repo)
    priority = ("auth", "permission", "middleware", "route", "api", "server", "config", "security")
    paths.sort(key=lambda name: (-sum(word in name.lower() for word in priority), name))
    records = []
    chunks = []
    used = 0
    for name in paths:
        record = {"path": name, "status": "skipped", "reason": "", "included_lines": 0, "total_lines": None}
        records.append(record)
        relative = PurePosixPath(name)
        if changed_paths is not None and name not in changed_paths:
            record["reason"] = "unchanged"
            continue
        if any(part in EXCLUDED_PARTS for part in relative.parts):
            record["reason"] = "generated_or_dependency_directory"
            continue
        if any(word in name.lower() for word in ("lock.json", ".env", "credential", "private-key")):
            record["reason"] = "credential_or_lock_file"
            continue
        if relative.name.lower() in {"report.json", "findings.json", "scan-results.json"}:
            record["reason"] = "generated_report"
            continue
        if relative.suffix.lower() not in SOURCE_SUFFIXES and relative.name not in {"Dockerfile", "Makefile"}:
            record["reason"] = "unsupported_file_type"
            continue
        remaining = limit - used
        header = "\nFILE {}\n".format(name)
        if remaining < len(header) + 30:
            record["reason"] = "context_budget"
            continue
        try:
            file = safe_file(repo, name)
            if file.stat().st_size > 250000:
                record["reason"] = "file_larger_than_250_kb"
                continue
            lines = file.read_text(errors="replace").splitlines()
        except (OSError, ValueError, RuntimeError):
            record["reason"] = "unreadable_or_symbolic_link"
            continue
        record["total_lines"] = len(lines)
        part = header
        truncated_line = False
        for number, line in enumerate(lines[:250], 1):
            value = "{}: {}\n".format(number, redact_source(line[:500]))
            if len(part) + len(value) > remaining:
                if not record["included_lines"] and remaining - len(part) > 10:
                    part += value[:remaining - len(part)]
                    record["included_lines"] += 1
                truncated_line = True
                break
            part += value
            record["included_lines"] += 1
            truncated_line |= len(line) > 500
        if not record["included_lines"] and lines:
            record["reason"] = "context_budget"
            continue
        chunks.append(part)
        used += len(part)
        partial = record["included_lines"] < len(lines) or truncated_line
        record["status"] = "partial" if partial else "included"
        record["reason"] = "line_or_context_limit" if partial else "provided_to_model"
    if changed_paths is not None:
        existing = set(paths)
        for deleted in sorted(changed_paths - existing):
            records.append({"path": deleted, "status": "skipped", "reason": "deleted_file", "included_lines": 0, "total_lines": 0})
    totals = {status: sum(record["status"] == status for record in records) for status in ("included", "partial", "skipped")}
    coverage = {"mode": "incremental" if changed_paths is not None else "full", "files": records,
                "totals": totals, "characters": used, "character_limit": limit,
                "meaning": "Included and partial files were supplied as model context. This records coverage, not proof of correctness."}
    return "".join(chunks), coverage


def incremental_diff(repo, baseline):
    base_repo = Path(baseline["repo_path"])
    base_commit = baseline.get("commit", "")
    if not re.fullmatch(r"[a-f0-9]{40,64}", base_commit):
        raise ValueError("Baseline scan has no usable commit")
    result = git(repo, ["fetch", "--no-tags", "--depth", "1", str(base_repo), base_commit], 30)
    if result.returncode:
        raise RuntimeError("Baseline checkout is unavailable. Run a full scan first.")
    return commit_diff(repo, base_commit, baseline["id"])


def commit_diff(repo, base_commit, base_scan=None):
    result = git(repo, ["diff", "--no-ext-diff", "--no-textconv", "--name-only", "-z", base_commit, "HEAD"])
    if result.returncode:
        raise RuntimeError("Could not compare repository commits")
    changed = set(name for name in result.stdout.split("\0") if name)
    diff = git(repo, ["diff", "--no-ext-diff", "--no-textconv", "--unified=3", base_commit, "HEAD"])
    return changed, {"base_scan": base_scan, "base_commit": base_commit,
                     "changed_files": sorted(changed), "diff": redact_source(diff.stdout[:20000])}


def budget_policy(value):
    value = value if isinstance(value, dict) else {}
    def integer(name, default, minimum, maximum):
        try:
            number = int(value.get(name, default))
        except (ValueError, TypeError, OverflowError) as exc:
            raise ValueError("{} must be a whole number".format(name)) from exc
        if not minimum <= number <= maximum:
            raise ValueError("{} must be between {} and {}".format(name, minimum, maximum))
        return number
    cost = value.get("max_cost_usd")
    if cost in (None, ""):
        cost = None
    else:
        try:
            cost = float(cost)
        except (ValueError, TypeError, OverflowError) as exc:
            raise ValueError("Cost limit must be numeric") from exc
        if not math.isfinite(cost) or cost < 0 or cost > 100:
            raise ValueError("Cost limit must be between 0 and 100 USD")
    fallbacks = value.get("fallbacks", [])
    if not isinstance(fallbacks, list) or len(fallbacks) > 3:
        raise ValueError("Choose up to three fallback routes")
    return {"max_input_tokens": integer("max_input_tokens", 22000, 2000, 100000),
            "max_output_tokens": integer("max_output_tokens", 5000, 512, 16000),
            "max_cost_usd": cost, "fallbacks": fallbacks}


def token_estimate(messages):
    return math.ceil(sum(len(item.get("content", "").encode()) for item in messages) / 3) + len(messages) * 12


def diff_text(path, before, after, new_file=False):
    def quoted(value):
        return '"' + value.replace('\\', '\\\\').replace('"', '\\"') + '"' if any(char.isspace() or char == '"' for char in value) else value
    old_name = "/dev/null" if new_file else quoted("a/" + path)
    new_name = quoted("b/" + path)
    lines = difflib.unified_diff(before.splitlines(keepends=True), after.splitlines(keepends=True), fromfile=old_name, tofile=new_name)
    body = "".join(line if line.endswith("\n") else line + "\n\\ No newline at end of file\n" for line in lines)
    header = "diff --git {} {}\n".format(quoted("a/" + path), new_name)
    if new_file:
        header += "new file mode 100644\n"
    return header + body if body else ""


def materialize_plan(repo, plan):
    edits = plan.get("edits")
    tests = plan.get("test_files")
    if not isinstance(edits, list) or not 1 <= len(edits) <= 10 or not isinstance(tests, list) or not 1 <= len(tests) <= 5:
        raise ValueError("Provide 1 to 10 exact source edits and 1 to 5 new regression files")
    original, changed = {}, {}
    for edit in edits:
        if not isinstance(edit, dict) or not all(isinstance(edit.get(key), str) for key in ("path", "old_text", "new_text")):
            raise ValueError("Each edit needs path, old_text, and new_text strings")
        name = edit["path"]
        path = safe_file(repo, name)
        if path.stat().st_size > 250000 or not edit["old_text"] or len(edit["new_text"]) > 50000:
            raise ValueError("Source edit exceeds size limits")
        if name not in original:
            original[name] = path.read_text()
            changed[name] = original[name]
        if changed[name].count(edit["old_text"]) != 1:
            raise ValueError("Exact source text must match once in {}".format(name))
        changed[name] = changed[name].replace(edit["old_text"], edit["new_text"], 1)
    fix = "".join(diff_text(name, original[name], value) for name, value in changed.items())
    test_patch = ""
    seen = set()
    for test in tests:
        if not isinstance(test, dict) or not isinstance(test.get("path"), str) or not isinstance(test.get("content"), str):
            raise ValueError("Each regression file needs path and content")
        name, content = test["path"], test["content"]
        relative = PurePosixPath(name)
        if (relative.is_absolute() or ".." in relative.parts or ".git" in relative.parts or "\\" in name
                or name in seen or (repo / name).exists() or len(content) > 50000):
            raise ValueError("Regression files must use unique, new, safe repository paths")
        seen.add(name)
        test_patch += diff_text(name, "", content.rstrip("\n") + "\n", new_file=True)
    return dict(plan, fix_patch=fix, test_patch=test_patch)


def parse_plan(text, repo=None):
    value = text.strip()
    if value.startswith("```"):
        value = re.sub(r"^```(?:json)?\s*|\s*```$", "", value)
    try:
        plan = json.loads(value[value.index("{"):value.rindex("}") + 1])
    except (ValueError, RecursionError) as exc:
        raise ValueError("Model did not return a valid repair plan JSON object") from exc
    if isinstance(plan, dict) and isinstance(plan.get("verdict"), str) and plan["verdict"] in {"rejected", "needs_validation"}:
        reason = plan.get("reason")
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError("A rejected or blocked candidate needs a source-grounded reason")
        return {"valid": False, "assessment": plan["verdict"], "reason": reason[:3000]}
    if isinstance(plan, dict) and ("fix_patch" not in plan or "test_patch" not in plan):
        if repo is None:
            raise ValueError("A checkout is required to build exact-edit patches")
        plan = materialize_plan(repo, plan)
    required = ("summary", "fix_patch", "test_patch", "failure_marker", "success_marker", "pr_title")
    if not isinstance(plan, dict) or not all(isinstance(plan.get(name), str) for name in required):
        raise ValueError("Repair plan is missing required text fields")
    if plan.get("runtime") not in RUNTIME_IMAGES:
        raise ValueError("Choose the Python or Node isolated runtime")
    command = plan.get("command")
    allowed = {"python": {"python", "python3"}, "node": {"node", "npm"}}
    if (not isinstance(command, list) or not 1 <= len(command) <= 20
            or not all(isinstance(arg, str) and 0 < len(arg) <= 500 and "\0" not in arg for arg in command)
            or command[0] not in allowed[plan["runtime"]]):
        raise ValueError("Repair plan must supply a Python or Node command as an argument array")
    for marker in ("failure_marker", "success_marker"):
        if not 3 <= len(plan[marker]) <= 200:
            raise ValueError("Regression output markers must contain 3 to 200 characters")
    if plan["failure_marker"] == plan["success_marker"]:
        raise ValueError("Failure and success markers must differ")
    plan["command"] = command
    result = {name: plan[name] for name in required + ("runtime", "command")}
    result["security_boundary"] = str(plan.get("security_boundary", ""))[:2000]
    return result


def patch_paths(patch):
    if not patch.strip() or len(patch.encode()) > MAX_PATCH_BYTES:
        raise ValueError("Patch must contain 1 to 200,000 bytes")
    blocked = ("GIT binary patch", "new file mode 120000", "new file mode 160000", "rename from ", "rename to ")
    if any(value in patch for value in blocked):
        raise ValueError("Binary, symbolic-link, submodule, and rename patches require manual review")
    result = subprocess.run(["git", "apply", "--numstat", "-z", "-"], input=patch,
                            env=git_environment(os.devnull), capture_output=True, text=True, timeout=10)
    if result.returncode:
        raise ValueError("Patch is not a valid unified Git diff")
    paths = []
    for record in result.stdout.split("\0"):
        if not record:
            continue
        fields = record.split("\t", 2)
        if len(fields) != 3 or "-" in fields[:2]:
            raise ValueError("Patch contains an unsupported file entry")
        name = fields[2]
        relative = PurePosixPath(name)
        if (relative.is_absolute() or ".." in relative.parts or ".git" in relative.parts or "\\" in name
                or any(ord(char) < 32 for char in name) or len(name) > 240):
            raise ValueError("Patch contains an unsafe path")
        paths.append(name)
    if not paths or len(paths) > 20:
        raise ValueError("Patch must change between 1 and 20 files")
    return paths


def copy_snapshot(repo, destination):
    total = 0
    for name in tracked_files(repo):
        if any(part in EXCLUDED_PARTS for part in PurePosixPath(name).parts):
            continue
        try:
            source = safe_file(repo, name)
        except ValueError:
            continue
        size = source.stat().st_size
        total += size
        if size > 8 * 1024 * 1024 or total > MAX_SNAPSHOT_BYTES:
            raise ValueError("Verification snapshot exceeds the 64 MB total or 8 MB per-file limit")
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    result = git(destination, ["init", "--quiet"])
    if result.returncode:
        raise RuntimeError("Could not initialize the disposable patch workspace")


def apply_patch(repo, patch):
    result = git(repo, ["apply", "--check", "-"], input_text=patch)
    if result.returncode:
        raise ValueError("Patch does not apply to this scan's commit: " + result.stderr[-300:])
    result = git(repo, ["apply", "-"], input_text=patch)
    if result.returncode:
        raise ValueError("Could not apply patch in disposable workspace")


def validate_plan(repo, plan):
    if plan.get("assessment") in {"rejected", "needs_validation"}:
        return plan
    fix_paths = patch_paths(plan["fix_patch"])
    test_paths = patch_paths(plan["test_patch"])
    if set(fix_paths) & set(test_paths):
        raise ValueError("Fix and regression-test patches must change separate files")
    for name in fix_paths + test_paths:
        parent = (repo / name).parent.resolve()
        if not parent.is_relative_to(repo.resolve()) or (repo / name).is_symlink():
            raise ValueError("Patch targets an unsafe symbolic-link path")
    with tempfile.TemporaryDirectory(prefix="trace-plan-") as directory:
        snapshot = Path(directory)
        copy_snapshot(repo, snapshot)
        apply_patch(snapshot, plan["test_patch"])
        apply_patch(snapshot, plan["fix_patch"])
    result = dict(plan)
    result.update(valid=True, fix_paths=fix_paths, test_paths=test_paths)
    return result


def docker_environment():
    allowed = {"PATH", "HOME", "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG", "SYSTEMROOT"}
    return {key: value for key, value in os.environ.items() if key in allowed}


def runner_status():
    if not shutil.which("docker"):
        return {"available": False, "reason": "Docker CLI is unavailable", "images": {}}
    environment = docker_environment()
    try:
        host = environment.get("DOCKER_HOST")
        if not host:
            result = bounded_process(["docker", "context", "inspect", "--format", '{{.Endpoints.docker.Host}}'], environment, 5)
            host = result.stdout.strip()
        if not host.startswith(("unix://", "npipe://")):
            return {"available": False, "reason": "Verification requires a local Docker daemon", "images": {}}
        result = bounded_process(["docker", "info", "--format", '{{.ServerVersion}}'], environment, 5)
        if result.returncode:
            return {"available": False, "reason": "Start Docker Desktop to run isolated verification", "images": {}}
        images = {}
        for runtime, tag in RUNTIME_IMAGES.items():
            image = bounded_process(["docker", "image", "inspect", "--format", '{{.Id}}', tag], environment, 5)
            images[runtime] = {"tag": tag, "available": image.returncode == 0, "id": image.stdout.strip() if image.returncode == 0 else None}
        return {"available": True, "reason": "Local Docker available", "images": images}
    except (OSError, RuntimeError):
        return {"available": False, "reason": "Docker did not respond", "images": {}}


def run_container(snapshot, plan, image_id, timeout=40):
    environment = docker_environment()
    name = "trace-verify-" + uuid.uuid4().hex[:16]
    user = str(os.getuid()) if hasattr(os, "getuid") else "1000"
    group = str(os.getgid()) if hasattr(os, "getgid") else "1000"
    command = ["docker", "run", "--pull", "never", "--name", name, "--network", "none", "--read-only",
               "--user", user + ":" + group, "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
               "--pids-limit", "64", "--memory", "512m", "--memory-swap", "512m", "--cpus", "1",
               "--ulimit", "nofile=128:128", "--ulimit", "fsize=8388608:8388608", "--log-driver", "none",
               "--mount", "type=bind,source={},target=/input,readonly".format(snapshot),
               "--tmpfs", "/workspace:rw,size=128m,uid={},gid={}".format(user, group),
               "--tmpfs", "/tmp:rw,size=32m,uid={},gid={}".format(user, group), "--workdir", "/workspace",
               "--env", "HOME=/tmp", "--env", "LANG=C.UTF-8", "--env", "CI=true",
               "--entrypoint", "/bin/sh", image_id, "-c",
               'cp -R /input/. /workspace/ && exec timeout -s KILL 40 "$@"', "trace-regression"] + plan["command"]
    output = bytearray()
    total = [0]
    process = subprocess.Popen(command, env=environment, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    def read_output():
        try:
            while True:
                chunk = process.stdout.read(4096)
                if not chunk:
                    break
                total[0] += len(chunk)
                output.extend(chunk[:max(0, 65536 - len(output))])
        except (OSError, ValueError):
            pass
    reader = threading.Thread(target=read_output, daemon=True)
    reader.start()
    timed_out = False
    started = time.monotonic()
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
    finally:
        try:
            subprocess.run(["docker", "rm", "--force", name], env=environment,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
        finally:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=5)
            reader.join(timeout=2)
            process.stdout.close()
    return {"exit_code": process.returncode, "timed_out": timed_out,
            "output": redact_source(output.decode(errors="replace")), "output_truncated": total[0] > len(output),
            "duration_seconds": round(time.monotonic() - started, 2), "image_id": image_id}


def verify_plan(repo, plan):
    status = runner_status()
    runtime = status.get("images", {}).get(plan["runtime"], {})
    if not status["available"] or not runtime.get("available"):
        return {"status": "blocked", "reason": status["reason"] if not status["available"] else "Cache image {} before verification".format(RUNTIME_IMAGES[plan["runtime"]])}
    with tempfile.TemporaryDirectory(prefix="trace-verification-") as directory:
        root = Path(directory)
        baseline, patched = root / "baseline", root / "patched"
        baseline.mkdir()
        patched.mkdir()
        copy_snapshot(repo, baseline)
        copy_snapshot(repo, patched)
        apply_patch(baseline, plan["test_patch"])
        apply_patch(patched, plan["test_patch"])
        apply_patch(patched, plan["fix_patch"])
        before = run_container(baseline, plan, runtime["id"])
        after = run_container(patched, plan, runtime["id"])
    result = {"baseline": before, "patched": after, "command": plan["command"],
              "limits": {"network": "none", "memory_mb": 512, "cpus": 1, "pids": 64, "workspace_mb": 128, "seconds_per_run": 40}}
    if before["timed_out"] or after["timed_out"]:
        result.update(status="blocked", reason="Regression exceeded the isolated-run deadline")
    elif before["exit_code"] != 0 and plan["failure_marker"] in before["output"] and after["exit_code"] == 0 and plan["success_marker"] in after["output"]:
        result.update(status="reproduced", reason="Regression failed on the original code and passed with the proposed fix. Review the test's meaning before disclosure.")
    elif before["exit_code"] == 0:
        result.update(status="not_reproduced", reason="The regression did not fail on the original code")
    elif after["exit_code"] != 0:
        result.update(status="fix_failed", reason="The proposed fix did not pass the regression")
    else:
        result.update(status="blocked", reason="Expected regression markers were missing. Check dependencies and the test plan.")
    return result


def pr_document(job, finding):
    plan = finding.get("remediation") or {}
    verification = finding.get("verification") or {"status": "not_run"}
    title = plan.get("pr_title") or "Fix: " + finding["title"]
    ready = bool(plan.get("valid") and verification.get("status") == "reproduced"
                 and (finding.get("assessment") or {}).get("verdict") not in {"rejected", "needs_validation"}
                 and (finding.get("triage") or {}).get("decision") not in {"dismissed", "rejected"})
    command = shlex.join(plan.get("command", [])) or "Verification command pending"
    lines = ["## Summary", "", plan.get("summary") or finding["fix"], "", "## Security impact", "",
             finding["impact"], "", "## Evidence", "", "- Source commit `{}`".format(job.get("commit", "unknown")),
             "- Location `{}:{}`".format(finding["path"], finding["line"]),
             "- Classification {}".format(finding["cwe"]), "", finding["evidence"],
             "", "## Reproduction", "", finding["reproduction"], "", "```sh", command, "```", "", "## Verification", "",
             "Status: {}".format(verification["status"]), "", verification.get("reason", "Execution pending. This report currently contains source-review evidence only.")]
    if finding.get("assessment"):
        lines.extend(["", "## Candidate assessment", "", finding["assessment"].get("verdict", "pending"),
                      "", finding["assessment"].get("reason", "")])
    for label in ("baseline", "patched"):
        run = verification.get(label)
        if run:
            lines.extend(["", "### {} run".format(label.capitalize()), "", "Exit code `{}`".format(run["exit_code"]), "", "```text", run["output"][:12000].replace("```", "'''"), "```"])
    lines.extend(["", "## Changes", ""])
    lines.extend("- `{}`".format(name) for name in plan.get("fix_paths", []) + plan.get("test_paths", []))
    lines.extend(["", "## Review checklist", "", "- [ ] Review the proposed patch and regression test",
                  "- [ ] Confirm repository/program scope and disclosure rules", "- [ ] Re-run the relevant project suite",
                  "- [ ] Check for regressions beyond this finding", "", "## Limits", "",
                  "This PR draft reports the source evidence and recorded test results. Bounty eligibility and production impact require owner review."])
    if not ready:
        lines.insert(0, "> Draft: reproduction or a validated patch is still pending.\n")
    commit = job.get("commit", "")
    base = " " + commit if re.fullmatch(r"[a-f0-9]{40,64}", commit) else ""
    return {"title": title[:180], "body": "\n".join(lines).strip() + "\n", "ready": ready,
            "apply_commands": "set -e\ngit switch -c fix/trace-{}{}\ngit apply fix.patch\ngit apply regression.patch\n{}\ngit diff --check\n".format(finding["id"], base, command)}


def pr_bundle(job, finding):
    document = pr_document(job, finding)
    plan = finding.get("remediation", {})
    content = {"PR.md": "# " + document["title"] + "\n\n" + document["body"],
               "APPLY.txt": document["apply_commands"], "fix.patch": plan.get("fix_patch", ""),
               "regression.patch": plan.get("test_patch", ""),
               "evidence.json": json.dumps({"repository": job["url"], "commit": job.get("commit"), "finding": finding}, indent=2),
               "coverage.json": json.dumps(job.get("coverage", {}), indent=2)}
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, value in content.items():
            archive.writestr(name, value)
    return stream.getvalue()

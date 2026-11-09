import io
import http.client
import json
import os
import socket
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import bugbounty_agent
import server


def report(findings=None):
    return {"summary": "Reviewed fixture", "findings": findings or [], "limitations": []}


def finding(**changes):
    item = {"title": "Fixture", "severity": "low", "confidence": "high", "cwe": "CWE-200",
            "path": "app.py", "line": 1, "evidence": "Source", "impact": "Fixture impact",
            "reproduction": "Local check", "fix": "Fixture fix", "pr_checklist": ["Check fixture"]}
    item.update(changes)
    return item


class MemorySocket:
    def __init__(self, request):
        self.input = io.BytesIO(request)
        self.output = bytearray()

    def makefile(self, *args):
        return self.input

    def sendall(self, content):
        self.output.extend(content)

    def settimeout(self, timeout):
        pass


def request(method, path, body=None, authenticated=True, **headers):
    payload = b"" if body is None else json.dumps(body).encode()
    values = {"Host": "127.0.0.1:{}".format(server.PORT), "Content-Type": "application/json",
              "Content-Length": str(len(payload)), **headers}
    if authenticated:
        values["Authorization"] = "Bearer " + server.SESSION_TOKEN
    raw = "{} {} HTTP/1.0\r\n".format(method, path)
    raw += "".join("{}: {}\r\n".format(key, value) for key, value in values.items())
    connection = MemorySocket(raw.encode() + b"\r\n" + payload)
    server.Handler(connection, ("127.0.0.1", 12345), SimpleNamespace())
    head, content = bytes(connection.output).split(b"\r\n\r\n", 1)
    status = int(head.split(b" ")[1])
    value = json.loads(content) if content and b"application/json" in head else content or None
    return status, value, head


class CoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.data_patch = mock.patch.object(server, "DATA", self.folder)
        self.data_patch.start()
        self.addCleanup(self.data_patch.stop)
        for collection in (server.JOBS, server.KEYS, server.MODELS, server.PROVIDERS,
                           server.ACTIVE_KEYS, server.ACTIVE_CHATS, server.ACTIVE_WORKFLOWS,
                           server.TRIAGE, server.MODEL_PRICES):
            collection.clear()

    def test_repository_url_and_clone_deadline(self):
        for url in ("https://evil.test/owner/repo", "https://github.com/a/b?x=1",
                    "https://github.com/a/b/c", "https://github.com/a/b:999"):
            with self.assertRaises(ValueError):
                server.resolve_repo_url(url)
        with mock.patch.object(bugbounty_agent, "bounded_process") as run:
            run.return_value = SimpleNamespace(returncode=0)
            bugbounty_agent.resolve_repo("https://github.com/a/b", self.folder)
            self.assertEqual(180, run.call_args.kwargs["timeout"])
            self.assertEqual("0", run.call_args.kwargs["env"]["GIT_TERMINAL_PROMPT"])

    def test_private_repository_failure_is_actionable(self):
        failure = "fatal: could not read Username for 'https://github.com': terminal prompts disabled"
        with mock.patch.object(bugbounty_agent, "bounded_process", return_value=SimpleNamespace(returncode=128, stderr=failure)):
            with self.assertRaises(bugbounty_agent.RepositoryAccessError):
                bugbounty_agent.resolve_repo("https://github.com/owner/private-repo", self.folder)
        legacy = server.visible({"id": "old-scan", "status": "failed", "error": "Clone failed: " + failure})
        self.assertEqual("repository_access_required", legacy["error_code"])
        self.assertEqual("cloning", legacy["failed_stage"])
        self.assertNotIn("terminal prompts", legacy["error"])

    def test_private_clone_uses_selected_account_without_url_credentials(self):
        calls = []
        def run(command, **options):
            calls.append((command, options))
            if command[0] == 'gh':
                return SimpleNamespace(returncode=0, stdout="dummy-github-token\n")
            return SimpleNamespace(returncode=0, stderr="")
        with mock.patch.object(bugbounty_agent, "github_accounts", return_value=[{"login": "owner"}]), \
             mock.patch.object(bugbounty_agent, "bounded_process", side_effect=run):
            bugbounty_agent.resolve_repo("https://github.com/owner/private-repo", self.folder, "owner")
        command, options = calls[-1]
        self.assertNotIn("dummy-github-token", " ".join(command))
        self.assertIn("http.followRedirects=false", command)
        self.assertEqual("http.https://github.com/.extraheader", options["env"]["GIT_CONFIG_KEY_0"])
        self.assertTrue(options["env"]["GIT_CONFIG_VALUE_0"].startswith("Authorization: Basic "))
        with mock.patch.dict(os.environ, {"GH_TOKEN": "unrelated-token"}):
            self.assertNotIn("GH_TOKEN", bugbounty_agent.github_cli_environment())

    def test_scan_delete_removes_only_completed_scan_data(self):
        scan_id = "a" * 12
        job = {"id": scan_id, "status": "failed", "messages": []}
        server.JOBS[scan_id] = job
        server.save(job)
        server.ACTIVE_CHATS.add(scan_id)
        self.assertEqual(409, request("DELETE", "/api/scans/" + scan_id, {})[0])
        self.assertTrue((self.folder / scan_id).exists())
        server.ACTIVE_CHATS.clear()
        self.assertEqual(200, request("DELETE", "/api/scans/" + scan_id, {})[0])
        self.assertFalse((self.folder / scan_id).exists())
        self.assertNotIn(scan_id, server.JOBS)

    def test_private_scan_stores_account_name_only(self):
        with mock.patch.object(server, "github_accounts", return_value=[{"login": "owner"}]), \
             mock.patch.object(server.threading, "Thread"):
            status, job, _ = request("POST", "/api/scans", {
                "url": "https://github.com/owner/private-repo", "github_account": "owner"})
        self.assertEqual(202, status)
        self.assertEqual("owner", job["github_account"])
        self.assertNotIn("Authorization", (self.folder / job["id"] / "job.json").read_text())

    def test_malformed_report_and_paths(self):
        repo = self.folder / "repo"
        repo.mkdir()
        (repo / "app.py").write_text("line one\n")
        (repo / "outside.py").symlink_to(self.folder / "private.py")
        (self.folder / "private.py").write_text("private\n")
        data = report([finding(), finding(path="../private.py"), finding(path="outside.py"),
                       finding(line=0), finding(line=True), finding(line=2),
                       finding(severity=[]), finding(confidence={})])
        data["limitations"] = ["Valid", None, {"bad": "value"}]
        checked = bugbounty_agent.validate_findings(data, repo)
        self.assertEqual(1, len(checked["findings"]))
        self.assertTrue(all(isinstance(item, str) for item in checked["limitations"]))
        bugbounty_agent.render_markdown(checked, "fixture", None)
        with self.assertRaises(RuntimeError):
            server.parse_report("not JSON")

    def test_large_first_file_still_supplies_bounded_source(self):
        repo = self.folder / "repo"
        repo.mkdir()
        (repo / "auth.py").write_text("x = 1 # " + "x" * 300 + "\n" * 10)
        with mock.patch.object(server.workflow, "tracked_files", return_value=["auth.py"]):
            excerpt, coverage = server.workflow.coverage_context(repo, 200)
        self.assertEqual(1, coverage["totals"]["partial"])
        self.assertLessEqual(len(excerpt), 200)

    def test_scan_export_keeps_source_url_and_bad_output_finishes(self):
        repo = self.folder / "repo"
        repo.mkdir()
        (repo / "app.py").write_text("line one\n")
        url = "https://github.com/owner/repository"
        job = {"id": "fixture", "url": url, "focus": "auth", "model": "openrouter|vendor/model:free",
               "key_alias": "key", "status": "queued", "messages": []}
        server.JOBS["fixture"] = job
        server.KEYS["key"] = "dummy-provider-key"
        server.save(job)
        coverage = {"totals": {"included": 1, "partial": 0, "skipped": 0}, "files": [], "characters": 14, "character_limit": 65000}
        with mock.patch.object(server, "resolve_repo", return_value=(repo, url)), \
             mock.patch.object(server.workflow, "coverage_context", return_value=("SOURCE_EXCERPT", coverage)), \
             mock.patch.object(server, "custom_completion", return_value=json.dumps(report())), \
             mock.patch.object(server.workflow, "git", return_value=SimpleNamespace(returncode=0, stdout="commit")):
            server.run_scan("fixture")
        self.assertEqual("complete", job["status"])
        text = (self.folder / "fixture/report.md").read_text()
        self.assertIn("Source: `" + url + "`", text)
        self.assertNotIn("SOURCE_EXCERPT", text)
        with mock.patch.object(server, "resolve_repo", side_effect=subprocess.TimeoutExpired("git", 180)):
            server.run_scan("fixture")
        self.assertEqual("failed", job["status"])

    def test_api_auth_is_port_scoped_header_and_cross_origin_rejected(self):
        self.assertEqual(401, request("GET", "/api/models", authenticated=False)[0])
        self.assertEqual(401, request("GET", "/api/models", authenticated=False,
                                      Cookie="trace_session=" + server.SESSION_TOKEN)[0])
        status, _, head = request("GET", "/?token=" + server.SESSION_TOKEN, authenticated=False)
        self.assertEqual(302, status)
        self.assertNotIn(b"Set-Cookie", head)
        self.assertIn(b"/#token=", head)
        self.assertEqual(200, request("GET", "/api/models")[0])
        self.assertEqual(403, request("POST", "/api/models", {}, Origin="https://evil.test")[0])

    def test_failed_configuration_save_is_retryable(self):
        with mock.patch.object(server, "save_models", side_effect=OSError("disk full")):
            self.assertEqual(500, request("POST", "/api/models", {"id": "fixture-model"})[0])
        self.assertEqual([], server.MODELS)
        self.assertEqual(201, request("POST", "/api/models", {"id": "fixture-model"})[0])
        self.assertEqual(["fixture-model"], json.loads((self.folder / "models.json").read_text()))
        with mock.patch.object(server, "save_models", side_effect=OSError("disk full")):
            self.assertEqual(500, request("DELETE", "/api/models", {"model": "fixture-model"})[0])
        self.assertEqual(["fixture-model"], server.MODELS)

    def test_key_errors_are_json_and_active_key_cannot_be_deleted(self):
        server.KEYS["fixture"] = "dummy-test-key"
        with mock.patch.object(server, "delete_key", side_effect=RuntimeError("Keychain error")):
            self.assertEqual(500, request("DELETE", "/api/keys", {"alias": "fixture"})[0])
        with server.model_work("fixture"):
            self.assertEqual(409, request("DELETE", "/api/keys", {"alias": "fixture"})[0])
        with mock.patch.object(server, "keychain_enabled", return_value=False):
            self.assertEqual(200, request("DELETE", "/api/keys", {"alias": "fixture"})[0])

    def test_partial_keychain_write_reconciles_actual_state(self):
        server.KEYS["fixture"] = "old-dummy-key"
        with mock.patch.object(server, "keychain_enabled", return_value=True), \
             mock.patch.object(server, "write_keychain", side_effect=subprocess.TimeoutExpired("security", 15)), \
             mock.patch.object(server.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout="new-dummy-key\n")):
            with self.assertRaises(subprocess.TimeoutExpired):
                server.store_key("fixture", "new-dummy-key")
        self.assertEqual("new-dummy-key", server.KEYS["fixture"])
        self.assertEqual(["fixture"], json.loads((self.folder / "key_aliases.json").read_text()))

    def test_partial_keychain_delete_reconciles_missing_item(self):
        server.KEYS["fixture"] = "dummy-key"
        results = [subprocess.TimeoutExpired("security", 15), SimpleNamespace(returncode=44)]
        with mock.patch.object(server, "keychain_enabled", return_value=True), \
             mock.patch.object(server.subprocess, "run", side_effect=results):
            with self.assertRaises(subprocess.TimeoutExpired):
                with server.LOCK:
                    server.delete_key("fixture")
        self.assertNotIn("fixture", server.KEYS)
        self.assertEqual([], json.loads((self.folder / "key_aliases.json").read_text()))

    def test_data_root_and_saved_records_are_private(self):
        server.load_jobs()
        server.save({"id": "fixture"})
        self.assertEqual(0o700, self.folder.stat().st_mode & 0o777)
        self.assertEqual(0o600, (self.folder / "fixture/job.json").stat().st_mode & 0o777)

    def test_parallel_chats_are_rejected_and_context_is_preserved(self):
        job = {"id": "fixture", "status": "complete", "messages": [], "report": report()}
        server.JOBS["fixture"] = job
        started = threading.Event()
        finish = threading.Event()
        responses = []
        def reply(snapshot, question, model):
            started.set()
            self.assertTrue(finish.wait(2))
            return "answer"
        with mock.patch.object(server, "run_chat", side_effect=reply):
            worker = threading.Thread(target=lambda: responses.append(request("POST", "/api/scans/fixture/chat", {"message": "first"})))
            worker.start()
            try:
                self.assertTrue(started.wait(2))
                self.assertEqual(409, request("POST", "/api/scans/fixture/chat", {"message": "second"})[0])
            finally:
                finish.set()
                worker.join(3)
        self.assertEqual(200, responses[0][0])
        self.assertEqual(["first", "answer"], [item["content"] for item in server.JOBS["fixture"]["messages"]])

    def test_public_endpoint_and_connection_pin(self):
        public = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))]
        with mock.patch.object(server.socket, "getaddrinfo", return_value=public) as lookup:
            host, port, path, addresses = server.validate_endpoint("https://provider.test/v1/chat/completions")
        self.assertEqual(["8.8.8.8"], addresses)
        context = mock.Mock()
        connection_socket = mock.Mock()
        with mock.patch.object(server.ssl, "create_default_context", return_value=context), \
             mock.patch.object(server.socket, "create_connection", return_value=connection_socket) as connect:
            connection = server.PublicHTTPSConnection(host, port, addresses, 60)
            connection.connect()
            connect.assert_called_once_with(("8.8.8.8", 443), timeout=10)
            context.wrap_socket.assert_called_once_with(connection_socket, server_hostname="provider.test")
        private = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))]
        with mock.patch.object(server.socket, "getaddrinfo", return_value=private):
            with self.assertRaises(ValueError):
                server.validate_endpoint("https://provider.test/chat/completions")

    def test_free_model_id_and_replaced_key_redaction(self):
        server.KEYS["fixture"] = "old-private-test-key"
        connection = mock.Mock()
        connection.getresponse.return_value = SimpleNamespace(status=200, read=lambda size: b'{"choices":[{"message":{"content":"TRACE_MODEL_OK"}}]}')
        with mock.patch.object(server, "validate_endpoint", return_value=("openrouter.ai", 443, "/api/v1/chat/completions", ["8.8.8.8"])), \
             mock.patch.object(server, "PublicHTTPSConnection", return_value=connection):
            model = "openrouter|nvidia/nemotron-3-ultra-550b-a55b:free"
            self.assertEqual("TRACE_MODEL_OK", server.test_model(model, "fixture"))
            sent = json.loads(connection.request.call_args.kwargs["body"])
            self.assertEqual(model.split("|", 1)[1], sent["model"])
            server.KEYS.clear()
            self.assertNotIn("old-private-test-key", server.safe_error("old-private-test-key", ["old-private-test-key"]))
        with mock.patch.object(server, "custom_completion", return_value="wrong response"):
            with self.assertRaises(RuntimeError):
                server.test_model(model, "fixture")

    def test_deadline_closes_socket_owned_by_connection_close_response(self):
        server.KEYS["fixture"] = "dummy-test-key"
        aborted = threading.Event()
        raw_socket = SimpleNamespace(shutdown=lambda how: aborted.set())
        class Connection:
            def __init__(self):
                self.sock = raw_socket
                self.close_count = 0
            def request(self, *args, **kwargs): pass
            def close(self):
                self.close_count += 1
                self.sock = None
            def getresponse(self):
                self.sock = None
                return SimpleNamespace(status=200, read=self.read)
            def read(self, size):
                if not aborted.wait(1):
                    raise AssertionError("Deadline did not interrupt the response socket")
                raise OSError("socket closed")
        connection = Connection()
        with mock.patch.object(server, "validate_endpoint", return_value=("provider.test", 443, "/chat/completions", ["8.8.8.8"])), \
             mock.patch.object(server, "PublicHTTPSConnection", return_value=connection):
            with self.assertRaisesRegex(RuntimeError, "deadline"):
                server.custom_completion("openrouter|fixture/model", "fixture", [], 0.02)
        self.assertEqual(1, connection.close_count)

    def test_truncated_provider_response_is_controlled(self):
        server.KEYS["fixture"] = "dummy-test-key"
        connection = mock.Mock()
        response = mock.Mock(status=200)
        response.read.side_effect = http.client.IncompleteRead(b"partial", 10)
        connection.getresponse.return_value = response
        with mock.patch.object(server, "validate_endpoint", return_value=("provider.test", 443, "/chat/completions", ["8.8.8.8"])), \
             mock.patch.object(server, "PublicHTTPSConnection", return_value=connection):
            with self.assertRaisesRegex(RuntimeError, "connection failed"):
                server.custom_completion("openrouter|fixture/model", "fixture", [], 1)

    def test_codex_does_not_start_in_target_or_inherit_unrelated_keys(self):
        response = self.folder / "response.txt"
        def execute(command, **options):
            work = Path(command[command.index("-C") + 1])
            self.assertTrue((work / ".git").is_dir())
            self.assertIn("--ignore-user-config", command)
            self.assertNotIn("UNRELATED_SECRET_KEY", options["env"])
            self.assertIn('shell_environment_policy.inherit="none"', command)
            return SimpleNamespace(returncode=0)
        with mock.patch.dict(os.environ, {"UNRELATED_SECRET_KEY": "dummy"}), \
             mock.patch.object(bugbounty_agent.shutil, "which", return_value="/trusted/codex"), \
             mock.patch.object(bugbounty_agent, "bounded_process", side_effect=execute):
            bugbounty_agent.run_codex("Fixture prompt", response)

    def test_subprocess_timeout_cleans_up_process_group(self):
        process = mock.Mock(pid=123456)
        process.communicate.side_effect = subprocess.TimeoutExpired("fixture", 1)
        process.poll.return_value = None
        with mock.patch.object(bugbounty_agent.subprocess, "Popen", return_value=process), \
             mock.patch.object(bugbounty_agent.os, "killpg") as kill_group:
            with self.assertRaisesRegex(RuntimeError, "deadline"):
                bugbounty_agent.bounded_process(["fixture"], {}, 1)
            if os.name == "posix":
                kill_group.assert_called_once()
            process.wait.assert_called_once_with(timeout=5)


if __name__ == "__main__":
    unittest.main()

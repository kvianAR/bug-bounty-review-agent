import http.cookiejar
import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import mock

import server
from bugbounty_agent import validate_findings


class CoreTests(unittest.TestCase):
    def test_repository_urls_are_bounded_to_github(self):
        server.resolve_repo_url("https://github.com/owner/repo")
        for url in ("http://github.com/owner/repo", "https://evil.test/owner/repo",
                    "https://github.com/owner/repo?redirect=1", "https://github.com/owner/repo/extra"):
            with self.assertRaises(ValueError):
                server.resolve_repo_url(url)

    def test_findings_cannot_escape_checkout(self):
        with tempfile.TemporaryDirectory() as temp:
            repo = Path(temp) / "repo"
            repo.mkdir()
            (repo / "app.py").write_text("line 1\n")
            data = {"findings": [{"path": "app.py", "line": 1},
                                 {"path": "../secret", "line": 1},
                                 {"path": "app.py", "line": 2}]}
            self.assertEqual(1, len(validate_findings(data, repo)["findings"]))

    def test_openrouter_free_id_and_key_reach_chat_api(self):
        server.KEYS["test"] = "sk-or-private-test-value"
        class Reply:
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self, size):
                return b'{"choices":[{"message":{"content":"TRACE_MODEL_OK"}}]}'
        class Opener:
            def open(self, request, timeout):
                self_url = request.full_url
                self.assertTrue(self_url.endswith("/chat/completions"))
                self.assertEqual("nvidia/nemotron-3-ultra-550b-a55b:free", json.loads(request.data)["model"])
                self.assertEqual("Bearer sk-or-private-test-value", request.get_header("Authorization"))
                return Reply()
        opener = Opener()
        opener.assertTrue = self.assertTrue
        opener.assertEqual = self.assertEqual
        with mock.patch.object(server, "validate_endpoint"), mock.patch.object(server.urllib.request, "build_opener", return_value=opener):
            answer = server.custom_completion("openrouter|nvidia/nemotron-3-ultra-550b-a55b:free", "test",
                                              [{"role": "user", "content": "test"}], 10)
        self.assertEqual("TRACE_MODEL_OK", answer)
        self.assertNotIn("sk-or-private-test-value", json.dumps(server.MODELS))
        server.KEYS.clear()

    def test_report_parser_rejects_non_json(self):
        with self.assertRaises(RuntimeError):
            server.parse_report("not a report")
        report = server.parse_report('```json\n{"summary":"ok","findings":[],"limitations":[]}\n```')
        self.assertEqual([], report["findings"])

    def test_api_requires_private_access_link(self):
        with tempfile.TemporaryDirectory() as temp:
            previous_data = server.DATA
            previous_port = server.PORT
            server.DATA = Path(temp)
            server.DATA.mkdir(exist_ok=True)
            httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
            server.PORT = httpd.server_address[1]
            thread = threading.Thread(target=httpd.serve_forever, daemon=True)
            thread.start()
            base = "http://127.0.0.1:{}".format(server.PORT)
            try:
                with self.assertRaises(urllib.error.HTTPError) as error:
                    urllib.request.urlopen(base + "/api/models")
                self.assertEqual(401, error.exception.code)
                jar = http.cookiejar.CookieJar()
                client = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
                client.open(base + "/?token=" + server.SESSION_TOKEN)
                self.assertEqual({"models": server.MODELS}, json.load(client.open(base + "/api/models")))
                request = urllib.request.Request(base + "/api/models", data=b'{}',
                    headers={"Content-Type": "application/json", "Origin": "https://evil.test"})
                with self.assertRaises(urllib.error.HTTPError) as cross_origin:
                    client.open(request)
                self.assertEqual(403, cross_origin.exception.code)
                server.KEYS["delete-me"] = "test-key-value"
                delete = urllib.request.Request(base + "/api/keys", data=b'{"alias":"delete-me"}',
                    headers={"Content-Type": "application/json"}, method="DELETE")
                with mock.patch.object(server, "delete_key", side_effect=lambda alias: server.KEYS.pop(alias)):
                    self.assertNotIn("delete-me", json.load(client.open(delete))["keys"])
                server.MODELS.append("temporary-model")
                remove_model = urllib.request.Request(base + "/api/models", data=b'{"model":"temporary-model"}',
                    headers={"Content-Type": "application/json"}, method="DELETE")
                self.assertNotIn("temporary-model", json.load(client.open(remove_model))["models"])
            finally:
                httpd.shutdown()
                httpd.server_close()
                thread.join(timeout=2)
                server.DATA = previous_data
                server.PORT = previous_port


if __name__ == "__main__":
    unittest.main()

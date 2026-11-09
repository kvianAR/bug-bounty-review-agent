import http.cookiejar
import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

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

    def test_openrouter_key_is_only_in_process_environment(self):
        server.KEYS["test"] = "sk-or-private-test-value"
        args, env = server.model_options("openrouter|vendor/model:floor", "test")
        self.assertIn("vendor/model:floor", args)
        self.assertEqual("sk-or-private-test-value", env["OPENROUTER_API_KEY"])
        self.assertNotIn("sk-or-private-test-value", " ".join(args))
        with self.assertRaises(ValueError):
            server.model_options("openrouter|vendor/model:floor", "missing")
        server.KEYS.clear()

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
            finally:
                httpd.shutdown()
                httpd.server_close()
                thread.join(timeout=2)
                server.DATA = previous_data
                server.PORT = previous_port


if __name__ == "__main__":
    unittest.main()

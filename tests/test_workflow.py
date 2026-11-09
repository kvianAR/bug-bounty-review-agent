import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

import review_workflow as workflow
import server
import bugbounty_agent
from test_core import finding, report, request


VULNERABLE = '''from pathlib import Path

def read_note(root, name):
    return (Path(root) / name).read_text()
'''

FIXED = '''from pathlib import Path

def read_note(root, name):
    base = Path(root).resolve()
    target = (base / name).resolve()
    if not target.is_relative_to(base):
        raise ValueError("Path escapes notes root")
    return target.read_text()
'''

REGRESSION = '''import sys
import tempfile
from pathlib import Path
from storage import read_note

with tempfile.TemporaryDirectory() as directory:
    root = Path(directory) / "notes"
    root.mkdir()
    (Path(directory) / "private.txt").write_text("fixture")
    try:
        read_note(root, "../private.txt")
    except ValueError:
        print("TRACE_REGRESSION_PASS")
        sys.exit(0)
    print("TRACE_REGRESSION_FAIL")
    sys.exit(1)
'''


def fixture_repository(root):
    repo = root / "repo"
    repo.mkdir()
    workflow.git(repo, ["init", "--quiet"])
    (repo / "storage.py").write_text(VULNERABLE)
    (repo / "README.md").write_text("Fixture source\n")
    workflow.git(repo, ["add", "."])
    result = workflow.git(repo, ["-c", "user.name=Trace Fixture", "-c", "user.email=fixture@example.test", "commit", "-qm", "fixture"])
    if result.returncode:
        raise AssertionError(result.stderr)
    commit = workflow.git(repo, ["rev-parse", "HEAD"]).stdout.strip()
    (repo / "storage.py").write_text(FIXED)
    fix = workflow.git(repo, ["diff", "--", "storage.py"]).stdout
    (repo / "test_trace.py").write_text(REGRESSION)
    workflow.git(repo, ["add", "test_trace.py"])
    test_patch = workflow.git(repo, ["diff", "--cached", "--", "test_trace.py"]).stdout
    workflow.git(repo, ["reset", "--hard", "HEAD"])
    plan = {"summary": "Reject paths outside the notes root", "fix_patch": fix, "test_patch": test_patch,
            "runtime": "python", "command": ["python3", "test_trace.py"],
            "failure_marker": "TRACE_REGRESSION_FAIL", "success_marker": "TRACE_REGRESSION_PASS",
            "pr_title": "Fix notes path traversal"}
    return repo, commit, plan


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo, self.commit, self.plan = fixture_repository(self.root)
        self.data = self.root / "data"
        self.data.mkdir()
        patch = mock.patch.object(server, "DATA", self.data)
        patch.start()
        self.addCleanup(patch.stop)
        for state in (server.JOBS, server.KEYS, server.MODELS, server.TRIAGE, server.MODEL_PRICES,
                      server.ACTIVE_CHATS, server.ACTIVE_WORKFLOWS, server.ACTIVE_KEYS):
            state.clear()

    def job(self):
        item = finding(path="storage.py", line=4, cwe="CWE-22", title="Notes traversal")
        item = workflow.attach_findings(self.repo, "https://github.com/owner/fixture", [item])[0]
        value = {"id": "a" * 12, "url": "https://github.com/owner/fixture", "repo_path": str(self.repo),
                 "commit": self.commit, "status": "complete", "created_at": "2026-11-09T00:00:00+00:00",
                 "messages": [], "report": report([item]), "model": "openrouter|fixture/primary:free",
                 "key_alias": "primary", "policy": workflow.budget_policy({"max_cost_usd": 0})}
        server.JOBS[value["id"]] = value
        server.KEYS["primary"] = "dummy-primary-key"
        server.save(value)
        return value

    def test_coverage_records_skipped_and_submitted_files(self):
        excerpt, coverage = workflow.coverage_context(self.repo, 5000)
        records = {item["path"]: item for item in coverage["files"]}
        self.assertEqual("included", records["storage.py"]["status"])
        self.assertEqual("unsupported_file_type", records["README.md"]["reason"])
        self.assertIn("read_note", excerpt)
        self.assertEqual(len(excerpt), coverage["characters"])
        _, changed = workflow.coverage_context(self.repo, 5000, {"storage.py"})
        self.assertEqual("unchanged", next(item for item in changed["files"] if item["path"] == "README.md")["reason"])

    def test_fingerprints_survive_line_shifts_and_deduplicate(self):
        item = finding(path="storage.py", line=4, cwe="CWE-22")
        original = workflow.attach_findings(self.repo, "https://github.com/Owner/Fixture.git", [item, item])
        self.assertEqual(1, len(original))
        self.assertEqual(1, original[0]["duplicates"])
        (self.repo / "storage.py").write_text("\n" + VULNERABLE)
        shifted = workflow.attach_findings(self.repo, "https://github.com/owner/fixture", [dict(item, line=5)])
        self.assertEqual(original[0]["id"], shifted[0]["id"])

    def test_incremental_comparison_uses_real_commits(self):
        head = self.root / "head"
        clone = workflow.bounded_process(["git", "clone", "--quiet", str(self.repo), str(head)],
                                         workflow.git_environment(self.root), 10)
        self.assertEqual(0, clone.returncode)
        (head / "storage.py").write_text(FIXED)
        workflow.git(head, ["add", "storage.py"])
        workflow.git(head, ["-c", "user.name=Trace Fixture", "-c", "user.email=fixture@example.test", "commit", "-qm", "fix"])
        changed, comparison = workflow.incremental_diff(head, {"id": "baseline", "repo_path": str(self.repo), "commit": self.commit})
        self.assertEqual({"storage.py"}, changed)
        self.assertEqual(self.commit, comparison["base_commit"])
        _, coverage = workflow.coverage_context(head, 5000, changed)
        self.assertEqual("incremental", coverage["mode"])

    def test_evidence_anchor_does_not_export_secret_source(self):
        (self.repo / "storage.py").write_text('api_key = "dummy-sensitive-source-value"\n')
        item = workflow.attach_findings(self.repo, "https://github.com/owner/fixture", [finding(path="storage.py", line=1)])[0]
        self.assertNotIn("dummy-sensitive-source-value", json.dumps(item["evidence_view"]))

    def test_plan_validation_and_patch_workspace_do_not_change_checkout(self):
        plan = workflow.validate_plan(self.repo, workflow.parse_plan(json.dumps(self.plan)))
        self.assertTrue(plan["valid"])
        self.assertEqual(["storage.py"], plan["fix_paths"])
        self.assertEqual(VULNERABLE, (self.repo / "storage.py").read_text())
        self.assertFalse((self.repo / "test_trace.py").exists())
        with self.assertRaises(ValueError):
            workflow.patch_paths(self.plan["fix_patch"].replace("b/storage.py", "b/../../outside.py"))

    def test_exact_edit_plan_builds_valid_patches(self):
        value = {key: item for key, item in self.plan.items() if key not in {"fix_patch", "test_patch"}}
        value["edits"] = [{"path": "storage.py", "old_text": VULNERABLE, "new_text": FIXED}]
        value["test_files"] = [{"path": "test_trace.py", "content": REGRESSION}]
        result = workflow.validate_plan(self.repo, workflow.parse_plan(json.dumps(value), self.repo))
        self.assertTrue(result["valid"])
        self.assertEqual(["test_trace.py"], result["test_paths"])
        value["edits"][0]["old_text"] = "not present"
        with self.assertRaisesRegex(ValueError, "match once"):
            workflow.parse_plan(json.dumps(value), self.repo)

    def test_pull_request_uses_merge_base_and_selected_credential(self):
        base, head, ancestor = "a" * 40, "b" * 40, "c" * 40
        responses = [
            io.BytesIO(json.dumps({"base": {"sha": base}, "head": {"sha": head}}).encode()),
            io.BytesIO(json.dumps({"merge_base_commit": {"sha": ancestor}}).encode()),
        ]
        opener = mock.Mock()
        opener.open.side_effect = responses
        with mock.patch.object(bugbounty_agent.urllib.request, "build_opener", return_value=opener):
            result = bugbounty_agent.pull_request_metadata("owner", "fixture", 7, "fixture-credential")
        self.assertEqual(ancestor, result["base_commit"])
        self.assertEqual(base, result["base_tip"])
        request = opener.open.call_args_list[1].args[0]
        self.assertIn(base + "..." + head, request.full_url)
        self.assertEqual("Bearer fixture-credential", request.get_header("Authorization"))

    def test_rejected_assessment_cannot_produce_ready_pr(self):
        job = self.job()
        item = job["report"]["findings"][0]
        for verdict in ("rejected", "needs_validation"):
            plan = workflow.validate_plan(self.repo, {"assessment": verdict})
            self.assertNotIn("fix_patch", plan)
            item["assessment"] = {"verdict": verdict}
            item["remediation"] = {"valid": True}
            item["verification"] = {"status": "reproduced"}
            self.assertFalse(workflow.pr_document(job, item)["ready"])

    def test_regression_classification_requires_both_expected_results(self):
        plan = workflow.validate_plan(self.repo, self.plan)
        runtime = {"available": True, "images": {"python": {"available": True, "id": "sha256:fixture"}}}
        before = {"exit_code": 1, "timed_out": False, "output": "TRACE_REGRESSION_FAIL"}
        after = {"exit_code": 0, "timed_out": False, "output": "TRACE_REGRESSION_PASS"}
        with mock.patch.object(workflow, "runner_status", return_value=runtime), \
             mock.patch.object(workflow, "run_container", side_effect=[before, after]):
            result = workflow.verify_plan(self.repo, plan)
        self.assertEqual("reproduced", result["status"])
        with mock.patch.object(workflow, "runner_status", return_value=runtime), \
             mock.patch.object(workflow, "run_container", side_effect=[dict(before, output="missing dependency"), after]):
            result = workflow.verify_plan(self.repo, plan)
        self.assertEqual("blocked", result["status"])

    def test_pr_bundle_has_copy_ready_body_and_honest_verification(self):
        job = self.job()
        item = job["report"]["findings"][0]
        item["remediation"] = workflow.validate_plan(self.repo, self.plan)
        pending = workflow.pr_document(job, item)
        self.assertFalse(pending["ready"])
        self.assertIn("verification", pending["body"].lower())
        item["verification"] = {"status": "reproduced", "reason": "Fixture regression passed"}
        ready = workflow.pr_document(job, item)
        self.assertTrue(ready["ready"])
        with zipfile.ZipFile(io.BytesIO(workflow.pr_bundle(job, item))) as archive:
            self.assertIn("PR.md", archive.namelist())
            self.assertIn("fix.patch", archive.namelist())
            self.assertIn("regression.patch", archive.namelist())
            self.assertIn(self.commit, archive.read("PR.md").decode())
            self.assertNotIn("key_alias", archive.read("evidence.json").decode())

    def test_triage_persists_and_applies_to_later_scan(self):
        job = self.job()
        finding_id = job["report"]["findings"][0]["id"]
        status, _, _ = request("POST", f'/api/scans/{job["id"]}/findings/{finding_id}/triage',
                               {"decision": "dismissed", "note": "Fixture false positive"})
        self.assertEqual(200, status)
        self.assertTrue((self.data / "triage.json").exists())
        new_scan = dict(job, id="b" * 12)
        server.JOBS[new_scan["id"]] = new_scan
        self.assertEqual("dismissed", server.visible(new_scan)["report"]["findings"][0]["triage"]["decision"])

    def test_workflow_entrypoints_prepare_verify_and_export(self):
        job = self.job()
        item = job["report"]["findings"][0]
        job["operation"] = {"kind": "prepare", "finding_id": item["id"], "status": "running"}
        plan = workflow.validate_plan(self.repo, self.plan)
        with mock.patch.object(server, "execute_model", return_value=plan):
            server.run_workflow(job["id"], item["id"], "prepare", job["model"], job["key_alias"])
        self.assertEqual("complete", job["operation"]["status"])
        self.assertTrue(item["remediation"]["valid"])
        with mock.patch.object(workflow, "verify_plan", return_value={"status": "reproduced", "reason": "Fixture proof"}):
            server.run_workflow(job["id"], item["id"], "verify", "", "")
        status, document, _ = request("GET", f'/api/scans/{job["id"]}/findings/{item["id"]}/pr')
        self.assertEqual(200, status)
        self.assertTrue(document["ready"])
        status, bundle, _ = request("GET", f'/api/scans/{job["id"]}/findings/{item["id"]}/bundle')
        self.assertEqual(200, status)
        with zipfile.ZipFile(io.BytesIO(bundle)) as archive:
            self.assertIn("TRACE_REGRESSION_FAIL", archive.read("regression.patch").decode())

    def test_budget_update_cannot_erase_recorded_spend(self):
        job = self.job()
        job["usage"] = [{"charged_or_reserved_usd": 0.25}]
        status, _, _ = request("POST", f'/api/scans/{job["id"]}/budget', {"max_cost_usd": 0.1})
        self.assertEqual(400, status)
        status, value, _ = request("POST", f'/api/scans/{job["id"]}/budget', {"max_cost_usd": 0.5})
        self.assertEqual(200, status)
        self.assertEqual(0.5, value["policy"]["max_cost_usd"])

    def test_budget_and_explicit_fallback_record_usage(self):
        job = self.job()
        primary, fallback = job["model"], "openrouter|fixture/fallback:free"
        server.MODELS.extend([primary, fallback])
        server.KEYS.update(primary="dummy-primary-key", fallback="dummy-fallback-key")
        job["policy"]["fallbacks"] = [{"model": fallback, "key_alias": "fallback"}]
        calls = []
        def completion(model, key, messages, timeout, **options):
            calls.append((model, key, options))
            if model == primary:
                raise RuntimeError("fixture rate limit")
            options["usage_callback"]({"prompt_tokens": 12, "completion_tokens": 3, "cost": 0})
            return "fixture response"
        with mock.patch.object(server, "custom_completion", side_effect=completion):
            result = server.execute_model(job["id"], "scan", [{"role": "user", "content": "fixture"}], primary, "primary")
        self.assertEqual("fixture response", result)
        self.assertEqual(["failed", "complete"], [entry["status"] for entry in job["usage"]])
        self.assertEqual(3, job["usage"][1]["completion_tokens"])
        self.assertEqual(5000, calls[1][2]["max_output_tokens"])

    def test_cost_limit_stops_request_before_dispatch(self):
        job = self.job()
        job["model"] = "custom|Fixture|model"
        server.MODEL_PRICES[job["model"]] = {"input": 10, "output": 10, "request": 0}
        with mock.patch.object(server, "custom_completion") as completion:
            with self.assertRaisesRegex(RuntimeError, "budget"):
                server.execute_model(job["id"], "chat", [{"role": "user", "content": "fixture"}], job["model"], "primary")
            completion.assert_not_called()

    def test_pull_request_urls_and_policy_validation(self):
        url, number = server.parse_scan_target("https://github.com/owner/repository/pull/42")
        self.assertEqual(("https://github.com/owner/repository", 42), (url, number))
        with self.assertRaises(ValueError):
            workflow.budget_policy({"max_output_tokens": None})
        with self.assertRaises(ValueError):
            workflow.budget_policy({"max_cost_usd": float("nan")})


if __name__ == "__main__":
    unittest.main()

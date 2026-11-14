#!/usr/bin/env python3
"""Evaluate source-review precision on small labelled synthetic repositories."""
import argparse
import json
import os
import subprocess
import tempfile
from pathlib import Path

import accuracy_review
from bugbounty_agent import SCHEMA
import review_workflow as workflow

# Labels stay outside repository source. Each pair changes its actual control.
CASES = [
    {'id': 'case_01', 'label': True, 'class': 'CWE-639', 'files': {
        'api.py': 'from service import load_document\ndef get_document(session_user, document_id):\n    return load_document(session_user, document_id)\n',
        'service.py': 'DOCUMENTS = {"a": {"owner": "alice", "body": "private"}}\ndef load_document(user, document_id):\n    return DOCUMENTS[document_id]["body"]\n'}},
    {'id': 'case_02', 'label': False, 'class': 'CWE-639', 'files': {
        'api.py': 'from service import load_document\ndef get_document(session_user, document_id):\n    return load_document(session_user, document_id)\n',
        'service.py': 'DOCUMENTS = {"a": {"owner": "alice", "body": "private"}}\ndef load_document(user, document_id):\n    document = DOCUMENTS[document_id]\n    if document["owner"] != user:\n        raise PermissionError("Forbidden")\n    return document["body"]\n'}},
    {'id': 'case_03', 'label': True, 'class': 'CWE-89', 'files': {
        'api.py': 'def public_search(db, query):\n    return db.execute("SELECT title FROM articles WHERE title = " + "\\\'" + query + "\\\'").fetchall()\n'}},
    {'id': 'case_04', 'label': False, 'class': 'CWE-89', 'files': {
        'api.py': 'def public_search(db, query):\n    return db.execute("SELECT title FROM articles WHERE title = ?", (query,)).fetchall()\n'}},
    {'id': 'case_05', 'label': True, 'class': 'CWE-79', 'files': {
        'api.py': 'def public_html_response(query):\n    """Served as text/html in a victim browser from an attacker-shared URL."""\n    return "<h1>" + query + "</h1>"\n'}},
    {'id': 'case_06', 'label': False, 'class': 'CWE-79', 'files': {
        'api.py': 'import html\ndef public_html_response(query):\n    """Served as text/html in a victim browser from an attacker-shared URL."""\n    return "<h1>" + html.escape(query) + "</h1>"\n'}},
    {'id': 'case_07', 'label': False, 'class': 'hardening', 'files': {
        'api.py': 'from service import create_key\ndef create_my_key(verified_session, name):\n    return create_key(verified_session.user_id, name)\n',
        'service.py': 'def create_key(user_id, name):\n    cleaned = (name or "API Key").strip()[:120]\n    return {"owner": user_id, "name": cleaned}\n'}},
    {'id': 'case_08', 'label': False, 'class': 'admin-output', 'files': {
        'api.py': 'def print_own_token(authenticated_user):\n    """User-requested local CLI output, visible only to that principal."""\n    print(authenticated_user.own_token)\n'}},
]


AUTH_SOURCE = """import os
import hmac

def authenticate(request):
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        raise PermissionError("Unauthenticated")
    supplied = header[7:]
    for user in ("alice", "bob"):
        expected = os.environ.get("TRACE_" + user.upper() + "_TOKEN", "")
        if expected and hmac.compare_digest(supplied, expected):
            return user
    raise PermissionError("Unauthenticated")
"""
IDOR_HTTP = """from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
from auth import authenticate
from service import load_document

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            user = authenticate(self)
            document_id = parse_qs(urlparse(self.path).query)["id"][0]
            body = load_document(user, document_id)
        except PermissionError:
            self.send_error(403)
            return
        self.send_response(200)
        self.end_headers()
        self.wfile.write(body.encode())

if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
"""
for case in CASES[:2]:
    case["files"].update({"api.py": IDOR_HTTP, "auth.py": AUTH_SOURCE})
for case in CASES[2:4]:
    query_function = case["files"]["api.py"].replace("WHERE title =", "WHERE public = 1 AND title =")
    case["files"]["api.py"] = """import sqlite3
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

""" + query_function + """
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        query = parse_qs(urlparse(self.path).query).get("q", [""])[0]
        db = sqlite3.connect(":memory:")
        db.execute("CREATE TABLE articles (title TEXT, public INTEGER)")
        db.executemany("INSERT INTO articles VALUES (?, ?)", [("announcement", 1), ("private-plan", 0)])
        try:
            rows = public_search(db, query)
        finally:
            db.close()
        self.send_response(200)
        self.end_headers()
        self.wfile.write(str(rows).encode())

if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
"""
for case in CASES[4:6]:
    case["files"]["api.py"] += """
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        query = parse_qs(urlparse(self.path).query).get("q", [""])[0]
        body = public_html_response(query)
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(body.encode())

if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
"""
CASES[6]["files"]["auth.py"] = AUTH_SOURCE
CASES[6]["files"]["api.py"] = """import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from auth import authenticate
from service import create_key

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        try:
            user = authenticate(self)
        except PermissionError:
            self.send_error(403)
            return
        payload = json.loads(self.rfile.read(min(int(self.headers.get("Content-Length", 0)), 4096)))
        record = create_key(user, payload.get("name", "API Key"))
        self.send_response(200)
        self.end_headers()
        self.wfile.write(json.dumps(record).encode())

if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
"""
CASES[7]["files"]["api.py"] = """import os
import getpass
import hmac

def main():
    user = getpass.getuser()
    own_token = os.environ["TRACE_OWN_TOKEN"]
    supplied = getpass.getpass("Re-enter your own token to display it: ")
    if not hmac.compare_digest(supplied, own_token):
        raise PermissionError("Denied")
    print(own_token)

if __name__ == "__main__":
    main()
"""


def score(predictions, cases=CASES):
    counts = dict(tp=0, fp=0, tn=0, fn=0, abstained=0)
    for case in cases:
        prediction = predictions.get(case['id'])
        if prediction not in ('supported', 'clear'):
            counts['abstained'] += 1
            continue
        positive = prediction == 'supported'
        counts['tp' if case['label'] and positive else 'fn' if case['label'] else 'fp' if positive else 'tn'] += 1
    tp, fp, tn, fn = (counts[key] for key in ('tp', 'fp', 'tn', 'fn'))
    return dict(counts, precision=tp / (tp + fp) if tp + fp else None,
                recall=tp / sum(case['label'] for case in cases) if any(case['label'] for case in cases) else None,
                false_positive_rate=fp / (fp + tn) if fp + tn else None,
                decision_coverage=(len(cases) - counts['abstained']) / len(cases))


def evaluate(case, call, root):
    repo = root / case['id']
    repo.mkdir()
    for name, content in case['files'].items():
        (repo / name).write_text(content)
    workflow.git(repo, ['init', '--quiet'])
    workflow.git(repo, ['add', '.'])
    report, coverage = accuracy_review.review(repo, call, 30000, SCHEMA, 'Trace public inputs and authorization controls')
    supported = [item for item in report['findings'] if item['source_review']['verdict'] == 'supported']
    undecided = [item for item in report['findings'] if item['source_review']['verdict'] == 'needs_validation']
    read_any_source = coverage['totals']['included'] + coverage['totals']['partial'] > 0
    expected_classes = {'CWE-639': {'CWE-639', 'CWE-862', 'CWE-863', 'CWE-284'}, 'CWE-89': {'CWE-89'}, 'CWE-79': {'CWE-79'}}
    matches = [item for item in supported if item['cwe'] in expected_classes.get(case['class'], {item['cwe']})]
    malformed = any('Malformed model findings' in item for item in report['limitations'])
    decision = 'abstained' if not read_any_source or malformed else 'supported' if (matches if case['label'] else supported) else 'abstained' if undecided else 'clear'
    return {'decision': decision, 'off_target_supported': len(supported) - len(matches),
            'report': report, 'coverage': coverage['totals']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--predictions', type=Path, help='Score a JSON mapping case IDs to supported/clear/abstained')
    parser.add_argument('--model', help='Saved route such as openrouter|provider/model:free')
    parser.add_argument('--key-alias', default='', help='macOS Keychain alias, or set TRACE_BENCHMARK_KEY')
    parser.add_argument('--max-cost-usd', type=float, default=0, help='Total provider estimate cap, default free routes only')
    parser.add_argument('--case', choices=[case['id'] for case in CASES])
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--publish', action='store_true', help='Show this live synthetic benchmark summary in the website')
    args = parser.parse_args()
    cases = [case for case in CASES if not args.case or case['id'] == args.case]
    if args.publish and args.predictions:
        parser.error('--publish is available only for a live model evaluation')
    if args.predictions:
        predictions = json.loads(args.predictions.read_text())
        result = {'predictions': predictions, 'metrics': score(predictions, cases)}
    else:
        if not args.model:
            parser.error('Choose --model for a live evaluation or --predictions for scoring')
        import server
        original_data = server.DATA
        providers = original_data / 'providers.json'
        if providers.exists():
            server.PROVIDERS.extend(json.loads(providers.read_text()))
        prices = original_data / 'model_prices.json'
        if prices.exists():
            server.MODEL_PRICES.update(json.loads(prices.read_text()))
        key = os.environ.get('TRACE_BENCHMARK_KEY', '')
        if not key and args.key_alias:
            key = subprocess.check_output(['security', 'find-generic-password', '-a', args.key_alias,
                                          '-s', 'ai.trace.repository-review', '-w'], text=True).strip()
        if not key and args.model.startswith(('openrouter|', 'custom|')):
            parser.error('Supply a key alias or TRACE_BENCHMARK_KEY')
        server.KEYS['benchmark'] = key
        server.MODELS.append(args.model)
        outputs = {}
        with tempfile.TemporaryDirectory(prefix='trace-benchmark-') as folder:
            root = Path(folder)
            server.DATA = root
            job_id = 'benchmark'
            server.JOBS[job_id] = {'id': job_id, 'policy': workflow.budget_policy({'max_cost_usd': args.max_cost_usd}), 'usage': []}
            def call(phase, messages, validator):
                return server.execute_model(job_id, phase, messages, args.model, 'benchmark', validator=validator)
            for case in cases:
                try:
                    outputs[case['id']] = evaluate(case, call, root)
                except (RuntimeError, ValueError, OSError) as exc:
                    outputs[case['id']] = {'decision': 'abstained', 'error': str(exc)}
                print(case['id'], outputs[case['id']]['decision'], flush=True)
                args.output.write_text(json.dumps({'partial': True, 'cases': outputs}, indent=2) + '\n')
            predictions = {name: item['decision'] for name, item in outputs.items()}
            result = {'model': args.model, 'predictions': predictions, 'cases': outputs,
                      'metrics': score(predictions, cases), 'usage': server.JOBS[job_id]['usage']}
    result['limitations'] = ['Small synthetic source-review benchmark. It does not measure real-world bounty success or establish runtime exploitability. Recall counts positive abstentions as misses.']
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    if args.publish:
        from datetime import datetime, timezone
        summary = {'model': args.model, 'cases': len(cases), 'metrics': result['metrics'],
                   'updated_at': datetime.now(timezone.utc).isoformat(), 'scope': 'synthetic_source_review',
                   'reported_cost_usd': sum(entry.get('actual_cost_usd') or 0 for entry in result.get('usage', []))}
        server.private_write(original_data / 'accuracy-benchmark.json', json.dumps(summary, indent=2) + '\n')
    print(json.dumps(result['metrics'], indent=2))


if __name__ == '__main__':
    main()

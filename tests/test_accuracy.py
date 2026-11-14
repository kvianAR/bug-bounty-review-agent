import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import accuracy_review as accuracy
import accuracy_benchmark as benchmark
import review_workflow as workflow
from test_core import finding, report
from bugbounty_agent import render_markdown


class AccuracyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        workflow.git(self.root, ['init', '--quiet'])
        (self.root / 'api.py').write_text('from service import clean_name\ndef route(user, name):\n    return clean_name(name)\n')
        (self.root / 'service.py').write_text('\n' * 300 + 'def clean_name(name):\n    return name.strip()[:120]\n')
        workflow.git(self.root, ['add', '.'])
        self.repository = accuracy.Repository(self.root, 10000)
        self.repository.manifest()

    def test_prose_navigation_reply_does_not_approve_a_finding(self):
        value = accuracy.investigation_response("No more source requests needed.")
        self.assertEqual([], value['requests'])
        self.assertNotIn('verdict', value)
        with self.assertRaises(ValueError):
            accuracy.check_assessment(self.repository, "Looks confirmed")

    def test_review_json_accepts_explanation_and_fenced_object(self):
        value = accuracy.json_object('Review result\n```JSON\n{"verdict":"rejected"}\n```')
        self.assertEqual('rejected', value['verdict'])
        with self.assertRaises(ValueError):
            accuracy.json_object('{"verdict":"rejected"} {"verdict":"supported"}')

    def test_helper_after_line_250_can_be_requested_and_coverage_records_exact_ranges(self):
        hits = json.loads(self.repository.search('clean_name'))
        self.assertTrue(any(item['path'] == 'service.py' and item['line'] == 301 for item in hits))
        source = self.repository.actions([{'action': 'read', 'path': 'service.py', 'start': 299, 'end': 305}], 10000)
        self.assertIn('302:     return name.strip()[:120]', source)
        coverage = self.repository.coverage()
        service = next(item for item in coverage['files'] if item['path'] == 'service.py')
        self.assertEqual([[299, 302]], service['ranges'])
        self.assertEqual(4, service['included_lines'])
        with self.assertRaises(ValueError):
            self.repository.read('../secret', 1, 2)

    def test_verdict_needs_real_citation_and_explicit_boundary(self):
        self.repository.read('service.py', 301, 302)
        value = {'verdict': 'supported', 'reason': 'Claim', 'citations': [{'path': 'service.py', 'line': 302, 'quote': 'does_not_exist'}]}
        result = accuracy.check_assessment(self.repository, json.dumps(value))
        self.assertEqual('needs_validation', result['verdict'])
        value['citations'][0]['quote'] = 'name.strip()[:120]'
        self.assertEqual('needs_validation', accuracy.check_assessment(self.repository, json.dumps(value))['verdict'])
        value['verdict'] = 'rejected'
        self.assertEqual('rejected', accuracy.check_assessment(self.repository, json.dumps(value))['verdict'])

    def test_discovery_finding_is_challenged_with_helper_and_hidden_as_rejected(self):
        candidate = finding(path='api.py', line=3, title='Unbounded name')
        phases = []
        def call(phase, messages, validator):
            phases.append(phase)
            if phase in {'investigate', 'trace_candidate'}:
                answer = {'requests': [{'action': 'read', 'path': 'service.py', 'start': 301, 'end': 302}], 'notes': 'Helper trims input'}
            elif phase == 'discover':
                answer = report([candidate])
            else:
                answer = {'verdict': 'rejected', 'reason': 'Service truncates the name.',
                          'citations': [{'path': 'service.py', 'line': 302, 'quote': 'name.strip()[:120]'}]}
            return validator(json.dumps(answer))
        result, coverage = accuracy.review(self.root, call, 18000, {}, 'review')
        self.assertEqual('rejected', result['findings'][0]['accuracy_status'])
        self.assertIn('0 source-supported', result['summary'])
        self.assertIn('1 rejected', result['summary'])
        markdown = render_markdown(result, 'https://github.com/owner/repo', 'fixture')
        self.assertIn('Review status: rejected', markdown)
        self.assertIn('Service truncates the name.', markdown)
        self.assertIn('independent_review', phases)
        self.assertGreater(coverage['totals']['partial'], 0)

    def test_review_failure_keeps_candidate_unverified(self):
        def call(phase, messages, validator):
            if phase == 'independent_review':
                raise RuntimeError('fixture provider unavailable')
            return validator(json.dumps(report([finding(path='api.py', line=3)]) if phase == 'discover' else {'requests': [], 'notes': ''}))
        value, _ = accuracy.review(self.root, call, 18000, {})
        self.assertEqual('needs_validation', value['findings'][0]['accuracy_status'])

    def test_sarif_never_promotes_an_alert_and_rejects_outside_paths(self):
        def result(path):
            return {'ruleId': 'example', 'message': {'text': 'untrusted lead'}, 'locations': [{'physicalLocation': {'artifactLocation': {'uri': path}, 'region': {'startLine': 3}}}]}
        sarif = {'version': '2.1.0', 'runs': [{'results': [result('api.py'), result('../secret')]}]}
        leads = accuracy.sarif_leads(sarif, self.root)
        self.assertEqual(1, len(leads))
        self.assertEqual('unverified_tool_lead', leads[0]['status'])

    def test_benchmark_secure_pairs_have_real_behavior_difference(self):
        for case in benchmark.CASES:
            for name, source in case['files'].items():
                compile(source, name, 'exec')
        for index, expected in ((2, True), (3, False)):
            namespace = {}
            exec(benchmark.CASES[index]['files']['api.py'], namespace)
            db = sqlite3.connect(':memory:')
            self.addCleanup(db.close)
            db.execute('CREATE TABLE articles (title TEXT, public INTEGER)')
            db.execute("INSERT INTO articles VALUES ('private', 0)")
            rows = namespace['public_search'](db, "' OR 1=1 --")
            self.assertEqual(expected, bool(rows))
        for index, vulnerable in ((0, True), (1, False)):
            namespace = {}
            exec(benchmark.CASES[index]['files']['service.py'], namespace)
            if vulnerable:
                self.assertEqual('private', namespace['load_document']('bob', 'a'))
            else:
                with self.assertRaises(PermissionError):
                    namespace['load_document']('bob', 'a')

    def test_benchmark_metrics_include_abstentions_and_false_positives(self):
        predictions = {'case_01': 'supported', 'case_02': 'supported', 'case_03': 'abstained',
                       'case_04': 'clear', 'case_05': 'clear', 'case_06': 'clear', 'case_07': 'clear', 'case_08': 'clear'}
        value = benchmark.score(predictions)
        self.assertEqual(0.5, value['precision'])
        self.assertEqual(1 / 3, value['recall'])
        self.assertEqual(0.2, value['false_positive_rate'])
        self.assertEqual(1, value['abstained'])

    def test_runtime_success_without_source_and_test_review_is_not_pr_ready(self):
        item = dict(finding(path='api.py', line=3), id='fixture')
        item['verification'] = {'status': 'reproduced'}
        item['remediation'] = {'valid': True}
        item['assessment'] = {'verdict': 'supported'}
        job = {'url': 'https://github.com/owner/repo', 'commit': 'fixture'}
        self.assertFalse(workflow.pr_document(job, item)['ready'])
        item['source_review'] = {'verdict': 'supported'}
        self.assertFalse(workflow.pr_document(job, item)['ready'])

"""Optional isolated static analyzer. Results are investigation leads only."""
import json
import tempfile
from pathlib import Path

import accuracy_review
import review_workflow as workflow

SEMGREP_IMAGE = 'semgrep/semgrep:1.143.0'


def semgrep(repo):
    environment = workflow.docker_environment()
    try:
        local = workflow.runner_status()
        if not local['available']:
            return {'status': 'unavailable', 'reason': local['reason'], 'leads': []}
        image = workflow.bounded_process(['docker', 'image', 'inspect', '--format', '{{.Id}}', SEMGREP_IMAGE], environment, 5)
        if image.returncode:
            return {'status': 'unavailable', 'reason': 'Cache ' + SEMGREP_IMAGE + ' to enable Semgrep.', 'leads': []}
        with tempfile.TemporaryDirectory(prefix='trace-semgrep-') as folder:
            snapshot = Path(folder)
            workflow.copy_snapshot(repo, snapshot)
            # Ignore repository configuration. Only app-owned rules are executed.
            (snapshot / '.trace-semgrep.yml').write_text((Path(__file__).parent / 'tools/semgrep-rules.yml').read_text())
            plan = {'command': ['semgrep', 'scan', '--config', '.trace-semgrep.yml', '--sarif',
                                 '--metrics', 'off', '--disable-version-check', '--no-git-ignore', '.']}
            result = workflow.run_container(snapshot, plan, image.stdout.strip(), redact_output=False)
        if result['timed_out'] or result['output_truncated'] or result['exit_code'] != 0:
            return {'status': 'blocked', 'reason': 'Semgrep exceeded a limit or could not finish.', 'leads': []}
        output = result['output']
        start = output.find('{')
        sarif, _ = json.JSONDecoder().raw_decode(output[start:])
        return {'status': 'complete', 'reason': 'App-owned Semgrep rules ran in an offline container.',
                'leads': accuracy_review.sarif_leads(sarif, repo), 'image_id': image.stdout.strip()}
    except (OSError, ValueError, RuntimeError) as exc:
        return {'status': 'blocked', 'reason': str(exc)[:500], 'leads': []}

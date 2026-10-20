from pathlib import Path
from urllib.parse import urlsplit
import datetime
import hashlib
import json
import os
import subprocess

root = Path('/home/nzsn/Repos/DumpAnalyzer')
base = Path('/tmp/dumpanalyzer-p6-live-20261020')
attempt = base / 'attempts/02-configured-gateway'
preflight = json.loads((base / 'preflight.json').read_text())
for name, digest in preflight['sourceSha256'].items():
    assert hashlib.sha256((root / name).read_bytes()).hexdigest() == digest, name
settings = json.loads(Path('/home/nzsn/.claude/settings.json').read_text())
configured = settings.get('env', {})
destination = configured.get('ANTHROPIC_BASE_URL')
parsed = urlsplit(destination)
assert parsed.scheme == 'https' and parsed.hostname == 'claude.jlcops.com'
assert parsed.username is None and parsed.password is None and not parsed.query
assert destination.rstrip('/') == 'https://claude.jlcops.com/api'
assert configured.get('ANTHROPIC_AUTH_TOKEN')
allowed = [
    'ANTHROPIC_BASE_URL', 'ANTHROPIC_AUTH_TOKEN', 'ANTHROPIC_API_KEY',
    'CLAUDE_CODE_OAUTH_TOKEN', 'ANTHROPIC_MODEL',
    'ANTHROPIC_DEFAULT_OPUS_MODEL', 'ANTHROPIC_DEFAULT_SONNET_MODEL',
    'ANTHROPIC_DEFAULT_HAIKU_MODEL', 'API_TIMEOUT_MS',
]
env = os.environ.copy()
for name in allowed:
    env.pop(name, None)
for name in allowed:
    if name in configured:
        env[name] = str(configured[name])
if not env.get('ANTHROPIC_MODEL') and settings.get('model'):
    env['ANTHROPIC_MODEL'] = str(settings['model'])
env.update({
    'DISABLE_TELEMETRY': '1', 'DISABLE_ERROR_REPORTING': '1',
    'CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC': '1',
    'DUMP_ANALYZER_LIVE_TEST_OUTPUT': str(attempt / 'live-capture.json'),
    'PATH': str(attempt / 'bridge') + os.pathsep + os.environ['PATH'],
})
command = [
    'cargo', 'test', '--offline', '--locked', '--test', 'claude_runner',
    'live_reasoner_over_synthetic_fixture_without_remote_dump_transfer',
    '--', '--ignored', '--exact', '--nocapture',
]
metadata = {
    'schema': 'dumpanalyzer.p6.execution/v1',
    'startedUtc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
    'sourceHead': preflight['head'], 'command': command,
    'destination': destination, 'modelSelection': env.get('ANTHROPIC_MODEL'),
    'configurationSource': '~/.claude/settings.json',
    'loadedSettingNames': [name for name in allowed if name in configured],
    'credentialValuesRecorded': False, 'productionIsolationFlagsUnchanged': True,
}
(attempt / 'execution.json').write_text(json.dumps(metadata, indent=2, sort_keys=True) + '\n')
with (attempt / 'live-test.log').open('w') as log:
    result = subprocess.run(command, cwd=root, env=env, stdout=log, stderr=subprocess.STDOUT)
metadata.update({
    'finishedUtc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
    'exitCode': result.returncode,
    'liveCaptureCreated': (attempt / 'live-capture.json').is_file(),
})
(attempt / 'execution.json').write_text(json.dumps(metadata, indent=2, sort_keys=True) + '\n')
print(json.dumps({'attempt': 2, 'exitCode': result.returncode, 'liveCaptureCreated': metadata['liveCaptureCreated']}))
raise SystemExit(result.returncode)

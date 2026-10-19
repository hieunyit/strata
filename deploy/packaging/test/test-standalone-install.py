#!/usr/bin/env python3
"""Fresh disposable systemd container: real packages, core bundle, HTTP and updates.

This does not certify a clean VM or the five-minute installation target.
"""
import argparse
import hashlib
import json
import subprocess
import time
import uuid
from pathlib import Path

ap = argparse.ArgumentParser(description=__doc__)
ap.add_argument('--image', required=True)
ap.add_argument('--cpuset', default='6-9')
ap.add_argument('--rpm-nginx-repo-only', action='store_true',
                help='lab only: disable unused OS repos; DNF still validates all deps and signatures')
ap.add_argument('--negative-bundles', type=Path, required=True)
for name in ['packages', 'bundle', 'update', 'key']:
    ap.add_argument('--' + name, type=Path, required=True)
a = ap.parse_args()
root = Path(__file__).resolve().parents[3]


def run(argv, *, text=None, check=True, timeout=60):
    r = subprocess.run(argv, input=text, text=True, capture_output=True, timeout=timeout)
    if check and r.returncode:
        raise AssertionError(f'{argv}: {r.returncode}\n{r.stdout}\n{r.stderr}')
    return r


name = 'strata-standalone-install-' + uuid.uuid4().hex[:10]
container = run(['docker', 'run', '-d', '--name', name, '--label',
                 'strata.review=standalone-install', '--privileged',
                 '--cgroupns=private', '--cpuset-cpus=' + a.cpuset, '--tmpfs', '/run',
                 '--tmpfs', '/run/lock', a.image]).stdout.strip()


def x(*argv, text=None, check=True, timeout=60):
    return run(['docker', 'exec', '-i', container, *argv], text=text,
               check=check, timeout=timeout)


def until(check):
    end = time.monotonic() + 30
    while time.monotonic() < end:
        if check():
            return
        time.sleep(.2)
    raise AssertionError('condition did not become true within 30s')


def active(unit):
    return x('systemctl', 'is-active', '-q', unit, check=False).returncode == 0


started = time.monotonic()
try:
    until(lambda: x('systemctl', 'is-system-running', check=False).stdout.strip()
          in ['running', 'degraded'])
    if a.rpm_nginx_repo_only:
        x('sh', '-ec', "sed -i 's/^enabled=1/enabled=0/' /etc/yum.repos.d/rocky*.repo")
    assert x('sh', '-c', 'command -v nginx || command -v strata-agent', check=False).returncode != 0
    x('mkdir', '-p', '/tmp/install/packages')
    for package in a.packages.glob('*'):
        if package.suffix in ['.deb', '.rpm']:
            run(['docker', 'cp', str(package), container + ':/tmp/install/packages/'])
    for src, dst in [(a.bundle, 'bundle.sbn'), (a.update, 'update.sbn'), (a.key, 'bundle.pub'),
                     (root / 'deploy/packaging/install.sh', 'install.sh'),
                     (root / 'deploy/packaging/install-standalone.sh', 'install-standalone.sh')]:
        run(['docker', 'cp', str(src), container + ':/tmp/install/' + dst])
    run(['docker', 'cp', str(a.negative_bundles), container + ':/tmp/install/negative'])
    base = ['sh', '/tmp/install/install-standalone.sh', '--packages', '/tmp/install/packages',
            '--bundle', '/tmp/install/bundle.sbn', '--pubkey', '/tmp/install/bundle.pub',
            '--policy', 'example-api', '--listen', '127.0.0.1:18080', '--upstream', '127.0.0.1:18081']
    assert 'cannot enroll' in x('sh', '/tmp/install/install.sh', '--packages', '/tmp/install/packages', '--packages-only', '--server', 'example:443', check=False).stderr
    # Hostile grammar must fail before any package install/configuration.
    for flag, value in [('--policy', 'example-api;'), ('--policy', 'x' * 56),
                        ('--listen', '127.0.0.1:80\ninclude /tmp/evil;'),
                        ('--upstream', '127.0.0.1:80\nroot /tmp;'),
                        ('--listen', '127.0.0.1:0'), ('--upstream', 'host:65536'),
                        ('--nginx', '1.30.5\n1.30.5')]:
        assert x(*(base + [flag, value]), check=False).returncode != 0, (flag, value)
    x('mkdir', '-p', '/var/lib/strata/identity')
    x('touch', '/var/lib/strata/identity/node-id')
    assert 'Fleet identity' in x(*base, check=False).stderr
    x('rm', '/var/lib/strata/identity/node-id')
    x('sh', '-ec', "mkdir -p /etc/nginx; echo 'strata on;' > /etc/nginx/unmanaged.conf")
    assert 'existing Strata configuration' in x(*base, check=False).stderr
    x('rm', '/etc/nginx/unmanaged.conf')
    x('python3', '-c', "from pathlib import Path;p=Path('/tmp/install/oversize.sbn');f=p.open('wb');f.truncate(268435457);f.close();Path('/tmp/install/key65').write_bytes(bytes(65))")
    assert 'bundle exceeds' in x(*(base + ['--bundle', '/tmp/install/oversize.sbn']), check=False).stderr
    assert '32 or 64' in x(*(base + ['--pubkey', '/tmp/install/key65']), check=False).stderr
    assert x('sh', '-c', 'command -v strata-agent', check=False).returncode != 0
    # Build the local upstream without a shared lab/control-plane dependency.
    x('sh', '-ec', "mkdir -p /tmp/backend; echo example-backend > /tmp/backend/index.html")
    x('systemd-run', '--unit=standalone-backend', '--working-directory=/tmp/backend',
      '/usr/bin/python3', '-m', 'http.server', '18081', '--bind', '127.0.0.1')
    install_started = time.monotonic()
    result = x(*base, timeout=600)
    print(result.stdout, result.stderr, flush=True)
    install_seconds = time.monotonic() - install_started
    assert 'ready on 127.0.0.1:18080' in result.stdout
    assert active('strata-agent-standalone.service') and active('nginx')
    assert not active('strata-agent.service') and not active('strata-agent.socket')
    # Freeze external access after package installation; requests below are local.
    run(['docker', 'network', 'disconnect', 'bridge', container])

    def status(path):
        return x('curl', '--noproxy', '*', '-s', '-H', 'Host: api.example.test', '-o', '/tmp/http-body', '-w', '%{http_code}',
                 'http://127.0.0.1:18080' + path, check=False).stdout

    until(lambda: status('/') == '200')
    assert status('/?q=1%27%20OR%201%3D1--') == '403', x('cat', '/tmp/http-body').stdout
    assert 'STR-' in x('cat', '/tmp/http-body').stdout
    assert status('/__standalone_update_fixture__') == '404'
    # A second install must not overwrite an active node.
    before = x('sha256sum', '/etc/nginx/nginx.conf', '/etc/strata/standalone.env').stdout
    assert 'active bundle exists' in x(*base, check=False).stderr
    assert before == x('sha256sum', '/etc/nginx/nginx.conf', '/etc/strata/standalone.env').stdout
    master = x('cat', '/run/nginx.pid').stdout.strip()
    children_path = f'/proc/{master}/task/{master}/children'
    children = x('cat', children_path).stdout
    assert children.strip()
    old_control = x('sha256sum', '/var/lib/strata/bundles/control').stdout
    x('install', '-o', 'root', '-g', 'strata', '-m', '0640', '/tmp/install/update.sbn',
      '/var/lib/strata/standalone/incoming.sbn')
    x('mv', '/var/lib/strata/standalone/incoming.sbn', '/var/lib/strata/standalone/source.sbn')
    until(lambda: x('sha256sum', '/var/lib/strata/bundles/control').stdout != old_control)
    until(lambda: status('/__standalone_update_fixture__') == '403')
    assert status('/?q=1%27%20OR%201%3D1--') == '403'
    assert x('cat', '/run/nginx.pid').stdout.strip() == master
    assert x('cat', children_path).stdout == children
    control = x('sha256sum', '/var/lib/strata/bundles/control').stdout
    # Tampered signature and unauthorized version rollback preserve current state.
    x('python3', '-c', "from pathlib import Path;p=Path('/tmp/install/update.sbn');b=bytearray(p.read_bytes());b[-1]^=1;Path('/tmp/install/bad').write_bytes(b)")
    for src in ['/tmp/install/bad', '/tmp/install/bundle.sbn']:
        x('install', '-o', 'root', '-g', 'strata', '-m', '0640', src,
          '/var/lib/strata/standalone/incoming.sbn')
        x('mv', '/var/lib/strata/standalone/incoming.sbn', '/var/lib/strata/standalone/source.sbn')
        time.sleep(2.5)
        assert x('sha256sum', '/var/lib/strata/bundles/control').stdout == control
        assert status('/?q=1%27%20OR%201%3D1--') == '403'
    raw = x('cat', '/var/log/strata/events.jsonl').stdout
    events = [json.loads(line) for line in raw.splitlines()]
    assert any(e.get('action') == 'ACTION_BLOCK' and e.get('block_id') for e in events), events
    assert any(e.get('bundle_version') == '2' and 199999 in e.get('rule_ids', []) for e in events)
    assert any(942100 in e.get('rule_ids', []) for e in events)
    # Reuse only this disposable node for failure cases after proving the fresh
    # one-command path. These resets are never applied to a shared lab node.
    x('systemctl', 'disable', '--now', 'nginx', 'strata-agent-standalone.service',
      'strata-agent-standalone.socket')
    x('python3', '-c', "from pathlib import Path;p=Path('/etc/nginx/nginx.conf');p.write_text(''.join(p.read_text().splitlines(True)[1:]))")
    x('rm', '/etc/nginx/conf.d/strata-standalone.conf', '/etc/strata/bundle.pub',
      '/var/lib/strata/bundles/control')
    original = x('sha256sum', '/etc/nginx/nginx.conf').stdout
    missing = x(*(base + ['--policy', 'missing']), check=False, timeout=180)
    assert missing.returncode != 0 and 'not found' in missing.stderr
    for fixture, message in [('tamper', 'signature does not verify'),
                             ('shadow', 'not full enforce'), ('canary', 'not full enforce'),
                             ('layout', 'native module rejected')]:
        rejected = x(*(base + ['--bundle', '/tmp/install/negative/' + fixture + '.sbn']),
                     check=False, timeout=180)
        assert rejected.returncode != 0 and message in rejected.stderr, rejected
        assert 'ready on' not in rejected.stdout
        assert not active('strata-agent-standalone.service') and not active('nginx')
        assert x('test', '-e', '/etc/nginx/conf.d/strata-standalone.conf', check=False).returncode != 0
        assert original == x('sha256sum', '/etc/nginx/nginx.conf').stdout
    # A valid bundle must not hide a missing conf.d include. Verify activation
    # failure restores the caller's config and disables the started pair.
    x('python3', '-c', "import re;from pathlib import Path;p=Path('/etc/nginx/nginx.conf');p.write_text(re.sub(r'include\\s+/etc/nginx/conf.d/\\*.conf;', '', p.read_text()))")
    original = x('sha256sum', '/etc/nginx/nginx.conf').stdout
    rejected = x(*base, check=False, timeout=180)
    assert rejected.returncode != 0 and 'does not include the managed route' in rejected.stderr, rejected
    assert original == x('sha256sum', '/etc/nginx/nginx.conf').stdout
    assert not active('strata-agent-standalone.service') and not active('strata-agent-standalone.socket')
    assert not active('nginx')
    assert x('test', '-e', '/etc/nginx/conf.d/strata-standalone.conf', check=False).returncode != 0
    print(json.dumps({'image': a.image, 'cpuset': a.cpuset, 'install_seconds': round(install_seconds, 3),
                      'total_seconds': round(time.monotonic() - started, 3),
                      'events': len(events), 'rpm_nginx_repo_only': a.rpm_nginx_repo_only, 'core_sha256': hashlib.sha256(a.bundle.read_bytes()).hexdigest(),
                      'result': 'PASS: fresh packages, hostile args, Fleet refusal, SQLi, update, stable workers, tamper/rollback, signed policy/layout refusal, config recovery'}, indent=2))
finally:
    print(x('journalctl', '-u', 'strata-agent-standalone', '--no-pager', '-n', '25', check=False).stdout)
    run(['docker', 'rm', '-f', container], check=False)

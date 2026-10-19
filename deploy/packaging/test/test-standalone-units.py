#!/usr/bin/env python3
"""Real systemd install/upgrade/remove lab, with no network or control plane."""
import argparse
import hashlib
import json
import subprocess
import time
import uuid
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--image', required=True)
parser.add_argument('--format', choices=['deb', 'rpm'], required=True)
for name in ['old', 'new', 'bundle', 'key']:
    parser.add_argument('--' + name, type=Path, required=True)
args = parser.parse_args()
for name in ['old', 'new', 'bundle', 'key']:
    assert getattr(args, name).is_file(), name


def run(argv, *, text=None, check=True):
    return subprocess.run(argv, input=text, text=True, capture_output=True,
                          timeout=60, check=check)


name = 'strata-standalone-units-' + uuid.uuid4().hex[:10]
container = run(['docker', 'run', '-d', '--name', name, '--label',
                 'strata.review=standalone-units', '--network', 'none',
                 '--privileged', '--cgroupns=private', '--cpuset-cpus=6-9',
                 '--tmpfs', '/run', '--tmpfs', '/run/lock', args.image]).stdout.strip()


def x(*argv, text=None, check=True):
    return run(['docker', 'exec', '-i', container, *argv], text=text, check=check)


def active(unit):
    return x('systemctl', 'is-active', '-q', unit, check=False).returncode == 0


def until(test):
    end = time.monotonic() + 30
    while time.monotonic() < end:
        if test():
            return
        time.sleep(.2)
    raise AssertionError('condition did not become true within 30 seconds')


def pid():
    return x('systemctl', 'show', '-p', 'MainPID', '--value',
             'strata-agent-standalone.service').stdout.strip()


def packet_program(count, prefix, delay=0):
    return f'''import socket,time
s=socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM);s.settimeout(5)
s.connect('/run/strata/events.sock')
for i in range({count}):
 b=('{prefix}'+str(i)).encode();s.send(bytes([10,len(b)])+b);time.sleep({delay})
'''


def events():
    raw = x('cat', '/var/log/strata/events fixture.jsonl').stdout
    return [json.loads(line) for line in raw.splitlines()]


def install(which):
    if args.format == 'deb':
        x('dpkg', '-i', '/tmp/' + which)
    else:
        x('rpm', '-Uvh', '/tmp/' + which)


started = time.monotonic()
try:
    until(lambda: x('systemctl', 'is-system-running', check=False).stdout.strip()
          in ['running', 'degraded'])
    for attr, dst in [('old', '/tmp/old'), ('new', '/tmp/new'),
                      ('bundle', '/tmp/bundle'), ('key', '/tmp/key')]:
        run(['docker', 'cp', str(getattr(args, attr)), container + ':' + dst])
    install('old')
    assert not active('strata-agent.service')
    assert not active('strata-agent-standalone.service')
    x('systemd-analyze', 'verify', '/usr/lib/systemd/system/strata-agent-standalone.service',
      '/usr/lib/systemd/system/strata-agent-standalone.socket')
    x('sh', '-ec', '''install -d -o strata -g strata /var/lib/strata/standalone
install -o strata -g strata -m 0644 /tmp/bundle '/var/lib/strata/standalone/source fixture.sbn'
install -o root -g strata -m 0644 /tmp/key /etc/strata/bundle.pub
# Stale Fleet identity must not change the mode chosen by the operator.
echo fixture-enrolled-node > /var/lib/strata/identity/node-id
cat > /etc/strata/standalone.env''', text='''STRATA_BUNDLE_SOURCE="--bundle-file=/var/lib/strata/standalone/source fixture.sbn"
STRATA_EVENTS_JSONL="/var/log/strata/events fixture.jsonl"
STRATA_SYSLOG_ADDR=
STRATA_METRICS_ADDR=127.0.0.1:9469
STRATA_NODE_ID=example-api-standalone
''')
    env_hash = x('sha256sum', '/etc/strata/standalone.env').stdout
    x('systemctl', 'start', 'strata-agent.socket')
    x('systemctl', 'enable', '--now', 'strata-agent-standalone.service')
    until(lambda: active('strata-agent-standalone.service') and pid() != '0')
    until(lambda: x('test', '-s', '/var/lib/strata/bundles/control', check=False).returncode == 0)
    assert not active('strata-agent.socket') and not active('strata-agent.service')
    # Reproduce the source's aggregate-argument expansion with real systemd.
    x('sh', '-ec', 'cat > /run/systemd/system/strata-aggregate-probe.service', text='''[Service]
Type=oneshot
Environment="STRATA_STANDALONE_ARGS=--bundle-file=/tmp/bundle --bundle-pubkey=/tmp/key --events-jsonl=stdout"
ExecStart=/usr/bin/strata-agent run --standalone ${STRATA_STANDALONE_ARGS}
''')
    x('systemctl', 'daemon-reload')
    assert x('systemctl', 'start', 'strata-aggregate-probe.service', check=False).returncode != 0
    assert '--bundle-pubkey is required' in x('journalctl', '-u', 'strata-aggregate-probe.service',
                                            '--no-pager').stdout
    first_pid = pid()
    argv = x('cat', '/proc/' + first_pid + '/cmdline').stdout.split('\0')
    assert '--bundle-file=/var/lib/strata/standalone/source fixture.sbn' in argv
    assert '--events-jsonl=/var/log/strata/events fixture.jsonl' in argv
    inode = x('stat', '-c', '%i', '/run/strata/events.sock').stdout
    control = x('sha256sum', '/var/lib/strata/bundles/control').stdout
    x('python3', '-', text=packet_program(3, 'before-'))
    until(lambda: len(events()) == 3)
    sender = subprocess.Popen(['docker', 'exec', '-i', container, 'python3', '-'],
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              text=True)
    sender.stdin.write(packet_program(160, 'upgrade-', .025))
    sender.stdin.close()
    sender.stdin = None
    install('new')
    stdout, stderr = sender.communicate(timeout=30)
    assert sender.returncode == 0, (stdout, stderr)
    until(lambda: len(events()) == 163)
    assert pid() not in ['0', first_pid]
    assert inode == x('stat', '-c', '%i', '/run/strata/events.sock').stdout
    assert control == x('sha256sum', '/var/lib/strata/bundles/control').stdout
    assert env_hash == x('sha256sum', '/etc/strata/standalone.env').stdout
    assert not active('strata-agent.service') and not active('strata-agent.socket')
    # The socket queues and starts its own service, never the Fleet service.
    x('systemctl', 'stop', 'strata-agent-standalone.service')
    assert active('strata-agent-standalone.socket')
    x('python3', '-', text=packet_program(1, 'activation-'))
    until(lambda: active('strata-agent-standalone.service') and len(events()) == 164)
    rows = events()
    expected = {'before-' + str(i) for i in range(3)} | {'upgrade-' + str(i) for i in range(160)} | {'activation-0'}
    assert {row['block_id'] for row in rows} == expected
    assert all(row['node_id'] == 'example-api-standalone' for row in rows)
    assert inode == x('stat', '-c', '%i', '/run/strata/events.sock').stdout
    # The same unit accepts exactly one URL source argument too.
    x('sh', '-ec', 'python3 -m http.server 18080 --bind 127.0.0.1 --directory /tmp '
      '>/tmp/source-http.log 2>&1 &')
    until(lambda: x('python3', '-c', "import urllib.request; urllib.request.urlopen('http://127.0.0.1:18080/bundle', timeout=1).read()", check=False).returncode == 0)
    x('sh', '-ec', "sed -i 's|^STRATA_BUNDLE_SOURCE=.*|STRATA_BUNDLE_SOURCE=--bundle-url=http://127.0.0.1:18080/bundle|' /etc/strata/standalone.env")
    x('systemctl', 'restart', 'strata-agent-standalone.service')
    until(lambda: active('strata-agent-standalone.service') and pid() != '0')
    until(lambda: int(x('grep', '-c', 'GET /bundle', '/tmp/source-http.log').stdout.strip()) >= 2)
    x('python3', '-', text=packet_program(1, 'url-'))
    until(lambda: len(events()) == 165)
    rows = events()
    assert {row['block_id'] for row in rows} == expected | {'url-0'}
    assert all(row['node_id'] == 'example-api-standalone' for row in rows)
    assert '--bundle-url=http://127.0.0.1:18080/bundle' in x('cat', '/proc/' + pid() + '/cmdline').stdout.split('\0')
    assert control == x('sha256sum', '/var/lib/strata/bundles/control').stdout
    # Verify Fleet upgrade selection too, using a local sleep stub, no CP.
    x('systemctl', 'disable', '--now', 'strata-agent-standalone.service',
      'strata-agent-standalone.socket')
    x('sh', '-ec', 'mkdir -p /run/systemd/system/strata-agent.service.d; '
      'cat > /run/systemd/system/strata-agent.service.d/probe.conf', text='''[Service]
ExecStart=
ExecStart=/usr/bin/sleep infinity
''')
    x('systemctl', 'daemon-reload')
    x('systemctl', 'enable', '--now', 'strata-agent.service')
    fleet_pid = x('systemctl', 'show', '-p', 'MainPID', '--value', 'strata-agent.service').stdout
    fleet_inode = x('stat', '-c', '%i', '/run/strata/events.sock').stdout
    if args.format == 'deb':
        install('new')
    else:
        x('rpm', '-Uvh', '--replacepkgs', '/tmp/new')
    assert active('strata-agent.service') and active('strata-agent.socket')
    assert x('systemctl', 'show', '-p', 'MainPID', '--value', 'strata-agent.service').stdout != fleet_pid
    assert x('stat', '-c', '%i', '/run/strata/events.sock').stdout == fleet_inode
    assert not active('strata-agent-standalone.service') and not active('strata-agent-standalone.socket')
    if args.format == 'deb':
        x('dpkg', '-r', 'strata-agent')
    else:
        x('rpm', '-e', 'strata-agent')
    assert not active('strata-agent-standalone.service') and not active('strata-agent-standalone.socket')
    x('test', '-s', '/var/log/strata/events fixture.jsonl')
    print(json.dumps({'result': 'PASS', 'image': args.image, 'format': args.format,
                      'events': len(rows), 'socket_inode_preserved': True,
                      'control_unchanged': True, 'mode_preserved': True,
                      'environment_preserved': True, 'socket_activation': True,
                      'aggregate_argument_rejected': True, 'fleet_hook_selection_with_stub': True,
                      'loopback_url_source': True,
                      'elapsed_seconds': round(time.monotonic() - started, 3),
                      'old_sha256': hashlib.sha256(args.old.read_bytes()).hexdigest(),
                      'new_sha256': hashlib.sha256(args.new.read_bytes()).hexdigest()}))
except Exception:
    print(x('journalctl', '-u', 'strata-agent-standalone.service', '--no-pager', '-n', '40', check=False).stdout)
    raise
finally:
    run(['docker', 'rm', '-f', container])

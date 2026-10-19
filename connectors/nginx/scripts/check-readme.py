#!/usr/bin/env python3
"""Check the README example against a real NGINX/module and signed test bundle."""
import argparse
import hashlib
import re
import subprocess
import tempfile
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--version', required=True)
parser.add_argument('--bin-dir', type=Path, required=True)
args = parser.parse_args()
root = Path(__file__).resolve().parents[3]
if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', args.version):
    parser.error('expected numeric NGINX version')
nginx = root / f'build/nginx-{args.version}/objs/nginx'
module = nginx.parent / 'ngx_http_strata_module.so'
fixtures = root / 'connectors/nginx/t/fixtures'
bins = args.bin_dir.resolve()
readme = (root / 'connectors/nginx/README.md').read_text()
example, = re.findall(r'```nginx\n(.*?)```', readme, re.S)


def command(argv):
    result = subprocess.run([str(a) for a in argv], capture_output=True,
                            text=True, timeout=30, check=False)
    if result.returncode:
        raise RuntimeError(result.stderr)


with tempfile.TemporaryDirectory(prefix='readme-config-', dir=root / 'build') as tmp:
    work = Path(tmp)
    bundle = work / 'bundle'
    bundle.mkdir()
    command([bins / 'strata-compile', '--rules',
             root / 'engine/compiler/examples/rules.yaml', '--policies',
             fixtures / 'policies.yaml', '--key', fixtures / 'test.key',
             '--version', '1', '--out', bundle / 'bundle-1.sbn'])
    command([bins / 'mkbundle', 'control', '--out', work / 'control',
             '--generation', '2', '--version', '1', '--name', 'bundle-1.sbn',
             '--bundle', bundle / 'bundle-1.sbn'])
    config = example.replace('/usr/lib/nginx/modules/ngx_http_strata_module.so',
                             str(module))
    config = config.replace('/var/lib/strata/bundle', str(bundle))
    config = config.replace('/etc/strata/bundle.pub', str(fixtures / 'bundle.pub'))
    config = config.replace('/run/strata/', str(work) + '/')
    (work / 'block.html').write_text('<p>{{block_id}} {{time}} {{support_contact}}</p>')
    (work / 'large.html').write_bytes(b'x' * 65537)
    extra = (f'strata_bundle_check 1s; strata_node_id example-api; '
             f'strata_identity $remote_user; strata_block_page {work}/block.html;')
    cases = [('README signed example', config, True, ''),
             ('remaining directives', config.replace('access_log off;',
                                                     'access_log off; ' + extra), True, ''),
             ('two trusted raw keys', config.replace(str(fixtures / 'bundle.pub'),
                                                     str(fixtures / 'rotation.pub')), True, ''),
             ('invalid mode', config.replace('strata_mode shadow;',
                                             'strata_mode enforce;'), False, 'invalid value'),
             ('invalid body mode', config.replace('body_mode buffer;',
                                                  'body_mode by_policy;'), False, 'invalid value'),
             ('invalid breaker action', config.replace('breaker_action degrade;',
                                                       'breaker_action bypass;'), False, 'invalid value'),
             ('invalid old breaker syntax', config.replace('2% 10s 200 open=30s',
                                                           'engine 0.05 10s 30s'), False,
              'invalid strata_breaker_threshold'),
             ('plain event socket', config.replace('unix:' + str(work), str(work)),
              False, 'expected unix:<path>'),
             ('oversize page', config.replace('access_log off;',
                 f'access_log off; strata_block_page {work}/large.html;'), False, '65536'),
             ('missing trusted key', config.replace(
                 f'strata_bundle_pubkey {fixtures}/bundle.pub;', ''), False, 'is required'),
             ('stream/enforce conflict', config.replace('body_mode buffer;',
                                                       'body_mode stream;'), False,
              'which only runs in shadow')]
    for name, text, accepted, diagnostic in cases:
        path = work / 'nginx.conf'
        path.write_text(text)
        result = subprocess.run([str(nginx), '-t', '-p', str(work) + '/', '-c', str(path)],
                                capture_output=True, text=True, timeout=15, check=False)
        if (result.returncode == 0) != accepted or diagnostic not in result.stderr:
            raise AssertionError(f'{name}: exit={result.returncode}\n{result.stderr}')
        print(f'PASS: {name}')
    for binary in (nginx, module):
        print(f'SHA256 {binary.name}: {hashlib.sha256(binary.read_bytes()).hexdigest()}')
    print(f'NGINX {args.version}: {len(cases)} configuration cases PASS')

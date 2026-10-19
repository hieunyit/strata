#!/usr/bin/env python3
"""Lab fixtures only: public repository test key; Python stdlib + OpenSSL.

Set STRATA_COMPILE/STRATA_EVAL to matching real compiler/eval executables.
"""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

ap = argparse.ArgumentParser(description=__doc__)
ap.add_argument('--repo', type=Path, required=True)
ap.add_argument('--rules-tool', type=Path, required=True)
ap.add_argument('--out', type=Path, required=True)
a = ap.parse_args()
root, out, tool = a.repo.resolve(), a.out.resolve(), a.rules_tool.resolve()
out.mkdir(parents=True, exist_ok=False)
key = root / 'connectors/nginx/t/fixtures/test.key'


def release(n, rules):
    dest = out / f'core-{n}'
    subprocess.run([str(tool), 'release', '--repo', str(root), '--rules', str(rules),
                    '--version', f'lab-standalone-{n}', '--bundle-version', str(n),
                    '--key', str(key), '--out', str(dest), '--pack', 'core',
                    '--policies', str(root / 'engine/compiler/examples/policies.yaml')], check=True)
    subprocess.run([str(tool), 'verify', '--pub', str(root / 'connectors/nginx/t/fixtures/bundle.pub'),
                    str(dest)], check=True)
    manifest = json.loads((dest / 'manifest.json').read_text())
    return (dest / manifest['bundle']).read_bytes()


first = release(1, root / 'rules')
with tempfile.TemporaryDirectory(prefix='standalone-fixtures-', dir=out) as tmp:
    work = Path(tmp)
    rules = work / 'rules'
    shutil.copytree(root / 'rules', rules)
    (rules / 'update-fixture.yaml').write_text('''rule:
  id: 199999
  name: Standalone update fixture
  layer: protocol
  stage: request_headers
  action_mode: block_alone
  match:
    all:
    - targets: [{var: uri_raw}]
      operator: {type: contains, value: /__standalone_update_fixture__}
  score: 100
  severity: critical
  metadata: {source: organization, license: Apache-2.0, author: test-fixture}
''')
    release(2, rules)
    invalid = out / 'invalid'
    invalid.mkdir()
    # PKCS#8 structure + the existing public TEST seed, not a deployment key.
    der = work / 'public-test-key.der'
    der.write_bytes(bytes.fromhex('302e020100300506032b657004220420') + key.read_bytes()[:32])
    der.chmod(0o600)
    body = work / 'signing-input'
    for name, offset, value in [('shadow', 120, 0), ('canary', 123, 1), ('layout', 121, 2)]:
        data = bytearray(first[:-64])
        data[offset] = value
        body.write_bytes(data)
        sig = subprocess.check_output(['openssl', 'pkeyutl', '-sign', '-rawin',
                                       '-keyform', 'DER', '-inkey', str(der), '-in', str(body)])
        assert len(sig) == 64
        (invalid / f'{name}.sbn').write_bytes(data + sig)
    data = bytearray(first)
    data[-1] ^= 1
    (invalid / 'tamper.sbn').write_bytes(data)
print(f'Prepared {out}: core 1/2 and signed invalid policy/layout fixtures (TEST KEY ONLY)')

#!/usr/bin/env python3
"""ASan NGINX/SQLite assertions for signed policy exception artifacts."""
import argparse
import hashlib
import json
import os
from pathlib import Path
from urllib.parse import quote

import header_probe as probe


def run():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fixture-dir', default='build/m2-runtime-http-fixture')
    parser.add_argument('--out-dir', default='build/m2-runtime-http/probe')
    parser.add_argument('--expected', choices=['exempt', 'enforced'], default='exempt')
    args = parser.parse_args()
    sql = "-1 UNION SELECT '" + probe.MARKER + "'--"
    probe.cases = lambda: [
        {'id': 'selected-header', 'uri': '/header-sql',
         'headers': {'X-Example-Filter': sql}, 'malicious': True, 'oracle': True},
        {'id': 'other-field-still-blocked', 'uri': '/header-sql?id=' + quote(sql),
         'headers': {'X-Example-Filter': sql}, 'malicious': True, 'oracle': True},
        {'id': 'benign', 'uri': '/header-sql',
         'headers': {'X-Example-Filter': '1'}, 'malicious': False},
    ]
    out = Path(args.out_dir).resolve()
    out.mkdir(parents=True, exist_ok=True)
    os.environ['ASAN_OPTIONS'] = ('detect_leaks=0:detect_odr_violation=0:abort_on_error=1:log_path='
                                  + str(out / 'asan'))
    os.environ['UBSAN_OPTIONS'] = 'print_stacktrace=1:halt_on_error=1:log_path=' + str(out / 'ubsan')
    fixture = Path(args.fixture_dir)
    probe.run(argparse.Namespace(
        nginx='build/nginx-1.30.5-asan/objs/nginx',
        module='build/nginx-1.30.5-asan/objs/ngx_http_strata_module.so',
        mkbundle='target/release/mkbundle', bundle=str(fixture / 'bundle.sbn'),
        pubkey=str(fixture / 'bundle.pub'), out=str(out), policy='example-api',
        rounds=1, http_check_command=[]))
    rows = [json.loads(line) for line in (out / 'requests.jsonl').read_text().splitlines()]
    first = 'backend_sql_oracle_reached' if args.expected == 'exempt' else 'signature_block'
    assert [row['classification'] for row in rows] == [first, 'signature_block', 'benign_pass'], rows
    for row in rows:
        if row['classification'] == 'signature_block':
            assert row['proxy']['rules'] == '700011', row
    assert not list(out.glob('asan.*')) and not list(out.glob('ubsan.*'))
    metadata = json.loads((out / 'metadata.json').read_text())
    metadata['exception_probe_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    metadata['scope'] = 'explicit_header_exception_and_other_field_enforcement'
    metadata['expected'] = args.expected
    (out / 'metadata.json').write_text(json.dumps(metadata, indent=2) + '\n')
    print('exception HTTP assertions PASS; expected=' + args.expected + '; no sanitizer reports')


if __name__ == '__main__':
    run()

#!/usr/bin/env python3
"""Signed staging through real ASan/UBSan NGINX; no automatic-writer/SLA claim."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
from urllib.parse import quote

import header_probe as probe


def run():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out-dir', required=True, help='new, private output directory')
    parser.add_argument('--nginx-version', choices=['1.30.5', '1.31.6'], required=True)
    args = parser.parse_args()
    out = Path(args.out_dir).resolve()
    out.mkdir(parents=True, exist_ok=False)
    fixture = out / 'fixture'
    fixture.mkdir()
    compiler = Path('target/release/strata-compile').resolve()
    mkbundle = Path('target/release/mkbundle').resolve()
    key, pub = fixture / 'example.key', fixture / 'bundle.pub'
    subprocess.run([str(mkbundle), 'keygen', '--seed', '07' * 32,
                    '--key-out', str(key), '--pub-out', str(pub)], check=True, timeout=10)
    key.chmod(0o600)  # known test seed, never a production key
    rules = []
    for rule_id, field, operator in [(700011, 'id', 'detect_sqli'), (700012, 'x', 'detect_xss')]:
        rules.append({'id': rule_id, 'name': 'example ' + operator, 'layer': 'managed',
                      'stage': 'request_headers', 'score': 100, 'severity': 'critical',
                      'match': {'all': [{'targets': [{'var': 'args', 'key': field}],
                                         'operator': {'type': operator}}]},
                      'metadata': {'source': 'organization', 'license': 'Apache-2.0'}})
    rule_file, policy_file, bundle = fixture / 'rules.json', fixture / 'policies.json', fixture / 'bundle.sbn'
    rule_file.write_text(json.dumps({'ir_version': 1, 'ruleset': {'name': 'example', 'version': '1'}, 'rules': rules}))
    policy_file.write_text(json.dumps({'policies': [
        {'name': 'example-api', 'mode': 'enforce', 'staged_rules': [700011]},
        {'name': 'example-web', 'mode': 'enforce'}]}))
    subprocess.run([str(compiler), '--rules', str(rule_file), '--policies', str(policy_file),
                    '--key', str(key), '--version', '1', '--created-at', '1760000000000',
                    '--out', str(bundle)], check=True, timeout=60)
    key.unlink()  # no signing key needed by the running proxy
    sql = '-1 UNION SELECT \'' + probe.MARKER + "'--"
    sql_uri = '/query-sql?id=' + quote(sql)
    xss = quote('<script>alert(1)</script>')
    cases = [
        {'id': 'selected-sqli', 'uri': sql_uri, 'headers': {}, 'malicious': True, 'oracle': True},
        {'id': 'healthy-xss', 'uri': '/query-sql?id=1&x=' + xss, 'headers': {}, 'malicious': True},
        {'id': 'both', 'uri': sql_uri + '&x=' + xss, 'headers': {}, 'malicious': True, 'oracle': True},
        {'id': 'clean', 'uri': '/query-sql?id=1', 'headers': {}, 'malicious': False},
    ]
    probe.cases = lambda: cases
    for policy in ['example-api', 'example-web']:
        result_dir = out / policy
        result_dir.mkdir()
        os.environ['ASAN_OPTIONS'] = 'detect_leaks=0:detect_odr_violation=0:abort_on_error=1:log_path=' + str(result_dir / 'asan')
        os.environ['UBSAN_OPTIONS'] = 'print_stacktrace=1:halt_on_error=1:log_path=' + str(result_dir / 'ubsan')
        probe.run(argparse.Namespace(
            nginx=f'build/nginx-{args.nginx_version}-asan/objs/nginx',
            module=f'build/nginx-{args.nginx_version}-asan/objs/ngx_http_strata_module.so',
            mkbundle=str(mkbundle), bundle=str(bundle), pubkey=str(pub),
            out=str(result_dir), policy=policy, rounds=1, http_check_command=[]))
        rows = [json.loads(line) for line in (result_dir / 'requests.jsonl').read_text().splitlines()]
        expected = [200, 403, 403, 200] if policy == 'example-api' else [403, 403, 403, 200]
        assert [r['baseline']['status'] for r in rows] == [200] * 4, rows
        assert [r['proxy']['status'] for r in rows] == expected, rows
        assert rows[0]['proxy']['oracle'] == (policy == 'example-api'), rows[0]
        actions = ['log', 'block', 'block', 'allow'] if policy == 'example-api' else ['block', 'block', 'block', 'allow']
        assert [r['proxy']['action'] for r in rows] == actions, rows
        assert rows[0]['proxy']['event_id'].startswith('EVT-' if policy == 'example-api' else 'STR-'), rows[0]
        for index in [1, 2]:
            ids = str(rows[index]['proxy']['rules']).replace(',', ' ').split()
            assert '700012' in ids and rows[index]['proxy']['event_id'].startswith('STR-'), rows[index]
        assert not list(result_dir.glob('asan.*')) and not list(result_dir.glob('ubsan.*'))
        metadata = json.loads((result_dir / 'metadata.json').read_text())
        metadata.update(staging_probe_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                        compiler_sha256=hashlib.sha256(compiler.read_bytes()).hexdigest(),
                        scope='synthetic_staging_policy_isolation_and_healthy_rule_enforcement',
                        not_proven=['automatic writer', 'five-minute SLA', 'Fleet/event delivery', 'browser XSS', 'accuracy corpus'])
        (result_dir / 'metadata.json').write_text(json.dumps(metadata, indent=2) + '\n')
    print('PASS: 8 paired cases / 16 HTTP attempts; correct policy/log/block IDs; no sanitizer reports')


if __name__ == '__main__':
    run()

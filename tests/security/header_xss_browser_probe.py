#!/usr/bin/env python3
"""Private Header XSS oracle: actual browser, explicit downstream transforms.

No rule changes or production-context claim. Uses the pinned candidate artifact.
"""
import argparse
import base64
import hashlib
import html
import json
import os
from pathlib import Path
import re
from urllib.parse import parse_qs, quote, unquote_plus, urlsplit

import header_probe as probe


class Reflector(probe.BaseHTTPRequestHandler):
    def do_GET(self):
        query = parse_qs(urlsplit(self.path).query)
        encoder = {'0': 'URL', '1': 'Base64Flat'}.get(query.get('e', ['0'])[0])
        context = {'0': 'raw', '1': 'strip', '2': 'escaped'}.get(query.get('c', ['0'])[0])
        value = self.headers.get('X-Example-Text', '')
        if len(self.path) > 1024 or len(value) > 8192:
            self.send_error(413)
            return
        try:
            if encoder == 'URL':
                value = unquote_plus(value)
            elif encoder == 'Base64Flat':
                value = base64.b64decode(value, validate=True).decode('utf-8')
            else:
                raise ValueError('unknown encoder')
            if context in ('strip', 'escaped'):
                value = re.sub(r'<[^>]*>', '', value)
            elif context != 'raw':
                raise ValueError('unknown context')
            if context == 'escaped':
                value = html.escape(value, quote=True)
        except (ValueError, UnicodeError):
            self.send_error(400)
            return
        # Deliberately vulnerable local fixture. The prelude records real handler
        # calls without modal dialogs; focus is dispatched by the real browser.
        body = ('<!doctype html><meta charset="utf-8"><title>example reflector</title>'
                '<script>window.__h7alerts=[];window.alert=(value)=>window.__h7alerts.push(String(value));</script>'
                '<label>Example <input id="probe" value="' + value + '"></label>').encode()
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('X-Example-Origin', f'http://127.0.0.1:{self.server.server_port}')
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def run():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out-dir', required=True)
    parser.add_argument('--network-container', required=True)
    parser.add_argument('--host-repo', required=True)
    parser.add_argument('--variant', choices=('release', 'asan'), required=True)
    args = parser.parse_args()
    out = Path(args.out_dir).resolve()
    if Path.cwd().resolve() not in out.parents or 'build' not in out.parts:
        raise ValueError('private repo build directory required')
    out.mkdir(parents=True, exist_ok=False)
    bundle = Path('build/h7-browser-input/candidate.sbn')
    expected = 'b9e6fafc4c5b7f4f401f6bac335a42d7cc565dbf48a544337b98dbb3e3fa1d0a'
    if hashlib.sha256(bundle.read_bytes()).hexdigest() != expected:
        raise ValueError('candidate artifact differs from the archived H7 measurement')
    report = json.loads(Path('docs/reports/h7-header-coverage/gotestwaf.json').read_text())
    payloads = {row['payload'] for row in report['bypassed']}
    if len(payloads) != 1 or {row['encoder'] for row in report['bypassed']} != {'URL', 'Base64Flat'}:
        raise ValueError('expected one shared payload for the two encoder cases')
    payload = payloads.pop()
    cases = [
        {'id': 'benign', 'uri': '/reflect', 'headers': {'X-Example-Text': 'ordinary header'}, 'malicious': False},
        {'id': 'positive-control', 'uri': '/reflect', 'headers': {'X-Example-Text': quote('" autofocus onfocus=alert(1)//')}, 'malicious': True},
        {'id': 'URL-obfuscated', 'uri': '/reflect', 'headers': {'X-Example-Text': quote(payload)}, 'malicious': True},
        {'id': 'Base64-obfuscated', 'uri': '/reflect?e=1', 'headers': {'X-Example-Text': base64.b64encode(payload.encode()).decode()}, 'malicious': True},
    ]
    probe.Oracle = Reflector
    probe.cases = lambda: cases
    os.environ['ASAN_OPTIONS'] = 'detect_leaks=0:detect_odr_violation=0:abort_on_error=1:log_path=' + str(out / 'asan')
    os.environ['UBSAN_OPTIONS'] = 'print_stacktrace=1:halt_on_error=1:log_path=' + str(out / 'ubsan')
    try:
        probe.run(argparse.Namespace(
        out=str(out), nginx=f'build/nginx-1.30.5-{args.variant}/objs/nginx', module=f'build/nginx-1.30.5-{args.variant}/objs/ngx_http_strata_module.so',
        mkbundle='target/release/mkbundle', bundle=str(bundle), pubkey='connectors/nginx/t/fixtures/bundle.pub', policy='example-api', rounds=1,
        http_check_command=['docker', 'run', '--rm', '--pull', 'never', '--network', 'container:' + args.network_container,
                            '--cpuset-cpus=11-12', '-u', f'{os.getuid()}:{os.getgid()}', '-v', args.host_repo + ':/src', '-w', '/src',
                            'mcr.microsoft.com/playwright:v1.64.0-noble', 'node', 'tests/security/header_xss_browser_probe.mjs', '--proxy', '{url}', '--out', str(out)]))
    finally:
        metadata = json.loads((out / 'metadata.json').read_text()) if (out / 'metadata.json').exists() else {}
        metadata.update(variant=args.variant, scope='actual paired Header browser contexts; explicit synthetic tag stripping; no production-context claim',
                        wrapper_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                        browser_script_sha256=hashlib.sha256(Path('tests/security/header_xss_browser_probe.mjs').read_bytes()).hexdigest(),
                        not_tested=['real application sanitizer/CSP', 'production accuracy', 'performance SLO', 'rule release approval'])
        (out / 'metadata.json').write_text(json.dumps(metadata, indent=2) + '\n')
    rows = [json.loads(line) for line in (out / 'requests.jsonl').read_text().splitlines()]
    if [r['proxy']['action'] for r in rows] != ['allow', 'block', 'allow', 'allow']:
        raise RuntimeError('unexpected WAF actions; inspect raw records')
    if list(out.glob('asan.*')) or list(out.glob('ubsan.*')):
        raise RuntimeError('sanitizer report present')
    print('PASS: paired WAF/Chromium oracle; only explicit strip-tag application contexts execute the obfuscated cases')


if __name__ == '__main__':
    run()

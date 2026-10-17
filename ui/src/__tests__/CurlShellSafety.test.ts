import { execFileSync } from 'node:child_process';
import { describe, expect, it } from 'vitest';
import type { Event } from '../api/client';
import { buildCurlFromEvent } from '../lib/curl';

const base: Event = {
  block_id: 'STR-TEST-0000-0000-0000', timestamp: '2026-10-17T00:00:00Z',
  node_id: 'example-node', connector_type: 'nginx', policy_id: 'example-api',
  policy_version: 1, http_method: 'GET', http_host: 'api.example.test',
  http_path: '/probe', client_ip: '192.0.2.1', status_code: 403, action: 'block',
  score_protocol: 0, score_sqli: 0, score_xss: 0, score_anomaly: 100,
};

// No real curl/network or filesystem side effects: capture the argument vector
// with a shell function. ID is a harmless canary for command substitution.
function shellArguments(event: Event): string[] {
  const script = `curl() { printf '%s\\0' "$@"; }\nID() { printf CURL_CANARY; }\n${buildCurlFromEvent(event)}`;
  return execFileSync('/bin/sh', ['-c', script], { timeout: 1000 }).toString().split('\0').slice(0, -1);
}

describe('cURL event data stays literal through a POSIX shell', () => {
  const cases: { name: string; event: Partial<Event>; argument: string }[] = [
    { name: 'method', event: { http_method: 'GET`ID`' }, argument: 'GET`ID`' },
    { name: 'host', event: { http_host: "api.'`ID`'.test" }, argument: "Host: api.'`ID`'.test" },
    { name: 'path', event: { http_path: "/'`ID`'" }, argument: "https://api.example.test/'`ID`'" },
    { name: 'header name', event: { headers: [{ name: "X-'`ID`'", value: 'trace' }] }, argument: "X-'`ID`': trace" },
    { name: 'client IP', event: { client_ip: "192.0.2.'`ID`'" }, argument: "X-Forwarded-For: 192.0.2.'`ID`'" },
    { name: 'header value', event: { headers: [{ name: 'X-Trace', value: "x'`ID`'" }] }, argument: "X-Trace: x'`ID`'" },
  ];
  it.each(cases)('quotes $name as one literal argument', ({ event, argument }) => {
    const args = shellArguments({ ...base, ...event });
    expect(args.join('\0')).not.toContain('CURL_CANARY');
    expect(args).toContain(argument);
  });
  it('omits invalid header names so curl cannot interpret a header as a file', () => {
    const args = shellArguments({ ...base, headers: [{ name: '@/example-file', value: 'x' }] });
    expect(args).not.toContain('@/example-file: x');
    expect(args.filter((v) => v === '-H')).toHaveLength(2); // Host and client IP
  });
});

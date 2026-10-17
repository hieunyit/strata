import { describe, it, expect } from 'vitest';
import { buildCurlFromEvent } from '../lib/curl';
import { Event } from '../api/client';

describe('buildCurlFromEvent', () => {
  it('generates a simple GET curl command', () => {
    const event: Event = {
      block_id: 'blk-1',
      timestamp: '2026-10-16T12:00:00Z',
      node_id: 'node-1',
      connector_type: 'nginx',
      policy_id: 'example-api',
      policy_version: 1,
      client_ip: '192.0.2.1',
      http_method: 'GET',
      http_host: 'api.example.com',
      http_path: '/v1/users',
      status_code: 200,
      action: 'pass',
      user_agent: 'curl/8.0.1',
      referer: '',
      score_anomaly: 5,
      score_protocol: 0,
      score_sqli: 5,
      score_xss: 0,
    };

    const cmd = buildCurlFromEvent(event);
    expect(cmd).toContain("curl -i -X 'GET' 'https://api.example.com/v1/users'");
    expect(cmd).toContain("-H 'Host: api.example.com'");
    expect(cmd).toContain("-H 'User-Agent: curl/8.0.1'");
    expect(cmd).toContain("-H 'X-Forwarded-For: 192.0.2.1'");
  });

  it('escapes single quotes correctly for shell safety', () => {
    const event: Event = {
      block_id: 'blk-2',
      timestamp: '2026-10-16T12:00:00Z',
      node_id: 'node-1',
      connector_type: 'nginx',
      policy_id: 'example-api',
      policy_version: 1,
      client_ip: '198.51.100.2',
      http_method: 'POST',
      http_host: 'shop.example.test',
      http_path: "/search?q=' OR '1'='1",
      status_code: 403,
      action: 'block',
      user_agent: "Mozilla/5.0 (compatible; Hacker's Tool/1.0)",
      referer: "https://shop.example.test/referral'test",
      score_anomaly: 10,
      score_protocol: 0,
      score_sqli: 10,
      score_xss: 0,
      violations: [
        {
          rule_id: 942100,
          layer: 'sqli',
          field: 'body.payload',
          snippet: "username='admin'--",
        },
      ],
    };

    const cmd = buildCurlFromEvent(event);
    expect(cmd).toContain(String.raw`curl -i -X 'POST' 'https://shop.example.test/search?q='\'' OR '\''1'\''='\''1'`);
    expect(cmd).toContain("-H 'User-Agent: Mozilla/5.0 (compatible; Hacker'\\''s Tool/1.0)'");
    expect(cmd).toContain("-H 'Referer: https://shop.example.test/referral'\\''test'");
    expect(cmd).toContain("--data-raw 'username='\\''admin'\\''--'");
  });

  it('omits redacted or masked headers', () => {
    const event: Event = {
      block_id: 'blk-3',
      timestamp: '2026-10-16T12:00:00Z',
      node_id: 'node-1',
      connector_type: 'nginx',
      policy_id: 'example-api',
      policy_version: 1,
      client_ip: '***.***.***.***',
      http_method: 'GET',
      http_host: 'api.example.com',
      http_path: '/status',
      status_code: 200,
      action: 'shadow',
      user_agent: 'TestAgent',
      referer: '',
      score_anomaly: 0,
      score_protocol: 0,
      score_sqli: 0,
      score_xss: 0,
      headers: [
        { name: 'Authorization', value: '[REDACTED]' },
        { name: 'X-Api-Key', value: '[MASKED]' },
        { name: 'X-Custom-Trace', value: 'trace-123' },
      ],
    };

    const cmd = buildCurlFromEvent(event);
    expect(cmd).not.toContain('Authorization');
    expect(cmd).not.toContain('X-Api-Key');
    expect(cmd).toContain("-H 'X-Custom-Trace: trace-123'");
    expect(cmd).not.toContain('X-Forwarded-For');
  });
});

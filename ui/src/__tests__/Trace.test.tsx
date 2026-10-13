import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { StaticAuthProvider } from '../context/AuthContext';
import { EventTrace } from '../components/events/EventTrace';
import { Event } from '../api/client';
import { fieldLocation, markPath } from '../lib/trace';
import '../i18n';

describe('trace helpers (W09-F-01)', () => {
  it('names where a field points', () => {
    expect(fieldLocation('ARGS:id')).toEqual({ kind: 'arg', name: 'id' });
    expect(fieldLocation('ARGS_GET:q')).toEqual({ kind: 'arg', name: 'q' });
    expect(fieldLocation('query.q')).toEqual({ kind: 'arg', name: 'q' });
    expect(fieldLocation('body.password')).toEqual({ kind: 'arg', name: 'password' });
    expect(fieldLocation('REQUEST_BODY')).toEqual({ kind: 'body', name: '' });
    expect(fieldLocation('REQUEST_HEADERS:User-Agent')).toEqual({ kind: 'header', name: 'User-Agent' });
    expect(fieldLocation('REQUEST_COOKIES:sid')).toEqual({ kind: 'cookie', name: 'sid' });
    expect(fieldLocation('REQUEST_URI_RAW').kind).toBe('path');
    expect(fieldLocation('TX:anomaly').kind).toBe('other');
  });

  it('marks the violating argument of the path, and only it', () => {
    const segs = markPath('/search?page=2&q=%3Cscript%3E&sort=asc', ['ARGS:q']);
    expect(segs.filter((s) => s.mark).map((s) => s.text)).toEqual(['q=%3Cscript%3E']);
    expect(segs.map((s) => s.text).join('')).toBe('/search?page=2&q=%3Cscript%3E&sort=asc');
    // case-insensitive, encoded names
    expect(markPath('/a?User%20Name=x', ['ARGS:user name']).some((s) => s.mark)).toBe(true);
    // a path field marks the whole path; no field, nothing marked
    expect(markPath('/files/%2e%2e/etc', ['REQUEST_URI_RAW'])).toEqual([{ text: '/files/%2e%2e/etc', mark: true }]);
    expect(markPath('/a?x=1', ['REQUEST_HEADERS:Referer']).some((s) => s.mark)).toBe(false);
    expect(markPath('/a', ['ARGS:x']).some((s) => s.mark)).toBe(false);
  });
});

const event: Event = {
  block_id: 'STR-8F3K-Q2VD-7XNM-A1PC',
  timestamp: new Date().toISOString(),
  node_id: 'node-1',
  connector_type: 'nginx',
  policy_id: 'example-api',
  policy_version: 1,
  client_ip: '198.51.100.42',
  identity: '',
  request_id: '',
  http_method: 'GET',
  http_host: 'api.example.test',
  http_path: '/search?page=2&q=1%27%20OR%201=1',
  status_code: 403,
  action: 'block',
  score_protocol: 0,
  score_sqli: 100,
  score_xss: 0,
  score_anomaly: 105,
  matched_rules: [942100, 600001],
  violations: [
    { rule_id: 942100, layer: 'managed', field: 'ARGS:q', snippet: "1' OR 1=1" },
    { rule_id: 600001, layer: 'managed', field: 'REQUEST_HEADERS:User-Agent', snippet: 'sqlmap' },
  ],
  received_at: new Date().toISOString(),
};

const rules = {
  '942100': { name: 'SQL Injection Attack Detected via libinjection', source: 'owasp-crs', license: 'Apache-2.0' },
  '600001': { name: 'Suspicious scanner User-Agent', source: 'sigma', author: 'A. Author (Example Org)', license: 'DRL-1.1' },
};

describe('EventTrace decision trace (W09-F-01)', () => {
  it('marks the violating fields and shows the author of a Sigma rule only', () => {
    render(
      <StaticAuthProvider roles={['operator']}>
        <EventTrace event={event} rules={rules} />
      </StaticAuthProvider>,
    );
    expect(screen.getAllByTestId('field-highlight').map((e) => e.textContent)).toEqual([
      'ARGS:q',
      'REQUEST_HEADERS:User-Agent',
    ]);
    expect(screen.getAllByTestId('path-highlight').map((e) => e.textContent)).toEqual(['q=1%27%20OR%201=1']);
    const meta = screen.getAllByTestId('rule-meta');
    expect(meta[0].textContent).toContain('SQL Injection Attack Detected via libinjection');
    expect(meta[1].textContent).toContain('Suspicious scanner User-Agent');
    const authors = screen.getAllByTestId('rule-author');
    expect(authors).toHaveLength(1); // the CRS rule shows no author line
    expect(authors[0].textContent).toContain('A. Author (Example Org)');
  });

  it('without a catalog, shows the Rule IDs as before', () => {
    render(
      <StaticAuthProvider roles={['viewer']}>
        <EventTrace event={event} />
      </StaticAuthProvider>,
    );
    expect(screen.queryByTestId('rule-meta')).not.toBeInTheDocument();
    expect(screen.getAllByTestId('field-highlight')).toHaveLength(2);
    // the viewer still gets no snippet
    expect(screen.getAllByTestId('violation-snippet')[0].textContent).not.toContain("OR 1=1");
  });
});

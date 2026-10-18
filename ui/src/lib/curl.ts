import { Event } from '../api/client';

const shellQuote = (value: string) => `'${value.replace(/'/g, "'\\''")}'`;
const headerName = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;

/**
 * Builds an executable cURL command reproducing the HTTP request from a WAF event.
 * Properly escapes single quotes and shell characters for bash/zsh.
 */
export function buildCurlFromEvent(event: Event): string {
  const method = (event.http_method || 'GET').toUpperCase();
  const host = event.http_host || 'localhost';
  const path = event.http_path || '/';
  const proto = 'https';
  const url = `${proto}://${host}${path.startsWith('/') ? path : '/' + path}`;

  const lines: string[] = [`curl -i -X ${shellQuote(method)} ${shellQuote(url)}`];

  if (event.http_host) {
    lines.push(`  -H ${shellQuote(`Host: ${event.http_host}`)}`);
  }
  if (event.user_agent) {
    lines.push(`  -H ${shellQuote(`User-Agent: ${event.user_agent}`)}`);
  }
  if (event.referer) {
    lines.push(`  -H ${shellQuote(`Referer: ${event.referer}`)}`);
  }
  if (event.headers && Array.isArray(event.headers)) {
    for (const h of event.headers) {
      if (h.name && headerName.test(h.name) && h.value && h.value !== '[REDACTED]' && h.value !== '[MASKED]') {
        const lower = h.name.toLowerCase();
        if (lower !== 'host' && lower !== 'user-agent' && lower !== 'referer') {
          lines.push(`  -H ${shellQuote(`${h.name}: ${h.value}`)}`);
        }
      }
    }
  }
  if (event.client_ip && !event.client_ip.includes('*') && event.client_ip !== '[REDACTED]') {
    lines.push(`  -H ${shellQuote(`X-Forwarded-For: ${event.client_ip}`)}`);
  }

  const bodyViolation = (event.violations || []).find((v) => (v.field || '').startsWith('body'));
  if (bodyViolation && bodyViolation.snippet && bodyViolation.snippet !== '[REDACTED FOR VIEWER ROLE]') {
    lines.push(`  --data-raw ${shellQuote(bodyViolation.snippet)}`);
  }

  return lines.join(' \\\n');
}

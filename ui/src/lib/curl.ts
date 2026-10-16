import { Event } from '../api/client';

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

  const lines: string[] = [`curl -i -X ${method} '${url}'`];

  if (event.http_host) {
    lines.push(`  -H 'Host: ${event.http_host}'`);
  }
  if (event.user_agent) {
    const safeUa = event.user_agent.replace(/'/g, "'\\''");
    lines.push(`  -H 'User-Agent: ${safeUa}'`);
  }
  if (event.referer) {
    const safeRef = event.referer.replace(/'/g, "'\\''");
    lines.push(`  -H 'Referer: ${safeRef}'`);
  }
  if (event.headers && Array.isArray(event.headers)) {
    for (const h of event.headers) {
      if (h.name && h.value && h.value !== '[REDACTED]' && h.value !== '[MASKED]') {
        const lower = h.name.toLowerCase();
        if (lower !== 'host' && lower !== 'user-agent' && lower !== 'referer') {
          const safeVal = h.value.replace(/'/g, "'\\''");
          lines.push(`  -H '${h.name}: ${safeVal}'`);
        }
      }
    }
  }
  if (event.client_ip && !event.client_ip.includes('*') && event.client_ip !== '[REDACTED]') {
    lines.push(`  -H 'X-Forwarded-For: ${event.client_ip}'`);
  }

  const bodyViolation = (event.violations || []).find((v) => (v.field || '').startsWith('body'));
  if (bodyViolation && bodyViolation.snippet && bodyViolation.snippet !== '[REDACTED FOR VIEWER ROLE]') {
    const safeBody = bodyViolation.snippet.replace(/'/g, "'\\''");
    lines.push(`  --data-raw '${safeBody}'`);
  }

  return lines.join(' \\\n');
}

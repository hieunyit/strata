import { Event } from '../api/client';

/**
 * Sanitizes a string for safe inclusion inside single quotes in bash/zsh.
 * Also removes raw carriage returns and newlines to prevent terminal injection.
 */
function sanitizeShell(str: string): string {
  return str.replace(/[\r\n]/g, '').replace(/'/g, "'\\''");
}

/**
 * Builds an executable cURL command reproducing the HTTP request from a WAF event.
 * Properly escapes single quotes, validates HTTP methods, and sanitizes headers to prevent command injection.
 */
export function buildCurlFromEvent(event: Event): string {
  const rawMethod = (event.http_method || 'GET').toUpperCase().trim();
  const method = /^[A-Z]+$/.test(rawMethod) ? rawMethod : 'GET';

  const host = event.http_host || 'localhost';
  const path = event.http_path || '/';
  const safeHost = sanitizeShell(host);
  const safePath = sanitizeShell(path);
  const proto = 'https';
  const url = `${proto}://${safeHost}${safePath.startsWith('/') ? safePath : '/' + safePath}`;

  const lines: string[] = [`curl -i -X ${method} '${url}'`];

  if (event.http_host) {
    const safeHostHdr = sanitizeShell(event.http_host);
    lines.push(`  -H 'Host: ${safeHostHdr}'`);
  }
  if (event.user_agent) {
    const safeUa = sanitizeShell(event.user_agent);
    lines.push(`  -H 'User-Agent: ${safeUa}'`);
  }
  if (event.referer) {
    const safeRef = sanitizeShell(event.referer);
    lines.push(`  -H 'Referer: ${safeRef}'`);
  }
  if (event.headers && Array.isArray(event.headers)) {
    for (const h of event.headers) {
      if (h.name && h.value && h.value !== '[REDACTED]' && h.value !== '[MASKED]') {
        const safeHdrName = h.name.replace(/[^a-zA-Z0-9_-]/g, '');
        if (!safeHdrName) continue;

        const lower = safeHdrName.toLowerCase();
        if (lower !== 'host' && lower !== 'user-agent' && lower !== 'referer') {
          const safeVal = sanitizeShell(h.value);
          lines.push(`  -H '${safeHdrName}: ${safeVal}'`);
        }
      }
    }
  }
  if (event.client_ip && !event.client_ip.includes('*') && event.client_ip !== '[REDACTED]') {
    const safeIp = sanitizeShell(event.client_ip);
    lines.push(`  -H 'X-Forwarded-For: ${safeIp}'`);
  }

  const bodyViolation = (event.violations || []).find((v) => (v.field || '').startsWith('body'));
  if (bodyViolation && bodyViolation.snippet && bodyViolation.snippet !== '[REDACTED FOR VIEWER ROLE]') {
    const safeBody = bodyViolation.snippet.replace(/'/g, "'\\''");
    lines.push(`  --data-raw '${safeBody}'`);
  }

  return lines.join(' \\\n');
}


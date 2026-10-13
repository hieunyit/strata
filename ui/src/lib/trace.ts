// Decision trace helpers (W09-F-01): where in the request a violation's
// field points, and the request path split so that this place is marked.

export type FieldKind = 'arg' | 'header' | 'cookie' | 'path' | 'body' | 'other';

export interface FieldLocation {
  kind: FieldKind;
  /** argument, header or cookie name; empty for the path or the body */
  name: string;
}

/**
 * The location a violation field names. Fields come from libstrata as
 * VARIABLE:name (ARGS:id, REQUEST_HEADERS:User-Agent, REQUEST_COOKIES:sid,
 * REQUEST_URI, REQUEST_BODY...) or, in older events, as dotted names
 * (query.q, body.password, header.referer).
 */
export function fieldLocation(field: string): FieldLocation {
  const f = field.trim();
  const colon = f.indexOf(':');
  const dot = f.indexOf('.');
  const [variable, name] =
    colon > 0 ? [f.slice(0, colon), f.slice(colon + 1)] : dot > 0 ? [f.slice(0, dot), f.slice(dot + 1)] : [f, ''];
  const v = variable.toUpperCase();
  if (v.startsWith('ARGS') || v === 'QUERY' || v === 'QUERY_STRING') {
    return { kind: 'arg', name };
  }
  if (v === 'BODY' || v === 'REQUEST_BODY' || v === 'XML' || v.startsWith('FILES')) {
    // a named body field (body.password) is an argument of the body
    return name ? { kind: 'arg', name } : { kind: 'body', name: '' };
  }
  if (v.startsWith('REQUEST_HEADERS') || v === 'HEADER' || v === 'HEADERS') {
    return { kind: 'header', name };
  }
  if (v.startsWith('REQUEST_COOKIES') || v === 'COOKIE' || v === 'COOKIES') {
    return { kind: 'cookie', name };
  }
  if (['REQUEST_URI', 'REQUEST_URI_RAW', 'REQUEST_FILENAME', 'REQUEST_BASENAME', 'PATH', 'URI', 'REQUEST_LINE'].includes(v)) {
    return { kind: 'path', name: '' };
  }
  return { kind: 'other', name };
}

export interface Segment {
  text: string;
  mark: boolean;
}

/**
 * The request path (with its query) in segments: the part a violation of
 * one of fields points to is marked, the whole path for a path field, each
 * name=value of the query for an argument field.
 */
export function markPath(path: string, fields: string[]): Segment[] {
  const locs = fields.map(fieldLocation);
  if (locs.some((l) => l.kind === 'path')) {
    return [{ text: path, mark: true }];
  }
  const args = new Set(locs.filter((l) => l.kind === 'arg' && l.name).map((l) => l.name.toLowerCase()));
  const q = path.indexOf('?');
  if (q < 0 || args.size === 0) {
    return [{ text: path, mark: false }];
  }
  const out: Segment[] = [{ text: path.slice(0, q + 1), mark: false }];
  const pairs = path.slice(q + 1).split('&');
  pairs.forEach((pair, i) => {
    const raw = pair.split('=')[0];
    let name = raw;
    try {
      name = decodeURIComponent(raw.replace(/\+/g, ' '));
    } catch {
      // keep the raw name of a malformed escape
    }
    out.push({ text: pair, mark: args.has(name.toLowerCase()) });
    if (i < pairs.length - 1) out.push({ text: '&', mark: false });
  });
  return out;
}

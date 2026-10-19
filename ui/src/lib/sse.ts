// Server-sent events read with fetch: EventSource cannot send the
// Authorization header, and the control plane takes no token in the URL.

export interface SseEvent {
  event: string;
  data: string;
}

// SseParser takes chunks of the stream as they come and gives the complete
// events (an event ends with a blank line). Comment lines (":") and fields
// other than event/data/retry are skipped; "retry" sets retryMs.
export class SseParser {
  private buf = '';
  private event = '';
  private data: string[] = [];
  retryMs = 3000;

  push(chunk: string): SseEvent[] {
    this.buf += chunk;
    const out: SseEvent[] = [];
    let nl: number;
    while ((nl = this.buf.search(/\r\n|\r|\n/)) >= 0) {
      const line = this.buf.slice(0, nl);
      this.buf = this.buf.slice(nl + (this.buf.startsWith('\r\n', nl) ? 2 : 1));
      if (line === '') {
        if (this.data.length) out.push({ event: this.event || 'message', data: this.data.join('\n') });
        this.event = '';
        this.data = [];
        continue;
      }
      if (line.startsWith(':')) continue;
      const i = line.indexOf(':');
      const field = i < 0 ? line : line.slice(0, i);
      let value = i < 0 ? '' : line.slice(i + 1);
      if (value.startsWith(' ')) value = value.slice(1);
      if (field === 'event') this.event = value;
      else if (field === 'data') this.data.push(value);
      else if (field === 'retry' && /^\d+$/.test(value)) this.retryMs = Number(value);
    }
    return out;
  }
}

// toCsv renders headers + rows as CSV text. Values are quoted and embedded
// quotes doubled, so a comma or a quote in a field never breaks a column
// (W08-F-01).
//
// A text cell starting with = + - @ (or a tab or CR) is prefixed with a
// quote: spreadsheets would run it as a formula, and paths, hosts and user
// agents in events come from the attacker (OWASP "CSV Injection").
export function toCsv(headers: string[], rows: (string | number)[][]): string {
  const cell = (v: string | number) => {
    let s = String(v);
    if (typeof v === 'string' && /^[=+\-@\t\r]/.test(s) || typeof v === 'string' && /^[\s\uFEFF]*[=+\-@]/.test(s)) s = `'${s}`;
    return `"${s.replace(/"/g, '""')}"`;
  };
  return [headers.map(cell).join(','), ...rows.map((r) => r.map(cell).join(','))].join('\r\n');
}

// downloadCsv builds a CSV and triggers a browser download.
export function downloadCsv(filename: string, headers: string[], rows: (string | number)[][]): void {
  const blob = new Blob([toCsv(headers, rows)], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.setAttribute('href', url);
  link.setAttribute('download', filename);
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

// csvDate is the YYYY-MM-DD used in exported file names.
export function csvDate(): string {
  return new Date().toISOString().slice(0, 10);
}

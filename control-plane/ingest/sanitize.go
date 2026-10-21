package ingest

import (
	"github.com/strata/strata/control-plane/auth"
	"net/netip"
)

func MaskIP(ip string) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return "[REDACTED]"
	}
	addr = addr.Unmap().WithZone("")
	bits := 48
	if addr.Is4() {
		bits = 24
	}
	return netip.PrefixFrom(addr, bits).Masked().String()
}

// sanitizeEvent masks the full client IP and the input snippets unless the
// caller may read them (nginx-module.md › Giao diện quản trị: not for viewer).
func SanitizeEvent(e Event, p *auth.Principal) Event {
	e = RedactEvent(e, nil)
	if p.Can(auth.PermEventsReadSensitive) {
		return e
	}

	e.ClientIP = MaskIP(e.ClientIP)
	e.Identity = "[REDACTED]"
	maskedViolations := make([]Violation, len(e.Violations))
	for i, v := range e.Violations {
		v.Snippet = "[REDACTED]"
		maskedViolations[i] = v
	}
	e.Violations = maskedViolations
	// RV-G2-01 context: header names and the User-Agent stay, values and
	// the Referer (it may carry personal data in its query) do not
	if e.Referer != "" {
		e.Referer = "[REDACTED]"
	}
	if len(e.Headers) > 0 {
		hs := make([]Header, len(e.Headers))
		for i, h := range e.Headers {
			hs[i] = Header{Name: h.Name, Value: "[REDACTED]"}
		}
		e.Headers = hs
	}
	return e
}

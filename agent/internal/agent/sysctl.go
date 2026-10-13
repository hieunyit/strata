package agent

import (
	"log/slog"
	"os"
	"strconv"
	"strings"
)

// procDgramQlen is where Linux exposes net.unix.max_dgram_qlen.
const procDgramQlen = "/proc/sys/net/unix/max_dgram_qlen"

// MinDgramQlen is the queue depth of the event socket the node needs
// (docs/decisions/ring-buffer.md): with the kernel default of 512 a short
// stall of the agent drops events at 10,000 events/s already. Packages set
// it in /etc/sysctl.d/90-strata.conf.
const MinDgramQlen = 8192

// checkDgramQlen reads the sysctl at path and warns when it is below
// MinDgramQlen. It returns 0 when the value cannot be read (not Linux, or
// /proc not mounted): the metric then says "unknown", not "too low".
func checkDgramQlen(path string) int {
	b, err := os.ReadFile(path)
	if err != nil {
		slog.Warn("cannot read net.unix.max_dgram_qlen", "path", path, "err", err)
		return 0
	}
	v, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || v <= 0 {
		slog.Warn("net.unix.max_dgram_qlen is not a positive number", "path", path, "value", strings.TrimSpace(string(b)))
		return 0
	}
	if v < MinDgramQlen {
		slog.Warn("net.unix.max_dgram_qlen is too low: NGINX workers will drop events under load; set it to 8192 (/etc/sysctl.d/90-strata.conf)",
			"value", v, "want", MinDgramQlen)
	}
	return v
}

package apidiscovery

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

var approvalID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$`)
var collectorID = regexp.MustCompile(`^sa:[A-Za-z0-9-]{1,64}$`)

func Settings(enabled bool, reference, expiry, collectors string, now time.Time) (Gate, error) {
	out := Gate{Enabled: enabled, ApprovalReference: reference, TrustedCollectors: map[string]bool{}}
	if !enabled {
		return out, nil
	}
	if len(collectors) > 4096 || len(strings.Split(collectors, ",")) > 32 {
		return out, fmt.Errorf("discovery: collector limit")
	}
	at, err := time.Parse(time.RFC3339, expiry)
	if err != nil || !now.Before(at) || at.After(now.Add(366*24*time.Hour)) || !approvalID.MatchString(reference) {
		return out, fmt.Errorf("discovery: current bounded legal approval required")
	}
	out.ApprovalExpires = at
	for _, id := range strings.Split(collectors, ",") {
		id = strings.TrimSpace(id)
		if !collectorID.MatchString(id) || len(out.TrustedCollectors) >= 32 {
			return out, fmt.Errorf("discovery: trusted machine collectors required")
		}
		out.TrustedCollectors[id] = true
	}
	return out, nil
}

package main

import (
	"context"
	"encoding/hex"
	"errors"
	"net/netip"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/strata/strata/control-plane/config"
	"github.com/strata/strata/control-plane/delivery"
)

func startOutbound(ctx context.Context, pool *pgxpool.Pool, endpoint, keyFile, allowCIDRs string, audit bool) (*delivery.Outbox, error) {
	if pool == nil {
		if endpoint != "" || audit {
			return nil, errors.New("outbound delivery requires PostgreSQL")
		}
		return nil, nil
	}
	o := &delivery.Outbox{Pool: pool}
	if endpoint == "" {
		if audit {
			return nil, errors.New("audit export requires a configured HTTPS webhook")
		}
		return nil, o.ConfigureAudit(ctx, false)
	}
	encoded, err := config.ReadSecretFile(keyFile)
	if err != nil {
		return nil, errors.New("outbound signing key could not be read")
	}
	key, err := hex.DecodeString(encoded)
	if err != nil || len(key) != 32 {
		return nil, errors.New("outbound signing key must contain 32 bytes encoded as hex")
	}
	allow := []netip.Prefix{}
	if allowCIDRs != "" {
		for _, raw := range strings.Split(allowCIDRs, ",") {
			prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
			if err != nil {
				return nil, errors.New("invalid outbound private-network allowlist")
			}
			allow = append(allow, prefix)
		}
	}
	o.Sender, err = delivery.New(delivery.Config{URL: endpoint, Key: key, Allow: allow})
	if err != nil {
		return nil, err
	}
	if err := o.ConfigureAudit(ctx, audit); err != nil {
		o.Sender.Close()
		return nil, err
	}
	return o, nil
}

package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"github.com/strata/strata/control-plane/apidiscovery"
	"github.com/strata/strata/control-plane/config"
	"github.com/strata/strata/control-plane/store"
	"log"
	"time"
)

func loadDiscoveryGate(enabled bool, approval, expiry, collectors, keyFile string) (apidiscovery.Gate, error) {
	gate, err := apidiscovery.Settings(enabled, approval, expiry, collectors, time.Now().UTC())
	if err != nil || !enabled {
		return gate, err
	}
	encoded, err := config.ReadSecretFile(keyFile)
	if err != nil {
		return gate, fmt.Errorf("discovery: private identity key unavailable")
	}
	gate.Key, err = hex.DecodeString(encoded)
	if err != nil || len(gate.Key) != 32 {
		return gate, fmt.Errorf("discovery: invalid identity key")
	}
	return gate, nil
}
func retainDiscovery(ctx context.Context, st *store.Store) {
	timer := time.NewTicker(time.Hour)
	defer timer.Stop()
	for {
		bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
		err := st.RetainDiscovery(bounded, time.Now().UTC())
		cancel()
		if err != nil && ctx.Err() == nil {
			log.Print("[WARN] discovery retention incomplete")
		}
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
	}
}

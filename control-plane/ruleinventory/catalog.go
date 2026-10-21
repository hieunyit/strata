// Package ruleinventory exposes configured rule metadata with explicit source
// limits. A catalog snapshot is not proof of activation on a proxy node.
package ruleinventory

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/strata/strata/control-plane/rulecat"
	"github.com/strata/strata/control-plane/store"
)

type Catalog struct {
	Store   *store.Store
	Paths   []string
	mu      sync.RWMutex
	current *rulecat.Catalog
	at      time.Time
	stale   bool
}

func (c *Catalog) Refresh(ctx context.Context) error {
	value, err := rulecat.Load(c.Paths)
	if err == nil {
		_, err = c.Store.RecordCatalog(ctx, value.Entries())
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err != nil {
		c.stale = true
		return err
	}
	c.current, c.at, c.stale = value, time.Now().UTC(), false
	return nil
}
func (c *Catalog) Current() (*rulecat.Catalog, time.Time, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.current, c.at, c.stale
}
func (c *Catalog) Run(ctx context.Context) {
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
			err := c.Refresh(bounded)
			cancel()
			if err != nil && ctx.Err() == nil {
				log.Print("[WARN] configured rule catalog refresh failed")
			}
		}
	}
}

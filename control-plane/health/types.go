package health

import (
	"context"
	"github.com/strata/strata/control-plane/ingest"
	"github.com/strata/strata/control-plane/store"
	"time"
)

const Freshness = 90 * time.Second
const (
	Healthy     = "healthy"
	Degraded    = "degraded"
	Unknown     = "unknown"
	Stale       = "stale"
	Unavailable = "unavailable"
)

type Check struct {
	ID         string     `json:"id"`
	State      string     `json:"state"`
	ObservedAt *time.Time `json:"observed_at"`
	Value      *string    `json:"value,omitempty"`
	Unit       string     `json:"unit,omitempty"`
	Advice     string     `json:"advice"`
}
type Node struct {
	ID     string  `json:"id"`
	Checks []Check `json:"checks"`
}
type Snapshot struct {
	At              time.Time `json:"at"`
	FreshForSeconds int64     `json:"fresh_for_seconds"`
	Version         string    `json:"version"`
	Scope           string    `json:"scope"`
	Checks          []Check   `json:"checks"`
	Nodes           []Node    `json:"nodes"`
	Truncated       bool      `json:"truncated"`
}
type Service struct {
	Store     *store.Store
	Events    ingest.EventStore
	Ready     func(context.Context) (map[string]string, bool)
	FreeBytes func() (uint64, error)
	Ingest    func() *ingest.IngestStats
	Now       func() time.Time
	Version   string
}

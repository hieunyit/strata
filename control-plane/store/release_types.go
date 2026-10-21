package store

import "time"

// ReleaseSnapshot is immutable metadata about a signed artifact containing all
// policy, rule and schema sections. No input path is recompiled on rollback.
type ReleaseSnapshot struct {
	Waves                  []float64          `json:"waves"`
	SoakSeconds            int64              `json:"soak_seconds"`
	Canary                 map[string]float64 `json:"canary"`
	ReplayBaselineMismatch bool               `json:"replay_baseline_mismatch"`
	Bundle                 Bundle             `json:"bundle"`
	PublicKey              []byte             `json:"public_key"`
	Baseline               uint64             `json:"baseline_bundle,string"`
	ReplayIDs              map[string]string  `json:"replay_ids"`
}
type Release struct {
	SnapshotHash    string          `json:"snapshot_hash"`
	ID              string          `json:"id"`
	Etag            string          `json:"etag"`
	State           string          `json:"state"`
	Snapshot        ReleaseSnapshot `json:"snapshot"`
	SourceRelease   string          `json:"source_release"`
	CreatedBy       string          `json:"created_by"`
	CreatedSubject  string          `json:"created_subject"`
	ApprovedBy      string          `json:"approved_by"`
	ApprovedSubject string          `json:"approved_subject"`
	CreatedAt       time.Time       `json:"created_at"`
	UpdatedAt       time.Time       `json:"updated_at"`
	BundleVersion   uint64          `json:"bundle_version,string"`
	RolloutID       int64           `json:"rollout_id"`
}

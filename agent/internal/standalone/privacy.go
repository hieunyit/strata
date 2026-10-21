package standalone

import "github.com/strata/strata/agent/pkg/privacy"

func (w *BundleWatcher) Privacy(version uint64, policy string) (*privacy.Filter, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if entries := w.privacy[version]; entries != nil {
		if filter, ok := entries[policy]; ok {
			return filter, nil
		}
	}
	return privacy.Strict(), nil
}

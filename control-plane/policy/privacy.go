package policy

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/strata/strata/agent/pkg/privacy"
	"github.com/strata/strata/control-plane/store"
)

type PrivacyResolver struct {
	Store       *store.Store
	IdentityKey func(context.Context) ([]byte, error)
}

func (r PrivacyResolver) Filter(ctx context.Context, name string, bundle uint64) (*privacy.Filter, error) {
	if name == "" || bundle == 0 {
		return privacy.Strict(), nil
	}
	raw, err := r.Store.BundlePolicySpec(ctx, bundle, name)
	if err != nil {
		return nil, err
	}
	var spec struct {
		Privacy *Privacy `json:"privacy"`
	}
	if err := json.Unmarshal(raw, &spec); err != nil {
		return nil, err
	}
	if spec.Privacy == nil {
		return nil, nil
	}
	p := spec.Privacy
	f, err := privacy.New(p.SensitiveFields, p.MaskPatterns)
	if err != nil {
		return nil, err
	}
	if p.Identity == "hmac" {
		if r.IdentityKey == nil {
			return nil, errors.New("privacy: identity key unavailable")
		}
		key, err := r.IdentityKey(ctx)
		if err != nil {
			return nil, err
		}
		return f.WithIdentityKey(key)
	}
	return f, nil
}

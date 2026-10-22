package store

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"github.com/strata/strata/control-plane/rulesets"
)

// ErrCustomRuleSetConflict: the etag is stale, or the name is taken.
var ErrCustomRuleSetConflict = errors.New("store: custom rule set conflict")

// MaxCustomRuleSets bounds the custom sets of a control plane.
const MaxCustomRuleSets = 256

// CustomRuleSet is a rule set made by an operator (RS-3c).
type CustomRuleSet struct {
	Name        string          `json:"name"`
	Title       string          `json:"title"`
	Description string          `json:"description"`
	Match       rulesets.Filter `json:"match"`
	Version     int             `json:"version"`
	Etag        string          `json:"etag"`
	CreatedBy   string          `json:"created_by"`
	UpdatedBy   string          `json:"updated_by"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
}

// Validate the parts an operator gives.
func (c *CustomRuleSet) Validate() error {
	if !rulesets.IsCustom(c.Name) {
		return errors.New("custom rule set: the name is custom- and up to 48 lower-case letters, digits or dashes")
	}
	if t := strings.TrimSpace(c.Title); t == "" || len(c.Title) > 128 || len(c.Description) > 1024 || !utf8.ValidString(c.Title+c.Description) {
		return errors.New("custom rule set: a title of 1 to 128 bytes and a description of at most 1024 are required")
	}
	if err := c.Match.Validate(); err != nil {
		return errors.New("custom rule set: " + err.Error())
	}
	return nil
}

const customRuleSetSelect = `SELECT name, title, description, match, version, etag, created_by, updated_by, created_at, updated_at FROM custom_rule_sets`

func scanCustomRuleSet(row pgx.Row) (CustomRuleSet, error) {
	var c CustomRuleSet
	var match []byte
	if err := row.Scan(&c.Name, &c.Title, &c.Description, &match, &c.Version, &c.Etag, &c.CreatedBy, &c.UpdatedBy, &c.CreatedAt, &c.UpdatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return c, ErrNotFound
		}
		return c, err
	}
	return c, json.Unmarshal(match, &c.Match)
}

// ListCustomRuleSets by name.
func (s *Store) ListCustomRuleSets(ctx context.Context) ([]CustomRuleSet, error) {
	rows, err := s.pool.Query(ctx, customRuleSetSelect+" ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []CustomRuleSet{}
	for rows.Next() {
		c, err := scanCustomRuleSet(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// GetCustomRuleSet name; ErrNotFound when there is none.
func (s *Store) GetCustomRuleSet(ctx context.Context, name string) (CustomRuleSet, error) {
	return scanCustomRuleSet(s.pool.QueryRow(ctx, customRuleSetSelect+" WHERE name=$1", name))
}

// CreateCustomRuleSet c (version 1); ErrCustomRuleSetConflict when the name is taken.
func (s *Store) CreateCustomRuleSet(ctx context.Context, c CustomRuleSet, audit Audit) (CustomRuleSet, error) {
	if err := c.Validate(); err != nil {
		return c, err
	}
	match, err := json.Marshal(c.Match)
	if err != nil {
		return c, err
	}
	var out CustomRuleSet
	err = s.inTx(ctx, func(tx pgx.Tx) error {
		var n int
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM custom_rule_sets").Scan(&n); err != nil {
			return err
		}
		if n >= MaxCustomRuleSets {
			return errors.New("custom rule set: too many custom sets")
		}
		tag, err := tx.Exec(ctx, `INSERT INTO custom_rule_sets (name, title, description, match, created_by, updated_by)
			VALUES ($1, $2, $3, $4, $5, $5) ON CONFLICT (name) DO NOTHING`, c.Name, strings.TrimSpace(c.Title), c.Description, match, audit.Actor)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrCustomRuleSetConflict
		}
		if out, err = scanCustomRuleSet(tx.QueryRow(ctx, customRuleSetSelect+" WHERE name=$1", c.Name)); err != nil {
			return err
		}
		audit.Resource = "rule-sets/" + c.Name
		audit.After = out
		return writeAudit(ctx, tx, audit)
	})
	return out, err
}

// UpdateCustomRuleSet the title, description and filter of c.Name read
// with etag: a new version.
func (s *Store) UpdateCustomRuleSet(ctx context.Context, c CustomRuleSet, etag string, audit Audit) (CustomRuleSet, error) {
	if err := c.Validate(); err != nil {
		return c, err
	}
	match, err := json.Marshal(c.Match)
	if err != nil {
		return c, err
	}
	var out CustomRuleSet
	err = s.inTx(ctx, func(tx pgx.Tx) error {
		before, err := scanCustomRuleSet(tx.QueryRow(ctx, customRuleSetSelect+" WHERE name=$1 FOR UPDATE", c.Name))
		if err != nil {
			return err
		}
		if etag == "" || before.Etag != etag {
			return ErrCustomRuleSetConflict
		}
		if _, err := tx.Exec(ctx, `UPDATE custom_rule_sets SET title=$2, description=$3, match=$4, version=version+1,
			etag=gen_random_uuid()::text, updated_by=$5, updated_at=now() WHERE name=$1`, c.Name, strings.TrimSpace(c.Title), c.Description, match, audit.Actor); err != nil {
			return err
		}
		if out, err = scanCustomRuleSet(tx.QueryRow(ctx, customRuleSetSelect+" WHERE name=$1", c.Name)); err != nil {
			return err
		}
		audit.Resource = "rule-sets/" + c.Name
		audit.Before, audit.After = before, out
		return writeAudit(ctx, tx, audit)
	})
	return out, err
}

// DeleteCustomRuleSet name read with etag. Policies keep their copy of
// its filter.
func (s *Store) DeleteCustomRuleSet(ctx context.Context, name, etag string, audit Audit) error {
	return s.inTx(ctx, func(tx pgx.Tx) error {
		before, err := scanCustomRuleSet(tx.QueryRow(ctx, customRuleSetSelect+" WHERE name=$1 FOR UPDATE", name))
		if err != nil {
			return err
		}
		if etag == "" || before.Etag != etag {
			return ErrCustomRuleSetConflict
		}
		if _, err := tx.Exec(ctx, "DELETE FROM custom_rule_sets WHERE name=$1", name); err != nil {
			return err
		}
		audit.Resource = "rule-sets/" + name
		audit.Before = before
		return writeAudit(ctx, tx, audit)
	})
}

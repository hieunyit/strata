// Package investigation runs bounded, private evidence export operations.
package investigation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/strata/strata/control-plane/auth"
	"github.com/strata/strata/control-plane/ingest"
	"github.com/strata/strata/control-plane/policy"
	"github.com/strata/strata/control-plane/store"
)

const MaxRows = 10000
const MaxBytes = 16 << 20

type Snapshot struct {
	RequiresSensitive bool
	Principal         auth.Principal
	Events            []auth.EventScope
}

func Capture(p *auth.Principal) Snapshot {
	v := Snapshot{Principal: *p}
	v.Principal.Access = nil
	if p.Access != nil {
		v.Events = append([]auth.EventScope(nil), p.Access.Events...)
	}
	return v
}

// Scope revalidates the current binding graph and requires the complete original
// artifact scope to remain authorized. A revoked route cannot survive in a file.
func Scope(ctx context.Context, st *store.Store, v store.EvidenceExport, p *auth.Principal) (context.Context, error) {
	if p == nil || p.Subject != v.Owner || !p.Can(auth.PermEventsRead) || v.Sensitive && !p.Can(auth.PermEventsReadSensitive) {
		return nil, store.ErrNotFound
	}
	scoped, err := st.ApplicationEventScope(ctx, v.ApplicationID, v.EnvironmentID, p)
	if err != nil {
		return nil, err
	}
	current := auth.FromContext(scoped)
	var saved Snapshot
	if err := json.Unmarshal(v.Principal, &saved); err != nil {
		return nil, err
	}
	if saved.RequiresSensitive && !p.Can(auth.PermEventsReadSensitive) {
		return nil, store.ErrNotFound
	}
	if len(saved.Events) == 0 {
		return nil, store.ErrNotFound
	}
	for _, want := range saved.Events {
		for _, node := range want.Nodes {
			found := false
			for _, have := range current.Access.Events {
				if have.Policy == want.Policy && have.Host == want.Host && have.Prefix == want.Prefix && slices.Contains(have.Nodes, node) {
					found = true
					break
				}
			}
			if !found {
				return nil, store.ErrNotFound
			}
		}
	}
	// Pin the creation scope even if current authorization expanded.
	clone := *current
	clone.Access = &auth.Access{Events: saved.Events}
	if !v.Sensitive {
		clone.Scopes = []auth.Permission{auth.PermEventsRead}
	}
	return auth.WithPrincipal(scoped, &clone), nil
}

// CSVCell follows the UI guard and also catches formula prefixes hidden behind
// whitespace or a BOM. encoding/csv handles delimiters, quotes and newlines.
func CSVCell(s string) string {
	trimmed := strings.TrimLeftFunc(s, func(r rune) bool { return unicode.IsSpace(r) || r == '\ufeff' })
	if strings.HasPrefix(s, "\t") || strings.HasPrefix(s, "\r") || len(trimmed) > 0 && strings.ContainsRune("=+-@", rune(trimmed[0])) {
		return "'" + s
	}
	return s
}

type Worker struct {
	Store   *store.Store
	Events  ingest.EventStore
	Objects policy.ObjectStore
}

func (w *Worker) Run(ctx context.Context) {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	cleanup := time.Time{}
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if time.Since(cleanup) > time.Minute {
				if err := w.Cleanup(ctx); err != nil {
					log.Print("[WARN] evidence retention failed")
				} else {
					cleanup = time.Now()
				}
			}
			if err := w.Once(ctx); err != nil && !errors.Is(err, store.ErrNotFound) && ctx.Err() == nil {
				log.Print("[WARN] evidence export failed")
			}
		}
	}
}
func (w *Worker) Once(ctx context.Context) error {
	v, err := w.Store.ClaimEvidence(ctx)
	if err != nil {
		return err
	}
	deadline := time.Now().Add(5 * time.Minute)
	if v.ExpiresAt.Before(deadline) {
		deadline = v.ExpiresAt
	}
	jobCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	err = w.build(jobCtx, &v)
	// The caller's canceled context must not turn completion into an unbounded
	// background write; leave its lease for a bounded crash retry on shutdown.
	if ctx.Err() != nil {
		return ctx.Err()
	}
	finishCtx, finishCancel := context.WithTimeout(ctx, 5*time.Second)
	defer finishCancel()
	if finishErr := w.Store.FinishEvidence(finishCtx, v, err == nil); finishErr != nil {
		return finishErr
	}
	return err
}
func (w *Worker) build(ctx context.Context, v *store.EvidenceExport) error {
	var snapshot Snapshot
	if err := json.Unmarshal(v.Principal, &snapshot); err != nil {
		return err
	}
	current, err := w.Store.EvidencePrincipal(ctx, snapshot.Principal)
	if err != nil {
		return err
	}
	scoped, err := Scope(ctx, w.Store, *v, current)
	if err != nil {
		return err
	}
	var filter ingest.SearchFilter
	if err := json.Unmarshal(v.Filter, &filter); err != nil {
		return err
	}
	if filter.To.After(v.CreatedAt) {
		filter.To = v.CreatedAt
	}
	filter.Limit, filter.Offset = 200, 0
	var output bytes.Buffer
	if err := writeRow(&output, []string{"block_id", "timestamp", "policy_id", "node_id", "method", "host", "path", "action", "client_ip", "rules"}); err != nil {
		return err
	}
	for filter.Offset < MaxRows {
		result, err := w.Events.SearchEvents(scoped, filter)
		if err != nil {
			return err
		}
		for _, raw := range result.Events {
			if err := ctx.Err(); err != nil {
				return err
			}
			e := ingest.SanitizeEvent(raw, auth.FromContext(scoped))
			rules := fmt.Sprint(e.MatchedRules)
			var row bytes.Buffer
			if err := writeRow(&row, []string{e.BlockID, e.Timestamp.UTC().Format(time.RFC3339Nano), e.PolicyID, e.NodeID, e.HTTPMethod, e.HTTPHost, e.HTTPPath, e.Action, e.ClientIP, rules}); err != nil {
				return err
			}
			if output.Len()+row.Len() > MaxBytes {
				v.Truncated = true
				break
			}
			output.Write(row.Bytes())
			v.RowCount++
		}
		filter.Offset += len(result.Events)
		if filter.Offset >= MaxRows && uint64(filter.Offset) < result.Total {
			v.Truncated = true
		}
		if v.Truncated || len(result.Events) == 0 || uint64(filter.Offset) >= result.Total {
			break
		}
	}
	// Resolve again after the scan; authorization may have changed while it ran.
	current, err = w.Store.EvidencePrincipal(ctx, snapshot.Principal)
	if err != nil {
		return err
	}
	if _, err = Scope(ctx, w.Store, *v, current); err != nil {
		return err
	}
	sum := sha256.Sum256(output.Bytes())
	v.SHA256 = hex.EncodeToString(sum[:])
	v.ArtifactKey = "evidence/" + v.ID + "/" + v.SHA256 + ".csv"
	if err := ctx.Err(); err != nil {
		return err
	}
	return w.Objects.Put(ctx, v.ArtifactKey, output.Bytes(), v.SHA256)
}
func writeRow(dst *bytes.Buffer, values []string) error {
	for i := range values {
		values[i] = CSVCell(values[i])
	}
	writer := csv.NewWriter(dst)
	writer.UseCRLF = true
	if err := writer.Write(values); err != nil {
		return err
	}
	writer.Flush()
	return writer.Error()
}
func (w *Worker) Cleanup(ctx context.Context) error {
	if err := w.Store.PurgeInvestigationContent(ctx); err != nil {
		return err
	}
	rows, err := w.Store.ExpiredEvidence(ctx)
	if err != nil {
		return err
	}
	deleter, ok := w.Objects.(interface {
		Delete(context.Context, string) error
	})
	if !ok {
		return errors.New("evidence objects lack deletion")
	}
	for _, v := range rows {
		// A crash after Put may leave a content-addressed retry artifact. Remove
		// every bounded attempt before deleting metadata.
		objects, err := w.Objects.List(ctx, "evidence/"+v.ID+"/")
		if err != nil {
			return err
		}
		if len(objects) > 10 {
			return errors.New("evidence artifact quota exceeded")
		}
		for _, object := range objects {
			if err := deleter.Delete(ctx, object.Key); err != nil {
				return err
			}
		}
		if err := w.Store.DeleteExpiredEvidence(ctx, v.ID); err != nil {
			return err
		}
	}
	return nil
}

// RetainContent also runs on API-only installations with no artifact store.
func RetainContent(ctx context.Context, st *store.Store) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := st.PurgeInvestigationContent(ctx); err != nil && ctx.Err() == nil {
				log.Print("[WARN] investigation retention failed")
			}
		}
	}
}

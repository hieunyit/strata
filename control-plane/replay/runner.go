package replay

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/strata/strata/control-plane/policy"
	"github.com/strata/strata/control-plane/store"
)

// Report is what the replay of a draft gives (W13-G2-01): strata-replay
// compare's output (engine/replay, W12-R-01), on the policy's traffic
// samples and on the corpus apart. It is stored with the operation and
// served by the admin API.
type Report struct {
	// Inputs identifies the snapshotted compiler inputs; hashes identify artifacts
	// actually passed to compare, without recording secrets or sample content.
	InputDigest    string   `json:"input_digest,omitempty"`
	DraftSHA256    string   `json:"draft_sha256,omitempty"`
	BaselineSHA256 string   `json:"baseline_sha256,omitempty"`
	ReplaySHA256   string   `json:"replay_sha256,omitempty"`
	SampleSHA256   []string `json:"sample_sha256,omitempty"`

	ElapsedMs uint64 `json:"elapsed_ms"`
	// The bundle in force the draft is compared with; 0 when there is none
	// yet (the baseline is then built from the policies as they are).
	BaselineBundle uint64 `json:"baseline_bundle"`
	// Traffic sample files of the policy from the last Days days, and their
	// size; Truncated when there were more than the limits.
	SampleFiles int   `json:"sample_files"`
	SampleBytes int64 `json:"sample_bytes"`
	Truncated   bool  `json:"truncated,omitempty"`
	// The comparison on the traffic samples (nil without any), and on the
	// benign and attack corpus (nil without one).
	Traffic *Route `json:"traffic,omitempty"`
	Corpus  *Route `json:"corpus,omitempty"`
}

// Samples replayed, traffic and corpus.
func (r *Report) Samples() uint64 {
	var n uint64
	for _, rt := range []*Route{r.Traffic, r.Corpus} {
		if rt != nil {
			n += rt.Samples
		}
	}
	return n
}

// Route is engine/replay's CompareRoute.
type Route struct {
	Samples             uint64            `json:"samples"`
	Draft               map[string]uint64 `json:"draft"`
	Baseline            map[string]uint64 `json:"baseline"`
	NewlyBlocked        uint64            `json:"newly_blocked"`
	NewlyAllowed        uint64            `json:"newly_allowed"`
	NewlyBlockedRules   map[string]uint64 `json:"newly_blocked_rules"`
	NewlyAllowedRules   map[string]uint64 `json:"newly_allowed_rules"`
	NewlyBlockedPaths   map[string]uint64 `json:"newly_blocked_paths"`
	NewlyBlockedSampled map[string]uint64 `json:"newly_blocked_sampled"`
	NewlyAllowedSampled map[string]uint64 `json:"newly_allowed_sampled"`
	ExamplesBlocked     []Example         `json:"examples_blocked"`
	ExamplesAllowed     []Example         `json:"examples_allowed"`
}

// Example is engine/replay's Example: an anonymized sample whose verdict
// changed.
type Example struct {
	TsMs          int64    `json:"ts_ms"`
	NodeID        string   `json:"node_id"`
	Method        string   `json:"method"`
	RawURI        string   `json:"raw_uri"`
	Draft         string   `json:"draft"`
	Baseline      string   `json:"baseline"`
	DraftRules    []uint32 `json:"draft_rules"`
	BaselineRules []uint32 `json:"baseline_rules"`
}

// RunnerStore is the part of store.Store the runner uses.
type RunnerStore interface {
	ClaimOperation(ctx context.Context, staleBefore time.Time) (store.Operation, bool, error)
	FinishOperation(ctx context.Context, id string, result json.RawMessage, errMsg string) error
	GetPolicy(ctx context.Context, id string) (store.Policy, error)
	GetPolicyVersion(ctx context.Context, id string, version int) (store.PolicyVersion, error)
}

// SampleObjects lists and reads the sample files (policy.S3).
type SampleObjects interface {
	List(ctx context.Context, prefix string) ([]policy.ObjectInfo, error)
	Get(ctx context.Context, key string) ([]byte, error)
}

// Runner replays queued policy versions, one at a time: it builds the
// bundle a deploy would make with the draft, signed with a key of its own
// that never signs anything the nodes get, and runs strata-replay compare
// against the bundle in force on the policy's samples of the last days
// and the corpus.
type Runner struct {
	Prepare func(context.Context, []policy.Named) (*policy.Prepared, error)

	Store RunnerStore
	// Deployable: the policies a deploy would build now (each at the
	// version it would take).
	Deployable func(ctx context.Context) ([]store.Policy, error)
	// Build compiles a bundle of policies signed with the Ed25519 seed in
	// keyFile (the runner's own key): ReplayBuilder of the deploys'
	// compiler.
	Build func(ctx context.Context, keyFile string, policies []policy.Named) ([]byte, error)
	// Baseline returns the bundle in force and its version, verified by
	// BaselinePub; store.ErrNotFound when none was deployed yet.
	Baseline    func(ctx context.Context) ([]byte, uint64, error)
	BaselinePub []byte
	Samples     SampleObjects // nil: corpus only
	// Corpus: a sample file made by strata-replay gen from the benign and
	// attack corpus; "": none.
	Corpus  string
	Binary  string        // default "strata-replay" from PATH
	Threads int           // default 2
	Timeout time.Duration // per replay, default 10 min
	Days    int           // of traffic samples, default 7
	// Limits on the traffic samples of one replay, newest days first:
	// default 200 files and 1 GiB.
	MaxFiles int
	MaxBytes int64
	Poll     time.Duration // default 2 s
	Now      func() time.Time

	kick chan struct{}
	key  ed25519.PrivateKey
}

// Init sets the defaults and the runner's signing key; call it before Run
// and Kick are used from several goroutines.
func (r *Runner) Init() error {
	if r.Binary == "" {
		r.Binary = "strata-replay"
	}
	if r.Threads <= 0 {
		r.Threads = 2
	}
	if r.Timeout <= 0 {
		r.Timeout = 10 * time.Minute
	}
	if r.Days <= 0 {
		r.Days = 7
	}
	if r.MaxFiles <= 0 {
		r.MaxFiles = 200
	}
	if r.MaxBytes <= 0 {
		r.MaxBytes = 1 << 30
	}
	if r.Poll <= 0 {
		r.Poll = 2 * time.Second
	}
	if r.Now == nil {
		r.Now = time.Now
	}
	if r.kick == nil {
		r.kick = make(chan struct{}, 1)
	}
	if r.key == nil {
		// a key per process: drafts are signed only to be loaded by
		// strata-replay here, never by a node
		_, k, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		r.key = k
	}
	return nil
}

// Kick asks the runner to look for queued operations now.
func (r *Runner) Kick() {
	if r.kick == nil {
		return
	}
	select {
	case r.kick <- struct{}{}:
	default:
	}
}

// Run replays queued operations until ctx ends.
func (r *Runner) Run(ctx context.Context) error {
	if err := r.Init(); err != nil {
		return err
	}
	t := time.NewTicker(r.Poll)
	defer t.Stop()
	for {
		for ctx.Err() == nil {
			if !r.RunOnce(ctx) {
				break
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		case <-r.kick:
		}
	}
}

// RunOnce replays one queued operation; false when none was queued (or the
// queue could not be read).
func (r *Runner) RunOnce(ctx context.Context) bool {
	if err := r.Init(); err != nil {
		log.Printf("[ERROR] replay: %v", err)
		return false
	}
	// a RUNNING operation older than twice the timeout lost its runner
	op, ok, err := r.Store.ClaimOperation(ctx, r.Now().Add(-2*r.Timeout))
	if err != nil {
		log.Printf("[WARN] replay: queue: %v", err)
		return false
	}
	if !ok {
		return false
	}
	rep, err := r.replay(ctx, op)
	var res json.RawMessage
	msg := ""
	if err == nil {
		res, err = json.Marshal(rep)
	}
	if err != nil {
		msg = err.Error()
		log.Printf("[WARN] replay: %s (policy %s version %d): %s", op.ID, op.PolicyID, op.Version, msg)
	} else {
		log.Printf("[INFO] replay: %s (policy %s version %d): %d samples in %d ms", op.ID, op.PolicyID, op.Version, rep.Samples(), rep.ElapsedMs)
	}
	// the result is written even when ctx just ended
	fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if err := r.Store.FinishOperation(fctx, op.ID, res, msg); err != nil {
		log.Printf("[ERROR] replay: %s: %v", op.ID, err)
	}
	return true
}

func (r *Runner) replay(ctx context.Context, op store.Operation) (*Report, error) {
	ctx, cancel := context.WithTimeout(ctx, r.Timeout)
	defer cancel()
	p, err := r.Store.GetPolicy(ctx, op.PolicyID)
	if err != nil {
		return nil, fmt.Errorf("policy %s: %w", op.PolicyID, err)
	}
	v, err := r.Store.GetPolicyVersion(ctx, op.PolicyID, op.Version)
	if err != nil {
		return nil, fmt.Errorf("policy %s version %d: %w", op.PolicyID, op.Version, err)
	}
	draftSpec, err := policy.Parse(v.Spec)
	if err != nil {
		return nil, fmt.Errorf("policy %s version %d: %w", op.PolicyID, op.Version, err)
	}
	ps, err := r.Deployable(ctx)
	if err != nil {
		return nil, fmt.Errorf("policies: %w", err)
	}
	var draft, base []policy.Named
	found := false
	for _, x := range ps {
		spec, err := policy.Parse(x.Spec)
		if err != nil {
			return nil, fmt.Errorf("policy %s version %d: %w", x.ID, x.CurrentVersion, err)
		}
		base = append(base, policy.Named{Name: x.Name, Spec: spec})
		if x.ID == p.ID {
			spec, found = draftSpec, true
		}
		draft = append(draft, policy.Named{Name: x.Name, Spec: spec})
	}
	if !found { // a policy no deploy has taken yet
		draft = append(draft, policy.Named{Name: p.Name, Spec: draftSpec})
	}
	sort.Slice(draft, func(i, j int) bool { return draft[i].Name < draft[j].Name })
	sort.Slice(base, func(i, j int) bool { return base[i].Name < base[j].Name })

	dir, err := os.MkdirTemp("", "strata-replay-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	seed := filepath.Join(dir, "draft.seed")
	if err := os.WriteFile(seed, r.key.Seed(), 0o600); err != nil {
		return nil, err
	}
	pub := filepath.Join(dir, "draft.pub")
	if err := os.WriteFile(pub, r.key.Public().(ed25519.PublicKey), 0o600); err != nil {
		return nil, err
	}
	rep := &Report{}
	var data []byte
	if r.Prepare != nil {
		snapshot, e := r.Prepare(ctx, draft)
		if e != nil {
			return nil, e
		}
		defer snapshot.Close()
		rep.InputDigest = snapshot.Digest
		data, err = snapshot.ReplayBuild(ctx, seed)
	} else {
		data, err = r.Build(ctx, seed, draft)
	}

	if err != nil {
		return nil, fmt.Errorf("building the draft bundle: %w", err)
	}
	draftFile := filepath.Join(dir, "draft.sbn")
	if err := os.WriteFile(draftFile, data, 0o600); err != nil {
		return nil, err
	}

	rep.DraftSHA256 = digest(data)
	baseFile, basePub := filepath.Join(dir, "baseline.sbn"), filepath.Join(dir, "baseline.pub")
	bdata, bver, err := r.Baseline(ctx)
	switch {
	case errors.Is(err, store.ErrNotFound):
		// nothing in force: the policies as they are, without the draft
		if len(base) == 0 {
			base = []policy.Named{{Name: p.Name, Spec: policy.Spec{Mode: "shadow"}}}
		}
		if bdata, err = r.Build(ctx, seed, base); err != nil {
			return nil, fmt.Errorf("building the baseline bundle: %w", err)
		}
		basePub = pub
	case err != nil:
		return nil, fmt.Errorf("the bundle in force: %w", err)
	default:
		rep.BaselineBundle = bver
		if err := os.WriteFile(basePub, r.BaselinePub, 0o600); err != nil {
			return nil, err
		}
	}
	rep.BaselineSHA256 = digest(bdata)
	if err := os.WriteFile(baseFile, bdata, 0o600); err != nil {
		return nil, err
	}

	files, err := r.fetchSamples(ctx, p.Name, dir, rep)
	if err != nil {
		return nil, err
	}
	if len(files) == 0 && r.Corpus == "" {
		return nil, errors.New("no traffic samples of the policy and no corpus to replay")
	}
	replayBin := r.Binary
	if r.Prepare != nil {
		bin, e := exec.LookPath(r.Binary)
		if e != nil {
			return nil, e
		}
		replayBin = filepath.Join(dir, "replay-bin")
		if rep.ReplaySHA256, err = copyReplayInput(ctx, bin, replayBin, 256<<20, 0700); err != nil {
			return nil, err
		}
	}
	corpus := r.Corpus
	if corpus != "" {
		corpus = filepath.Join(dir, "corpus.parquet")
		sum, e := copyReplayInput(ctx, r.Corpus, corpus, 1<<30, 0600)
		if e != nil {
			return nil, e
		}
		rep.SampleSHA256 = append(rep.SampleSHA256, sum)
	}
	for _, file := range files {
		sum, e := hashReplayInput(ctx, file)
		if e != nil {
			return nil, e
		}
		rep.SampleSHA256 = append(rep.SampleSHA256, sum)
	}
	compare := func(files []string) (*Route, uint64, error) {
		args := []string{"compare", "--bundle", draftFile, "--baseline", baseFile, "--pubkey", pub,
			"--baseline-pubkey", basePub, "--policy", p.Name, "--threads", strconv.Itoa(r.Threads)}
		cmd := exec.CommandContext(ctx, replayBin, append(args, files...)...)
		var out bytes.Buffer
		var stderr tail
		cmd.Stdout, cmd.Stderr = &limited{w: &out, n: 64 << 20}, &stderr
		if err := cmd.Run(); err != nil {
			if ctx.Err() != nil {
				return nil, 0, fmt.Errorf("strata-replay: stopped after %s: %w", r.Timeout, ctx.Err())
			}
			return nil, 0, fmt.Errorf("strata-replay: %w: %s", err, strings.TrimSpace(stderr.String()))
		}
		var cmp struct {
			ElapsedMs uint64           `json:"elapsed_ms"`
			Routes    map[string]Route `json:"routes"`
		}
		if err := json.Unmarshal(out.Bytes(), &cmp); err != nil {
			return nil, 0, fmt.Errorf("strata-replay output: %w", err)
		}
		// --policy runs every sample under the policy: one route
		rt := cmp.Routes[p.Name]
		return &rt, cmp.ElapsedMs, nil
	}
	if len(files) > 0 {
		rt, ms, err := compare(files)
		if err != nil {
			return nil, err
		}
		rep.Traffic, rep.ElapsedMs = rt, rep.ElapsedMs+ms
	}
	if r.Corpus != "" {
		rt, ms, err := compare([]string{corpus})
		if err != nil {
			return nil, err
		}
		rep.Corpus, rep.ElapsedMs = rt, rep.ElapsedMs+ms
	}
	return rep, nil
}

// fetchSamples downloads the policy's sample files of the last Days days,
// newest day first, within MaxFiles and MaxBytes.
func (r *Runner) fetchSamples(ctx context.Context, policyName, dir string, rep *Report) ([]string, error) {
	if r.Samples == nil {
		return nil, nil
	}
	var files []string
	day := r.Now().UTC()
	for d := 0; d < r.Days && !rep.Truncated; d++ {
		t := day.AddDate(0, 0, -d)
		prefix := fmt.Sprintf("replay/v1/%s/%04d/%02d/%02d/", policyName, t.Year(), t.Month(), t.Day())
		objs, err := r.Samples.List(ctx, prefix)
		if err != nil {
			return nil, fmt.Errorf("listing the samples: %w", err)
		}
		sort.Slice(objs, func(i, j int) bool { return objs[i].Key > objs[j].Key })
		for _, o := range objs {
			if !strings.HasSuffix(o.Key, ".parquet") {
				continue
			}
			if len(files) >= r.MaxFiles || rep.SampleBytes+o.Size > r.MaxBytes {
				rep.Truncated = true
				break
			}
			data, err := r.Samples.Get(ctx, o.Key)
			if err != nil {
				return nil, fmt.Errorf("sample %s: %w", o.Key, err)
			}
			f := filepath.Join(dir, fmt.Sprintf("s%04d-%s", len(files), path.Base(o.Key)))
			if err := os.WriteFile(f, data, 0o600); err != nil {
				return nil, err
			}
			files = append(files, f)
			rep.SampleFiles++
			rep.SampleBytes += int64(len(data))
		}
	}
	return files, nil
}

// limited writes at most n bytes and fails after.
type limited struct {
	w io.Writer
	n int64
}

func (l *limited) Write(p []byte) (int, error) {
	if int64(len(p)) > l.n {
		return 0, errors.New("strata-replay output too large")
	}
	l.n -= int64(len(p))
	return l.w.Write(p)
}

// tail keeps the last 2 KB written (strata-replay's error).
type tail struct{ b []byte }

func (t *tail) Write(p []byte) (int, error) {
	t.b = append(t.b, p...)
	if len(t.b) > 2048 {
		t.b = t.b[len(t.b)-2048:]
	}
	return len(p), nil
}

func (t *tail) String() string { return string(t.b) }

// ReplayBuilder builds with c, but signed with the seed in keyFile instead
// of c's signer or key (Runner.Build).
func ReplayBuilder(c policy.Compiler) func(context.Context, string, []policy.Named) ([]byte, error) {
	return func(ctx context.Context, keyFile string, ps []policy.Named) ([]byte, error) {
		c := c
		c.Signer, c.KeyFile = nil, keyFile
		return c.Build(ctx, 1, ps)
	}
}

func digest(b []byte) string { sum := sha256.Sum256(b); return hex.EncodeToString(sum[:]) }

// replayReader makes file hashing/copying cancellable between bounded reads.
type replayReader struct {
	ctx context.Context
	r   io.Reader
}

func (r replayReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}
func copyReplayInput(ctx context.Context, src, dst string, max int64, mode os.FileMode) (string, error) {
	in, err := os.Open(src)
	if err != nil {
		return "", err
	}
	defer in.Close()
	info, err := in.Stat()
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Size() > max {
		return "", fmt.Errorf("replay: input is not a bounded regular file")
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(out, h), io.LimitReader(replayReader{ctx, in}, max+1))
	closeErr := out.Close()
	if copyErr != nil {
		return "", copyErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	if n > max {
		return "", fmt.Errorf("replay: input too large")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func hashReplayInput(ctx context.Context, file string) (string, error) {
	in, err := os.Open(file)
	if err != nil {
		return "", err
	}
	defer in.Close()
	h := sha256.New()
	_, err = io.Copy(h, replayReader{ctx, in})
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

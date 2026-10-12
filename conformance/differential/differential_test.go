package differential

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func read(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("corpus", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Benign requests frame the same in both profiles.
func TestBenignAgrees(t *testing.T) {
	for _, name := range []string{"agree-benign-get.http", "agree-benign-post-cl.http", "agree-benign-post-chunked.http", "agree-dup-cl-both-reject.http"} {
		r := Compare(name, read(t, name))
		if r.Divergent {
			t.Errorf("%s: unexpected divergence: %s (%+v)", name, r.Reason, r.Framings)
		}
	}
}

// A Content-Length + Transfer-Encoding request is the classic smuggling
// vector: net/http drops the length and reads it chunked, a strict Servlet
// container rejects it. The harness must surface that as divergent.
func TestClTeDiverges(t *testing.T) {
	r := Compare("diverge-cl-te.http", read(t, "diverge-cl-te.http"))
	if !r.Divergent {
		t.Fatalf("CL+TE should diverge, got %+v", r.Framings)
	}
	var got []string
	for _, f := range r.Framings {
		got = append(got, f.Profile+"="+string(f.Body))
	}
	t.Logf("CL+TE framings: %s (%s)", strings.Join(got, ", "), r.Reason)
}

// The whole corpus runs: every "diverge-*" input is flagged divergent and
// every "agree-*" input is not (whether both stacks accept or both reject).
func TestCorpus(t *testing.T) {
	matches, _ := filepath.Glob(filepath.Join("corpus", "*.http"))
	if len(matches) == 0 {
		t.Fatal("no corpus files")
	}
	for _, m := range matches {
		name := filepath.Base(m)
		r := Compare(name, read(t, name))
		want := strings.HasPrefix(name, "diverge-")
		if r.Divergent != want {
			t.Errorf("%s: divergent=%v, want %v (%s) framings=%+v", name, r.Divergent, want, r.Reason, r.Framings)
		}
	}
}

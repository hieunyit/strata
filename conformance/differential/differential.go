// Package differential compares how two HTTP stacks frame the same raw
// request (W08-R-01). The interesting divergences are in message framing —
// method, target and, above all, how the body length is determined
// (Content-Length vs Transfer-Encoding) — because a WAF and an origin that
// disagree there is exactly a request-smuggling vector. Each divergent input
// is a candidate for the conformance corpus and for Strata's ambiguous-
// protocol rules (100126/100128/100139, action_mode block_alone).
//
// Profiles:
//   - go-net-http: Go's real net/http request parser (http.ReadRequest).
//   - spring:      a strict RFC 7230 framing model of a Servlet container
//     (Tomcat/Coyote, which Spring Boot embeds): it rejects a
//     message that carries both Content-Length and
//     Transfer-Encoding, and conflicting duplicate
//     Content-Length values, rather than pick one.
package differential

import (
	"bufio"
	"bytes"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// BodyKind is how a stack decides the request body length.
type BodyKind string

const (
	BodyNone    BodyKind = "none"    // no body (length 0)
	BodyLength  BodyKind = "length"  // framed by Content-Length
	BodyChunked BodyKind = "chunked" // framed by Transfer-Encoding: chunked
	BodyError   BodyKind = "error"   // the stack rejects the message
)

// Framing is what one profile makes of a raw request.
type Framing struct {
	Profile string   `json:"profile"`
	Method  string   `json:"method"`
	Target  string   `json:"target"`
	Body    BodyKind `json:"body"`
	Length  int64    `json:"length"` // for BodyLength
	Err     string   `json:"err,omitempty"`
}

// Profile parses raw request bytes into a Framing.
type Profile func(raw []byte) Framing

// Profiles returns the differential profiles by name.
func Profiles() map[string]Profile {
	return map[string]Profile{
		"go-net-http": goNetHTTP,
		"spring":      spring,
	}
}

func goNetHTTP(raw []byte) Framing {
	f := Framing{Profile: "go-net-http"}
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(raw)))
	if err != nil {
		f.Body = BodyError
		f.Err = err.Error()
		return f
	}
	f.Method = req.Method
	f.Target = req.RequestURI
	switch {
	case hasChunked(req.TransferEncoding):
		f.Body = BodyChunked
	case req.ContentLength > 0:
		f.Body, f.Length = BodyLength, req.ContentLength
	default:
		f.Body = BodyNone
	}
	return f
}

func hasChunked(te []string) bool {
	for _, v := range te {
		if strings.EqualFold(strings.TrimSpace(v), "chunked") {
			return true
		}
	}
	return false
}

// spring models a Servlet container's strict framing. It parses the request
// line and headers itself so it can reject the ambiguous cases a lenient
// parser would silently resolve.
func spring(raw []byte) Framing {
	f := Framing{Profile: "spring"}
	reject := func(msg string) Framing { f.Body, f.Err = BodyError, msg; return f }

	head := raw
	if i := bytes.Index(raw, []byte("\r\n\r\n")); i >= 0 {
		head = raw[:i]
	}
	lines := strings.Split(string(head), "\r\n")
	if len(lines) == 0 || lines[0] == "" {
		return reject("empty request line")
	}
	parts := strings.Split(lines[0], " ")
	if len(parts) != 3 {
		return reject("malformed request line")
	}
	f.Method, f.Target = parts[0], parts[1]

	var cls []string
	te := false
	for _, ln := range lines[1:] {
		if ln == "" {
			continue
		}
		// a leading space/tab is obsolete line folding: rejected.
		if ln[0] == ' ' || ln[0] == '\t' {
			return reject("obsolete header line folding")
		}
		c := strings.IndexByte(ln, ':')
		if c < 0 {
			return reject("header without a colon")
		}
		name := strings.ToLower(strings.TrimSpace(ln[:c]))
		val := strings.TrimSpace(ln[c+1:])
		switch name {
		case "content-length":
			cls = append(cls, val)
		case "transfer-encoding":
			if strings.Contains(strings.ToLower(val), "chunked") {
				te = true
			}
		}
	}

	// RFC 7230 §3.3.3: Transfer-Encoding and Content-Length together is a
	// framing conflict; a strict container rejects it.
	if te && len(cls) > 0 {
		return reject("both Transfer-Encoding and Content-Length")
	}
	if te {
		f.Body = BodyChunked
		return f
	}
	if len(cls) == 0 {
		f.Body = BodyNone
		return f
	}
	// duplicate Content-Length: accept only if all values agree.
	first := cls[0]
	for _, v := range cls[1:] {
		if v != first {
			return reject("conflicting duplicate Content-Length")
		}
	}
	n, err := strconv.ParseInt(first, 10, 64)
	if err != nil || n < 0 {
		return reject("invalid Content-Length")
	}
	if n == 0 {
		f.Body = BodyNone
	} else {
		f.Body, f.Length = BodyLength, n
	}
	return f
}

// Result is the comparison of all profiles on one input.
type Result struct {
	Name      string    `json:"name"`
	Framings  []Framing `json:"framings"`
	Divergent bool      `json:"divergent"`
	Reason    string    `json:"reason,omitempty"`
}

// Compare runs every profile and flags a framing divergence: a disagreement
// on the body kind/length, or one stack accepting what another rejects.
func Compare(name string, raw []byte) Result {
	profs := Profiles()
	order := []string{"go-net-http", "spring"}
	r := Result{Name: name}
	for _, p := range order {
		r.Framings = append(r.Framings, profs[p](raw))
	}
	a, b := r.Framings[0], r.Framings[1]
	switch {
	case a.Body != b.Body:
		r.Divergent = true
		r.Reason = fmt.Sprintf("body kind %s(%s) vs %s(%s)", a.Profile, a.Body, b.Profile, b.Body)
	case a.Body == BodyLength && a.Length != b.Length:
		r.Divergent = true
		r.Reason = fmt.Sprintf("content-length %d vs %d", a.Length, b.Length)
	}
	return r
}

// Command strata-emit sends test events to strata_event_socket, the way an
// NGINX worker does: one strata.event.v1.Event per datagram. It is a lab
// and debugging tool: each event gets a fresh Block ID, printed on
// stdout, so the event can be looked up in the control plane.
package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	eventv1 "github.com/strata/strata/agent/gen/strata/event/v1"
)

const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// blockID returns STR-XXXX-XXXX-XXXX-XXXX with random characters.
func blockID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("random: %w", err)
	}
	var sb strings.Builder
	sb.WriteString("STR")
	for i, c := range b {
		if i%4 == 0 {
			sb.WriteByte('-')
		}
		sb.WriteByte(crockford[c%32])
	}
	return sb.String(), nil
}

func main() {
	socket := flag.String("event-socket", "unix:/run/strata/events.sock", "event socket (strata_event_socket)")
	n := flag.Int("n", 1, "number of events")
	host := flag.String("host", "api.example.test", "Host of the test events")
	flag.Parse()

	path := strings.TrimPrefix(*socket, "unix:")
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		fmt.Fprintln(os.Stderr, "strata-emit:", err)
		os.Exit(1)
	}
	defer conn.Close()
	for i := 0; i < *n; i++ {
		id, err := blockID()
		if err != nil {
			fmt.Fprintln(os.Stderr, "strata-emit:", err)
			os.Exit(1)
		}
		b, err := proto.Marshal(&eventv1.Event{
			BlockId: id, TimeUnixMs: uint64(time.Now().UnixMilli()), PolicyId: "example-api", BundleVersion: 1,
			ClientIp: "192.0.2.10", Method: "GET", Host: *host, Path: "/strata-emit", Status: 403,
			Action: eventv1.Action_ACTION_BLOCK, LayerScores: map[string]int32{"protocol": 100, "anomaly": 100},
			RuleIds: []uint32{100011},
			Matches: []*eventv1.Match{{RuleId: 100011, Layer: "protocol", Field: "REQUEST_URI_RAW", Snippet: []byte("/%2e%2e/")}},
		})
		if err != nil {
			fmt.Fprintln(os.Stderr, "strata-emit:", err)
			os.Exit(1)
		}
		if _, err := conn.Write(b); err != nil {
			fmt.Fprintln(os.Stderr, "strata-emit:", err)
			os.Exit(1)
		}
		fmt.Println(id)
	}
}

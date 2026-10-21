package bundlefmt

import (
	"crypto/ed25519"
	"encoding/binary"
	"reflect"
	"testing"
)

func TestRequirementsAuthenticatedAndBounded(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	body := build(t, priv, 1)
	body = body[:len(body)-sigSize]
	body[64+62] = 2
	body[64+63] = 4
	sign := func(b []byte) []byte { return append(append([]byte{}, b...), ed25519.Sign(priv, b)...) }
	got, err := Requirements(sign(body), pub)
	if err != nil || !reflect.DeepEqual(got, []string{"max_args", "snippet.4096"}) {
		t.Fatalf("%v %v", got, err)
	}
	body[64+62] = 3
	if _, err = Requirements(sign(body), pub); err == nil {
		t.Fatal("reserved snippet accepted")
	}
	body[64+62] = 0
	binary.LittleEndian.PutUint64(body[32:], ^uint64(0))
	binary.LittleEndian.PutUint64(body[40:], 24)
	if _, err = Requirements(sign(body), pub); err == nil {
		t.Fatal("overflowing sections accepted")
	}
	binary.LittleEndian.PutUint64(body[32:], 4096)
	if _, err = Requirements(sign(body), pub); err == nil {
		t.Fatal("out of bounds accepted")
	}
	bad := sign(body)
	bad[70] ^= 1
	if _, err = Requirements(bad, pub); err == nil {
		t.Fatal("tampering accepted")
	}
	if _, err = Requirements([]byte("short"), pub); err == nil {
		t.Fatal("truncated header accepted")
	}
}

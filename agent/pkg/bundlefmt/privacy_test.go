package bundlefmt

import (
	"crypto/ed25519"
	"encoding/binary"
	"testing"
)

func TestSignedPrivacyMetadataBoundsAndIdentity(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	// One policy; a single P-01 entry with one field, one pattern and HMAC.
	field, pattern := "customer_id", "PRIVATE-[0-9]+"
	section := make([]byte, 40+24+16+len(field)+len(pattern))
	binary.LittleEndian.PutUint32(section, 1)
	binary.LittleEndian.PutUint32(section[4:], 2)
	section[8] = 7
	binary.LittleEndian.PutUint32(section[48:], 1)
	binary.LittleEndian.PutUint32(section[52:], 1)
	binary.LittleEndian.PutUint32(section[56:], 1)
	binary.LittleEndian.PutUint32(section[60:], 1)
	binary.LittleEndian.PutUint32(section[68:], uint32(len(field)))
	binary.LittleEndian.PutUint32(section[72:], uint32(len(field)))
	binary.LittleEndian.PutUint32(section[76:], uint32(len(pattern)))
	copy(section[80:], field+pattern)
	body := make([]byte, 4096+32+len(section))
	copy(body, magic)
	binary.LittleEndian.PutUint16(body[8:], 1)
	binary.LittleEndian.PutUint32(body[12:], 1)
	binary.LittleEndian.PutUint64(body[32:], 4096)
	binary.LittleEndian.PutUint64(body[40:], uint64(32+len(section)))
	copy(body[64:], "example-api")
	body[126] = 4
	binary.LittleEndian.PutUint32(body[4096:], 1)
	binary.LittleEndian.PutUint32(body[4104:], 9)
	binary.LittleEndian.PutUint64(body[4112:], 4128)
	binary.LittleEndian.PutUint64(body[4120:], uint64(len(section)))
	copy(body[4128:], section)
	signed := func(b []byte) []byte { return append(append([]byte(nil), b...), ed25519.Sign(key, b)...) }
	filters, err := PrivacyFilters(signed(body), pub)
	if err != nil {
		t.Fatal(err)
	}
	f := filters["example-api"]
	if f.Field("ARGS:customer_id", "private") != "[MASKED]" || f.Text("PRIVATE-123") != "[MASKED]" {
		t.Fatal("policy privacy ignored")
	}
	identity := f.Identity("example-user")
	if identity == "example-user" || f.Identity(identity) != identity {
		t.Fatal("identity masking not stable")
	}
	for _, change := range []func([]byte){
		func(b []byte) { binary.LittleEndian.PutUint32(b[4128:], ^uint32(0)) },
		func(b []byte) { binary.LittleEndian.PutUint32(b[4128+40:], 1) },
		func(b []byte) { binary.LittleEndian.PutUint32(b[4128+68:], ^uint32(0)) },
		func(b []byte) { clear(b[4128+8 : 4128+40]) },
	} {
		broken := append([]byte(nil), body...)
		change(broken)
		if _, err := PrivacyFilters(signed(broken), pub); err == nil {
			t.Fatal("malformed signed privacy accepted")
		}
	}
	corrupt := signed(body)
	corrupt[64] ^= 1
	if _, err := PrivacyFilters(corrupt, pub); err == nil {
		t.Fatal("unauthenticated privacy accepted")
	}
}

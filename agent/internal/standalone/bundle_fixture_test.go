package standalone

import (
	"crypto/ed25519"
	"encoding/binary"
)

func makeTestBundleWithKey(version uint64, seed byte, priv ed25519.PrivateKey) []byte {
	data := make([]byte, 128)
	copy(data[:8], "STRBNDL\x00")
	binary.LittleEndian.PutUint16(data[8:], 1) // format = 1
	binary.LittleEndian.PutUint16(data[10:], 0)
	binary.LittleEndian.PutUint32(data[12:], 1) // 1 policy
	binary.LittleEndian.PutUint64(data[16:], version)
	binary.LittleEndian.PutUint64(data[24:], 1000)
	for i := 32; i < 64; i++ {
		data[i] = seed
	}

	body := data[:64]
	sig := ed25519.Sign(priv, body)
	return append(body, sig...)
}
func makeTestBundle(version uint64, seed byte) ([]byte, ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic(err)
	}
	return makeTestBundleWithKey(version, seed, priv), pub, priv
}

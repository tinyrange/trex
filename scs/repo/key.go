package repo

import (
	"crypto/sha256"
	"encoding/hex"
)

// Pointer-free index keys let the GC skip the multi-million-object indexes.
type objectKey [32]byte

func key(id ID) (k objectKey) {
	if len(id) != 64 {
		return
	}
	if _, e := hex.Decode(k[:], []byte(id)); e != nil {
		return objectKey{}
	}
	return
}
func keyBytes(b []byte) (k objectKey) { copy(k[:], b); return }
func (k objectKey) ID() ID {
	if k == (objectKey{}) {
		return ""
	}
	return ID(hex.EncodeToString(k[:]))
}

func digestKey(kind byte, data []byte) objectKey {
	h := sha256.New()
	h.Write([]byte{kind})
	h.Write(data)
	var k objectKey
	h.Sum(k[:0])
	return k
}

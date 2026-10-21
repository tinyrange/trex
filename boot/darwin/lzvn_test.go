package darwin

import (
	"bytes"
	"encoding/binary"
	"hash/adler32"
	"testing"
)

func lzvnCache(raw []byte) []byte {
	cache := make([]byte, 384)
	copy(cache, "complzvn")
	binary.BigEndian.PutUint32(cache[8:], adler32.Checksum(raw))
	binary.BigEndian.PutUint32(cache[12:], uint32(len(raw)))
	for off := 0; off < len(raw); {
		n := min(271, len(raw)-off)
		if n < 16 {
			cache = append(cache, byte(0xe0+n))
		} else {
			cache = append(cache, 0xe0, byte(n-16))
		}
		cache = append(cache, raw[off:off+n]...)
		off += n
	}
	cache = append(cache, 6, 0, 0, 0, 0, 0, 0, 0)
	binary.BigEndian.PutUint32(cache[16:], uint32(len(cache)-384))
	return cache
}
func TestLZVNKernelCacheIntegrityAndBounds(t *testing.T) {
	raw := fixture()
	good := lzvnCache(raw)
	img, err := Open(source{bytes.NewReader(good)})
	if err != nil || img.Entry != 0x200200 || !bytes.Equal(img.Data, raw) {
		t.Fatal("original decoded Mach-O differs", err)
	}
	for _, mutate := range []func([]byte){
		func(b []byte) { b[8] ^= 1 },
		func(b []byte) { binary.BigEndian.PutUint32(b[12:], MaxKernelSize+1) },
		func(b []byte) { binary.BigEndian.PutUint32(b[12:], uint32(len(raw)-1)) },
		func(b []byte) { b[len(b)-8] = 0x1e },
		func(b []byte) { b[16] ^= 1 },
	} {
		bad := bytes.Clone(good)
		mutate(bad)
		if img, err := Open(source{bytes.NewReader(bad)}); img != nil || err == nil {
			t.Fatal("invalid cache accepted", err)
		}
	}
	if img, err := Open(source{bytes.NewReader(good[:len(good)-1])}); img != nil || err == nil {
		t.Fatal("truncated cache accepted")
	}
}

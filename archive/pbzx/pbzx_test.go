package pbzx

import (
	"bytes"
	"encoding/binary"
	"github.com/tinyrange/trex/auto"
	encoder "github.com/ulikunitz/xz"
	"io"
	"testing"
)

func fixture(t *testing.T) []byte {
	t.Helper()
	var packed bytes.Buffer
	w, err := (encoder.WriterConfig{DictCap: 1 << 20}).NewWriter(&packed)
	if err != nil {
		t.Fatal(err)
	}
	w.Write(bytes.Repeat([]byte{'X'}, 4096))
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 12)
	copy(b, "pbzx")
	binary.BigEndian.PutUint64(b[4:], 4096)
	for _, pair := range []struct {
		size uint64
		data []byte
	}{{4096, packed.Bytes()}, {17, bytes.Repeat([]byte{'R'}, 17)}} {
		var h [16]byte
		binary.BigEndian.PutUint64(h[:], pair.size)
		binary.BigEndian.PutUint64(h[8:], uint64(len(pair.data)))
		b = append(b, h[:]...)
		b = append(b, pair.data...)
	}
	return b
}
func TestMixedChunksRandomAccess(t *testing.T) {
	f, err := Open(bytes.NewReader(fixture(t)), 0)
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 22)
	n, err := f.ReadAt(b, 4088)
	if n != 22 || err != nil || string(b) != string(bytes.Repeat([]byte{'X'}, 8))+string(bytes.Repeat([]byte{'R'}, 14)) {
		t.Fatalf("cross-chunk %q %d %v", b, n, err)
	}
	if _, err := f.ReadAt(b, 4100); err != io.EOF {
		t.Fatal("EOF", err)
	}
	if _, err := f.ReadAt(b, 0); err != nil {
		t.Fatal("backward", err)
	}
	if f.cache.Stats().Hits == 0 {
		t.Fatal("missing cache reuse")
	}
	result, err := auto.Identify(bytes.NewReader(fixture(t)), auto.Options{})
	if err != nil || result.Format != "pbzx" {
		t.Fatalf("auto %v %v", result, err)
	}
	if _, err := Open(bytes.NewReader(fixture(t)), 4096); err == nil {
		t.Fatal("limit not honored")
	}
}
func TestRejectBadFraming(t *testing.T) {
	for name, mutate := range map[string]func([]byte) []byte{
		"truncated": func(b []byte) []byte { return b[:len(b)-1] },
		"size":      func(b []byte) []byte { binary.BigEndian.PutUint64(b[12:], 4095); return b },
		"overflow":  func(b []byte) []byte { binary.BigEndian.PutUint64(b[20:], 1<<63); return b },
		"trailing":  func(b []byte) []byte { return append(b, 0) },
		"zero":      func(b []byte) []byte { binary.BigEndian.PutUint64(b[12:], 0); return b },
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Open(bytes.NewReader(mutate(fixture(t))), 0); err == nil {
				t.Fatal("accepted malformed PBZX")
			}
		})
	}
}
func TestRejectCorruptXZData(t *testing.T) {
	b := fixture(t)
	b[12+16+40] ^= 1
	f, err := Open(bytes.NewReader(b), 0)
	if err == nil {
		var p [1]byte
		if _, err = f.ReadAt(p[:], 0); err == nil {
			t.Fatal("accepted corrupt XZ")
		}
	}
}

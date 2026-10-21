package pbze

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
)

func frame(bound uint64, data ...[]byte) []byte {
	b := append([]byte("pbze"), make([]byte, 8)...)
	binary.BigEndian.PutUint64(b[4:], bound)
	for i, raw := range data {
		stored := raw
		if i%2 == 0 { // Use a valid LZFSE stored block, independently framed.
			stored = append([]byte("bvx-"), make([]byte, 4)...)
			binary.LittleEndian.PutUint32(stored[4:], uint32(len(raw)))
			stored = append(stored, raw...)
			stored = append(stored, []byte("bvx$")...)
		}
		h := make([]byte, 16)
		binary.BigEndian.PutUint64(h, uint64(len(raw)))
		binary.BigEndian.PutUint64(h[8:], uint64(len(stored)))
		b = append(append(b, h...), stored...)
	}
	return b
}

func TestChunkBoundaryReads(t *testing.T) {
	b := frame(8, []byte("abcdefgh"), []byte("ijklmnop"), []byte("qrst"))
	f, err := Open(bytes.NewReader(b), 20)
	if err != nil {
		t.Fatal(err)
	}
	p := make([]byte, 12)
	if n, err := f.ReadAt(p, 6); err != nil || n != 12 || string(p) != "ghijklmnopqr" {
		t.Fatalf("crossing read %d %q %v", n, p, err)
	}
	p = make([]byte, 5)
	if n, err := f.ReadAt(p, 18); err != io.EOF || n != 2 || string(p[:n]) != "st" {
		t.Fatalf("EOF read %d %q %v", n, p, err)
	}
	if _, err := f.ReadAt(p, -1); err == nil {
		t.Fatal("accepted negative offset")
	}
}

func TestRejectMalformedFraming(t *testing.T) {
	good := frame(8, []byte("abcdefgh"), []byte("ijk"))
	cases := map[string]func([]byte) []byte{
		"magic":           func(b []byte) []byte { b[3] = 'x'; return b },
		"zero-bound":      func(b []byte) []byte { binary.BigEndian.PutUint64(b[4:], 0); return b },
		"packed-overflow": func(b []byte) []byte { binary.BigEndian.PutUint64(b[20:], ^uint64(0)); return b },
		"size-mismatch":   func(b []byte) []byte { binary.BigEndian.PutUint64(b[12:], 7); return b },
		"truncated":       func(b []byte) []byte { return b[:len(b)-1] },
		"trailing":        func(b []byte) []byte { return append(b, 0) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Open(bytes.NewReader(mutate(bytes.Clone(good))), 0); err == nil {
				t.Fatal("accepted malformed stream")
			}
		})
	}
	if _, err := Open(bytes.NewReader(good), 10); err == nil {
		t.Fatal("ignored decoded bound")
	}
}

package binary

import (
	"bytes"
	"testing"
)

func TestSLIPWireAndChunkBoundaries(t *testing.T) {
	payload := []byte{0xff, 0x10, 0xc0, 0xdb, 0}
	wire := []byte{0xc0, 0xff, 0x10, 0xdb, 0xdc, 0xdb, 0xdd, 0, 0xc0}
	encoded, err := SLIPEncode(payload, 5)
	if err != nil || !bytes.Equal(encoded, wire) {
		t.Fatalf("wire=%x err=%v", encoded, err)
	}
	for split := range len(wire) + 1 {
		first, tail, err := SLIPDecode(wire[:split], 5)
		if err != nil {
			t.Fatal(err)
		}
		second, tail, err := SLIPDecode(append(tail, wire[split:]...), 5)
		if err != nil || len(tail) != 0 {
			t.Fatalf("split%d tail=%x err=%v", split, tail, err)
		}
		all := append(first, second...)
		if len(all) != 1 || !bytes.Equal(all[0], payload) {
			t.Fatalf("split%d packets=%x", split, all)
		}
	}
	packets, tail, err := SLIPDecode([]byte{0xc0, 0xc0, 1, 0xc0, 2, 0xc0, 3, 0xdb}, 5)
	if err != nil || len(packets) != 2 || !bytes.Equal(packets[0], []byte{1}) || !bytes.Equal(packets[1], []byte{2}) || !bytes.Equal(tail, []byte{3, 0xdb}) {
		t.Fatalf("packets=%x tail=%x err=%v", packets, tail, err)
	}
}

func TestSLIPRejectsMalformedAndOversizedFrames(t *testing.T) {
	for _, wire := range [][]byte{{1, 0xdb, 0xc0}, {1, 0xdb, 0x11, 0xc0}, {1, 2, 3, 0xc0}, {1, 0xc0, 2, 0xdb, 0x11}} {
		p, r, err := SLIPDecode(wire, 2)
		if err == nil || p != nil || r != nil {
			t.Fatalf("accepted malformed%x", wire)
		}
	}
	if _, err := SLIPEncode([]byte{1, 2, 3}, 2); err == nil {
		t.Fatal("encode limit ignored")
	}
	if _, _, err := SLIPDecode(nil, 0); err == nil {
		t.Fatal("invalid limit accepted")
	}
}

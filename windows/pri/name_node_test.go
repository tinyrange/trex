package pri

import (
	"encoding/hex"
	"testing"
)

func TestWinUIFilesNameNode(t *testing.T) {
	// Twelve-byte node at schema section offset228 in the hash-checked WinUI
	// PRI. Byte pool starts at offset3176 with NUL, Files, NUL.
	b, _ := hex.DecodeString("000005004600053001000100")
	n, err := ParseNameNode(b, false)
	if err != nil {
		t.Fatal(err)
	}
	if n.Parent != 0 || n.FullLength != 5 || n.Initial != 'F' || !n.Scope || !n.ByteString || n.Index != 1 || n.StringOffset != 1 {
		t.Fatalf("node: %+v", n)
	}
	name, err := n.Segment(nil, []byte("\x00Files\x00"))
	if err != nil || name != "Files" {
		t.Fatalf("segment %q: %v", name, err)
	}
}

func TestNameNodeOffsetBits(t *testing.T) {
	small := make([]byte, 12)
	small[7] = 0xff
	le.PutUint16(small[8:], 0xabcd)
	n, err := ParseNameNode(small, false)
	if err != nil || n.StringOffset != 0x3fabcd {
		t.Fatalf("small: %+v %v", n, err)
	}
	large := make([]byte, 20)
	le.PutUint32(large, 70000)
	le.PutUint32(large[16:], 80000)
	large[9] = 0x3f
	large[10] = 0xab
	le.PutUint16(large[12:], 0xcdef)
	n, err = ParseNameNode(large, true)
	if err != nil || n.StringOffset != 0x0fabcdef || n.Parent != 70000 || n.Index != 80000 || !n.Scope || !n.ByteString {
		t.Fatalf("large: %+v %v", n, err)
	}
	for _, large := range []bool{false, true} {
		for size := 0; size < 24; size++ {
			_, err := ParseNameNode(make([]byte, size), large)
			valid := (!large && size == 12) || (large && size == 20)
			if (err == nil) != valid {
				t.Fatalf("extent %d/%v: %v", size, large, err)
			}
		}
	}
}

func TestNameSegment(t *testing.T) {
	n := NameNode{SegmentLength: 2}
	value, err := n.Segment([]byte{0x3d, 0xd8, 0, 0xde, 0, 0}, nil)
	if err != nil || value != "😀" {
		t.Fatalf("UTF16: %q %v", value, err)
	}
	for _, pool := range [][]byte{{0, 0}, {0x3d, 0xd8, 0, 0, 0, 0}, {65, 0, 66, 0}, {65, 0, 66, 0, 1, 0}, {65, 0, 0, 0, 0, 0}} {
		if _, err := n.Segment(pool, nil); err == nil {
			t.Fatalf("accepted %x", pool)
		}
	}
	n = NameNode{ByteString: true, SegmentLength: 1}
	value, err = n.Segment(nil, []byte{0xff, 0})
	if err != nil || value != "\uffff" {
		t.Fatalf("signed byte: %q %v", value, err)
	}
	n.StringOffset = 0xffffffff
	if _, err := n.Segment(nil, []byte{0}); err == nil {
		t.Fatal("accepted out-of-pool offset")
	}
}

func FuzzNameNode(f *testing.F) {
	f.Add([]byte{0, 0, 5, 0, 70, 0, 5, 0x30, 1, 0, 1, 0}, false, []byte("\x00Files\x00"))
	f.Add(make([]byte, 20), true, []byte{0, 0})
	f.Fuzz(func(t *testing.T, data []byte, large bool, pool []byte) {
		n, err := ParseNameNode(data, large)
		if err != nil {
			return
		}
		_, _ = n.Segment(pool, pool)
	})
}

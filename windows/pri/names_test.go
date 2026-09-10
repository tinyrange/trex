package pri

import "testing"

func namesFixture(extended, large bool) []byte {
	h, nw, sw, iw := 24, 12, 8, 2
	if extended {
		h = 28
	}
	if large {
		nw, sw, iw = 20, 16, 4
	}
	pool := []byte("\x00Files\x00logo.png\x00")
	if !extended {
		wide := make([]byte, len(pool)*2)
		for i, b := range pool {
			wide[i*2] = b
		}
		pool = wide
	}
	b := make([]byte, h+3*nw+2*sw+iw+len(pool))
	le.PutUint32(b[4:], 3)
	le.PutUint32(b[8:], 2)
	le.PutUint32(b[12:], 1)
	le.PutUint32(b[20:], uint32(len(b)))
	if extended {
		le.PutUint32(b[24:], uint32(len(pool)))
	} else {
		le.PutUint32(b[16:], uint32(len(pool)/2))
	}
	if large {
		le.PutUint16(b[2:], 1)
	}
	for i := 0; i < 3; i++ {
		off := h + i*nw
		parent, full, initial, length, flags, offset, index := uint32(0), uint16(0), uint16(0), byte(0), byte(0x10), uint16(0), uint32(i)
		if i == 1 {
			full, initial, length, offset = 5, 'F', 5, 1
		}
		if i == 2 {
			parent, full, initial, length, flags, offset, index = 1, 14, 'L', 8, 0, 7, 0
		}
		if extended {
			flags |= 0x20
		}
		if large {
			le.PutUint32(b[off:], parent)
			le.PutUint16(b[off+4:], full)
			le.PutUint16(b[off+6:], initial)
			b[off+8], b[off+9] = length, flags
			le.PutUint16(b[off+12:], offset)
			le.PutUint32(b[off+16:], index)
		} else {
			le.PutUint16(b[off:], uint16(parent))
			le.PutUint16(b[off+2:], full)
			le.PutUint16(b[off+4:], initial)
			b[off+6], b[off+7] = length, flags
			le.PutUint16(b[off+8:], offset)
			le.PutUint16(b[off+10:], uint16(index))
		}
	}
	off := h + 3*nw
	// Scope zero points to node zero; scope one points to node one.
	le.PutUint16(b[off+sw:], 1)
	off += 2 * sw
	le.PutUint16(b[off:], 2)
	copy(b[off+iw:], pool)
	return b
}

func TestNamesTraversal(t *testing.T) {
	for _, extended := range []bool{false, true} {
		for _, large := range []bool{false, true} {
			b := namesFixture(extended, large)
			n, err := ParseNames(b, extended)
			if err != nil {
				t.Fatal(err)
			}
			name, err := n.ItemName(0)
			if err != nil || name != "Files/logo.png" || n.ItemCount() != 1 {
				t.Fatalf("name %q: %v", name, err)
			}
			if _, err := n.ItemName(1); err == nil {
				t.Fatal("accepted missing item")
			}
			for i := range b {
				if _, err := ParseNames(b[:i], extended); err == nil {
					t.Fatalf("accepted truncation %d", i)
				}
			}
		}
	}
}

func TestNamesMalformed(t *testing.T) {
	for _, tc := range []struct {
		offset int
		value  uint32
	}{
		{4, 0xffffffff}, {8, 0}, {12, 0xffffffff}, {16, 0xffffffff}, {20, 0}, {24, 0xffffffff},
		{28 + 36 + 8, 2}, {28 + 36 + 16, 1},
	} {
		b := namesFixture(true, false)
		le.PutUint32(b[tc.offset:], tc.value)
		if _, err := ParseNames(b, true); err == nil {
			t.Fatalf("accepted mutation %d", tc.offset)
		}
	}
	for _, parent := range []uint16{2, 65535} {
		b := namesFixture(true, false)
		le.PutUint16(b[28+24:], parent)
		n, err := ParseNames(b, true)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := n.ItemName(0); err == nil {
			t.Fatal("accepted cycle/out-of-range parent")
		}
	}
}

func FuzzNames(f *testing.F) {
	f.Add(namesFixture(true, false), true)
	f.Add(namesFixture(false, true), false)
	f.Fuzz(func(t *testing.T, b []byte, extended bool) {
		n, err := ParseNames(b, extended)
		if err != nil {
			return
		}
		if n.ItemCount() > 0 {
			_, _ = n.ItemName(0)
		}
	})
}

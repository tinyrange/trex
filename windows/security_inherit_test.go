package windows

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestInheritFileACLNativeFlags(t *testing.T) {
	// RtlpInheritAcl2 (base ntdll RVA 0x53e50), absent explicit ACL, auto=1,
	// supplied System owner and Administrators group, kind=1. Empty cases
	// return STATUS_NO_INHERITANCE, not a directive to install an empty DACL.
	callback := explicitTestHex(t, "09009800a90012000102000000000005200000002102000061727478f81c000000570049004e003a002f002f005300590053004100500050004900440010520000004d006900630072006f0073006f0066007400570069006e0064006f00770073002e0043006c00690065006e0074002e004300420053005f006300770035006e0031006800320074007800790065007700790086000000")
	owner := explicitTestHex(t, "010100000000000512000000")
	group := explicitTestHex(t, "01020000000000052000000020020000")
	type output struct {
		flags byte
		mask  uint32
	}
	for _, tc := range []struct {
		flags     byte
		file, dir []output
	}{
		{0, nil, nil},
		{1, []output{{16, 0x1200a9}}, []output{{25, 0xa0000000}}},
		{2, nil, []output{{16, 0x1200a9}, {26, 0xa0000000}}},
		{3, []output{{16, 0x1200a9}}, []output{{16, 0x1200a9}, {27, 0xa0000000}}},
		{5, []output{{16, 0x1200a9}}, nil},
		{6, nil, []output{{16, 0x1200a9}}},
		{7, []output{{16, 0x1200a9}}, []output{{16, 0x1200a9}}},
		{9, []output{{16, 0x1200a9}}, []output{{25, 0xa0000000}}},
		{10, nil, []output{{16, 0x1200a9}, {26, 0xa0000000}}},
		{11, []output{{16, 0x1200a9}}, []output{{16, 0x1200a9}, {27, 0xa0000000}}},
	} {
		for _, directory := range []bool{false, true} {
			ace := bytes.Clone(callback)
			ace[1] = tc.flags
			binary.LittleEndian.PutUint32(ace[4:], 0xa0000000)
			parent := explicitTestACL(ace)
			before := bytes.Clone(parent)
			got, err := InheritFileACL(parent, owner, group, directory)
			if err != nil {
				t.Fatal(err)
			}
			expected := tc.file
			if directory {
				expected = tc.dir
			}
			var wantACEs [][]byte
			for _, item := range expected {
				raw := bytes.Clone(callback)
				raw[1] = item.flags
				binary.LittleEndian.PutUint32(raw[4:], item.mask)
				wantACEs = append(wantACEs, raw)
			}
			if want := explicitTestACL(wantACEs...); !bytes.Equal(got, want) {
				t.Fatalf("flags=%x dir=%v: got %x want %x", tc.flags, directory, got, want)
			}
			if !bytes.Equal(parent, before) {
				t.Fatal("mutated parent")
			}
		}
	}
}

func TestInheritFileACLNativeCoverage(t *testing.T) {
	owner := explicitTestHex(t, "010100000000000512000000")
	ordinary := explicitTestHex(t, "00031800a900120001020000000000052000000020020000")
	callback := explicitTestHex(t, "09009800a90012000102000000000005200000002102000061727478f81c000000570049004e003a002f002f005300590053004100500050004900440010520000004d006900630072006f0073006f0066007400570069006e0064006f00770073002e0043006c00690065006e0074002e004300420053005f006300770035006e0031006800320074007800790065007700790086000000")
	for _, tc := range []struct {
		name      string
		ace       []byte
		masks     []uint32
		flags     []byte
		wantMasks []uint32
	}{
		{"ordinary duplicate", ordinary, []uint32{0xa0000000, 0xa0000000}, []byte{16, 27}, []uint32{0x1200a9, 0xa0000000}},
		{"callback duplicates retained", callback, []uint32{0xa0000000, 0xa0000000}, []byte{16, 27, 16, 27}, []uint32{0x1200a9, 0xa0000000, 0x1200a9, 0xa0000000}},
		{"earlier superset", ordinary, []uint32{0x1200a9, 0x120089}, []byte{19}, []uint32{0x1200a9}},
		{"later superset not coalesced", ordinary, []uint32{0x120089, 0x1200a9}, []byte{19, 19}, []uint32{0x120089, 0x1200a9}},
		{"joint coverage", ordinary, []uint32{1, 2, 3}, []byte{19, 19}, []uint32{1, 2}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var inputs, expected [][]byte
			for _, mask := range tc.masks {
				a := bytes.Clone(tc.ace)
				a[1] = 3
				binary.LittleEndian.PutUint32(a[4:], mask)
				inputs = append(inputs, a)
			}
			for i, mask := range tc.wantMasks {
				a := bytes.Clone(tc.ace)
				a[1] = tc.flags[i]
				binary.LittleEndian.PutUint32(a[4:], mask)
				expected = append(expected, a)
			}
			got, err := InheritFileACL(explicitTestACL(inputs...), owner, owner, true)
			want := explicitTestACL(expected...)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("got %x want %x: %v", got, want, err)
			}
		})
	}
	// Parent zero-mask creators differ from explicit creator propagation.
	creator := explicitTestHex(t, "0003140000000000010100000000000300000000")
	got, err := InheritFileACL(explicitTestACL(creator), owner, owner, true)
	want := explicitTestACL(explicitTestHex(t, "0010140000000000010100000000000512000000"))
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("zero creator: %x %v", got, err)
	}
}

func TestInheritFileACLBoundsAndUnsupported(t *testing.T) {
	owner := explicitTestHex(t, "010100000000000512000000")
	callback := explicitTestHex(t, "09009800a90012000102000000000005200000002102000061727478f81c000000570049004e003a002f002f005300590053004100500050004900440010520000004d006900630072006f0073006f0066007400570069006e0064006f00770073002e0043006c00690065006e0074002e004300420053005f006300770035006e0031006800320074007800790065007700790086000000")
	callback[1] = 3
	binary.LittleEndian.PutUint32(callback[4:], 0xa0000000)
	valid := explicitTestACL(callback)
	for i := 0; i < len(valid); i++ {
		if _, err := InheritFileACL(valid[:i], owner, owner, true); err == nil {
			t.Fatalf("accepted prefix %d", i)
		}
	}
	for _, mutate := range []func([]byte){
		func(b []byte) { b[9] |= 0x20 },
		func(b []byte) { b[8] = 0x12 },
		func(b []byte) { b[17] = 255 },
	} {
		source := bytes.Clone(valid)
		mutate(source)
		if _, err := InheritFileACL(source, owner, owner, true); err == nil {
			t.Fatal("accepted unsupported parent")
		}
	}
	large := explicitTestACL(bytes.Repeat(callback, 300))
	binary.LittleEndian.PutUint16(large[4:], 300)
	if _, err := InheritFileACL(large, owner, owner, true); err == nil {
		t.Fatal("accepted expanded ACL overflow")
	}
	if _, err := InheritFileACL(valid, owner, nil, true); err == nil {
		t.Fatal("accepted missing group")
	}
}

func TestInheritFileACLNativeAuditSeparation(t *testing.T) {
	owner := explicitTestHex(t, "010100000000000512000000")
	parent := explicitTestACL(explicitTestHex(t, "0243140001000000010100000000000100000000"), explicitTestHex(t, "0283140001000000010100000000000100000000"))
	want := explicitTestACL(explicitTestHex(t, "0253140001000000010100000000000100000000"), explicitTestHex(t, "0293140001000000010100000000000100000000"))
	got, err := InheritFileACL(parent, owner, owner, true)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("audit flags merged: %x %v", got, err)
	}
}

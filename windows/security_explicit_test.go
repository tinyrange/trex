package windows

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

func explicitTestHex(t *testing.T, text string) []byte {
	t.Helper()
	data, err := hex.DecodeString(text)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
func explicitTestACL(aces ...[]byte) []byte {
	out := []byte{2, 0, 0, 0, 0, 0, 0, 0}
	for _, ace := range aces {
		out = append(out, ace...)
	}
	binary.LittleEndian.PutUint16(out[2:], uint16(len(out)))
	binary.LittleEndian.PutUint16(out[4:], uint16(len(aces)))
	return out
}

func TestCopyExplicitFileACLNativeVectors(t *testing.T) {
	// Independent outputs of base ntdll RtlpCopyAces (RVA 0x55150), PDB
	// C3093720177DA6851519DCFFE8DF53FE1, executed by the in-process AMD64
	// emulator. Selection=all, clearFlags=0, effective=1, preserveInherited=0,
	// ACL kind=1; owner=System, group=Administrators. Every call returned 0.
	owner := explicitTestHex(t, "010100000000000512000000")
	group := explicitTestHex(t, "01020000000000052000000020020000")
	callback := explicitTestHex(t, "09009800a90012000102000000000005200000002102000061727478f81c000000570049004e003a002f002f005300590053004100500050004900440010520000004d006900630072006f0073006f0066007400570069006e0064006f00770073002e0043006c00690065006e0074002e004300420053005f006300770035006e0031006800320074007800790065007700790086000000")
	// The file-effective callback also independently equals WIM security 432.
	tests := []struct {
		name      string
		directory bool
		flags     byte
		mask      uint32
		source    []byte
		want      []string
	}{
		{"file callback", false, 3, 0xa0000000, callback, []string{hex.EncodeToString(callback)}},
		{"directory callback split", true, 3, 0xa0000000, callback, nil},
		{"directory mapped callback merged", true, 3, 0x1200a9, callback, nil},
		{"directory no propagate split", true, 7, 0xa0000000, callback, nil},
		{"file inherit only omitted", false, 11, 0xa0000000, callback, []string{}},
		{"directory inherit only retained", true, 11, 0xa0000000, callback, nil},
		{"file zero callback", false, 3, 0, callback, []string{}},
		{"directory zero callback", true, 3, 0, callback, nil},
		{"file maximum allowed clipped", false, 0, 0x02000000, callback, []string{}},
		{"file access system security clipped", false, 0, 0x01000000, callback, []string{}},
		{"creator owner file", false, 3, 0x10000000, explicitTestHex(t, "0003140000000010010100000000000300000000"), []string{"00001400ff011f00010100000000000512000000"}},
		{"creator owner directory", true, 3, 0x10000000, explicitTestHex(t, "0003140000000010010100000000000300000000"), []string{"00001400ff011f00010100000000000512000000", "000b140000000010010100000000000300000000"}},
		{"creator group directory", true, 3, 0x10000000, explicitTestHex(t, "0003140000000010010100000000000301000000"), []string{"00001800ff011f0001020000000000052000000020020000", "000b140000000010010100000000000301000000"}},
		{"zero creator owner", true, 3, 0, explicitTestHex(t, "0003140000000010010100000000000300000000"), []string{"0000140000000000010100000000000512000000", "000b140000000000010100000000000300000000"}},
		{"audit system security retained", false, 0xc3, 0x11000000, explicitTestHex(t, "02c0140016010d00010100000000000100000000"), []string{"02c01400ff011f01010100000000000100000000"}},
	}
	// Native callback outputs share exactly the WIM callback suffix, not a
	// reconstructed expression. Only headers/masks differ in these vectors.
	for i := range tests {
		tc := &tests[i]
		if tc.want != nil {
			continue
		}
		switch tc.name {
		case "directory callback split":
			tc.want = []string{hex.EncodeToString(callback), "090b9800000000a0" + hex.EncodeToString(callback[8:])}
		case "directory mapped callback merged":
			tc.want = []string{"09039800a9001200" + hex.EncodeToString(callback[8:])}
		case "directory no propagate split":
			tc.want = []string{hex.EncodeToString(callback), "090f9800000000a0" + hex.EncodeToString(callback[8:])}
		case "directory inherit only retained":
			tc.want = []string{"090b9800000000a0" + hex.EncodeToString(callback[8:])}
		case "directory zero callback":
			tc.want = []string{"090b980000000000" + hex.EncodeToString(callback[8:])}
		default:
			t.Fatal("missing native vector")
		}
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ace := bytes.Clone(tc.source)
			ace[1] = tc.flags
			binary.LittleEndian.PutUint32(ace[4:], tc.mask)
			source := explicitTestACL(ace)
			before := bytes.Clone(source)
			got, err := CopyExplicitFileACL(source, owner, group, tc.directory)
			if err != nil {
				t.Fatal(err)
			}
			var expected [][]byte
			for _, text := range tc.want {
				expected = append(expected, explicitTestHex(t, text))
			}
			want := explicitTestACL(expected...)
			if !bytes.Equal(got, want) {
				t.Fatalf("got %x\nwant %x", got, want)
			}
			if !bytes.Equal(source, before) {
				t.Fatal("mutated source")
			}
		})
	}
}

func TestCopyExplicitFileACLRejectsUnsupportedAndOverflow(t *testing.T) {
	owner := explicitTestHex(t, "010100000000000512000000")
	ace := explicitTestHex(t, "0003140000000010010100000000000512000000")
	valid := explicitTestACL(ace)
	for name, mutate := range map[string]func([]byte){
		"inherited":             func(b []byte) { b[9] |= 0x10 },
		"reserved flag":         func(b []byte) { b[9] |= 0x20 },
		"unknown type":          func(b []byte) { b[8] = 18 },
		"object ACE":            func(b []byte) { b[8] = 5 },
		"callback SID overflow": func(b []byte) { b[8] = 9; b[17] = 15 },
		"invalid SID":           func(b []byte) { b[16] = 2 },
		"server creator":        func(b []byte) { b[23] = 3; b[24] = 2 },
	} {
		t.Run(name, func(t *testing.T) {
			source := bytes.Clone(valid)
			mutate(source)
			if _, err := CopyExplicitFileACL(source, owner, owner, true); err == nil {
				t.Fatal("accepted unsupported input")
			}
		})
	}
	for i := 0; i < len(valid); i++ {
		if _, err := CopyExplicitFileACL(valid[:i], owner, owner, true); err == nil {
			t.Fatalf("accepted prefix %d", i)
		}
	}
	if _, err := CopyExplicitFileACL(valid, nil, owner, false); err == nil {
		t.Fatal("accepted missing owner")
	}
	large := explicitTestACL(bytes.Repeat(ace, 2000))
	binary.LittleEndian.PutUint16(large[4:], 2000)
	if _, err := CopyExplicitFileACL(large, owner, owner, true); err == nil {
		t.Fatal("accepted expanded ACL overflow")
	}
	// Empty ACL remains empty, and allocation slack is not interpreted as ACEs.
	empty := []byte{4, 0, 12, 0, 0, 0, 0, 0, 0xaa, 0xbb, 0xcc, 0xdd}
	got, err := CopyExplicitFileACL(empty, owner, owner, true)
	if err != nil || !bytes.Equal(got, []byte{4, 0, 8, 0, 0, 0, 0, 0}) {
		t.Fatalf("empty ACL: %x %v", got, err)
	}
}

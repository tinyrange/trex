package windows

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestInheritFileSecurityNative(t *testing.T) {
	// Independent field vectors from base ntdll RtlNewSecurityObjectEx,
	// flags=0x101b, token=NULL, file mapping, explicit System/Administrators.
	const ordinary = "0200200001000000000018008900120001020000000000052000000020020000"
	const inherited = "02001c000100000000101400ff011f00010100000000000512000000"
	const empty = "0200080000000000"
	for _, tc := range []struct {
		name, child, parent string
		dir                 bool
		control             uint16
		dacl, sacl          string
	}{
		{"sacl-merge", "O:SYG:BAD:S:(AU;SA;FR;;;WD)", "D:S:(AU;OICIFA;FW;;;BA)", false, 0x8c14, empty, "02003400020000000240140089001200010100000000000100000000029018001601120001020000000000052000000020020000"},
		{"sacl-protected", "O:SYG:BAD:S:P(AU;SAID;FR;;;WD)", "D:S:(AU;OICIFA;FW;;;BA)", false, 0xac14, empty, "02001c00010000000240140089001200010100000000000100000000"},
		{"auto-controls", "O:SYG:BAD:ARAI(A;;FR;;;BA)S:ARAI", "", false, 0x8c14, ordinary, empty},
		{"creator", "O:SYG:BAD:(A;OICI;GRGX;;;S-1-3-0)S:", "", true, 0x8c14, "020030000200000000001400a9001200010100000000000512000000000b1400000000a0010100000000000300000000", empty},
		{"protected", "O:SYG:BAD:P(A;OICI;GRGX;;;BA)S:P", "", false, 0xbc14, "020020000100000000001800a900120001020000000000052000000020020000", empty},
		{"merge-file", "O:SYG:BAD:(A;OICI;GRGX;;;BA)S:", "O:BAG:SYD:(A;OICI;FA;;;SY)S:", false, 0x8c14, "020034000200000000001800a90012000102000000000005200000002002000000101400ff011f00010100000000000512000000", empty},
		{"merge-directory", "O:SYG:BAD:(A;OICI;GRGX;;;BA)S:", "O:BAG:SYD:(A;OICI;FA;;;SY)S:", true, 0x8c14, "02004c000300000000001800a900120001020000000000052000000020020000000b1800000000a00102000000000005200000002002000000131400ff011f00010100000000000512000000", empty},
		{"absent", "O:SYG:BA", "", false, 0x9c00, "", ""},
		{"inherit", "O:SYG:BA", "D:(A;OICI;FA;;;SY)S:", false, 0x8c04, inherited, ""},
		{"empty-inherits", "O:SYG:BAD:", "D:(A;OICI;FA;;;SY)S:", false, 0x8c04, inherited, ""},
		{"protected-empty", "O:SYG:BAD:P", "D:(A;OICI;FA;;;SY)S:", false, 0x9c04, empty, ""},
		{"explicit", "O:SYG:BAD:(A;;FR;;;BA)", "", false, 0x8c04, ordinary, ""},
		{"empty-no-inheritance", "O:SYG:BAD:", "D:(A;;FA;;;SY)S:", false, 0x8c04, empty, ""},
		{"absent-no-inheritance", "O:SYG:BA", "D:(A;;FA;;;SY)S:", false, 0x9c00, "", ""},
		{"discard-inherited", "O:SYG:BAD:AI(A;ID;FR;;;BA)S:", "", false, 0x8c14, empty, empty},
		{"protected-inherited-becomes-explicit", "O:SYG:BAD:P(A;ID;FR;;;BA)S:", "", false, 0x9c14, ordinary, empty},
		{"replace-inherited", "O:SYG:BAD:(A;ID;FR;;;BA)S:", "D:(A;OICI;FA;;;SY)S:", false, 0x8c14, inherited, empty},
	} {
		t.Run(tc.name, func(t *testing.T) {
			child, err := CompileSDDL(tc.child)
			if err != nil {
				t.Fatal(err)
			}
			var parent []byte
			if tc.parent != "" {
				parent, err = CompileSDDL(tc.parent)
				if err != nil {
					t.Fatal(err)
				}
			}
			cb, pb := bytes.Clone(child), bytes.Clone(parent)
			got, err := InheritFileSecurity(child, parent, tc.dir)
			if err != nil {
				t.Fatal(err)
			}
			if control := binary.LittleEndian.Uint16(got[2:]); control != tc.control {
				t.Fatalf("control %x want %x", control, tc.control)
			}
			for _, f := range []struct {
				offset int
				acl    bool
				want   string
			}{
				{4, false, "010100000000000512000000"}, {8, false, "01020000000000052000000020020000"}, {12, true, tc.sacl}, {16, true, tc.dacl},
			} {
				offset := int(binary.LittleEndian.Uint32(got[f.offset:]))
				if f.want == "" {
					if offset != 0 {
						t.Fatalf("field %d not absent", f.offset)
					}
					continue
				}
				if offset < 20 || offset+8 > len(got) {
					t.Fatalf("invalid field %d offset", f.offset)
				}
				size := 8 + 4*int(got[offset+1])
				if f.acl {
					size = int(binary.LittleEndian.Uint16(got[offset+2:]))
				}
				if offset+size > len(got) || !bytes.Equal(got[offset:offset+size], explicitTestHex(t, f.want)) {
					t.Fatalf("field %d mismatch: %x", f.offset, got[offset:])
				}
			}
			if !bytes.Equal(child, cb) || !bytes.Equal(parent, pb) {
				t.Fatal("mutated input")
			}
		})
	}
}

func TestInheritFileSecurityRejectsUnresolvedPolicy(t *testing.T) {
	for _, sddl := range []string{"D:(A;;FR;;;BA)", "O:SYD:", "O:SYG:BAD:NO_ACCESS_CONTROL", "O:SYG:BAS:NO_ACCESS_CONTROL"} {
		data, err := CompileSDDL(sddl)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := InheritFileSecurity(data, nil, false); err == nil {
			t.Fatalf("accepted %s", sddl)
		}
	}
	data, _ := CompileSDDL("O:SYG:BAD:(A;;FR;;;BA)")
	for _, mutate := range []func([]byte){
		func(b []byte) { b[1] = 1 },
		func(b []byte) { b[2] |= 1 },
		func(b []byte) { b[3] |= 0x40 },
		func(b []byte) { b[16] = 0xff },
		func(b []byte) { off := int(binary.LittleEndian.Uint32(b[16:])); b[off] = 4 },
	} {
		bad := bytes.Clone(data)
		mutate(bad)
		if _, err := InheritFileSecurity(bad, nil, false); err == nil {
			t.Fatalf("accepted malformed/unsupported %x", bad)
		}
	}
	parent, _ := CompileSDDL("D:NO_ACCESS_CONTROL")
	parent[2] |= 8 // Defaulted parent DACL still requires separate policy.
	if _, err := InheritFileSecurity(data, parent, false); err == nil {
		t.Fatal("accepted defaulted parent NULL ACL")
	}
}

func TestInheritFileSecurityCombinedSizeLimit(t *testing.T) {
	child, _ := CompileSDDL("O:SYG:BAD:(A;;FR;;;BA)")
	start := int(binary.LittleEndian.Uint32(child[16:]))
	ace := bytes.Clone(child[start+8:])
	ace[0] = 9 // Callback entries are not deduplicated.
	var entries [][]byte
	for range 1400 {
		entries = append(entries, ace)
	}
	child = append(child[:start:start], explicitTestACL(entries...)...)
	parent := bytes.Clone(child)
	for i := start + 8; i < len(parent); i += len(ace) {
		parent[i+1] = 3
	}
	if _, err := InheritFileSecurity(child, parent, false); err == nil {
		t.Fatal("accepted overflowing combined ACL")
	}
}

func TestInheritFileSecurityNativeNullParents(t *testing.T) {
	// Pinned base ntdll flags=0x101b, NULL token, file mapping:
	// parent NULL DACL/SACL contribute no entries. They do not turn absent
	// or empty child ACLs into NULL ACLs, for either files or directories.
	for _, tc := range []struct {
		child   string
		control uint16
	}{
		{"O:SYG:SY", 0x9c00},
		{"O:SYG:SYD:S:", 0x8c14},
		{"O:SYG:SYD:(A;;FR;;;BA)S:(AU;SA;FR;;;WD)", 0x8c14},
	} {
		for _, parentSDDL := range []string{
			"O:BAG:BAD:NO_ACCESS_CONTROL",
			"O:BAG:BAS:NO_ACCESS_CONTROL",
			"O:BAG:BAD:NO_ACCESS_CONTROLS:NO_ACCESS_CONTROL",
		} {
			for _, dir := range []bool{false, true} {
				child, err := CompileSDDL(tc.child)
				if err != nil {
					t.Fatal(err)
				}
				parent, err := CompileSDDL(parentSDDL)
				if err != nil {
					t.Fatal(err)
				}
				beforeChild, beforeParent := bytes.Clone(child), bytes.Clone(parent)
				want := bytes.Clone(child)
				binary.LittleEndian.PutUint16(want[2:], tc.control)
				got, err := InheritFileSecurity(child, parent, dir)
				if err != nil {
					t.Fatal(err)
				}
				actual, err := readFileSecurityParts(got, false)
				if err != nil {
					t.Fatal(err)
				}
				expected, err := readFileSecurityParts(want, false)
				if err != nil {
					t.Fatal(err)
				}
				if actual.control != expected.control || !bytes.Equal(actual.owner, expected.owner) || !bytes.Equal(actual.group, expected.group) || !bytes.Equal(actual.dacl, expected.dacl) || !bytes.Equal(actual.sacl, expected.sacl) {
					t.Fatalf("child=%s parent=%s directory=%v: got %x want fields of %x", tc.child, parentSDDL, dir, got, want)
				}
				if !bytes.Equal(child, beforeChild) || !bytes.Equal(parent, beforeParent) {
					t.Fatal("mutated source or parent")
				}
			}
		}
	}
}

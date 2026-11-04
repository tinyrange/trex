package windows

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

func TestFileSecurityRightsMatchesNativeWRP(t *testing.T) {
	// Independently read security descriptor of image6/Windows/System32/kernel32.dll
	// from the 26300.9457 base WIM, including its SACL, owner and group.
	want, err := hex.DecodeString("010014901400000034000000f800000054000000010600000000000550000000b589fb381984c2cb5c6c236d5700776ec0026487010600000000000550000000b589fb381984c2cb5c6c236d5700776ec00264870200a4000600000000002800ff011f00010600000000000550000000b589fb381984c2cb5c6c236d5700776ec002648700001800a90012000102000000000005200000002002000000001400a900120001010000000000051200000000001800a90012000102000000000005200000002102000000001800a9001200010200000000000f020000000100000000001800a9001200010200000000000f020000000200000002001c000100000002c0140016010d00010100000000000100000000")
	if err != nil {
		t.Fatal(err)
	}
	ti := "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
	raw, err := CompileSDDL("O:" + ti + "G:" + ti + "D:P(A;;FA;;;" + ti + ")(A;;GRGX;;;BA)(A;;GRGX;;;SY)(A;;GRGX;;;BU)(A;;GRGX;;;S-1-15-2-1)(A;;GRGX;;;S-1-15-2-2)S:(AU;FASA;0x000D0116;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	original := bytes.Clone(raw)
	got, err := MapFileSecurityRights(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("descriptor:\ngot  %x\nwant %x", got, want)
	}
	if !bytes.Equal(raw, original) {
		t.Fatal("mutated source")
	}
	again, err := MapFileSecurityRights(got)
	if err != nil || !bytes.Equal(again, got) {
		t.Fatalf("not idempotent: %v", err)
	}
}

func TestFileSecurityRightsPreservesConditionsAndStates(t *testing.T) {
	raw, err := CompileSDDL(`O:SYD:PAI(XA;OICI;GRGX;;;BU;(WIN://SYSAPPID Contains "x"))S:NO_ACCESS_CONTROL`)
	if err != nil {
		t.Fatal(err)
	}
	expected := bytes.Clone(raw)
	d := int(binary.LittleEndian.Uint32(raw[16:]))
	binary.LittleEndian.PutUint32(expected[d+12:], 0x1200a9)
	got, err := MapFileSecurityRights(raw)
	if err != nil || !bytes.Equal(got, expected) {
		t.Fatalf("changed other bytes: %v", err)
	}
	for _, sddl := range []string{"O:SY", "D:", "D:NO_ACCESS_CONTROL"} {
		raw, err := CompileSDDL(sddl)
		if err != nil {
			t.Fatal(err)
		}
		got, err := MapFileSecurityRights(raw)
		if err != nil || !bytes.Equal(raw, got) {
			t.Fatalf("%s: %v", sddl, err)
		}
	}
}

func TestFileSecurityRightsRejectsMalformed(t *testing.T) {
	valid, err := CompileSDDL("O:SYD:(A;;GR;;;BU)")
	if err != nil {
		t.Fatal(err)
	}
	d := int(binary.LittleEndian.Uint32(valid[16:]))
	for name, mutate := range map[string]func([]byte){
		"missing present":    func(b []byte) { b[2] &= ^byte(4) },
		"overlap":            func(b []byte) { binary.LittleEndian.PutUint32(b[4:], uint32(d+8)) },
		"unaligned":          func(b []byte) { binary.LittleEndian.PutUint32(b[16:], uint32(d+1)) },
		"unknown ACE":        func(b []byte) { b[d+8] = 0x12 },
		"short callback SID": func(b []byte) { b[d+8] = 9; b[d+17] = 15 },
		"bad owner revision": func(b []byte) { b[20] = 2 },
	} {
		t.Run(name, func(t *testing.T) {
			raw := bytes.Clone(valid)
			mutate(raw)
			if _, err := MapFileSecurityRights(raw); err == nil {
				t.Fatal("accepted malformed descriptor")
			}
		})
	}
	for i := 0; i < len(valid); i++ {
		if _, err := MapFileSecurityRights(valid[:i]); err == nil {
			t.Fatalf("accepted prefix %d", i)
		}
	}
}

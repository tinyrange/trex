package windows

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestInheritFileACLNativeMandatoryLabel(t *testing.T) {
	// Independent base-image ntdll RtlNewSecurityObjectEx (RVA 0x510a0),
	// flags 0x101b, token NULL, explicit O:SYG:SY, parent S:(ML;...;0/7;;;LW).
	// These are parent-only labels; no token-default label is selected.
	owner := explicitTestHex(t, "010100000000000512000000")
	for _, tc := range []struct {
		mask      uint32
		flags     byte
		directory bool
		want      string
	}{
		{0, 0, false, "0200080000000000"},
		{0, 0, true, "0200080000000000"},
		{0, 1, false, "02001c00010000001110140000000000010100000000001000100000"},
		{0, 1, true, "02001c00010000001119140000000000010100000000001000100000"},
		{0, 2, false, "0200080000000000"},
		{0, 2, true, "02001c00010000001112140000000000010100000000001000100000"},
		{0, 3, false, "02001c00010000001110140000000000010100000000001000100000"},
		{0, 3, true, "02001c00010000001113140000000000010100000000001000100000"},
		{0, 4, false, "0200080000000000"},
		{0, 4, true, "0200080000000000"},
		{0, 5, false, "02001c00010000001110140000000000010100000000001000100000"},
		{0, 5, true, "0200080000000000"},
		{0, 6, false, "0200080000000000"},
		{0, 6, true, "02001c00010000001110140000000000010100000000001000100000"},
		{0, 7, false, "02001c00010000001110140000000000010100000000001000100000"},
		{0, 7, true, "02001c00010000001110140000000000010100000000001000100000"},
		{0, 8, false, "0200080000000000"},
		{0, 8, true, "0200080000000000"},
		{0, 9, false, "02001c00010000001110140000000000010100000000001000100000"},
		{0, 9, true, "02001c00010000001119140000000000010100000000001000100000"},
		{0, 10, false, "0200080000000000"},
		{0, 10, true, "02001c00010000001112140000000000010100000000001000100000"},
		{0, 11, false, "02001c00010000001110140000000000010100000000001000100000"},
		{0, 11, true, "02001c00010000001113140000000000010100000000001000100000"},
		{0, 12, false, "0200080000000000"},
		{0, 12, true, "0200080000000000"},
		{0, 13, false, "02001c00010000001110140000000000010100000000001000100000"},
		{0, 13, true, "0200080000000000"},
		{0, 14, false, "0200080000000000"},
		{0, 14, true, "02001c00010000001110140000000000010100000000001000100000"},
		{0, 15, false, "02001c00010000001110140000000000010100000000001000100000"},
		{0, 15, true, "02001c00010000001110140000000000010100000000001000100000"},
		{7, 0, false, "0200080000000000"},
		{7, 0, true, "0200080000000000"},
		{7, 1, false, "02001c00010000001110140007000000010100000000001000100000"},
		{7, 1, true, "02001c00010000001119140007000000010100000000001000100000"},
		{7, 2, false, "0200080000000000"},
		{7, 2, true, "02001c00010000001112140007000000010100000000001000100000"},
		{7, 3, false, "02001c00010000001110140007000000010100000000001000100000"},
		{7, 3, true, "02001c00010000001113140007000000010100000000001000100000"},
		{7, 4, false, "0200080000000000"},
		{7, 4, true, "0200080000000000"},
		{7, 5, false, "02001c00010000001110140007000000010100000000001000100000"},
		{7, 5, true, "0200080000000000"},
		{7, 6, false, "0200080000000000"},
		{7, 6, true, "02001c00010000001110140007000000010100000000001000100000"},
		{7, 7, false, "02001c00010000001110140007000000010100000000001000100000"},
		{7, 7, true, "02001c00010000001110140007000000010100000000001000100000"},
		{7, 8, false, "0200080000000000"},
		{7, 8, true, "0200080000000000"},
		{7, 9, false, "02001c00010000001110140007000000010100000000001000100000"},
		{7, 9, true, "02001c00010000001119140007000000010100000000001000100000"},
		{7, 10, false, "0200080000000000"},
		{7, 10, true, "02001c00010000001112140007000000010100000000001000100000"},
		{7, 11, false, "02001c00010000001110140007000000010100000000001000100000"},
		{7, 11, true, "02001c00010000001113140007000000010100000000001000100000"},
		{7, 12, false, "0200080000000000"},
		{7, 12, true, "0200080000000000"},
		{7, 13, false, "02001c00010000001110140007000000010100000000001000100000"},
		{7, 13, true, "0200080000000000"},
		{7, 14, false, "0200080000000000"},
		{7, 14, true, "02001c00010000001110140007000000010100000000001000100000"},
		{7, 15, false, "02001c00010000001110140007000000010100000000001000100000"},
		{7, 15, true, "02001c00010000001110140007000000010100000000001000100000"},
	} {
		ace := explicitTestHex(t, "1103140001000000010100000000001000100000")
		ace[1] = tc.flags
		binary.LittleEndian.PutUint32(ace[4:], tc.mask)
		parent := explicitTestACL(ace)
		before := bytes.Clone(parent)
		got, err := InheritFileACL(parent, owner, owner, tc.directory)
		if err != nil || !bytes.Equal(got, explicitTestHex(t, tc.want)) {
			t.Fatalf("mask=%x flags=%x dir=%v: got %x want %s: %v", tc.mask, tc.flags, tc.directory, got, tc.want, err)
		}
		if !bytes.Equal(parent, before) {
			t.Fatal("mutated parent label")
		}
	}
}

func TestInheritFileACLMandatoryLabelBoundaries(t *testing.T) {
	owner := explicitTestHex(t, "010100000000000512000000")
	label := explicitTestHex(t, "1103140001000000010100000000001000100000")
	for _, mutate := range []func([]byte){
		func(a []byte) { a[1] |= 0x40 },
		func(a []byte) { a[1] |= 0x20 },
		func(a []byte) { a[4] = 8 },
		func(a []byte) { a[7] = 0x80 },
		func(a []byte) { a[15] = 5 },
		func(a []byte) { a[9] = 2 },
	} {
		bad := bytes.Clone(label)
		mutate(bad)
		if _, err := InheritFileACL(explicitTestACL(bad), owner, owner, true); err == nil {
			t.Fatalf("accepted unsupported label %x", bad)
		}
	}
	if _, err := InheritFileACL(explicitTestACL(label, label), owner, owner, true); err == nil {
		t.Fatal("accepted multiple labels without selection policy")
	}
	if _, err := CopyExplicitFileACL(explicitTestACL(label), owner, owner, true); err == nil {
		t.Fatal("explicit label assignment needs token policy")
	}
	source, err := CompileSDDL("O:SYG:SYS:(ML;OICIIO;1;;;LW)")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := InheritFileSecurity(source, nil, true); err == nil {
		t.Fatal("descriptor construction accepted token-dependent label")
	}
	child, err := CompileSDDL("O:SYG:SY")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := InheritFileSecurity(child, source, true); err == nil {
		t.Fatal("descriptor construction implicitly widened its contract")
	}
}

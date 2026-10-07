package cc

import "testing"

func TestSMCLionFixedWidthCommandsWithoutLength(t *testing.T) {
	s := newSMC(nil)
	// Unlike Linux, original Lion omits the length byte for fixed-width requests.
	smcPort(t, s, 0x304, true, 0x12)
	smcPort(t, s, 0x300, true, 0, 0, 0, 0)
	key := smcRead(t, s, 4)
	if string(key) != "#KEY" {
		t.Fatalf("bad index zero: %q", key)
	}
	smcPort(t, s, 0x304, true, 0x13)
	smcPort(t, s, 0x300, true, key...)
	info := smcRead(t, s, 6)
	if info[0] != 4 || string(info[1:5]) != "ui32" {
		t.Fatalf("bad key metadata: %x", info)
	}
}

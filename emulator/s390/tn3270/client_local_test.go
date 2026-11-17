package tn3270

import (
	"bytes"
	"github.com/tinyrange/trex/emulator/s390"
	"testing"
)

func TestClientLocalCommandCodes(t *testing.T) {
	// Original IBM LAN3274 negotiation leads to a local 05 Erase/Write,
	// WCC 47, protected connection banner and unprotected trailing field.
	local := append([]byte{5, 0x47, 0x1d, 0x20}, s390.EncodeEBCDIC("CONNECTED")...)
	local = append(local, 0x1d, 1)
	remote := append([]byte(nil), local...)
	remote[0] = 0xf5
	a, b := NewClient(), NewClient()
	for _, pair := range []struct{ a, b []byte }{
		{frame(local), frame(remote)},
		{frame([]byte{1, 0xc2}), frame([]byte{0xf1, 0xc2})},
		{frame([]byte{0x11, 0, 5, 1, 0xff, 2}), frame([]byte{0xf3, 0, 5, 1, 0xff, 2})},
	} {
		ar, ae := a.Feed(pair.a)
		br, be := b.Feed(pair.b)
		if ae != nil || be != nil || !bytes.Equal(ar, br) || a.Display.Text() != b.Display.Text() {
			t.Fatalf("local/remote mismatch: %x %v vs %x %v", ar, ae, br, be)
		}
	}
	ar, ae := a.Key("ENTER")
	br, be := b.Key("ENTER")
	if ae != nil || be != nil || !bytes.Equal(ar, br) {
		t.Fatalf("input mismatch: %x %v / %x %v", ar, ae, br, be)
	}
}

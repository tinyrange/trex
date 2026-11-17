package tn3270

import (
	"bytes"
	"github.com/tinyrange/trex/emulator/s390"
	"testing"
)

func TestRemoteReadBufferStartsAtZeroAfterSBA(t *testing.T) {
	c := NewClient()
	c.Display.Exec(5, append([]byte{0xc2}, s390.EncodeEBCDIC("START")...), false)
	// NIP writes SBA 1681, then asks Read Buffer to detect the terminal.
	if _, err := c.Feed(frame([]byte{1, 0xc3, 0x11, 0x5a, 0xd1})); err != nil {
		t.Fatal(err)
	}
	out, err := c.Feed(frame([]byte{2}))
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1925 || !bytes.Equal(out[3:8], s390.EncodeEBCDIC("START")) {
		t.Fatalf("truncated or shifted remote buffer: len=%d prefix=%x", len(out), out[:min(12, len(out))])
	}
	// The read-only remote view must not replace channel chaining semantics.
	channel, _, _ := c.Display.Exec(2, nil, false)
	if len(channel) != 242 {
		t.Fatalf("channel position changed: %d", len(channel))
	}
}

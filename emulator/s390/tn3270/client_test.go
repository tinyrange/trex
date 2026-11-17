package tn3270

import (
	"bytes"
	"github.com/tinyrange/trex/emulator/s390"
	"strings"
	"testing"
)

func TestClientSplitNegotiationAndPresentationSpace(t *testing.T) {
	wire := []byte{iac, do, optTType, iac, sb, optTType, 1, iac, se, iac, will, optBin, iac, do, optBin, iac, will, optEOR, iac, do, optEOR, iac, do, optTN3E}
	want := append([]byte{iac, will, optTType, iac, sb, optTType, 0}, []byte("IBM-3278-2-E")...)
	want = append(want, iac, se, iac, do, optBin, iac, will, optBin, iac, do, optEOR, iac, will, optEOR, iac, wont, optTN3E)
	for split := 0; split <= len(wire); split++ {
		c := NewClient()
		first, err := c.Feed(wire[:split])
		if err != nil {
			t.Fatal(err)
		}
		rest, err := c.Feed(wire[split:])
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(append(first, rest...), want) {
			t.Fatalf("split %d negotiation mismatch", split)
		}
	}
	c := NewClient()
	// A protected output field and a separate unprotected input field, with
	// insert cursor at its first character. Every wire byte arrives separately.
	record := append([]byte{0xf5, 0xc3, 0x1d, 0x20}, s390.EncodeEBCDIC("P390 READY")...)
	record = append(record, 0x11, 0xc1, 0x50, 0x1d, 0, 0x13)
	for _, b := range frame(record) {
		if _, err := c.Feed([]byte{b}); err != nil {
			t.Fatal(err)
		}
	}
	if !strings.Contains(c.Display.Text(), "P390 READY") || c.Records != 1 {
		t.Fatal("remote write not rendered")
	}
	if err := c.Type("ACK390"); err != nil {
		t.Fatal(err)
	}
	reply, err := c.Key("ENTER")
	if err != nil {
		t.Fatal(err)
	}
	if reply[0] != s390.AIDEnter || !bytes.Contains(reply, s390.EncodeEBCDIC("ACK390")) || !bytes.HasSuffix(reply, []byte{iac, eor}) {
		t.Fatalf("not a real Read Modified: %x", reply)
	}
	if err := c.Type("again"); err == nil {
		t.Fatal("inhibited keyboard accepted text")
	}
	if _, err := c.Feed(frame([]byte{0xf1, 0xc2})); err != nil {
		t.Fatal(err)
	}
	if err := c.Type("unlocked"); err != nil {
		t.Fatal(err)
	}
}

func TestClientEscapingQueryAndBounds(t *testing.T) {
	c := NewClient()
	// Query reply is generated from the presentation-space implementation,
	// not a locally fabricated MVS success string.
	reply, err := c.Feed(frame([]byte{0xf3, 0, 5, 1, 0xff, 2}))
	if err != nil || len(reply) < 8 || reply[0] != 0x88 || !bytes.HasSuffix(reply, []byte{iac, eor}) {
		t.Fatalf("query: %x %v", reply, err)
	}
	c = NewClient()
	if _, err := c.Feed(frame([]byte{0xf5, 0xc2, 0xff})); err != nil {
		t.Fatal(err)
	}
	if c.Records != 1 {
		t.Fatal("escaped IAC split a record")
	}
	for _, wire := range [][]byte{{iac, sb, optTType, 1, iac, 0}, {0x00, iac, eor}, bytes.Repeat([]byte{0x40}, 65537), append([]byte{iac, sb}, bytes.Repeat([]byte{1}, 1025)...)} {
		c = NewClient()
		if _, err := c.Feed(wire); err == nil {
			t.Fatal("malformed wire accepted")
		}
		if _, err := c.Feed(frame([]byte{0xf5, 0xc2})); err == nil {
			t.Fatal("poisoned client silently recovered")
		}
	}
}

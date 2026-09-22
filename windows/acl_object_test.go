package windows

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestObjectACE(t *testing.T) {
	principal, _ := hex.DecodeString("01010000000000050b000000")
	got, err := ObjectACE(5, 2, 0x10, principal, "bf967aba-0de6-11d0-a285-00aa003049e2", "")
	want, _ := hex.DecodeString("050228001000000001000000ba7a96bfe60dd011a28500aa003049e201010000000000050b000000")
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("ACE %x, %v; want %x", got, err, want)
	}
	if _, err := ObjectACE(5, 0, 1, principal, "invalid", ""); err == nil {
		t.Fatal("invalid GUID accepted")
	}
	if _, err := ObjectACE(0, 0, 1, principal, "", ""); err == nil {
		t.Fatal("non-object ACE accepted")
	}
}

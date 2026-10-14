package binary

import (
	"bytes"
	"testing"
)

func TestIBM037TextRoundTripAndTermination(t *testing.T) {
	raw := []byte{0xc4, 0x85, 0x83, 0x96, 0x94, 0x97, 0x99, 0x85, 0xa2, 0xa2, 0xf1}
	text, err := DecodeText(raw, "ibm-037", false)
	if err != nil || text != "Decompress1" {
		t.Fatal(text, err)
	}
	encoded, err := EncodeText(text, "cp037", true)
	if err != nil || !bytes.Equal(encoded, append(append([]byte{}, raw...), 0)) {
		t.Fatal(encoded, err)
	}
	text, err = DecodeText(append(encoded, 0xc1), "IBM037", true)
	if err != nil || text != "Decompress1" {
		t.Fatal(text, err)
	}
	all := make([]byte, 256)
	for i := range all {
		all[i] = byte(i)
	}
	text, err = DecodeText(all, "cp037", false)
	if err != nil {
		t.Fatal(err)
	}
	round, err := EncodeText(text, "ibm037", false)
	if err != nil || !bytes.Equal(round, all) {
		t.Fatal("byte identity lost", err)
	}
	if _, err := EncodeText("😀", "ibm037", false); err == nil {
		t.Fatal("unrepresentable character accepted")
	}
}

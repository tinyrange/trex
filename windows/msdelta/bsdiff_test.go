package msdelta

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func appendBSDiffTestInt(data []byte, value int64) []byte {
	magnitude := uint64(value)
	if value < 0 {
		magnitude = uint64(-value) | uint64(1)<<63
	}
	var encoded [8]byte
	binary.LittleEndian.PutUint64(encoded[:], magnitude)
	return append(data, encoded[:]...)
}

func appendBSDiffTestBlock(data []byte, add, insert, seek int64, difference, literal []byte) []byte {
	data = appendBSDiffTestInt(data, add)
	data = appendBSDiffTestInt(data, insert)
	data = appendBSDiffTestInt(data, seek)
	data = append(data, difference...)
	return append(data, literal...)
}

func TestApplyBSDiffControls(t *testing.T) {
	patch := appendBSDiffTestBlock(nil, 3, 1, -3, []byte{0, 0, 0}, []byte{'-'})
	patch = appendBSDiffTestBlock(patch, 3, 0, 0, []byte{0, 0, 0}, nil)
	target, err := applyBSDiff([]byte("abcXYZ"), 7, patch)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(target, []byte("abc-abc")) {
		t.Fatalf("target = %q", target)
	}
}

func TestApplyBSDiffUsesZeroOutsideSource(t *testing.T) {
	patch := appendBSDiffTestBlock(nil, 1, 0, -2, []byte{0}, nil)
	patch = appendBSDiffTestBlock(patch, 2, 0, 0, []byte{'A', 'B'}, nil)
	target, err := applyBSDiff(nil, 3, patch)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(target, []byte{0, 'A', 'B'}) {
		t.Fatalf("target = %x", target)
	}
}

func TestApplyBSDiffRejectsMalformedPatch(t *testing.T) {
	negative := appendBSDiffTestBlock(nil, -1, 0, 0, nil, nil)
	addOverrun := appendBSDiffTestBlock(nil, 2, 0, 0, []byte{0, 0}, nil)
	insertOverrun := appendBSDiffTestBlock(nil, 0, 2, 0, nil, []byte("xx"))
	truncatedDifference := appendBSDiffTestBlock(nil, 1, 0, 0, nil, nil)
	truncatedInsertion := appendBSDiffTestBlock(nil, 0, 1, 0, nil, nil)
	valid := appendBSDiffTestBlock(nil, 0, 1, 0, nil, []byte{'x'})
	for _, test := range []struct {
		name   string
		patch  []byte
		target uint64
	}{
		{name: "control", patch: []byte{0}, target: 1},
		{name: "negative length", patch: negative, target: 1},
		{name: "add overrun", patch: addOverrun, target: 1},
		{name: "insert overrun", patch: insertOverrun, target: 1},
		{name: "truncated difference", patch: truncatedDifference, target: 1},
		{name: "truncated insertion", patch: truncatedInsertion, target: 1},
		{name: "trailing data", patch: append(valid, 0), target: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := applyBSDiff(nil, test.target, test.patch); err == nil {
				t.Fatal("malformed patch was accepted")
			}
		})
	}
}

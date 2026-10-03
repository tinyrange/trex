package ckd

import (
	"bytes"
	"testing"
)

func TestIGWAllocationSelectorsAndPhysicalDisorder(t *testing.T) {
	b := make([]byte, 4*4096)
	copy(b[3*4096:], bytes.Repeat([]byte{0xaa}, 4096))
	copy(b[4096:], bytes.Repeat([]byte{0xbb}, 4096))
	g := &IGW{source: raw(b)}
	object := [6]byte{0, 0, 0, 0, 0, 4}
	first := igwKey(3, object, 0x7003)
	second := first
	be.PutUint32(second[16:], 1)
	attrs := map[[20]byte][]byte{first: testRun(3, 1), second: testRun(1, 1)}
	c, err := g.objectAllocation(attrs, 3, object, false)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 4)
	if _, err = c.ReadAt(got, 4094); err != nil || !bytes.Equal(got, []byte{0xaa, 0xaa, 0xbb, 0xbb}) {
		t.Fatal(got, err)
	}
	delete(attrs, second)
	be.PutUint32(second[16:], 2)
	attrs[second] = testRun(1, 1)
	if _, err := g.objectAllocation(attrs, 3, object, false); err == nil {
		t.Fatal("allocation gap silently filled")
	}
	delete(attrs, second)
	be.PutUint32(second[16:], 1)
	attrs[second] = testRun(1, 1)
	attrs[first] = testRun(2, 2)
	if _, err := g.objectAllocation(attrs, 3, object, false); err == nil {
		t.Fatal("overlap accepted")
	}
}

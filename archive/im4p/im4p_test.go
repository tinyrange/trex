package im4p

import (
	"bytes"
	"github.com/tinyrange/trex/auto"
	"io"
	"testing"
)

func fixture() []byte {
	children := []byte{0x16, 4, 'I', 'M', '4', 'P', 0x16, 4, 'r', 'd', 's', 'k', 0x16, 1, '0', 4, 4, 'd', 'a', 't', 'a', 0x30, 6, 2, 1, 1, 2, 1, 4}
	return append([]byte{0x30, byte(len(children))}, children...)
}
func TestBorrowedPayloadMetadataAndAuto(t *testing.T) {
	b := fixture()
	f, err := Open(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(io.NewSectionReader(f.Payload, 0, f.Payload.Size()))
	if err != nil || string(got) != "data" || f.Type != "rdsk" || f.ExpectedSize != 4 || len(f.Extras) != 1 {
		t.Fatalf("%+v %q %v", f, got, err)
	}
	b[19] = 'D'
	f.Payload.ReadAt(got, 0)
	if string(got) != "Data" {
		t.Fatal("payload copied rather than borrowed")
	}
	id, err := auto.Identify(bytes.NewReader(b), auto.Options{})
	if err != nil || id.Format != "im4p" {
		t.Fatalf("auto %v %v", id, err)
	}
}
func TestRejectDERBoundsAndNesting(t *testing.T) {
	b := fixture()
	for _, bad := range [][]byte{b[:len(b)-1], append(append([]byte(nil), b...), 0), {0x30, 0x80, 0, 0}, {0x30, 0x81, 1, 0}} {
		if _, err := Open(bytes.NewReader(bad)); err == nil {
			t.Fatal("accepted malformed envelope")
		}
	}
	for i := 0; i < 40; i++ {
		b = append([]byte{0x30, byte(len(b))}, b...)
	}
	if _, err := Open(bytes.NewReader(b)); err == nil {
		t.Fatal("unbounded nesting")
	}
}

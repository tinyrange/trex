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

func TestPrivateHighTagMetadata(t *testing.T) {
	// PAYP metadata uses a constructed private tag whose number is the
	// four-character property name (here kcbf), enclosing a DER sequence.
	property := []byte{0xff, 0x86, 0xdb, 0x8d, 0xc4, 0x66, 0x0e,
		0x30, 0x0c, 0x16, 4, 'k', 'c', 'b', 'f', 2, 4, 2, 0x2b, 0, 0}
	b := fixture()
	b[1] += byte(len(property))
	b = append(b, property...)
	f, err := Open(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	extra := f.Extras[1]
	if extra.Tag != 0xff || len(extra.Children) != 1 || len(extra.Children[0].Children) != 2 {
		t.Fatalf("metadata not parsed: %+v", extra)
	}
	raw, err := io.ReadAll(io.NewSectionReader(extra.Raw, 0, extra.Raw.Size()))
	if err != nil || !bytes.Equal(raw, property) {
		t.Fatalf("metadata changed: %x %v", raw, err)
	}
	id, err := auto.Identify(bytes.NewReader(b), auto.Options{})
	if err != nil || id.Format != "im4p" {
		t.Fatalf("auto %v %v", id, err)
	}
}

func TestRejectMalformedHighTags(t *testing.T) {
	for _, metadata := range [][]byte{
		{0xff, 0x80, 0x1f, 0}, // leading zero
		{0xff, 0x1e, 0},       // low number in long form
		{0xff, 0x81},          // unfinished identifier
		{0xff, 0x1f},          // missing length
		{0xff, 0x1f, 0x80},    // indefinite length
		{0xff, 0x1f, 0x81, 0}, // noncanonical length
		{0xff, 0x1f, 2, 0},    // extent outside parent
		{0xff, 0x82, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0, 0}, // overflow
	} {
		b := fixture()
		b[1] += byte(len(metadata))
		b = append(b, metadata...)
		if _, err := Open(bytes.NewReader(b)); err == nil {
			t.Fatalf("accepted malformed identifier: %x", metadata)
		}
	}
}

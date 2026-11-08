package rpm

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

type field struct {
	tag, typ, count uint32
	data            []byte
}

func headerFixture(fields ...field) []byte {
	b := make([]byte, 16+16*len(fields))
	copy(b, []byte{0x8e, 0xad, 0xe8, 1})
	binary.BigEndian.PutUint32(b[8:], uint32(len(fields)))
	data := []byte{}
	for i, f := range fields {
		align := 1
		if f.typ >= 3 && f.typ <= 5 {
			align = 1 << (f.typ - 2)
		}
		for len(data)%align != 0 {
			data = append(data, 0)
		}
		idx := b[16+i*16:]
		binary.BigEndian.PutUint32(idx, f.tag)
		binary.BigEndian.PutUint32(idx[4:], f.typ)
		binary.BigEndian.PutUint32(idx[8:], uint32(len(data)))
		binary.BigEndian.PutUint32(idx[12:], f.count)
		data = append(data, f.data...)
	}
	binary.BigEndian.PutUint32(b[12:], uint32(len(data)))
	return append(b, data...)
}
func fixture(fields ...field) ([]byte, int, int) {
	b := make([]byte, 96)
	copy(b, []byte{0xed, 0xab, 0xee, 0xdb, 3, 0})
	binary.BigEndian.PutUint16(b[78:], 5)
	b = append(b, headerFixture(field{1005, 7, 3, []byte{1, 2, 3}})...)
	for len(b)%8 != 0 {
		b = append(b, 0)
	}
	start := len(b)
	b = append(b, headerFixture(fields...)...)
	payload := len(b)
	return append(b, []byte("unread payload")...), start, payload
}

type guarded struct {
	*bytes.Reader
	payload int64
}

func (r guarded) ReadAt(p []byte, off int64) (int, error) {
	if off+int64(len(p)) > r.payload {
		return 0, io.ErrClosedPipe
	}
	return r.Reader.ReadAt(p, off)
}
func TestMetadataAndBorrowedPayload(t *testing.T) {
	b, _, off := fixture(
		field{1000, 6, 1, []byte("example\x00")},
		field{1004, 9, 2, []byte("English\x00French\x00")},
		field{1006, 4, 1, []byte{0x67, 0x89, 0xab, 0xcd}},
		field{1044, 6, 1, []byte("example-1-2.src.rpm\x00")},
		field{6000, 5, 1, []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
		field{6001, 3, 2, []byte{0x12, 0x34, 0xab, 0xcd}},
		field{6002, 2, 1, []byte{255}}, field{6003, 1, 1, []byte{128}},
		field{6004, 8, 2, []byte("a\x00b\x00")}, field{6005, 0, 0, nil},
	)
	// Parsing must never read the payload, even to sniff its compression.
	f, err := Open(guarded{bytes.NewReader(b), int64(off)}, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if f.PayloadOffset != int64(off) || f.Source || f.Header.Entries[0].Text[0] != "example" || f.Header.Entries[2].Numbers[0] != 0x6789abcd || f.Header.Entries[4].Numbers[0] != ^uint64(0) || f.Header.Entries[5].Numbers[1] != 0xabcd {
		t.Fatalf("incorrect metadata: %+v", f)
	}
	if !bytes.Equal(f.Signature.Entries[0].Bytes, []byte{1, 2, 3}) {
		t.Fatal("signature bytes")
	}
	f, err = Open(bytes.NewReader(b), DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(io.NewSectionReader(f.Payload, 0, f.Payload.Size()))
	if err != nil || string(got) != "unread payload" {
		t.Fatalf("payload: %q %v", got, err)
	}
	b[4] = 4 // Legacy IBM CSM RPMs use a v4 lead with the same header layout.
	binary.BigEndian.PutUint16(b[6:], 1)
	f, err = Open(bytes.NewReader(b), DefaultLimits())
	if err != nil || !f.Source {
		t.Fatal("source package", err)
	}
	v, err := Builtin(nil, nil, starlark.Tuple{starfile.NewReader("fixture.rpm", bytes.NewReader(b))}, nil)
	if err != nil {
		t.Fatal(err)
	}
	fields, err := v.(starlark.HasAttrs).Attr("fields")
	if err != nil {
		t.Fatal(err)
	}
	value, ok, err := fields.(*starlark.Dict).Get(starlark.String("source_rpm"))
	if err != nil || !ok || value != starlark.String("example-1-2.src.rpm") {
		t.Fatal(value, err)
	}
}
func TestRejectMalformedAndLimits(t *testing.T) {
	original, start, payload := fixture(field{1000, 6, 1, []byte("example\x00")})
	cases := map[string]func([]byte){
		"magic":            func(b []byte) { b[0] = 0 },
		"lead-version":     func(b []byte) { b[4] = 5 },
		"legacy-signature": func(b []byte) { b[79] = 1 },
		"padding":          func(b []byte) { b[start-1] = 1 },
		"header-version":   func(b []byte) { b[start+3] = 2 },
		"reserved":         func(b []byte) { b[start+4] = 1 },
		"huge-index":       func(b []byte) { binary.BigEndian.PutUint32(b[start+8:], 0xffffffff) },
		"huge-store":       func(b []byte) { binary.BigEndian.PutUint32(b[start+12:], 0xffffffff) },
		"offset":           func(b []byte) { binary.BigEndian.PutUint32(b[start+24:], 9) },
		"string-count":     func(b []byte) { binary.BigEndian.PutUint32(b[start+28:], 2) },
		"unterminated":     func(b []byte) { b[payload-1] = 'x' },
		"unknown-type":     func(b []byte) { binary.BigEndian.PutUint32(b[start+20:], 10) },
		"alignment": func(b []byte) {
			binary.BigEndian.PutUint32(b[start+20:], 4)
			binary.BigEndian.PutUint32(b[start+24:], 1)
		},
		"count": func(b []byte) {
			binary.BigEndian.PutUint32(b[start+20:], 4)
			binary.BigEndian.PutUint32(b[start+28:], 0xffffffff)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			b := bytes.Clone(original)
			mutate(b)
			if _, err := Open(bytes.NewReader(b), DefaultLimits()); err == nil {
				t.Fatal("accepted malformed RPM")
			}
		})
	}
	for n := 0; n < payload; n++ {
		if _, err := Open(bytes.NewReader(original[:n]), DefaultLimits()); err == nil {
			t.Fatalf("accepted truncation at %d", n)
		}
	}
	for _, limits := range []Limits{{0, 1024}, {1, 1024}, {10, 32}, {10, 15}, {1 << 21, 1024}, {10, 257 << 20}} {
		if _, err := Open(bytes.NewReader(original), limits); err == nil {
			t.Fatal("ignored limits", limits)
		}
	}
	dup, _, _ := fixture(field{1000, 6, 1, []byte("a\x00")}, field{1000, 6, 1, []byte("b\x00")})
	if _, err := Open(bytes.NewReader(dup), DefaultLimits()); err == nil {
		t.Fatal("accepted duplicate tag")
	}
	// Repeated offsets may alias valid data, but must not amplify it without bound.
	fields := make([]field, 20)
	for i := range fields {
		fields[i] = field{uint32(6000 + i), 6, 1, nil}
	}
	fields[0].data = append(bytes.Repeat([]byte("x"), 1000), 0)
	alias, at, _ := fixture(fields...)
	for i := range fields {
		binary.BigEndian.PutUint32(alias[at+16+i*16+8:], 0)
	}
	if _, err := Open(bytes.NewReader(alias), Limits{100, 4096}); err == nil {
		t.Fatal("accepted decoded alias amplification")
	}
	// A huge count in a small store must be rejected before allocating.
	binary.BigEndian.PutUint32(alias[at+16+4:], 8)
	binary.BigEndian.PutUint32(alias[at+16+12:], 0x7fffffff)
	if _, err := Open(bytes.NewReader(alias), DefaultLimits()); err == nil {
		t.Fatal("accepted alias amplification")
	}
}
func FuzzOpen(f *testing.F) {
	b, _, _ := fixture(field{1000, 6, 1, []byte("test\x00")})
	f.Add(b)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = Open(bytes.NewReader(data), Limits{1024, 1 << 20})
	})
}

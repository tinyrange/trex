package mszip

import (
	"bytes"
	"compress/flate"
	"testing"
)

func testCompressed(t testing.TB, data, history []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	w, err := flate.NewWriterDict(&b, flate.BestSpeed, history)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}
func TestDecoderReuseDictionaryAndFailures(t *testing.T) {
	var d Decoder
	var history []byte
	for i := 0; i < 20; i++ {
		plain := bytes.Repeat([]byte("some repeated block content"), 100+i*11)
		encoded := testCompressed(t, plain, history)
		got, err := d.Decode(encoded, history, len(plain))
		if err != nil || !bytes.Equal(got, plain) {
			t.Fatalf("block %d: %v", i, err)
		}
		history = got // Deliberately borrow the prior decoder result as dictionary.
	}
	cases := [][]byte{
		{1, 4, 0, 't', 'e', 's', 't'},           // Early stored block omits NLEN.
		{0, 4, 0, 251, 255, 't', 'e', 's', 't'}, // CFDATA boundary without BFINAL.
		{1, 4, 0, 251, 255, 't', 'e', 's'},
		{7}, {},
	}
	for _, input := range cases {
		for _, expected := range []int{0, 3, 4, 5, 32768} {
			want, werr := Decode(input, nil, expected)
			got, gerr := d.Decode(input, nil, expected)
			if (werr == nil) != (gerr == nil) || werr == nil && !bytes.Equal(want, got) {
				t.Fatalf("%x size %d: got %x %v, want %x %v", input, expected, got, gerr, want, werr)
			}
		}
	}
	plain := []byte("after errors")
	got, err := d.Decode(testCompressed(t, plain, nil), nil, len(plain))
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("reset: %v", err)
	}
}
func FuzzDecoderMatchesStateless(f *testing.F) {
	f.Add([]byte{1, 4, 0, 't', 'e', 's', 't'}, []byte("history"), uint16(4))
	f.Add([]byte{0, 4, 0, 251, 255, 't', 'e', 's', 't'}, []byte{}, uint16(4))
	f.Fuzz(func(t *testing.T, encoded, history []byte, size uint16) {
		if len(encoded) > 512 || len(history) > 65536 {
			t.Skip()
		}
		expected := int(size) % 4096
		want, werr := Decode(encoded, history, expected)
		var d Decoder
		// Dirty the reusable state before testing arbitrary input.
		if _, err := d.Decode([]byte{1, 4, 0, 't', 'e', 's', 't'}, nil, 4); err != nil {
			t.Fatal(err)
		}
		got, gerr := d.Decode(encoded, history, expected)
		if (werr == nil) != (gerr == nil) || werr == nil && !bytes.Equal(want, got) {
			t.Fatalf("got %x %v, want %x %v", got, gerr, want, werr)
		}
	})
}
func BenchmarkDecoderBlock(b *testing.B) {
	plain := bytes.Repeat([]byte("cabinet dictionary payload 12345!"), 1024)
	encoded := testCompressed(b, plain, plain)
	for _, reuse := range []bool{false, true} {
		name := "stateless"
		if reuse {
			name = "reuse"
		}
		b.Run(name, func(b *testing.B) {
			var d Decoder
			d.Decode(encoded, plain, len(plain))
			b.SetBytes(int64(len(plain)))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				var got []byte
				var err error
				if reuse {
					got, err = d.Decode(encoded, plain, len(plain))
				} else {
					got, err = Decode(encoded, plain, len(plain))
				}
				if err != nil || !bytes.Equal(got, plain) {
					b.Fatalf("decode: %v", err)
				}
			}
		})
	}
}

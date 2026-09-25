package nsis

import (
	"bytes"
	"compress/flate"
	"errors"
	"testing"
)

func TestInflateNSIS(t *testing.T) {
	// Original hand-authored stored and fixed-Huffman wire fixtures.
	cases := []struct {
		name          string
		packed, plain []byte
	}{
		{"stored", []byte{1, 3, 0, 'a', 'b', 'c'}, []byte("abc")},
		{"empty fixed", []byte{3, 0}, nil},
		{"fixed literal", []byte{0x73, 0x04, 0}, []byte("A")},
		{"consecutive stored", []byte{0, 1, 0, 'a', 1, 2, 0, 'b', 'c'}, []byte("abc")},
	}
	// Differential check against Go's independent encoder, including long
	// overlapping back-references and a dynamic tree. Only its final empty
	// stored block needs conversion to the NSIS LEN-only representation.
	plain := bytes.Repeat([]byte("aabbbccccdddddeeeeeefffffff"), 4096)
	var encoded bytes.Buffer
	w, err := flate.NewWriter(&encoded, flate.BestCompression)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	packed := encoded.Bytes()
	if !bytes.HasSuffix(packed, []byte{0, 0, 255, 255}) {
		t.Fatal("unexpected trailer")
	}
	cases = append(cases, struct {
		name          string
		packed, plain []byte
	}{"dynamic overlap", packed[:len(packed)-2], plain})
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := inflateNSIS(tc.packed, int64(len(tc.plain)))
			if err != nil || !bytes.Equal(got, tc.plain) {
				t.Fatalf("decode: %v, got %d bytes", err, len(got))
			}
			if len(tc.plain) > 0 {
				if _, err := inflateNSIS(tc.packed, int64(len(tc.plain)-1)); !errors.Is(err, ErrLimit) {
					t.Fatalf("bound: %v", err)
				}
			}
			for end := 0; end < len(tc.packed); end++ {
				if _, err := inflateNSIS(tc.packed[:end], int64(len(tc.plain))); err == nil {
					t.Fatalf("accepted truncation %d", end)
				}
			}
			if _, err := inflateNSIS(append(bytes.Clone(tc.packed), 0), int64(len(tc.plain))); err == nil {
				t.Fatal("accepted trailing byte")
			}
		})
	}
	for _, invalid := range [][]byte{{7}, {1, 255, 255}, {0x03, 0x02}, {0x05, 0, 0, 0}} {
		if _, err := inflateNSIS(invalid, 1024); err == nil {
			t.Fatalf("accepted invalid %x", invalid)
		}
	}
	if _, err := makeHuffman([]int{1, 1, 1}); err == nil {
		t.Fatal("accepted oversubscribed tree")
	}
}

func FuzzInflateNSIS(f *testing.F) {
	for _, seed := range [][]byte{{1, 3, 0, 'a', 'b', 'c'}, {3, 0}, {0x73, 4, 0}, {7}} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<16 {
			t.Skip()
		}
		out, err := inflateNSIS(data, 1<<16)
		if err == nil && len(out) > 1<<16 {
			t.Fatal("output limit exceeded")
		}
	})
}

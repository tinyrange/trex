package compressed

import (
	"bytes"
	"compress/gzip"
	"encoding/hex"
	starfile "github.com/tinyrange/trex/storage/star"
	"io"
	"testing"
)

func gzipBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	w := gzip.NewWriter(&out)
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func TestStreams(t *testing.T) {
	bz, _ := hex.DecodeString("425a68393141592653594eece83600000251800010400006449080200031064c4101a7a9a580bb9431f8bb9229c28482776741b0")
	for _, format := range []string{"gzip", "bzip2"} {
		t.Run(format, func(t *testing.T) {
			data := []byte("hello world\n")
			encoded := bz
			if format == "gzip" {
				encoded = gzipBytes(t, data)
			}
			for _, copies := range []int{1, 2} {
				input := bytes.Repeat(encoded, copies)
				want := bytes.Repeat(data, copies)
				f, err := Open(&starfile.Bytes{Data: input}, format, int64(len(want)))
				if err != nil {
					t.Fatal(err)
				}
				got, err := starfile.ReadAll(f)
				if err != nil || !bytes.Equal(got, want) {
					t.Fatalf("%q %v", got, err)
				}
				if _, err := Open(&starfile.Bytes{Data: input}, format, int64(len(want)-1)); err == nil {
					t.Fatal("accepted oversized output")
				}
			}
			for n := 0; n < len(encoded); n++ {
				if _, err := Open(&starfile.Bytes{Data: encoded[:n]}, format, 100); err == nil {
					t.Fatalf("accepted prefix %d", n)
				}
			}
			corrupt := bytes.Clone(encoded)
			corrupt[len(corrupt)-5] ^= 1
			if _, err := Open(&starfile.Bytes{Data: corrupt}, format, 100); err == nil {
				t.Fatal("accepted corrupt checksum")
			}
		})
	}
}

func TestChunkBoundaries(t *testing.T) {
	data := bytes.Repeat([]byte("abcdefg"), chunkSize/7+100)
	f, err := Open(&starfile.Bytes{Data: gzipBytes(t, data)}, "gzip", int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	for _, off := range []int64{0, chunkSize - 3, chunkSize, int64(len(data) - 2), int64(len(data))} {
		got := make([]byte, 17)
		n, err := f.ReadAt(got, off)
		want := data[off:min(int64(len(data)), off+17)]
		if !bytes.Equal(got[:n], want) || n < len(got) && err != io.EOF {
			t.Fatalf("offset %d n=%d err=%v", off, n, err)
		}
	}
	if _, err := f.ReadAt(make([]byte, 1), -1); err == nil {
		t.Fatal("negative read")
	}
	empty, err := Open(&starfile.Bytes{Data: gzipBytes(t, nil)}, "gzip", 1)
	if err != nil || empty.Size() != 0 {
		t.Fatalf("empty %v", err)
	}
}

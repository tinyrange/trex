package gzip

import (
	"bytes"
	stdgzip "compress/gzip"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/tinyrange/trex/auto"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func encode(t *testing.T, data []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	w := stdgzip.NewWriter(&out)
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func TestLazyWindowReplayAndConcurrentReads(t *testing.T) {
	data := make([]byte, 3*cacheBytes+123)
	for i := range data {
		data[i] = byte(i*13 + i/17)
	}
	f, err := Open(&starfile.Bytes{Data: encode(t, data)}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, known := f.KnownSize(); known {
		t.Fatal("eager length discovery")
	}
	for _, off := range []int64{0, 100, cacheBytes - 23, 2*cacheBytes + 123, 0, int64(len(data)) - 1} {
		got := make([]byte, min(77, int64(len(data))-off))
		if _, err := f.ReadAt(got, off); err != nil || !bytes.Equal(got, data[off:off+int64(len(got))]) {
			t.Fatalf("offset %d: %v", off, err)
		}
		if cap(f.cache) > cacheBytes {
			t.Fatal("unbounded cache", cap(f.cache))
		}
	}
	if size, known := f.KnownSize(); !known || size != int64(len(data)) {
		t.Fatal(size, known)
	}
	var wg sync.WaitGroup
	for _, off := range []int64{4, cacheBytes + 5, 2*cacheBytes + 6} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var got [40]byte
			if _, err := f.ReadAt(got[:], off); err != nil || !bytes.Equal(got[:], data[off:off+40]) {
				t.Errorf("concurrent offset %d: %v", off, err)
			}
		}()
	}
	wg.Wait()
	if n, err := f.ReadAt(make([]byte, 5), int64(len(data))-2); n != 2 || err != io.EOF {
		t.Fatal(n, err)
	}
}

func TestConcatenationIntegrityEmptyAndExplicitLimit(t *testing.T) {
	encoded := append(encode(t, []byte("hello")), encode(t, []byte(" world"))...)
	encoded = append(encoded, encode(t, nil)...)
	for _, maximum := range []int64{0, 11} {
		f, err := Open(&starfile.Bytes{Data: encoded}, maximum)
		if err != nil {
			t.Fatal(err)
		}
		if size, err := f.Validate(); size != 11 || err != nil {
			t.Fatal(size, err)
		}
		var got [11]byte
		if _, err := f.ReadAt(got[:], 0); err != nil || string(got[:]) != "hello world" {
			t.Fatal(string(got[:]), err)
		}
	}
	f, err := Open(&starfile.Bytes{Data: encoded}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Validate(); !errors.Is(err, auto.ErrLimit) || !strings.Contains(err.Error(), "maximum_bytes 10") {
		t.Fatal(err)
	}
	bad := bytes.Clone(encoded)
	bad[len(bad)-8] ^= 1
	for _, encoded := range [][]byte{bad, encoded[:len(encoded)-3]} {
		f, err := Open(&starfile.Bytes{Data: encoded}, 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Validate(); err == nil {
			t.Fatal("invalid trailer accepted")
		}
		if f.Size() != -1 {
			t.Fatal("failed size should be unknown")
		}
	}
	empty, err := Open(&starfile.Bytes{Data: encode(t, nil)}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := empty.ReadAt(make([]byte, 1), 0); n != 0 || err != io.EOF {
		t.Fatal(n, err)
	}
	if size, known := empty.KnownSize(); size != 0 || !known {
		t.Fatal(size, known)
	}
}

func TestAutoBeyondDefaultMaximumAndExplicitCap(t *testing.T) {
	// Half a GiB of decoded bytes is represented by less than a MiB of input.
	member := encode(t, make([]byte, 1<<20))
	source := &starfile.Bytes{Data: bytes.Repeat(member, 513)}
	result, err := auto.Identify(source, auto.Options{})
	if err != nil {
		t.Fatal(err)
	}
	f := result.View.(*auto.DecodedView).Reader.(*File)
	if _, known := f.KnownSize(); known {
		t.Fatal("auto materialized stream")
	}
	var got [1]byte
	if _, err := f.ReadAt(got[:], 512<<20); err != nil || got[0] != 0 {
		t.Fatal(got, err)
	}
	if size, err := f.Validate(); size != 513<<20 || err != nil {
		t.Fatal(size, err)
	}
	if cap(f.cache) != cacheBytes {
		t.Fatal(cap(f.cache))
	}
	result, err = auto.Identify(source, auto.Options{MaxExpandedBytes: 512 << 20})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := result.View.(*auto.DecodedView).Reader.ReadAt(got[:], 512<<20); !errors.Is(err, auto.ErrLimit) {
		t.Fatal(err)
	}
}

func TestBuiltinBoundedReadDoesNotDiscoverLength(t *testing.T) {
	source := &starfile.Bytes{Data: encode(t, make([]byte, 3*cacheBytes))}
	v, err := Builtin(nil, nil, starlark.Tuple{source}, nil)
	if err != nil {
		t.Fatal(err)
	}
	f := v.(*File)
	read, err := f.Attr("bytes")
	if err != nil {
		t.Fatal(err)
	}
	got, err := starlark.Call(&starlark.Thread{}, read, starlark.Tuple{starlark.MakeInt(7), starlark.MakeInt(16)}, nil)
	if err != nil || len(got.(starlark.Bytes)) != 16 {
		t.Fatal(got, err)
	}
	if _, known := f.KnownSize(); known {
		t.Fatal("bounded Starlark read scanned stream")
	}
	for _, limit := range []starlark.Value{starlark.MakeInt(0), starlark.MakeInt(-1), starlark.None} {
		if _, err := Builtin(nil, nil, starlark.Tuple{source}, []starlark.Tuple{{starlark.String("maximum_bytes"), limit}}); err == nil {
			t.Fatal("invalid limit accepted", limit)
		}
	}
}

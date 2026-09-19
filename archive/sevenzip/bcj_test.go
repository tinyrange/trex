package sevenzip

import (
	"bytes"
	"io"
	"testing"
)

func TestBCJOffsetsAndStreaming(t *testing.T) {
	for _, offset := range []int{0, 1, 65532, 65533, 65534, 65535, 65536} {
		input := append(bytes.Repeat([]byte{0x90}, offset), 0xe8, 0, 0, 0, 0, 0xe9, 0xff, 0xff, 0xff, 0xff)
		want := append([]byte(nil), input...)
		s := &bcjReader{}
		bcjX86Filter(s, want)
		for _, chunk := range []int{1, 7, 65536} {
			r, e := newBCJReader(bytes.NewReader(input), uint64(len(input)), nil)
			if e != nil {
				t.Fatal(e)
			}
			var out bytes.Buffer
			buf := make([]byte, chunk)
			for {
				n, e := r.Read(buf)
				out.Write(buf[:n])
				if e == io.EOF {
					break
				}
				if e != nil {
					t.Fatal(e)
				}
			}
			if !bytes.Equal(want, out.Bytes()) {
				t.Fatalf("offset %d chunk %d", offset, chunk)
			}
		}
	}
	// Independent absolute-to-relative call vector (IP includes five-byte call).
	r, _ := newBCJReader(bytes.NewReader([]byte{0xe8, 0x20, 0, 0, 0}), 5, nil)
	got, e := io.ReadAll(r)
	if e != nil || !bytes.Equal(got, []byte{0xe8, 0x1b, 0, 0, 0}) {
		t.Fatalf("%x %v", got, e)
	}
	r, _ = newBCJReader(bytes.NewReader([]byte{0xe8, 0x20, 0, 0, 0}), 5, []byte{0x10, 0, 0, 0})
	got, e = io.ReadAll(r)
	if e != nil || !bytes.Equal(got, []byte{0xe8, 0x0b, 0, 0, 0}) {
		t.Fatalf("start IP: %x %v", got, e)
	}
	r, _ = newBCJReader(bytes.NewReader([]byte{1, 2}), 3, nil)
	if _, e = io.ReadAll(r); e == nil {
		t.Fatal("accepted truncation")
	}
}

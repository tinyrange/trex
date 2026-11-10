package lzx

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

type boundedLZXSource struct {
	data           []byte
	maximum, reads int
	failAt         int64
	failure        error
}

func (s *boundedLZXSource) ReadAt(p []byte, off int64) (int, error) {
	s.maximum = max(s.maximum, len(p))
	s.reads++
	if s.failure != nil && off >= s.failAt {
		return 0, s.failure
	}
	return bytes.NewReader(s.data).ReadAt(p, off)
}

func TestDecompressReaderToHistoryAndInputBoundaries(t *testing.T) {
	for _, bits := range []int{15, 17, 21} {
		input, size := lzxStreamingHistoryFixture(bits)
		want, err := Decompress(input, bits, size)
		if err != nil {
			t.Fatal(err)
		}
		source := &boundedLZXSource{data: input}
		var got bytes.Buffer
		if err := DecompressReaderTo(&got, source, int64(len(input)), bits, size); err != nil || !bytes.Equal(got.Bytes(), want) {
			t.Fatalf("window %d: %v", bits, err)
		}
		if source.maximum > lzxInputBufferSize || source.reads < 2 {
			t.Fatalf("not bounded input: %+v", source.maximum)
		}
	}
	// Raw blocks can straddle input buffers and output frames, including odd
	// padding and prefetched words rewound across a previous buffer boundary.
	for _, size := range []int{65513, 65517, 65519, 65521, 65523, 65525, 65527, 65529, 65531, 65533, 65535, 65537, 100001} {
		blocks := [][]byte{bytes.Repeat([]byte{0x71}, size), {1, 2, 3}, bytes.Repeat([]byte{0xe8}, 100003)}
		input := lzxTestUncompressedStream(blocks...)
		n := size + 3 + 100003
		want, err := Decompress(input, 15, n)
		if err != nil {
			t.Fatal(err)
		}
		var got bytes.Buffer
		if err := DecompressReaderTo(&got, bytes.NewReader(input), int64(len(input)), 15, n); err != nil || !bytes.Equal(got.Bytes(), want) {
			t.Fatalf("size %d: %v", size, err)
		}
	}
}

func TestDecompressReaderToErrors(t *testing.T) {
	input, size := lzxStreamingHistoryFixture(17)
	sentinel := errors.New("source failure")
	source := &boundedLZXSource{data: input, failAt: lzxInputBufferSize, failure: sentinel}
	if err := DecompressReaderTo(io.Discard, source, int64(len(input)), 17, size); !errors.Is(err, sentinel) {
		t.Fatalf("lost source error: %v", err)
	}
	for _, n := range []int{0, 1, 2, 11, len(input) / 2, len(input) - 10} {
		if err := DecompressReaderTo(io.Discard, bytes.NewReader(input[:n]), int64(len(input)), 17, size); err == nil {
			t.Fatalf("accepted short reader %d", n)
		}
	}
	if err := DecompressReaderTo(io.Discard, nil, 1, 15, 1); err == nil {
		t.Fatal("nil source")
	}
	if err := DecompressReaderTo(io.Discard, bytes.NewReader(input), -1, 15, 1); err == nil {
		t.Fatal("negative size")
	}
}

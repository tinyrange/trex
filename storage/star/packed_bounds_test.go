package star

import (
	"bytes"
	"testing"
)

func TestPackedChunkRejectsCorruptionAndWrongExtent(t *testing.T) {
	store, err := NewPackedFileStore(0, false)
	if err != nil {
		t.Fatal(err)
	}
	input := bytes.Repeat([]byte("bounded chunk with verified checksum"), 300)
	file, err := store.Pack("bounds", input)
	if err != nil {
		t.Fatal(err)
	}
	packed := file.(*PackedFile)
	original := bytes.Clone(packed.chunks[0].data)
	for _, tc := range []struct {
		name   string
		data   []byte
		length int64
	}{
		{"truncated", original[:len(original)-1], int64(len(input))},
		{"short extent", original, int64(len(input) - 1)},
		{"long extent", original, int64(len(input) + 1)},
		{"trailing data", append(bytes.Clone(original), 0xff), int64(len(input))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			packed.chunks[0].data = tc.data
			packed.length = tc.length
			if _, err := packed.ReadAt(make([]byte, 1), 0); err == nil {
				t.Fatal("invalid encoded extent accepted")
			}
		})
	}
	corrupt := bytes.Clone(original)
	corrupt[len(corrupt)-1] ^= 1
	packed.chunks[0].data = corrupt
	packed.length = int64(len(input))
	if _, err := packed.ReadAt(make([]byte, 1), 0); err == nil {
		t.Fatal("checksum corruption accepted")
	}
	packed.chunks[0].data = original
	got, err := ReadAll(packed)
	if err != nil || !bytes.Equal(got, input) {
		t.Fatal("failed decode contaminated later reads", err)
	}
}

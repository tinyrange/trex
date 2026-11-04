package lzms

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"testing"
)

func TestDCSBlocksAndBounds(t *testing.T) {
	// Raw block from the independent Microsoft Compression API pattern fixture.
	raw, err := base64.StdEncoding.DecodeString("OBPQvwAA0HSBfr66/srvvq3e")
	if err != nil {
		t.Fatal(err)
	}
	one, err := Decompress(raw, 8192)
	if err != nil {
		t.Fatal(err)
	}
	data := []byte{'D', 'C', 'S', 1, 2, 0, 0, 0, 0, 64, 0, 0}
	for i := 0; i < 2; i++ {
		data = binary.LittleEndian.AppendUint32(data, uint32(len(raw)+4))
		data = binary.LittleEndian.AppendUint32(data, 8192)
		data = append(data, raw...)
	}
	got, err := DecompressDCS(data, 16384)
	if err != nil || !bytes.Equal(got, append(append([]byte(nil), one...), one...)) {
		t.Fatalf("two blocks: %v", err)
	}
	for n := 0; n < len(data); n++ {
		if _, err := DecompressDCS(data[:n], 16384); err == nil {
			t.Fatalf("accepted truncation %d", n)
		}
	}
	for _, offset := range []int{4, 8, 12, 16} {
		corrupt := append([]byte(nil), data...)
		binary.LittleEndian.PutUint32(corrupt[offset:], 0xffffffff)
		if _, err := DecompressDCS(corrupt, 16384); err == nil {
			t.Fatalf("accepted overflow at %d", offset)
		}
	}
	if _, err := DecompressDCS(data, 16383); err == nil {
		t.Fatal("ignored bound")
	}
	if _, err := DecompressDCS(append(data, 0), 16384); err == nil {
		t.Fatal("ignored trailing byte")
	}
}

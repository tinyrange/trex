package msdelta

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"hash/crc32"
	"testing"
)

func TestLiteralReverseExactLengthAndIntegrity(t *testing.T) {
	source := []byte("admitted installed bytes")
	for _, size := range []int{0, 1, 15, 16, 255, 256, 4095, 4096, 65535, 65536, 1000000} {
		target := make([]byte, size)
		for i := range target {
			target[i] = byte(i * 31)
		}
		predicted, err := LiteralReversePSFRecordSize(uint64(size), 128<<20)
		if err != nil {
			t.Fatal(err)
		}
		record, err := CreateLiteralReversePSFRecord(sha256.Sum256(source), target, ^uint64(0), 128<<20)
		if err != nil || int64(len(record)) != predicted {
			t.Fatalf("size %d: predicted %d actual %d err %v", size, predicted, len(record), err)
		}
		recovered, err := ApplyPSFRecordBounded(source, record, 128<<20)
		if err != nil || !bytes.Equal(recovered, target) {
			t.Fatalf("roundtrip size %d: %v", size, err)
		}
		if _, err := ApplyPSFRecordBounded([]byte("wrong source"), record, 128<<20); err == nil {
			t.Fatal("unbound source accepted")
		}
		h, err := ParsePSFRecord(record)
		if err != nil || h.TargetFileTime != ^uint64(0) {
			t.Fatal("timestamp", err)
		}
		if size > 0 {
			record[len(record)-1] ^= 1
			binary.LittleEndian.PutUint32(record, crc32.ChecksumIEEE(record[4:]))
			if _, err := ApplyPSFRecordBounded(source, record, 128<<20); err == nil {
				t.Fatal("checksum-valid target corruption accepted")
			}
		}
	}
	for _, size := range []uint64{128 << 20, 129 << 20, ^uint64(0)} {
		if _, err := LiteralReversePSFRecordSize(size, 128<<20); err == nil {
			t.Fatal("encoded bound ignored")
		}
	}
}

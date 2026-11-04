package msdelta

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"hash/crc32"
	"math/rand"
	"strings"
	"testing"
)

func TestCreateReversePSFRoundTrip(t *testing.T) {
	random := rand.New(rand.NewSource(1))
	base := make([]byte, 65537)
	random.Read(base)
	modified := bytes.Clone(base)
	for i := 0; i < len(modified); i += 97 {
		modified[i] ^= 0x55
	}
	for _, tc := range []struct {
		name           string
		source, target []byte
	}{
		{"empty", nil, nil}, {"literal", nil, []byte("checkpoint")},
		{"delete", base, nil}, {"identical", base, base},
		{"sparse", modified, base}, {"inserted", append([]byte("prefix"), base...), base},
		{"longer", base, append(bytes.Clone(base), []byte("suffix")...)},
		{"shorter", base, base[:1025]},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const timestamp = 123456789
			record, err := CreateReversePSFRecord(tc.source, tc.target, timestamp, 1<<20)
			if err != nil {
				t.Fatal(err)
			}
			got, err := ApplyPSFRecordBounded(tc.source, record, uint64(len(tc.target)))
			if err != nil || !bytes.Equal(got, tc.target) {
				t.Fatalf("roundtrip: %v", err)
			}
			header, err := ParsePSFRecord(record)
			sourceHash, targetHash := sha256.Sum256(tc.source), sha256.Sum256(tc.target)
			if err != nil || header.Version != "PA31" || header.FileTypeSet&0x100 == 0 || header.TargetFileTime != timestamp || !bytes.Equal(header.ExtensionHash, sourceHash[:]) || !bytes.Equal(header.TargetHash, targetHash[:]) {
				t.Fatalf("envelope: %+v %v", header, err)
			}
			again, err := CreateReversePSFRecord(tc.source, tc.target, timestamp, 1<<20)
			if err != nil || !bytes.Equal(again, record) {
				t.Fatal("nondeterministic record")
			}
			wrong := append(bytes.Clone(tc.source), 0)
			if _, err := ApplyPSFRecordBounded(wrong, record, 1<<20); err == nil || !strings.Contains(err.Error(), "source") {
				t.Fatalf("wrong source accepted: %v", err)
			}
			corrupt := bytes.Clone(record)
			corrupt[len(corrupt)-1] ^= 0x80
			if _, err := ApplyPSFRecordBounded(tc.source, corrupt, 1<<20); err == nil {
				t.Fatal("CRC corruption accepted")
			}
			// A checksum-valid payload mutation must still fail framing or the
			// independent target SHA256, not silently publish wrong bytes.
			binary.LittleEndian.PutUint32(corrupt, crc32.ChecksumIEEE(corrupt[4:]))
			if len(tc.target) > 0 && tc.name == "literal" {
				if _, err := ApplyPSFRecordBounded(tc.source, corrupt, 1<<20); err == nil {
					t.Fatal("target mutation accepted")
				}
			}
		})
	}
}

func TestReverseWriterBoundsAndIntegerExtremes(t *testing.T) {
	for _, maximum := range []uint64{0, 128<<20 + 1, 1, 8} {
		if _, err := CreateReversePSFRecord([]byte("source"), []byte("target"), 0, maximum); err == nil {
			t.Fatalf("accepted bound %d", maximum)
		}
	}
	tree, err := newHuffman(defaultHuffmanLengths(intFormatSymbols), 16)
	if err != nil {
		t.Fatal(err)
	}
	format := intFormat{tree: tree}
	for _, value := range []int64{0, 1, 2, 3, 4, 7, 8, 255, 256, 65535, 65536, -1, -2, -17, -65537, 1 << 62, 1<<63 - 1, -1 << 63} {
		w := newDeltaWriter()
		w.integer(value)
		r, err := newBitReader(w.finish())
		if err != nil {
			t.Fatal(err)
		}
		got, err := format.read(r)
		if err != nil || got != value || !r.atEnd() {
			t.Fatalf("integer %d -> %d: %v", value, got, err)
		}
	}
}

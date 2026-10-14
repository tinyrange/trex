package apfs

import (
	"bytes"
	"testing"
)

func TestCanonicalInodeStreamSparseAndFieldOrder(t *testing.T) {
	b := make([]byte, 96+3*4+8+40+8)
	le.PutUint64(b[48:], 0x8000|8|512|65536)
	le.PutUint32(b[60:], 7)
	le.PutUint32(b[64:], 23)
	le.PutUint16(b[92:], 3)
	le.PutUint16(b[94:], 56)
	copy(b[96:], []byte{13, 2, 8, 0, 8, 0x20, 40, 0, 4, 2, 5, 0})
	le.PutUint64(b[108:], 4096)
	le.PutUint64(b[116:], 8193)
	le.PutUint64(b[124:], 12288)
	le.PutUint64(b[132:], 91)
	le.PutUint64(b[140:], 8193)
	le.PutUint64(b[148:], 500)
	copy(b[156:], []byte{'n', 'a', 'm', 'e', 0, 0xaa, 0xaa, 0xaa})
	original := append([]byte(nil), b...)
	got, err := canonicalInode(b, 123456789)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b, original) {
		t.Fatal("source inode mutated")
	}
	for off := 16; off < 48; off += 8 {
		if le.Uint64(got[off:]) != 123456789 {
			t.Fatal("timestamp not canonical")
		}
	}
	if le.Uint64(got[48:]) != 0x8000 || le.Uint32(got[60:]) != 0 || le.Uint32(got[64:]) != 1 {
		t.Fatal("inode flags/protection/generation")
	}
	if le.Uint16(got[92:]) != 2 || le.Uint16(got[94:]) != 48 || !bytes.Equal(got[96:104], []byte{4, 2, 5, 0, 8, 0x20, 40, 0}) || !bytes.Equal(got[104:112], []byte{'n', 'a', 'm', 'e', 0, 0, 0, 0}) {
		t.Fatal("sparse field removal, sorting or padding")
	}
	if le.Uint64(got[112:]) != 8193 || le.Uint64(got[120:]) != 12288 || le.Uint64(got[128:]) != 91 || le.Uint64(got[136:]) != 1 || le.Uint64(got[144:]) != 1 {
		t.Fatal("stream sizes/crypto ID/counters")
	}
	again, err := canonicalInode(got, 123456789)
	if err != nil || !bytes.Equal(got, again) {
		t.Fatalf("canonical inode not idempotent: %v", err)
	}
}

func TestCanonicalInodeRejectsMalformedFields(t *testing.T) {
	for _, b := range [][]byte{make([]byte, 91), make([]byte, 93), make([]byte, 97)} {
		if _, err := canonicalInode(b, 1); err == nil {
			t.Fatal("accepted truncated/trailing inode fields")
		}
	}
	b := make([]byte, 100)
	le.PutUint16(b[92:], 1)
	copy(b[96:], []byte{8, 0x20, 40, 0})
	if _, err := canonicalInode(b, 1); err == nil {
		t.Fatal("accepted out-of-bounds stream field")
	}
}

func TestCanonicalRecordsMovesExtentsAndNormalizesAttributeStreams(t *testing.T) {
	xattr := make([]byte, 52)
	le.PutUint16(xattr, 1)
	le.PutUint16(xattr[2:], 48)
	le.PutUint64(xattr[4:], 21)
	le.PutUint64(xattr[12:], 4100)
	le.PutUint64(xattr[20:], 8192)
	le.PutUint64(xattr[28:], 37)
	le.PutUint64(xattr[36:], 4100)
	leaf := tree([]pair{
		inodePair(2, 2, 0, 0x41ed),
		drec("file", 20),
		{append(fsKey(20, 4), []byte{2, 0, 'a', 0}...), xattr},
		{le.AppendUint64(fsKey(21, 8), 0), make([]byte, 24)},
	}, false)
	c := &Container{Source: bytes.NewReader(leaf), BlockSize: 4096, Blocks: 1}
	v := &Volume{container: c, Flags: 1, RootTreeType: 0x40000002}
	hash := Record{le.AppendUint64(fsKey(21, 13), 1<<56), make([]byte, 35)}
	le.PutUint16(hash.Value, 2)
	hash.Value[2] = 32
	got, err := v.CanonicalRecords(987654321, []Record{hash})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 || le.Uint64(got[3].Key)>>60 != 13 || !bytes.Equal(got[3].Value, hash.Value) {
		t.Fatal("extent removal/hash insertion")
	}
	if le.Uint64(got[1].Value[8:]) != 987654321 || le.Uint64(got[2].Value[36:]) != 1 || le.Uint64(got[2].Value[44:]) != 1 || !bytes.Equal(got[2].Value[:36], xattr[:36]) {
		t.Fatal("date added or xattr stream canonicalization")
	}
	source, err := v.Records()
	if err != nil || !bytes.Equal(source[2].Value, xattr) {
		t.Fatalf("source records changed: %v", err)
	}
	if _, err := v.CanonicalRecords(1, []Record{hash, hash}); err == nil {
		t.Fatal("accepted duplicate data hash")
	}
	for _, size := range []byte{0, 31, 33} {
		bad := Record{hash.Key, make([]byte, int(size)+3)}
		le.PutUint16(bad.Value, 1)
		bad.Value[2] = size
		if _, err := v.CanonicalRecords(1, []Record{bad}); err == nil {
			t.Fatal("accepted invalid hash size", size)
		}
	}
}

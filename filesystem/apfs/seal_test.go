package apfs

import (
	"bytes"
	"crypto/sha256"
	"strings"
	"testing"
)

func sealedFixture() (*Volume, []byte) {
	b := make([]byte, 4*4096)
	dataHash := make([]byte, 35)
	le.PutUint16(dataHash, 1)
	dataHash[2] = 32
	child := tree([]pair{inodePair(2, 2, 0, 0x41ed), inodePair(10, 11, 0, 0x81a4), drec("empty", 10), {le.AppendUint64(fsKey(11, 13), 1<<56), dataHash}}, false)
	clear(child[:32])
	clear(child[4056:])
	le.PutUint16(child[32:], 0x1a)
	for i := 0; i < 4; i++ {
		p := child[56+i*8:]
		le.PutUint16(p[4:], le.Uint16(p[4:])+40)
	}
	h := sha256.Sum256(child)
	value := le.AppendUint64(nil, 2)
	value = append(value, h[:]...)
	root := tree([]pair{{fsKey(2, 3), value}}, false)
	clear(root[:32])
	le.PutUint16(root[32:], 0x19)
	le.PutUint16(root[34:], 1)
	le.PutUint32(root[4056:], 0x1c2)
	h = sha256.Sum256(root)
	im := block(30, 7)
	le.PutUint32(im[32:], 2)
	le.PutUint32(im[40:], 1)
	le.PutUint32(im[44:], 128)
	copy(im[128:], h[:])
	seal(im)
	copy(b, im)
	copy(b[4096:], root)
	copy(b[2*4096:], child)
	c := &Container{Source: bytes.NewReader(b), BlockSize: 4096, Blocks: 4}
	// Child IDs are relative to root OID 1000; physical blocks are deliberately
	// noncontiguous with respect to those IDs.
	return &Volume{container: c, Flags: 1, Incompatible: 0x28, Integrity: 7, RootTree: 1000, RootTreeType: 2, omap: map[uint64]mapping{7: {address: 0}, 1000: {address: 1}, 1002: {address: 2}}}, b
}

func TestSealedRelativeTreeAuthentication(t *testing.T) {
	v, b := sealedFixture()
	s, err := v.SealInformation()
	if err != nil {
		t.Fatal(err)
	}
	r, d, err := v.VerifySeal(s.RootHash)
	if err != nil || r != 4 || d != 1 {
		t.Fatalf("records=%d hashes=%d err=%v", r, d, err)
	}
	entries, err := v.Entries(false)
	if err != nil || len(entries) != 2 || entries[1].Path != "/empty" {
		t.Fatalf("entries=%v err=%v", entries, err)
	}
	if _, _, err := v.VerifySeal(make([]byte, 32)); err == nil {
		t.Fatal("accepted wrong trusted root")
	}
	b[2*4096+200] ^= 1
	if _, _, err := v.VerifySeal(nil); err == nil || !strings.Contains(err.Error(), "seal hash mismatch") {
		t.Fatalf("accepted child modification: %v", err)
	}
}

func TestIntegrityMetadataValidation(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func([]byte)
	}{
		{"version", func(b []byte) { le.PutUint32(b[32:], 3) }},
		{"hash", func(b []byte) { le.PutUint32(b[40:], 9) }},
		{"hash-in-header", func(b []byte) { le.PutUint32(b[44:], 16) }},
		{"hash-outside", func(b []byte) { le.PutUint32(b[44:], 4090) }},
		{"broken-flags", func(b []byte) { le.PutUint32(b[36:], 1) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, b := sealedFixture()
			tc.edit(b[:4096])
			seal(b[:4096])
			if _, err := v.SealInformation(); err == nil {
				t.Fatal("accepted invalid metadata")
			}
		})
	}
	v, b := sealedFixture()
	le.PutUint32(b[36:], 1)
	le.PutUint64(b[48:], 5)
	seal(b[:4096])
	if _, err := v.SealInformation(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := v.VerifySeal(nil); err == nil {
		t.Fatal("accepted broken seal")
	}
}

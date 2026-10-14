package macho

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
)

func TestFilesetSharesCollectionOffsets(t *testing.T) {
	b := make(source, 300)
	copy(b, filesetFixture())
	u32, u64 := binary.LittleEndian.PutUint32, binary.LittleEndian.PutUint64
	h := b[96:128]
	u32(h[12:], 11)
	u32(h[16:], 1)
	u32(h[20:], 72)
	c := b[128:200]
	u32(c, 0x19)
	u32(c[4:], 72)
	copy(c[8:], "__TEXT")
	u64(c[24:], 0xfffffe0007004000)
	u64(c[32:], 4)
	u64(c[40:], 256)
	u64(c[48:], 4)
	copy(b[256:], "CODE")
	outer, err := Open(b, ARM64)
	if err != nil {
		t.Fatal(err)
	}
	inner, err := outer.Fileset("com.apple.kernel")
	if err != nil || inner.Type != 11 || inner.Source.Size() != int64(len(b)) {
		t.Fatalf("embedded image=%+v err=%v", inner, err)
	}
	data, err := inner.At(0xfffffe0007004000, 4)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(io.NewSectionReader(data, 0, 4))
	if err != nil || !bytes.Equal(got, []byte("CODE")) {
		t.Fatalf("shared segment=%q err=%v", got, err)
	}
	if _, err := outer.Fileset("absent"); err == nil {
		t.Fatal("accepted absent entry")
	}
	u32(h[4:], AMD64)
	if _, err := outer.Fileset("com.apple.kernel"); err == nil {
		t.Fatal("accepted mismatched embedded CPU")
	}
}

func TestBoundFilesetStrippedIndirectPlaceholders(t *testing.T) {
	b := make(source, 1024)
	copy(b, filesetFixture())
	binary.LittleEndian.PutUint64(b[48:], 608)
	inner := importFixture()
	copy(b[608:], inner[:368])
	binary.LittleEndian.PutUint32(b[608+276:], 0) // stripped LC_SYMTAB nsyms
	// The bound collection retains four zero indirect slots without names.
	outer, err := Open(b, ARM64)
	if err != nil {
		t.Fatal(err)
	}
	member, err := outer.Fileset("com.apple.kernel")
	if err != nil || len(member.Imports) != 0 {
		t.Fatalf("stripped imports=%+v err=%v", member, err)
	}
	binary.LittleEndian.PutUint32(b[480:], 1)
	if _, err := outer.Fileset("com.apple.kernel"); err == nil {
		t.Fatal("accepted nonzero index with no shared symbol metadata")
	}
}

func filesetFixture() source {
	b := make(source, 128)
	u32, u64 := binary.LittleEndian.PutUint32, binary.LittleEndian.PutUint64
	u32(b, 0xfeedfacf)
	u32(b[4:], ARM64)
	u32(b[8:], 0xc0000002) // arm64e with capability bits
	u32(b[12:], 12)
	u32(b[16:], 1)
	u32(b[20:], 56)
	c := b[32:88]
	u32(c, 0x80000035)
	u32(c[4:], 56)
	u64(c[8:], 0xfffffe0007004000)
	u64(c[16:], 96)
	u32(c[24:], 32)
	copy(c[32:], "com.apple.kernel")
	copy(b[96:], b[:32])
	return b
}

func TestARM64Fileset(t *testing.T) {
	b := filesetFixture()
	image, err := OpenSubtype(b, ARM64, 0xc0000002)
	if err != nil {
		t.Fatal(err)
	}
	if len(image.FilesetEntries) != 1 || image.FilesetEntries[0].Name != "com.apple.kernel" || image.FilesetEntries[0].Offset != 96 || image.FilesetEntries[0].Address != 0xfffffe0007004000 {
		t.Fatalf("fileset %+v", image.FilesetEntries)
	}
	if _, err := Open(b, AMD64); err == nil {
		t.Fatal("accepted mismatched CPU")
	}
	for name, edit := range map[string]func(source){
		"wrong-type":         func(b source) { binary.LittleEndian.PutUint32(b[12:], 2) },
		"reserved":           func(b source) { b[60] = 1 },
		"name-in-header":     func(b source) { binary.LittleEndian.PutUint32(b[56:], 24) },
		"name-after-command": func(b source) { binary.LittleEndian.PutUint32(b[56:], 56) },
		"empty-name":         func(b source) { b[64] = 0 },
		"unterminated-name": func(b source) {
			for i := 64; i < 88; i++ {
				b[i] = 'x'
			}
		},
		"header-outside-file": func(b source) { binary.LittleEndian.PutUint64(b[48:], 97) },
	} {
		t.Run(name, func(t *testing.T) {
			b := filesetFixture()
			edit(b)
			if _, err := Open(b, ARM64); err == nil {
				t.Fatal("accepted malformed fileset")
			}
		})
	}
}

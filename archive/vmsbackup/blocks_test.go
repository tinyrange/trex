package vmsbackup

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
)

func sealBlock(b []byte) {
	binary.LittleEndian.PutUint16(b[254:], headerChecksum(b[:256]))
	binary.LittleEndian.PutUint32(b[36:], blockChecksum(b))
}

func testBlock(sequence uint32, kind uint16) []byte {
	b := make([]byte, 512)
	binary.LittleEndian.PutUint16(b, 256)
	binary.LittleEndian.PutUint16(b[2:], 0x400)
	binary.LittleEndian.PutUint16(b[4:], 1)
	binary.LittleEndian.PutUint16(b[6:], kind)
	binary.LittleEndian.PutUint32(b[8:], sequence)
	if kind == 1 {
		binary.LittleEndian.PutUint32(b[40:], 512)
		binary.LittleEndian.PutUint16(b[256:], 240)
		binary.LittleEndian.PutUint16(b[258:], 4)
		binary.LittleEndian.PutUint32(b[260:], 0x12345678)
		binary.LittleEndian.PutUint32(b[264:], 7)
		binary.LittleEndian.PutUint32(b[268:], 9)
		for i := 272; i < len(b); i++ {
			b[i] = byte(i) ^ byte(sequence)
		}
	}
	sealBlock(b)
	return b
}

func TestReadBlocks(t *testing.T) {
	a, b, parity := testBlock(1, 1), testBlock(2, 1), testBlock(3, 2)
	for i := 256; i < 512; i++ {
		parity[i] = a[i] ^ b[i]
	}
	sealBlock(parity)
	input := append(append(bytes.Clone(a), b...), parity...)
	limits := Limits{MaximumBlocks: 3, MaximumRecords: 2, MaximumBlockSize: 512}
	blocks, err := ReadBlocks(bytes.NewReader(input), limits)
	if err != nil || len(blocks) != 3 {
		t.Fatal(blocks, err)
	}
	if !blocks[2].Parity || len(blocks[2].Records) != 0 || blocks[1].Offset != 512 {
		t.Fatal("parity/framing", blocks)
	}
	r := blocks[0].Records[0]
	data, err := io.ReadAll(io.NewSectionReader(r.Data, 0, r.Data.Size()))
	if err != nil || !bytes.Equal(data, a[272:]) || r.Offset != 256 || r.Kind != 4 || r.Flags != 0x12345678 || r.Address != 7 || r.Reserved != 9 {
		t.Fatal(r, err)
	}
	// Borrowed view, not a copied/flattened payload.
	input[272] ^= 1
	var one [1]byte
	_, _ = r.Data.ReadAt(one[:], 0)
	if one[0] != input[272] {
		t.Fatal("payload was copied")
	}
	input[272] ^= 1
	for name, mutate := range map[string]func([]byte){
		"crc":           func(p []byte) { p[300] ^= 1 },
		"sequence":      func(p []byte) { binary.LittleEndian.PutUint32(p[8:], 2); sealBlock(p[:512]) },
		"record bounds": func(p []byte) { binary.LittleEndian.PutUint16(p[256:], 241); sealBlock(p[:512]) },
		"header size":   func(p []byte) { binary.LittleEndian.PutUint16(p, 255); sealBlock(p[:512]) },
		"format":        func(p []byte) { p[3] = 3; sealBlock(p[:512]) },
		"kind":          func(p []byte) { p[6] = 3; sealBlock(p[:512]) },
		"parity":        func(p []byte) { p[1400] ^= 1; sealBlock(p[1024:]) },
		"block size":    func(p []byte) { binary.LittleEndian.PutUint32(p[552:], 256); sealBlock(p[512:1024]) },
	} {
		t.Run(name, func(t *testing.T) {
			bad := bytes.Clone(input)
			mutate(bad)
			if _, err := ReadBlocks(bytes.NewReader(bad), limits); err == nil {
				t.Fatal("accepted invalid block")
			}
		})
	}
	for _, size := range []int{0, 255, 511, 1535} {
		if _, err := ReadBlocks(bytes.NewReader(input[:size]), limits); err == nil {
			t.Fatal("accepted truncation", size)
		}
	}
	for _, limit := range []Limits{{2, 2, 512}, {3, 1, 512}, {3, 2, 511}, {0, 2, 512}} {
		if _, err := ReadBlocks(bytes.NewReader(input), limit); err == nil {
			t.Fatal("accepted limits", limit)
		}
	}
	if _, err := ReadBlocks(bytes.NewReader(input[:512]), limits); err != nil {
		t.Fatal("unprotected group", err)
	}
}

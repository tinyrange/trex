package pbzx

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// XZ can return the entire requested buffer together with a checksum error.
// io.ReadFull would suppress that error once the buffer is full; never admit
// such output into either decoded or fast-compressed cache.
func TestReplayRejectsFinalChecksum(t *testing.T) {
	packed, _ := replayFixture(t)
	length := int(binary.BigEndian.Uint64(packed[20:28]))
	xz := packed[28 : 28+length]
	indexSize := (int(binary.LittleEndian.Uint32(xz[len(xz)-8:len(xz)-4])) + 1) * 4
	indexStart := len(xz) - 12 - indexSize
	xz[indexStart-1] ^= 1 // final byte of the block checksum, just before Index
	for _, budget := range []int64{0, 1 << 20} {
		f, err := OpenWithReplayCache(bytes.NewReader(packed), 0, budget)
		if err != nil {
			t.Fatalf("index/framing should remain valid: %v", err)
		}
		var b [4096]byte
		if _, err := f.ReadAt(b[:], 0); err == nil {
			t.Fatal("accepted bad trailing checksum")
		}
		if f.cache.Stats().Loads != 0 {
			t.Fatal("cached failed verification")
		}
		if f.replay != nil && f.replay.Stats().Loads != 0 {
			t.Fatal("replay cached failed verification")
		}
	}
}

package lzx

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// Exercise actual frame offsets without allocating a gigabyte-long fixture.
func TestCABIntelTransformStopsAfterFirstGiB(t *testing.T) {
	d := lzxDecoder{intelStarted: true, intelSize: 0x7fffffff}
	original := make([]byte, 32)
	original[2] = 0xe8
	binary.LittleEndian.PutUint32(original[3:7], 12345)
	for _, start := range []int{(1 << 30) - lzxFrameSize, 1 << 30, (1 << 30) + lzxFrameSize} {
		frame := bytes.Clone(original)
		d.undoCABFrame(frame, start)
		if start < 1<<30 {
			want := uint32(int32(12345) - int32(start+2))
			if got := binary.LittleEndian.Uint32(frame[3:7]); got != want {
				t.Fatalf("last translated frame: got %#x, want %#x", got, want)
			}
		} else if !bytes.Equal(frame, original) {
			t.Fatalf("frame at %#x was transformed past CAB cutoff", start)
		}
	}
}

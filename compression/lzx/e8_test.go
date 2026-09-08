package lzx

import (
	"bytes"
	"encoding/binary"
	"math/rand"
	"testing"
)

func TestE8ScanAgainstBytewiseReference(t *testing.T) {
	rng := rand.New(rand.NewSource(8))
	for trial := 0; trial < 200; trial++ {
		frame := make([]byte, rng.Intn(lzxFrameSize+1))
		rng.Read(frame)
		start := trial * lzxFrameSize
		intelSize := int32(12000000)
		for i := 0; i+5 < len(frame); i += 7 {
			frame[i] = 0xe8
			values := []int32{0, intelSize - 1, intelSize, -int32(start + i), -int32(start+i) - 1, 0xe8e8}
			binary.LittleEndian.PutUint32(frame[i+1:i+5], uint32(values[rng.Intn(len(values))]))
		}
		want := bytes.Clone(frame)
		for i := 0; i < len(want)-10; i++ {
			if want[i] != 0xe8 {
				continue
			}
			pos := int32(start + i)
			value := int32(binary.LittleEndian.Uint32(want[i+1 : i+5]))
			if value >= -pos && value < intelSize {
				if value >= 0 {
					value -= pos
				} else {
					value += intelSize
				}
				binary.LittleEndian.PutUint32(want[i+1:i+5], uint32(value))
			}
			i += 4
		}
		d := lzxDecoder{intelSize: intelSize, intelStarted: true}
		d.undoE8(frame, start)
		if !bytes.Equal(frame, want) {
			t.Fatalf("trial %d", trial)
		}
	}
}

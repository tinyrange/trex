package lzms

import (
	"bytes"
	"encoding/binary"
	"math/rand"
	"testing"
)

func referenceRestoreX86Addresses(data []byte) {
	const unseen = -1 << 30
	closestLikelyCode := unseen
	lastTargetUsage := make([]int, 1<<16)
	for index := range lastTargetUsage {
		lastTargetUsage[index] = unseen
	}
	for position := 1; position < len(data)-16; {
		// E9 is scan-only: consume its operand but do not let it participate in
		// translation or target-recency state.
		if data[position] == 0xe9 {
			position += 5
			continue
		}
		operandOffset, window, recognized := x86Candidate(data, position)
		if !recognized {
			position++
			continue
		}
		operand := position + operandOffset
		value := binary.LittleEndian.Uint32(data[operand : operand+4])
		operandEnd := operand + 3
		if position-closestLikelyCode <= window {
			value -= uint32(position)
			binary.LittleEndian.PutUint32(data[operand:operand+4], value)
		}
		key := uint16(uint32(position) + uint32(uint16(value)))
		if operandEnd-lastTargetUsage[key] <= 65535 {
			closestLikelyCode = operandEnd
		}
		lastTargetUsage[key] = operandEnd
		position = operandEnd + 1
	}
}

func TestX86WordSkippingMatchesScalarTransform(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for size := 0; size < 4096; size += 7 {
		input := make([]byte, size)
		rng.Read(input)
		// Exercise low-entropy regions and candidates on either side of word
		// boundaries, including interacting repeated targets and scan-only E9.
		for at := 0; at+16 < size; at += 31 {
			for n := 0; n < 8; n++ {
				input[at+n] = 0
			}
			copy(input[at+8:], []byte{0xe8, 0x40, 0, 0, 0, 0xe9, 0x48, 0x8d})
		}
		a, b := bytes.Clone(input), bytes.Clone(input)
		restoreX86Addresses(a)
		referenceRestoreX86Addresses(b)
		if !bytes.Equal(a, b) {
			t.Fatalf("transform changed at size %d", size)
		}
	}
}

func FuzzX86WordSkippingMatchesScalar(f *testing.F) {
	f.Add([]byte{0xe8, 0x48, 0x4c, 0xe9, 0xf0, 0xff})
	f.Add(bytes.Repeat([]byte{0, 0, 0, 0xe8, 0x40, 0, 0, 0}, 20))
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 1<<20 {
			t.Skip()
		}
		a, b := bytes.Clone(input), bytes.Clone(input)
		restoreX86Addresses(a)
		referenceRestoreX86Addresses(b)
		if !bytes.Equal(a, b) {
			t.Fatal("transform differs from scalar")
		}
	})
}

func BenchmarkX86Filter(b *testing.B) {
	input := make([]byte, 4<<20)
	for at := 64; at < len(input)-8; at += 1024 {
		copy(input[at:], []byte{0x48, 0x8d, 0x05, 0x40, 0, 0, 0})
	}
	for _, tc := range []struct {
		name string
		fn   func([]byte)
	}{{"scalar", referenceRestoreX86Addresses}, {"word", restoreX86Addresses}} {
		b.Run(tc.name, func(b *testing.B) {
			data := make([]byte, len(input))
			b.SetBytes(int64(len(input)))
			for b.Loop() {
				copy(data, input)
				tc.fn(data)
			}
		})
	}
}

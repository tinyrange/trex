package lzms

import (
	"bytes"
	"encoding/binary"
	"math/rand"
	"testing"
)

func restoreX86AddressesReference(data []byte) {
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

func TestX86CandidateDispatchMatchesOriginalScan(t *testing.T) {
	rng := rand.New(rand.NewSource(2314))
	for _, size := range []int{0, 1, 16, 17, 31, 512, 65536, 131072} {
		for variant := 0; variant < 8; variant++ {
			input := make([]byte, size)
			if variant != 0 {
				if _, err := rng.Read(input); err != nil {
					t.Fatal(err)
				}
			}
			// Exercise every leading byte and repeated targets across both recency
			// windows, with E9 scan-only operands interleaved among real candidates.
			if variant >= 4 {
				for pos := 1; pos+8 < size; pos += 19 {
					input[pos] = []byte{0xe8, 0xe9, 0x48, 0x4c, 0xf0, 0xff}[pos%6]
					input[pos+1], input[pos+2] = 0x8d, 0x05
					if input[pos] == 0xf0 {
						input[pos+1] = 0x83
					}
					if input[pos] == 0xff {
						input[pos+1] = 0x15
					}
					binary.LittleEndian.PutUint32(input[pos+3:], uint32(7-pos))
				}
			}
			want := bytes.Clone(input)
			got := bytes.Clone(input)
			restoreX86AddressesReference(want)
			restoreX86Addresses(got)
			if !bytes.Equal(got, want) {
				t.Fatalf("size=%d variant=%d", size, variant)
			}
		}
	}
}

func BenchmarkX86FilterDispatch(b *testing.B) {
	input := make([]byte, 1<<20)
	rng := rand.New(rand.NewSource(2314))
	_, _ = rng.Read(input)
	for _, test := range []struct {
		name string
		fn   func([]byte)
	}{{"original", restoreX86AddressesReference}, {"candidate_dispatch", restoreX86Addresses}} {
		b.Run(test.name, func(b *testing.B) {
			data := make([]byte, len(input))
			b.SetBytes(int64(len(input)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				copy(data, input)
				test.fn(data)
			}
		})
	}
}

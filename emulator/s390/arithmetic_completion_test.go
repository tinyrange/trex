package s390

import (
	"encoding/hex"
	"testing"
)

func TestFixedPointOverflowCompletesBeforeInterrupt(t *testing.T) {
	for _, arch := range []string{"s370", "esa390"} {
		for _, tc := range []struct {
			name    string
			code    []byte
			a, want uint32
		}{
			{"AR", []byte{0x1a, 0x12}, 0x7fffffff, 0x80000000},
			{"SR", []byte{0x1b, 0x12}, 0x80000000, 0x7fffffff},
			{"A", []byte{0x5a, 0x10, 0x30, 0}, 0x7fffffff, 0x80000000},
			{"S", []byte{0x5b, 0x10, 0x30, 0}, 0x80000000, 0x7fffffff},
			{"AH", []byte{0x4a, 0x10, 0x30, 2}, 0x7fffffff, 0x80000000},
			{"SH", []byte{0x4b, 0x10, 0x30, 2}, 0x80000000, 0x7fffffff},
			{"AHI", []byte{0xa7, 0x1a, 0, 1}, 0x7fffffff, 0x80000000},
		} {
			t.Run(arch+"/"+tc.name, func(t *testing.T) {
				ctor := newTest
				if arch == "s370" {
					ctor = newTest370
				}
				m, c := ctor(t, tc.code)
				c.GR[1], c.GR[2], c.GR[3] = tc.a, 1, 0x3000
				be.PutUint32(m.S.Mem[0x3000:], 1)
				c.PSW.ProgMask = 8
				m.Run(1)
				old := be.Uint64(m.S.Mem[pswPgmOld:])
				p, _ := DecodePSW(old)
				code := be.Uint16(m.S.Mem[0x8e:])
				if arch == "s370" {
					p.IA, p.CC = uint32(old)&0xffffff, byte(old>>28)&3
					code = uint16(old >> 32)
				}
				if c.GR[1] != tc.want || p.CC != 3 || p.IA != 0x1000+uint32(len(tc.code)) || code != pgmFixedOverflow {
					t.Fatalf("result=%08x old PSW=%016x code=%x", c.GR[1], old, code)
				}
			})
		}
	}
}

func TestPackedSignsIncludingZero(t *testing.T) {
	for _, arch := range []string{"s370", "esa390"} {
		for _, tc := range []struct {
			name       string
			op         byte
			a, b, want string
			cc         byte
		}{
			{"multiply_negative_zero", 0xfc, "000d", "1c", "000d", 2},
			{"multiply_negative_signs", 0xfc, "000b", "1d", "000c", 2},
			{"divide_negative_zero", 0xfd, "000d", "1c", "0d0d", 2},
			{"divide_negative_divisor", 0xfd, "000c", "1d", "0d0c", 2},
			{"divide_zero_quotient", 0xfd, "001d", "2c", "0d1d", 2},
			{"divide_zero_remainder", 0xfd, "002d", "2c", "1d0d", 2},
			{"negative_overflow_zero", 0xfa, "9d", "1d", "0d", 3},
			{"exact_zero_positive", 0xfa, "1d", "1c", "0c", 0},
		} {
			t.Run(arch+"/"+tc.name, func(t *testing.T) {
				a, _ := hex.DecodeString(tc.a)
				b, _ := hex.DecodeString(tc.b)
				code := []byte{tc.op, byte((len(a)-1)<<4 | (len(b) - 1)), 0x30, 0, 0x30, 0x10}
				ctor := newTest
				if arch == "s370" {
					ctor = newTest370
				}
				m, c := ctor(t, code)
				c.GR[3], c.PSW.CC = 0x3000, 2
				copy(m.S.Mem[0x3000:], a)
				copy(m.S.Mem[0x3010:], b)
				m.Run(1)
				got := hex.EncodeToString(m.S.Mem[0x3000 : 0x3000+len(a)])
				if got != tc.want || c.PSW.CC != tc.cc || c.PSW.IA != 0x1006 {
					t.Fatalf("result=%s cc=%d IA=%x", got, c.PSW.CC, c.PSW.IA)
				}
			})
		}
	}
}

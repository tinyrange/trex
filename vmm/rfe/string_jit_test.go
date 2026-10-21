package rfe

import (
	"context"
	"encoding/binary"
	"fmt"
	"j5.nz/cc/hypervisor"
	"testing"
	"time"
)

func TestJITLegacyStringIterationsAndZeroCountDifferential(t *testing.T) {
	for _, bits := range []int{16, 32} {
		for _, width := range []int{1, 2, 4} {
			for _, op := range []byte{0xa4, 0xa6, 0xaa, 0xac, 0xae} {
				for _, backward := range []bool{false, true} {
					name := fmt.Sprintf("%d/w%d/op%x/backward%v", bits, width, op, backward)
					t.Run(name, func(t *testing.T) {
						code := []byte{0x64} // FS source override, ES destination
						if width != 1 && width != bits/8 {
							code = append(code, 0x66)
						}
						aw := bits / 8
						if backward {
							code = append(code, 0x67)
							aw = 6 - aw
						}
						repeat := byte(0xf3)
						if backward {
							repeat = 0xf2
						}
						code = append(code, repeat)
						actualOp := op
						if width != 1 {
							actualOp++
						}
						code = append(code, actualOp, 0xe6, 0xf2)
						actual, expected := jitCPU(t, bits, code), jitCPU(t, bits, code)
						for _, c := range []*cpu{actual, expected} {
							c.system.Segments[4].Base = 0x9000
							ptr := uint64(0x200)
							if backward {
								ptr += 255 * uint64(width)
								c.core.Flags |= 1 << 10
							}
							c.core.R[0] = 0x07070707
							high := uint64(0x1234567800000000)
							c.core.R[1] = high | 256
							c.core.R[6], c.core.R[7] = high|ptr, high|ptr
							for j := 0x200; j < 0x1000; j++ {
								c.ram[0x9000+j] = 7
								c.ram[j] = 7
								if backward && (op == 0xa6 || op == 0xae) {
									c.ram[j] = 11
								}
							}
						}
						referenceToPort(t, expected)
						ctx, cancel := context.WithTimeout(context.Background(), time.Second)
						defer cancel()
						if _, err := actual.Run(ctx); err != nil {
							t.Fatal(err)
						}
						equalJITState(t, actual, expected)
						if actual.jit.Stats()["native"] == 0 {
							t.Fatal("string loop remained interpreted")
						}
						if op == 0xa6 || op == 0xae {
							for _, c := range []*cpu{actual, expected} {
								c.pending = nil
								c.core.PC = 0x1000
								ptr := uint64(0x200)
								if backward {
									ptr += 255 * uint64(width)
								}
								high := uint64(0x1234567800000000)
								c.core.R[1] = high | 256
								c.core.R[6], c.core.R[7] = high|ptr, high|ptr
								stop := ptr + 20*uint64(width)
								value := byte(11)
								if backward {
									stop = ptr - 20*uint64(width)
									value = 7
								}
								for j := 0; j < width; j++ {
									c.ram[stop+uint64(j)] = value
								}
							}
							referenceToPort(t, expected)
							if _, err := actual.Run(ctx); err != nil {
								t.Fatal(err)
							}
							equalJITState(t, actual, expected)
							if actual.core.R[1]&0xffff != 235 {
								t.Fatal("REP condition did not stop after matching/mismatching element", actual.core.R[1])
							}
						}
						// A warmed zero-count REP must not touch invalid segment
						// endpoints, change flags or truncate the high registers.
						for _, c := range []*cpu{actual, expected} {
							c.pending = nil
							c.core.PC = 0x1000
							mask := uint64(1)<<(aw*8) - 1
							c.core.R[1] &^= mask
							c.core.R[6] |= mask
							c.core.R[7] |= mask
						}
						referenceToPort(t, expected)
						if _, err := actual.Run(ctx); err != nil {
							t.Fatal(err)
						}
						equalJITState(t, actual, expected)
					})
				}
			}
		}
	}
}

// After a genuinely native prefix, neither a second-page MMIO exit nor a
// write-protection fault may replay copied words or consume the failing REP
// iteration. Compare the full registers, RAM, retirement and architectural PF.
func TestJITREPStringPreciseSecondPageExit(t *testing.T) {
	for _, paging := range []bool{false, true} {
		t.Run(fmt.Sprint(paging), func(t *testing.T) {
			actual := jitCPU(t, 32, []byte{0xf3, 0xa5, 0xe6, 0xf2})
			expected := jitCPU(t, 32, []byte{0xf3, 0xa5, 0xe6, 0xf2})
			for _, c := range []*cpu{actual, expected} {
				c.core.R[1], c.core.R[6], c.core.R[7] = 1024, 0x200, 0xfc00
				c.system.Segments[0].Limit = 0xffffffff
				for j := 0; j < 4096; j++ {
					c.ram[0x6200+j] = byte(j + 1)
				}
				if paging {
					binary.LittleEndian.PutUint32(c.ram[0x3000:], 0x4007)
					for p := 0; p < 256; p++ {
						binary.LittleEndian.PutUint32(c.ram[0x4000+p*4:], uint32(p*4096)|7)
					}
					binary.LittleEndian.PutUint32(c.ram[0x4000+16*4:], 0x10005)
					c.system.CR[0], c.system.CR[3] = 0x80010011, 0x3000
					c.system.IDTR.Limit = 0 // Fault delivery itself stops deterministically.
				} else {
					c.regions = []hypervisor.RAMRegion{{Address: 0, Size: 0x10000}, {Address: 0x11000, Offset: 0x11000, Size: 0xef000}}
				}
			}
			var referenceErr error
			for n := 0; n < 2000; n++ {
				referenceErr = expected.core.Step()
				if referenceErr != nil {
					break
				}
			}
			if referenceErr == nil {
				t.Fatal("reference did not reach failing second page")
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			ex, err := actual.Run(ctx)
			if paging {
				if err == nil || actual.system.CR[2] != 0x10000 || actual.system.FaultCount != expected.system.FaultCount {
					t.Fatal("REP page fault", err, actual.system.CR[2])
				}
			} else if err != nil || ex.Reason != hypervisor.X86ExitMMIO || ex.Address != 0x10000 || !ex.Write || ex.Size != 4 {
				t.Fatal("REP MMIO", ex, err)
			}
			if paging {
				// A read-only speculative refill may set A before the write
				// faults, but must never set D or change any permission/frame.
				for a := 0x3000; a < 0x5000; a += 4 {
					got := binary.LittleEndian.Uint32(actual.ram[a:])
					want := binary.LittleEndian.Uint32(expected.ram[a:])
					if (got^want)&^uint32(32) != 0 || want&32 != 0 && got&32 == 0 {
						t.Fatal("speculative walk changed non-A metadata", a, got, want)
					}
					binary.LittleEndian.PutUint32(expected.ram[a:], got)
				}
			}
			equalJITState(t, actual, expected)
			if actual.core.Retired != 256 || actual.core.R[1] != 768 || actual.jit.Stats()["native"] == 0 {
				t.Fatal("REP prefix replayed/lost", actual.core.Retired, actual.core.R[1], actual.jit.Stats())
			}
		})
	}
}

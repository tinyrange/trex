package rfe

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestNativeLongModeStringsAddressWidthAndSegments(t *testing.T) {
	for _, aw32 := range []bool{false, true} {
		for _, back := range []bool{false, true} {
			for _, seg := range []byte{0, 0x3e, 0x64, 0x65} {
				for _, op := range []byte{0xa4, 0xa6, 0xaa, 0xac, 0xae} {
					t.Run(fmt.Sprintf("32=%v/back=%v/seg=%x/op=%x", aw32, back, seg, op), func(t *testing.T) {
						code := []byte{}
						if seg != 0 {
							code = append(code, seg)
						}
						if aw32 {
							code = append(code, 0x67)
						}
						code = append(code, 0xf3, op, 0xe6, 0xf2)
						actual, expected := jitCPU(t, 64, code), jitCPU(t, 64, code)
						ptr := uint64(0x2200)
						if back {
							ptr += 255
						}
						high := uint64(0)
						if aw32 {
							high = 0x1234567800000000
						}
						for _, c := range []*cpu{actual, expected} {
							c.core.R[0] = 7
							c.core.R[1] = high | 256
							c.core.R[6] = high | ptr
							c.core.R[7] = high | ptr
							if back {
								c.core.Flags |= 1 << 10
							}
							c.system.FSBase, c.system.GSBase = 0x10000, 0x20000
							c.system.Segments[0].Base, c.system.Segments[3].Base = 0x90000, 0x90000
							for i := 0x2200; i < 0x2300; i++ {
								c.ram[i] = 7
								c.ram[i+0x10000] = 7
								c.ram[i+0x20000] = 7
							}
						}
						referenceToPort(t, expected)
						ctx, cancel := context.WithTimeout(context.Background(), time.Second)
						defer cancel()
						if _, err := actual.Run(ctx); err != nil {
							t.Fatal(err)
						}
						equalJITState(t, actual, expected)
						if actual.jit.Stats()["native64"] == 0 {
							t.Fatal("long-mode string remained interpreted")
						}
						if aw32 && actual.core.R[1]>>32 != 0 {
							t.Fatal("ECX update did not zero-extend")
						}
						// A warmed zero-count address-size override must not access invalid pointers
						// or zero-extend registers when no iteration actually executes.
						for _, c := range []*cpu{actual, expected} {
							c.pending = nil
							c.core.PC = 0x1000
							c.core.R[1] = high
							c.core.R[6] = ^uint64(0)
							c.core.R[7] = ^uint64(0)
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

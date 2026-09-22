//go:build linux && amd64

package cc

import (
	"bytes"
	"context"
	"encoding/binary"
	"testing"
	"time"

	blockstar "github.com/tinyrange/trex/block/star"
	"github.com/tinyrange/trex/vmm"
	"j5.nz/cc/hypervisor"
	"j5.nz/cc/hypervisor/x86state"
)

func TestIDEProtectedStringTransfer(t *testing.T) {
	requireKVM(t)
	for _, write := range []bool{false, true} {
		for _, width := range []int{2, 4} {
			for _, paged := range []bool{false, true} {
				t.Run(string(rune('0'+width))+map[bool]string{false: "read", true: "write"}[write]+map[bool]string{false: "flat", true: "paged"}[paged], func(t *testing.T) {
					ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
					defer cancel()
					cpu, err := hypervisor.NewX86(ctx)
					if err != nil {
						t.Fatal(err)
					}
					defer cpu.Close()
					ram, err := cpu.MapRAM(0, 16<<20)
					if err != nil {
						t.Fatal(err)
					}
					data := make([]byte, 4*512)
					binary.LittleEndian.PutUint16(data[510:], 0xaa55)
					want := make([]byte, 1024)
					for i := range want {
						want[i] = byte(i*37 + i/256)
					}
					if !write {
						copy(data[512:], want)
					}
					disk, err := blockstar.NewOverlayDevice(testBlock(t, data), 4096, 512)
					if err != nil {
						t.Fatal(err)
					}
					p, err := newPC(cpu, ram, vmm.Disk{Device: disk}, time.Now)
					if err != nil {
						t.Fatal(err)
					}
					// Cross a page boundary as well as an ATA sector boundary.
					const buffer = 0x2ff0
					if write {
						copy(ram[buffer:], want)
					}
					code := []byte{0xb9}
					code = binary.LittleEndian.AppendUint32(code, uint32(len(want)/width))
					code = append(code, 0xbe)
					code = binary.LittleEndian.AppendUint32(code, buffer)
					code = append(code, 0xbf)
					code = binary.LittleEndian.AppendUint32(code, buffer)
					code = append(code, 0xba, 0xf0, 1, 0, 0, 0xf3)
					if width == 2 {
						code = append(code, 0x66)
					}
					op := byte(0x6d)
					command := byte(0x20)
					if write {
						op, command = 0x6f, 0x30
					}
					code = append(code, op, 0xb0, 0x42, 0xe6, 0xf2, 0xeb, 0xfe)
					copy(ram[0x1000:], code)
					s, err := cpu.SystemRegisters()
					if err != nil {
						t.Fatal(err)
					}
					seg := x86state.Segment{Limit: 0xffffffff, Selector: 16, Type: 3, Present: 1, Db: 1, S: 1, G: 1}
					s.Cs, s.Ds, s.Es, s.Fs, s.Gs, s.Ss = seg, seg, seg, seg, seg, seg
					s.Cs.Selector, s.Cs.Type = 8, 11
					s.Cr0 |= 1
					if paged {
						binary.LittleEndian.PutUint32(ram[0x5000:], 0x83)
						s.Cr3, s.Cr4 = 0x5000, 0x10
						s.Cr0 |= 1 << 31
					}
					if err := cpu.SetSystemRegisters(s); err != nil {
						t.Fatal(err)
					}
					if err := cpu.SetRegisters(x86state.Registers{Rip: 0x1000, Rsp: 0x9000, Rflags: 2}); err != nil {
						t.Fatal(err)
					}
					p.ide.task[2], p.ide.task[3], p.ide.task[6] = 2, 1, 0xe0
					if err := p.ide.command(command); err != nil {
						t.Fatal(err)
					}
					exits := 0
					for {
						ex, err := p.runWithHandler(ctx, func(ex hypervisor.X86Exit) (bool, error) {
							if ex.Reason != hypervisor.X86ExitIO || ex.Port != 0x1f0 {
								return false, nil
							}
							exits++
							return true, p.handleIO(ex)
						})
						if err != nil {
							t.Fatal(err)
						}
						if ex.Reason == 0 {
							continue
						}
						if ex.Reason != hypervisor.X86ExitIO {
							t.Fatalf("unexpected exit %+v", ex)
						}
						if ex.Port == 0xf2 {
							break
						}
						if err := p.handleIO(ex); err != nil {
							t.Fatal(err)
						}
					}
					if err := cpu.CompleteIO(); err != nil {
						t.Fatal(err)
					}
					r, err := cpu.Registers()
					if err != nil {
						t.Fatal(err)
					}
					end := r.Rdi
					got := ram[buffer : buffer+len(want)]
					if write {
						end = r.Rsi
						got = make([]byte, len(want))
						if _, err := disk.ReadAt(got, 512); err != nil {
							t.Fatal(err)
						}
					}
					if !bytes.Equal(got, want) || r.Rcx != 0 || end != buffer+uint64(len(want)) || p.ide.remaining != 0 {
						t.Fatalf("transfer or register mismatch: regs=%+v remaining=%d", r, p.ide.remaining)
					}
					t.Logf("%d native I/O exits for %d bytes", exits, len(want))
				})
			}
		}
	}
}

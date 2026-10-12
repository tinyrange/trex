//go:build linux && amd64

package cc

import (
	"context"
	"encoding/binary"
	"github.com/tinyrange/trex/vmm"
	"j5.nz/cc/hypervisor"
	"testing"
	"time"
)

func TestBIOSKeyboardBlockingReadNative(t *testing.T) {
	requireKVM(t)
	data := make([]byte, 512)
	copy(data, []byte{
		0xb0, 1, 0xe6, 0xf2, // Test sync marker before first blocking call.
		0xb8, 0, 0, 0xcd, 0x16, 0xa3, 0, 0x80, // Save BIOS word.
		0xb0, 2, 0xe6, 0xf2,
		0xb8, 0, 0, 0xcd, 0x16, 0xa3, 2, 0x80, // A second empty read must block again.
		0xb0, 3, 0xe6, 0xf2, 0xeb, 0xfe,
	})
	binary.LittleEndian.PutUint16(data[510:], 0xaa55)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
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
	p, err := newPC(cpu, ram, vmm.Disk{Device: testBlock(t, data)}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if ram[0xf1000+0x68*4] != 0xcf {
		t.Fatal("absent software hook is not inert")
	}
	marker := byte(0)
	injected := false
	for {
		ex, err := p.run(ctx)
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
			marker = ex.Data[0]
			injected = false
			if marker == 3 {
				break
			}
			if marker != 1 && marker != 2 {
				t.Fatal("invalid marker")
			}
			if err := cpu.CompleteIO(); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err = p.handleIO(ex); err != nil {
			t.Fatal(err)
		}
		// Inject only after the empty INT16 trap, not before entering firmware.
		if ex.Port == biosPort && marker != 0 && !injected {
			r, err := cpu.Registers()
			if err != nil {
				t.Fatal(err)
			}
			if r.Rip == 0x2202 && r.Rflags&0x40 != 0 {
				key := "a"
				if marker == 2 {
					key = "b"
				}
				if err = p.keyboard.key(key, true); err != nil {
					t.Fatal(err)
				}
				if err = p.keyboard.key(key, false); err != nil {
					t.Fatal(err)
				}
				injected = true
			}
		}
	}
	if binary.LittleEndian.Uint16(ram[0x8000:]) != 0x1e61 || binary.LittleEndian.Uint16(ram[0x8002:]) != 0x3062 {
		t.Fatalf("BIOS input %x", ram[0x8000:0x8004])
	}
	r, err := cpu.Registers()
	if err != nil {
		t.Fatal(err)
	}
	if r.Rsp != 0x7c00 {
		t.Fatalf("stack leaked: %x", r.Rsp)
	}
}

//go:build linux && amd64

package cc

import (
	"bytes"
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
	// Stop at the architectural sleep point, after the ROM observed an
	// empty ring. Inject IRQ1 only then, so preloaded keys cannot pass.
	sleep := bytes.Index(ram[0xf2700:0xf2800], []byte{0xfb, 0xf4, 0xfa})
	if sleep < 0 {
		t.Fatal("keyboard read has no interruptible sleep")
	}
	debug := cpu.(interface{ SetBreakpoint(uint64) error })
	sleepPC := uint64(0xf2700 + sleep + 1)
	defer debug.SetBreakpoint(0)
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
		if ex.Reason == hypervisor.X86ExitDebug {
			if marker == 0 || injected {
				t.Fatal("unexpected sleep breakpoint")
			}
			if head, tail := p.keyboardBounds(); head != tail {
				t.Fatal("read did not sleep empty")
			}
			// Observe each empty read exactly once. An interrupt may return
			// to HLT and clear RF before IRQ1 is serviced, so leaving an
			// execution breakpoint armed here races unrelated timer IRQs.
			if err = debug.SetBreakpoint(0); err != nil {
				t.Fatal(err)
			}
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
			continue
		}
		if ex.Reason != hypervisor.X86ExitIO {
			t.Fatalf("unexpected exit %+v", ex)
		}
		if ex.Port == 0xf2 {
			if next := ex.Data[0]; next != marker+1 {
				t.Fatalf("marker sequence %d -> %d", marker, next)
			}
			if marker != 0 && !injected {
				t.Fatal("blocking read completed before empty-ring observation and IRQ1 input")
			}
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
			if err = debug.SetBreakpoint(sleepPC); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err = p.handleIO(ex); err != nil {
			t.Fatal(err)
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

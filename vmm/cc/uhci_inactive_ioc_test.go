package cc

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"j5.nz/cc/hypervisor"
)

// UHCI 1.1 section 3.2.2, TD bit 24: fetching an inactive IOC TD
// still interrupts at frame end, without a USB transaction or QH advance.
func TestUHCIInactiveIOCInterruptsWithoutConsumingTail(t *testing.T) {
	for _, queued := range []bool{false, true} {
		name := "frame-list"
		if queued {
			name = "queue-tail"
		}
		t.Run(name, func(t *testing.T) {
			u, ram, irq := usbTestController()
			u.interrupt = 4
			usbTestTD(ram, 0x2000, 1, 0x69, 0, 1, 8)
			binary.LittleEndian.PutUint32(ram[0x2004:], 1<<24)      // IOC, inactive.
			binary.LittleEndian.PutUint32(ram[0x200c:], 0xfffffff0) // Must not DMA.
			original := append([]byte(nil), ram[0x2000:0x2010]...)
			link := uint32(0x2000)
			if queued {
				binary.LittleEndian.PutUint32(ram[0x1000:], 1)
				binary.LittleEndian.PutUint32(ram[0x1004:], 0x2000)
				link = 0x1002
			}
			for frame := 0; frame < 2; frame++ {
				if err := u.schedule(link); err != nil {
					t.Fatal(err)
				}
				if err := u.updateIRQ(); err != nil {
					t.Fatal(err)
				}
				if u.status&1 == 0 || !*irq {
					t.Fatalf("inactive IOC did not interrupt on frame %d", frame)
				}
				if u.transactions != 0 || !bytes.Equal(original, ram[0x2000:0x2010]) {
					t.Fatal("inactive descriptor was executed or changed")
				}
				if queued && binary.LittleEndian.Uint32(ram[0x1004:]) != 0x2000 {
					t.Fatal("inactive QH tail advanced")
				}
				if err := u.io(hypervisor.X86Exit{Port: uint16(u.ioBase() + 2), Size: 2, Count: 1, Write: true, Data: []byte{1, 0}}, time.Unix(1, 0)); err != nil {
					t.Fatal(err)
				}
				if *irq {
					t.Fatal("W1C did not acknowledge interrupt")
				}
			}
		})
	}
}

package cc

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"

	"github.com/tinyrange/trex/channel"
)

type appleUSBPCITest struct {
	t     *testing.T
	board *protocolTestBus
	pci   *appleUSBPCI
	host  *channel.Memory
	irq   [2]int
}

func newAppleUSBPCITest(t *testing.T, capacity int) *appleUSBPCITest {
	t.Helper()
	d, host := usbDevice(t, capacity)
	f := &appleUSBPCITest{t: t, board: d, host: host}
	t.Cleanup(func() { host.Close(); d.usb.Close() })
	f.pci = newAppleUSBPCI(0x40018000, 0x50020000, d.usb, d.dmaMemory, func(a uint64, v uint32) error {
		if a != 0x1fff0040 || v < 66 || v > 67 {
			t.Fatalf("unexpected USB MSI %#x:%d", a, v)
		}
		f.irq[v-66]++
		return nil
	}, nil)
	if got, err := f.pci.read(0x40018000, 4); err != nil || got != 0x1a01106b {
		t.Fatalf("USB PCI identity %#x: %v", got, err)
	}
	f.configure()
	return f
}

func (f *appleUSBPCITest) configure() {
	f.t.Helper()
	f.write(0x40018004, 2, 6)
	if got, err := f.pci.read(0x50020012, 2); err != nil || got != 2 {
		f.t.Fatalf("USB queue count %d: %v", got, err)
	}
	f.write(0x50020014, 1, 3)
	f.write(0x50020008, 4, 1)
	f.write(0x5002000c, 4, 1)
	f.write(0x50020014, 1, 11)
	for q := uint64(0); q < 2; q++ {
		f.write(0x50020016, 2, q)
		f.write(0x50020018, 2, 8)
		f.write(0x5002001a, 2, q)
		f.write(0x50020020, 8, f.board.ramBase+q*0x400)
		f.write(0x50020028, 8, f.board.ramBase+q*0x400+0x100)
		f.write(0x50020030, 8, f.board.ramBase+q*0x400+0x200)
		f.write(0x5002001c, 2, 1)
		f.write(0x50023000+q*16, 8, 0x1fff0040)
		f.write(0x50023008+q*16, 4, 66+q)
		f.write(0x5002300c+q*16, 4, 0)
	}
	f.write(0x40018086, 2, 0x8001)
	f.write(0x50020014, 1, 15)
}

func (f *appleUSBPCITest) write(a uint64, n int, v uint64) {
	f.t.Helper()
	if err := f.pci.write(a, n, v); err != nil {
		f.t.Fatal(err)
	}
}

func (f *appleUSBPCITest) descriptor(q, index, offset, length int, flags, next uint16) {
	p := f.board.ram[q*0x400+index*16:]
	binary.LittleEndian.PutUint64(p, f.board.ramBase+uint64(offset))
	binary.LittleEndian.PutUint32(p[8:], uint32(length))
	binary.LittleEndian.PutUint16(p[12:], flags)
	binary.LittleEndian.PutUint16(p[14:], next)
}

func (f *appleUSBPCITest) submit(q int, index uint16) {
	f.t.Helper()
	binary.LittleEndian.PutUint16(f.board.ram[q*0x400+0x102:], index)
	f.write(0x50020016, 2, uint64(q))
	notify, err := f.pci.read(0x5002001e, 2)
	if err != nil {
		f.t.Fatal(err)
	}
	f.write(0x50021000+notify*4, 2, uint64(q))
}

func (f *appleUSBPCITest) used(q int) uint16 {
	return binary.LittleEndian.Uint16(f.board.ram[q*0x400+0x202:])
}

func TestAppleUSBPCIFragmentedControlAndIndependentQueues(t *testing.T) {
	f := newAppleUSBPCITest(t, 64)
	ram := f.board.ram
	rx := ram[0x1000 : 0x1000+appleUSBPCIReceiveSize]
	for i := range rx {
		rx[i] = 0xa5
	}
	f.descriptor(0, 0, 0x1000, appleUSBPCIReceiveSize, 2, 0)
	f.submit(0, 1)
	if f.used(0) != 0 || f.irq != [2]int{} {
		t.Fatal("empty host stream completed a receive")
	}
	// A guest response must progress while the host receive queue is pending.
	// This is the actual reset acknowledgement emitted by the original driver.
	copy(ram[0x22000:], []byte{4, 0x10})
	f.descriptor(1, 0, 0x22000, 2, 0, 0)
	f.submit(1, 1)
	var output [64]byte
	n, err := f.host.ReadAvailable(output[:])
	if err != nil || !bytes.Equal(output[:n], []byte{0, 0, 0, 0, 0x10, 4}) || f.used(1) != 1 || f.used(0) != 0 {
		t.Fatalf("independent reset response %x: %v", output[:n], err)
	}
	if f.irq != [2]int{0, 1} || binary.LittleEndian.Uint32(ram[0x608:]) != 0 {
		t.Fatal("readable response chain completion")
	}
	// Standard USB GET_DESCRIPTOR(Device), with the transport header fragmented
	// independently of its setup packet. No DMA may appear before the last byte.
	packet := []byte{8, 0, 0, 0, 0, 1, 0x80, 6, 0, 1, 0, 0, 18, 0}
	for i, b := range packet {
		if _, err := f.host.WriteAvailable([]byte{b}); err != nil {
			t.Fatal(err)
		}
		if err := nativeARM64PCI(f.pci.virtioPCI).Poll(); err != nil {
			t.Fatal(err)
		}
		if i < len(packet)-1 && (f.used(0) != 0 || !bytes.Equal(rx, bytes.Repeat([]byte{0xa5}, len(rx)))) {
			t.Fatal("partial control request reached guest RAM")
		}
	}
	if f.used(0) != 1 || f.irq != [2]int{1, 1} || !bytes.Equal(rx[:len(packet)], packet) || rx[len(packet)] != 0xa5 || binary.LittleEndian.Uint32(ram[0x208:]) != uint32(len(packet)) {
		t.Fatal("complete control request DMA or interrupt mismatch")
	}
}

func TestAppleUSBPCITransmitBackpressure(t *testing.T) {
	f := newAppleUSBPCITest(t, 16)
	ram := f.board.ram
	copy(ram[0x22000:], []byte{1, 0x81})
	copy(ram[0x22100:], "test")
	f.descriptor(1, 0, 0x22000, 2, 1, 1)
	f.descriptor(1, 1, 0x22100, 4, 0, 0)
	if _, err := f.board.usb.Write(make([]byte, 10)); err != nil {
		t.Fatal(err)
	}
	f.submit(1, 1)
	if f.used(1) != 0 || f.irq != [2]int{} {
		t.Fatal("backpressure completed or interrupted the guest")
	}
	var output [32]byte
	if n, err := f.host.ReadAvailable(output[:]); err != nil || n != 10 {
		t.Fatal("unexpected partial USB frame", n, err)
	}
	if err := nativeARM64PCI(f.pci.virtioPCI).Poll(); err != nil {
		t.Fatal(err)
	}
	n, err := f.host.ReadAvailable(output[:])
	if err != nil || !bytes.Equal(output[:n], []byte{4, 0, 0, 0, 0x81, 1, 't', 'e', 's', 't'}) || f.used(1) != 1 || f.irq != [2]int{0, 1} {
		t.Fatalf("transmit retry %x: %v", output[:n], err)
	}
	if err := nativeARM64PCI(f.pci.virtioPCI).Poll(); err != nil {
		t.Fatal(err)
	}
	if _, err := f.host.ReadAvailable(output[:]); !errors.Is(err, channel.ErrWouldBlock) {
		t.Fatal("completed packet transmitted twice", err)
	}
}

func TestAppleUSBPCIRejectsMalformedInputBeforeDMA(t *testing.T) {
	for _, truncated := range []bool{false, true} {
		f := newAppleUSBPCITest(t, 64)
		f.descriptor(0, 0, 0x1000, appleUSBPCIReceiveSize, 2, 0)
		f.submit(0, 1)
		if truncated {
			f.host.WriteAvailable([]byte{8, 0, 0})
			f.host.Close()
		} else {
			f.host.WriteAvailable([]byte{0, 0, 2, 0, 0, 1})
		}
		err := nativeARM64PCI(f.pci.virtioPCI).Poll()
		if err == nil || truncated && !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("invalid host frame accepted: truncated=%v err=%v", truncated, err)
		}
		if f.used(0) != 0 || f.irq != [2]int{} || !bytes.Equal(f.board.ram[0x1000:0x1010], make([]byte, 16)) {
			t.Fatal("malformed frame published guest completion or data")
		}
	}
}

func TestAppleUSBPCIResetPreservesStreamFraming(t *testing.T) {
	for name, prefixLength := range map[string]int{"empty": 0, "partial_header": 3, "partial_payload": 8} {
		t.Run(name, func(t *testing.T) {
			f := newAppleUSBPCITest(t, 64)
			rx := f.board.ram[0x1000 : 0x1000+appleUSBPCIReceiveSize]
			for i := range rx {
				rx[i] = 0xa5
			}
			f.descriptor(0, 0, 0x1000, appleUSBPCIReceiveSize, 2, 0)
			f.submit(0, 1)
			interrupted := []byte{8, 0, 0, 0, 0, 1, 0x80, 6, 0, 1, 0, 0, 18, 0}
			if prefixLength != 0 {
				if _, err := f.host.WriteAvailable(interrupted[:prefixLength]); err != nil {
					t.Fatal(err)
				}
				if err := nativeARM64PCI(f.pci.virtioPCI).Poll(); err != nil {
					t.Fatal(err)
				}
			}
			if f.used(0) != 0 || f.irq != [2]int{} {
				t.Fatal("partial frame completed before reset")
			}
			f.write(0x50020014, 1, 0)
			clear(f.board.ram[:0x800])
			f.configure()
			// A reset may also change the receive buffer capacity. The old
			// frame must be discarded independently of the new DMA buffer.
			next := []byte{0, 0, 0, 0, 0, 2}
			f.descriptor(0, 0, 0x1000, len(next), 2, 0)
			f.submit(0, 1)
			remaining := next
			if prefixLength != 0 {
				remaining = append(append([]byte(nil), interrupted[prefixLength:]...), next...)
			}
			if _, err := f.host.WriteAvailable(remaining); err != nil {
				t.Fatal(err)
			}
			if err := nativeARM64PCI(f.pci.virtioPCI).Poll(); err != nil {
				t.Fatal(err)
			}
			if f.used(0) != 1 || f.irq != [2]int{1, 0} || !bytes.Equal(rx[:len(next)], next) || !bytes.Equal(rx[len(next):], bytes.Repeat([]byte{0xa5}, len(rx)-len(next))) {
				t.Fatal("reset lost frame alignment or exposed the interrupted request")
			}
			if got := binary.LittleEndian.Uint32(f.board.ram[0x208:]); got != uint32(len(next)) {
				t.Fatalf("receive completion length %d, want %d", got, len(next))
			}
			var output [16]byte
			if _, err := f.host.ReadAvailable(output[:]); !errors.Is(err, channel.ErrWouldBlock) {
				t.Fatal("transport reset fabricated a USB response", err)
			}
		})
	}
}

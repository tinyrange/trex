package cc

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"

	"github.com/tinyrange/trex/channel"
)

func usbDevice(t *testing.T, capacity int) (*protocolTestBus, *channel.Memory) {
	t.Helper()
	host, guest, err := channel.NewMemoryPair(capacity)
	if err != nil {
		t.Fatal(err)
	}
	d := newProtocolTestBus(func(string, any) {})
	d.ramBase = 0x70000000
	d.ram = make([]byte, 2<<20)
	d.usb = guest
	return d, host
}
func usbDescriptor(d *protocolTestBus, off, data, size int, flags uint16) {
	r := d.ram[off:]
	binary.LittleEndian.PutUint64(r, d.ramBase+uint64(data))
	binary.LittleEndian.PutUint32(r[8:], uint32(size))
	binary.LittleEndian.PutUint16(r[12:], 1)
	binary.LittleEndian.PutUint16(r[14:], flags)
}

func TestAppleUSBFragmentedReceiveAndIndependentReadiness(t *testing.T) {
	d, host := usbDevice(t, 4096)
	usbDescriptor(d, 0, 4096, appleUSBPayloadLimit+6, 2)
	if err := d.submitUSB(d.ramBase); err != nil {
		t.Fatal(err)
	}
	for q, want := range []uint64{0, 1} {
		d.usbQueue = uint32(q)
		v, err := d.Read(0x30100010, 4)
		if err != nil || v != want {
			t.Fatal("readiness", q, v, err)
		}
	}
	packet := []byte{4, 0, 0, 0, 4, 1, 'D', 'T', 'R', 'E'}
	for i, b := range packet {
		host.WriteAvailable([]byte{b})
		if err := d.pollUSB(); err != nil {
			t.Fatal(err)
		}
		if i < len(packet)-1 && binary.LittleEndian.Uint16(d.ram[12:]) != 1 {
			t.Fatal("partial packet returned ownership")
		}
	}
	if !bytes.Equal(d.ram[4096:4106], packet) || binary.LittleEndian.Uint16(d.ram[12:]) != 0 || d.usbBusy[0] {
		t.Fatal("receive did not complete exactly")
	}
}

func TestAppleUSBTransmitFramingAndBackpressure(t *testing.T) {
	d, host := usbDevice(t, 16)
	usbDescriptor(d, 0, 256, 2, 1)
	usbDescriptor(d, 16, 512, 4, 0)
	copy(d.ram[256:], []byte{1, 4})
	copy(d.ram[512:], "test")
	d.usb.Write(make([]byte, 10))
	d.usbQueue = 1
	if err := d.submitUSB(d.ramBase); err != nil {
		t.Fatal(err)
	}
	if !d.usbBusy[1] || binary.LittleEndian.Uint16(d.ram[12:]) != 1 {
		t.Fatal("backpressure must retain ownership")
	}
	if err := d.submitUSB(d.ramBase); err == nil {
		t.Fatal("accepted overlapping TX")
	}
	var b [32]byte
	host.ReadAvailable(b[:])
	if err := d.pollUSB(); err != nil {
		t.Fatal(err)
	}
	n, err := host.ReadAvailable(b[:])
	if err != nil || !bytes.Equal(b[:n], []byte{4, 0, 0, 0, 4, 1, 't', 'e', 's', 't'}) {
		t.Fatalf("normalized packet %x %v", b[:n], err)
	}
	if d.usbBusy[1] || binary.LittleEndian.Uint16(d.ram[28:]) != 0 {
		t.Fatal("TX completion")
	}
}

func TestAppleUSBRejectsOversizeAndTruncation(t *testing.T) {
	for _, truncated := range []bool{false, true} {
		d, host := usbDevice(t, 64)
		usbDescriptor(d, 0, 4096, appleUSBPayloadLimit+6, 2)
		if err := d.submitUSB(d.ramBase); err != nil {
			t.Fatal(err)
		}
		if truncated {
			host.WriteAvailable([]byte{4, 0, 0})
			host.Close()
		} else {
			host.WriteAvailable([]byte{1, 0, 0x10, 0, 4, 1})
		}
		var err error
		for i := 0; i < 3 && err == nil; i++ {
			err = d.pollUSB()
		}
		if err == nil || truncated && !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("invalid input %v: %v", truncated, err)
		}
		if binary.LittleEndian.Uint16(d.ram[12:]) != 1 {
			t.Fatal("invalid input completed")
		}
	}
}

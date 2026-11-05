package cc

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/tinyrange/trex/vmm"
)

func TestSerialFIFOThresholdAndTimeout(t *testing.T) {
	now := time.Unix(100, 0)
	var edges []bool
	u := uart16550{dll: 12, lcr: 3, modem: 0xb0, setIRQ: func(line uint32, high bool) error {
		if line != 4 {
			t.Fatalf("IRQ %d", line)
		}
		edges = append(edges, high)
		return nil
	}}
	write := func(reg int, value byte) {
		t.Helper()
		if err := u.write(reg, value, now, nil); err != nil {
			t.Fatal(err)
		}
	}
	read := func(reg int) byte {
		t.Helper()
		v, err := u.read(reg, now)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	write(2, 0x81) // Eight-byte trigger, 16-byte FIFO.
	write(1, 1)
	write(4, 8)
	for i := 0; i < 4; i++ {
		u.receive(byte(i), now)
	}
	if err := u.syncIRQ(); err != nil {
		t.Fatal(err)
	}
	if u.irq || read(2) != 0xc1 {
		t.Fatal("RX threshold ignored")
	}
	if u.deadline().Sub(now) != 4*time.Second*10*12/115200 {
		t.Fatal("bad baud-derived timeout")
	}
	if err := u.poll(u.deadline().Add(-1)); err != nil {
		t.Fatal(err)
	}
	if u.irq {
		t.Fatal("early timeout")
	}
	if err := u.poll(u.deadline()); err != nil {
		t.Fatal(err)
	}
	if !u.irq || read(2) != 0xcc {
		t.Fatal("missing RX timeout IRQ")
	}
	if read(0) != 0 || u.irq {
		t.Fatal("RBR did not clear timeout")
	}
	for i := 4; i < 9; i++ {
		u.receive(byte(i), now)
	}
	if err := u.syncIRQ(); err != nil {
		t.Fatal(err)
	}
	if !u.irq || read(2) != 0xc4 {
		t.Fatal("missing threshold IRQ")
	}
	for i := 1; i < 9; i++ {
		if read(0) != byte(i) {
			t.Fatal("FIFO reordered bytes")
		}
	}
	if read(5)&1 != 0 || !u.deadline().IsZero() {
		t.Fatal("drained FIFO remained ready")
	}
	if !bytes.Equal(boolBytes(edges), []byte{1, 0, 1, 0}) {
		t.Fatalf("IRQ edges %v", edges)
	}
}

func boolBytes(values []bool) []byte {
	result := make([]byte, len(values))
	for i, v := range values {
		if v {
			result[i] = 1
		}
	}
	return result
}

func TestSerialDivisorLoopbackAndInterruptPriority(t *testing.T) {
	now := time.Unix(100, 0)
	u := uart16550{modem: 0xb0, attached: true}
	write := func(reg int, value byte) {
		t.Helper()
		if err := u.write(reg, value, now, nil); err != nil {
			t.Fatal(err)
		}
	}
	read := func(reg int) byte {
		t.Helper()
		v, err := u.read(reg, now)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	write(3, 0x80)
	write(0, 12)
	write(1, 2)
	if read(0) != 12 || read(1) != 2 || len(u.tx) != 0 {
		t.Fatal("divisor accesses transmitted data")
	}
	write(3, 3)
	write(1, 15)
	if u.irq {
		t.Fatal("OUT2 did not gate IRQ")
	}
	write(4, 0x1b) // Loopback DTR/RTS/OUT2 -> DSR/CTS/DCD.
	read(6)
	if read(2) != 2 || read(2) != 1 {
		t.Fatal("THRE interrupt did not acknowledge")
	}
	write(0, 0x65)
	write(0, 0x66) // One-byte receive register overrun.
	if read(2) != 6 {
		t.Fatal("line status priority")
	}
	if read(5)&3 != 3 {
		t.Fatal("line status missing overrun/data ready")
	}
	if read(2) != 4 || read(0) != 0x65 {
		t.Fatal("loopback data or receive priority")
	}
	if len(u.tx) != 0 {
		t.Fatal("loopback leaked to host")
	}
	if read(2) != 2 || read(2) != 1 {
		t.Fatal("transmit pending lost")
	}
	write(4, 0x10)
	if read(2) != 0 || read(6) != 0xb || read(2) != 1 {
		t.Fatal("modem delta status")
	}
	write(7, 0xa5)
	if read(7) != 0xa5 {
		t.Fatal("scratch register")
	}
}

func TestSerialChannelBackpressureAndRawBytes(t *testing.T) {
	p := &pc{now: func() time.Time { return time.Unix(100, 0) }}
	p.serial.attached = true
	if n, err := p.serialTransfer([]byte{1, 2}, true); n != 1 || err != nil {
		t.Fatalf("non-FIFO acceptance %d %v", n, err)
	}
	if n, err := p.serialTransfer([]byte{2}, true); n != 0 || err != nil || p.serial.overrun {
		t.Fatal("full receiver lost data instead of backpressure")
	}
	if v, _ := p.serial.read(0, p.now()); v != 1 {
		t.Fatal("first byte")
	}
	if n, err := p.serialTransfer([]byte{2}, true); n != 1 || err != nil {
		t.Fatal("receiver did not recover")
	}
	if v, _ := p.serial.read(0, p.now()); v != 2 {
		t.Fatal("second byte")
	}
	want := []byte{'\r', '\n', 0, 0xff}
	for _, b := range want {
		if err := p.serial.write(0, b, p.now(), nil); err != nil {
			t.Fatal(err)
		}
	}
	got := make([]byte, 8)
	if n, err := p.serialTransfer(got, false); n != len(want) || err != nil || !bytes.Equal(got[:n], want) {
		t.Fatalf("raw serial bytes %x %d %v", got, n, err)
	}
	p.serial.tx = make([]byte, serialCapacity)
	if lsr, _ := p.serial.read(5, p.now()); lsr&0x60 != 0 {
		t.Fatal("full transmitter claimed space")
	}
	if _, err := p.serialTransfer(got, false); err != nil {
		t.Fatal(err)
	}
	if lsr, _ := p.serial.read(5, p.now()); lsr&0x60 != 0x60 {
		t.Fatal("transmitter stayed blocked after read")
	}
	errIRQ := errors.New("IRQ failed")
	p.serial.setIRQ = func(uint32, bool) error { return errIRQ }
	p.serial.ier, p.serial.mcr = 2, 8
	if err := p.serial.syncIRQ(); !errors.Is(err, errIRQ) {
		t.Fatal("IRQ failure swallowed")
	}
}

func TestSerialChannelValidation(t *testing.T) {
	for _, tc := range []struct {
		channels []vmm.Channel
		valid    bool
	}{
		{[]vmm.Channel{{Name: "agent", Kind: "serial"}}, true},
		{[]vmm.Channel{{Name: "agent", Kind: "shared-memory"}}, true},
		{[]vmm.Channel{{Kind: "serial"}}, false},
		{[]vmm.Channel{{Name: "a", Kind: "serial"}, {Name: "b", Kind: "shared-memory"}}, false},
	} {
		found := false
		for _, issue := range (&Backend{}).Validate(vmm.Machine{Architecture: "i386", Channels: tc.channels}) {
			if issue.Field == "channels" {
				found = true
			}
		}
		if found == tc.valid {
			t.Fatalf("channel validation %v: valid=%v", tc.channels, !found)
		}
	}
}

func TestSerialBIOSInitializationAndStatus(t *testing.T) {
	p := &pc{now: func() time.Time { return time.Unix(0, 0) }}
	p.serial.attached, p.serial.modem = true, 0xb0
	for _, tc := range []struct {
		settings byte
		divisor  uint16
	}{{0xa3, 48}, {0xe3, 12}, {0x03, 1047}, {0x5e, 384}} {
		status, supported, err := p.serialBIOS(0, tc.settings, 0)
		if err != nil || !supported || status != 0x60b0 || uint16(p.serial.dll)|uint16(p.serial.dlm)<<8 != tc.divisor || p.serial.lcr != tc.settings&31 {
			t.Fatalf("settings %#x: status %#x supported %v, UART %+v, error %v", tc.settings, status, supported, p.serial, err)
		}
	}
	p.serial.receive(42, p.now())
	status, supported, err := p.serialBIOS(3, 0, 0)
	if err != nil || !supported || status != 0x61b0 || p.serial.rxCount != 1 {
		t.Fatalf("status consumed received data: %#x %v %v", status, supported, err)
	}
	if _, supported, _ := p.serialBIOS(0, 0xa3, 1); supported {
		t.Fatal("unadvertised COM2 accepted")
	}
	p.serial.attached = false
	if _, supported, _ := p.serialBIOS(0, 0xa3, 0); supported {
		t.Fatal("absent serial port accepted")
	}
}

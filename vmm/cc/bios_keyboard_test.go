package cc

import (
	"encoding/binary"
	"testing"

	"j5.nz/cc/hypervisor"
	"j5.nz/cc/hypervisor/x86state"
)

func keyboardFirmwarePC() *pc {
	p := &pc{ram: make([]byte, 1<<20)}
	p.installKeyboardFirmware()
	return p
}

func TestDisabledKeyboardControllerResponseDoesNotLatchIRQ(t *testing.T) {
	var level bool
	var edges int
	k := newKeyboard(func(irq uint32, active bool) error {
		if irq == 1 {
			if active && !level {
				edges++
			}
			level = active
		}
		return nil
	})
	command := func(value byte) {
		t.Helper()
		if err := k.io(hypervisor.X86Exit{Port: 0x64, Size: 1, Write: true, Data: []byte{value}}); err != nil {
			t.Fatal(err)
		}
	}
	read := func() byte {
		t.Helper()
		data := []byte{0}
		if err := k.io(hypervisor.X86Exit{Port: 0x60, Size: 1, Data: data}); err != nil {
			t.Fatal(err)
		}
		return data[0]
	}
	// VKD masks the PIC and polls the controller while the interface is
	// disabled. A spurious edge would survive the poll in the PIC's IRR.
	command(0xad)
	command(0x20)
	if level || edges != 0 || read() != 0x55 {
		t.Fatal("disabled controller response raised an interrupt or lost its data")
	}
	command(0xae)
	if level || edges != 0 {
		t.Fatal("consumed controller response became a phantom interrupt")
	}
	if err := k.key("a", true); err != nil {
		t.Fatal(err)
	}
	if !level || edges != 1 || read() != 0x1e || level {
		t.Fatal("reenabled interface did not deliver the next scan code")
	}
	command(0xad)
	command(0x20)
	command(0xae)
	if !level || edges != 2 || read() != 0x55 {
		t.Fatal("reenabling with an unread response did not assert IRQ1")
	}
}
func TestBIOSKeyboardIdentityMatchesController(t *testing.T) {
	p := keyboardFirmwarePC()
	// NTDETECT uses this firmware identity before the PnP keyboard driver
	// initializes the controller. Omitting it leaves XP's i8042 port idle.
	if p.ram[0x496]&0x10 == 0 {
		t.Fatal("firmware does not advertise the enhanced keyboard")
	}
	k := newKeyboard(func(uint32, bool) error { return nil })
	if err := k.io(hypervisor.X86Exit{Port: 0x60, Size: 1, Write: true, Data: []byte{0xf2}}); err != nil {
		t.Fatal(err)
	}
	for i, want := range []byte{0xfa, 0xab, 0x83} {
		if len(k.queue) <= i || k.queue[i].value != want || k.queue[i].mouse {
			t.Fatalf("enhanced keyboard ID response = %+v", k.queue)
		}
	}
}
func TestBIOSKeyboardTranslationAndStatus(t *testing.T) {
	p := keyboardFirmwarePC()
	for _, scan := range []byte{0x2a, 0x1e, 0x9e, 0xaa, 0x3a, 0x3a, 0xba, 0x30, 0xb0, 0x2a, 0x2e, 0xae, 0xaa, 0xe0, 0x48, 0xe0, 0xc8, 0x1d, 0x20, 0xa0, 0x9d} {
		p.keyboardScan(scan)
	}
	for _, want := range []uint16{0x1e41, 0x3042, 0x2e63, 0x48e0, 0x2004} {
		head, _ := p.keyboardBounds()
		f := uint16(0x0241)
		r := x86state.Registers{Rax: 0x1100, Rflags: 2}
		if !p.keyboardBIOS(&r, &f) || uint16(r.Rax) != want || f != 0x0201 {
			t.Fatalf("peek got %x flags %x want %x", r.Rax, f, want)
		}
		gotHead, _ := p.keyboardBounds()
		if head != gotHead {
			t.Fatal("peek consumed input")
		}
		r.Rax = 0x1000
		p.keyboardBIOS(&r, &f)
		if uint16(r.Rax) != want {
			t.Fatalf("read got %x want %x", r.Rax, want)
		}
	}
	r := x86state.Registers{Rax: 0x0100}
	f := uint16(0x0201)
	p.keyboardBIOS(&r, &f)
	if f != 0x0241 {
		t.Fatalf("empty status flags %x", f)
	}
	r.Rax = 0
	p.keyboardBIOS(&r, &f)
	if r.Rflags&0x40 == 0 || f != 0x0241 {
		t.Fatal("blocking read did not request ROM sleep or changed caller flags")
	}
}
func TestBIOSKeyboardRingWrapFullAndCorrupt(t *testing.T) {
	p := keyboardFirmwarePC()
	for i := 0; i < 15; i++ {
		if !p.storeKeyboardWord(uint16(i + 1)) {
			t.Fatal("early overflow")
		}
	}
	if p.storeKeyboardWord(99) {
		t.Fatal("full buffer overwrote unread input")
	}
	for i := 0; i < 40; i++ {
		r := x86state.Registers{}
		f := uint16(2)
		p.keyboardBIOS(&r, &f)
		if uint16(r.Rax) != uint16(i+1) {
			t.Fatalf("FIFO got %d want %d", r.Rax, i+1)
		}
		if !p.storeKeyboardWord(uint16(i + 16)) {
			t.Fatal("wrap overflow")
		}
	}
	binary.LittleEndian.PutUint16(p.ram[0x41c:], 0xffff)
	if p.storeKeyboardWord(99) {
		t.Fatal("accepted corrupt guest buffer pointer")
	}
}
func TestVGAReadableFirmwareFontAndGuestReplacement(t *testing.T) {
	text := make([]byte, 32768)
	v := newVGA(text)
	text[0], text[1] = 'A', 7
	v.syncText()
	img, err := v.screenshot()
	if err != nil {
		t.Fatal(err)
	}
	lit := 0
	for y := 0; y < 16; y++ {
		for x := 0; x < 8; x++ {
			if img.RGBAAt(x, y).R != 0 {
				lit++
			}
		}
	}
	if lit < 5 {
		t.Fatal("firmware text is unreadable")
	}
	clear(v.planes[2][:]) // A guest upload must be authoritative.
	img, err = v.screenshot()
	if err != nil {
		t.Fatal(err)
	}
	for y := 0; y < 16; y++ {
		for x := 0; x < 8; x++ {
			if img.RGBAAt(x, y).R != 0 {
				t.Fatal("renderer replaced guest font")
			}
		}
	}
	if err = v.setMode(3); err != nil {
		t.Fatal(err)
	}
	if v.planes[2][int('A')*32+3] == 0 {
		t.Fatal("mode reset did not reinstall firmware font")
	}
}

func TestBIOSKeyboardScansRingAndPolling(t *testing.T) {
	p := &pc{ram: make([]byte, 1<<20)}
	p.installKeyboardFirmware()
	// Shift+A, Ctrl+S, then an enhanced left arrow; release bytes must not
	// enqueue duplicate keys or leave modifiers latched.
	for _, scan := range []byte{0x2a, 0x1e, 0x9e, 0xaa, 0x1d, 0x1f, 0x9f, 0x9d, 0xe0, 0x4b, 0xe0, 0xcb} {
		p.keyboardScan(scan)
	}
	if p.ram[0x417] != 0 {
		t.Fatalf("modifiers %#x", p.ram[0x417])
	}
	flags := uint16(0x241)
	r := x86state.Registers{Rax: 0xaabb1100}
	if !p.keyboardBIOS(&r, &flags) || uint16(r.Rax) != 0x1e41 || r.Rax>>16 != 0xaabb || flags != 0x201 {
		t.Fatalf("peek %+v flags %#x", r, flags)
	}
	for _, want := range []uint16{0x1e41, 0x1f13, 0x4be0} {
		r.Rax = 0x1000
		if !p.keyboardBIOS(&r, &flags) || uint16(r.Rax) != want {
			t.Fatalf("key %#x, want %#x", r.Rax, want)
		}
	}
	r.Rax = 0x1100
	p.keyboardBIOS(&r, &flags)
	if flags&0x40 == 0 {
		t.Fatal("empty peek did not set ZF")
	}
	r.Rax = 0
	if !p.keyboardBIOS(&r, &flags) || r.Rflags&0x40 == 0 {
		t.Fatal("empty read must wait")
	}
	// Wrap the ring and prove it never overwrites an unread key.
	for round := 0; round < 3; round++ {
		for i := 0; i < 15; i++ {
			if !p.storeKeyboardWord(uint16(i + 1)) {
				t.Fatal("early full ring")
			}
		}
		if p.storeKeyboardWord(99) {
			t.Fatal("overwrote full ring")
		}
		for i := 0; i < 15; i++ {
			r.Rax = 0
			p.keyboardBIOS(&r, &flags)
			if r.Rax != uint64(i+1) {
				t.Fatal("ring order")
			}
		}
	}
}
func TestBIOSKeyboardBlockingReadSignalsROMWithoutChangingCallerFrame(t *testing.T) {
	cpu := &clockBIOSCPU{r: x86state.Registers{Rip: 0x2202, Rsp: 0x8000, Rax: 0x1000, Rflags: 2}, s: x86state.SystemRegisters{Cs: x86state.Segment{Base: 0xf0000}}}
	p := &pc{cpu: cpu, ram: make([]byte, 1<<20)}
	p.installKeyboardFirmware()
	binary.LittleEndian.PutUint16(p.ram[0x8004:], 0x841)
	if err := p.bios(); err != nil {
		t.Fatal(err)
	}
	if cpu.r.Rip != 0x2202 || cpu.r.Rflags&0x40 == 0 || binary.LittleEndian.Uint16(p.ram[0x8004:]) != 0x841 {
		t.Fatal("wait damaged frame or blocked IRQs")
	}
	p.keyboardScan(0x1e)
	cpu.r.Rip = 0x2202
	if err := p.bios(); err != nil {
		t.Fatal(err)
	}
	if cpu.r.Rax != 0x1e61 {
		t.Fatalf("read %#x", cpu.r.Rax)
	}
}

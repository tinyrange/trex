package cc

import (
	"encoding/binary"
	"j5.nz/cc/hypervisor/x86state"
	"testing"
)

func keyboardFirmwarePC() *pc {
	p := &pc{ram: make([]byte, 1<<20)}
	p.installKeyboardFirmware()
	return p
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

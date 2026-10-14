package cc

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

func TestAppleAESNISTCBCAndCompletion(t *testing.T) {
	decode := func(s string) []byte {
		b, e := hex.DecodeString(s)
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	// NIST SP800-38A F.2.5/F.2.6, AES256 CBC.
	key := decode("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
	iv := decode("000102030405060708090a0b0c0d0e0f")
	plain := decode("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710")
	want := decode("f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b")
	ram := make([]byte, 512)
	copy(ram, plain)
	level := false
	d := appleAES{address: 0x30220000, irq: func(v bool) error { level = v; return nil }, memory: func(a, n uint64, w bool) ([]byte, error) { return ram[a-0x170000000 : a-0x170000000+n], nil }}
	word := func(v uint32) {
		t.Helper()
		if e := d.Write(0x30220200, 4, uint64(v)); e != nil {
			t.Fatal(e)
		}
	}
	blob := func(b []byte) {
		for i := 0; i < len(b); i += 4 {
			word(binary.LittleEndian.Uint32(b[i:]))
		}
	}
	if e := d.Write(0x3022001c, 4, 1<<5); e != nil {
		t.Fatal(e)
	}
	word(0x10910000)
	blob(key)
	word(0x20000000)
	blob(iv)
	word(0x50000040)
	word(0x00010001)
	word(0x70000000)
	word(0x70000100)
	if !bytes.Equal(ram[256:320], want) {
		t.Fatalf("CBC ciphertext %x", ram[256:320])
	}
	if level {
		t.Fatal("interrupt before barrier")
	}
	word(0x88000037)
	if !level {
		t.Fatal("missing completion IRQ")
	}
	if v, _ := d.Read(0x30220030, 4); v != 0x37 {
		t.Fatalf("barrier flag %x", v)
	}
	if e := d.Write(0x30220018, 4, 1<<5); e != nil {
		t.Fatal(e)
	}
	if level {
		t.Fatal("IRQ not cleared")
	}
	word(0x10810000)
	blob(key)
	word(0x20000000)
	blob(iv)
	// Decrypt in place, and verify updated IV readback.
	word(0x50000040)
	word(0x00010001)
	word(0x70000100)
	word(0x70000100)
	if !bytes.Equal(ram[256:320], plain) {
		t.Fatal("CBC decryption")
	}
	word(0x60000001)
	word(0x70000180)
	if !bytes.Equal(ram[384:400], want[48:]) {
		t.Fatal("CBC IV readback")
	}
}
func TestAppleAESRejectsUnsupportedCommands(t *testing.T) {
	for _, v := range []uint32{0, 0x11910000, 0x10c10000, 0x10b10000, 0xd0000000, 0x51000010, 0x5000000f} {
		d := appleAES{address: 0x30220000}
		if e := d.fifo(v); e == nil {
			t.Fatalf("accepted %#x", v)
		}
	}
}

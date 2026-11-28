package linux

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestOpenBZImage(t *testing.T) {
	const payloadAt = 5 * 512
	data := make([]byte, payloadAt+16+7)
	le := binary.LittleEndian
	le.PutUint32(data[0x1f4:], 1)
	le.PutUint16(data[0x1fe:], 0xaa55)
	copy(data[0x200:], "\xeb\x6aHdrS")
	le.PutUint16(data[0x206:], 0x20f)
	data[0x211], data[0x234] = 1, 1
	le.PutUint32(data[0x230:], 2<<20)
	le.PutUint16(data[0x236:], 1)
	le.PutUint32(data[0x238:], 2047)
	le.PutUint32(data[0x248:], 1)
	le.PutUint32(data[0x24c:], 6)
	le.PutUint64(data[0x258:], 16<<20)
	le.PutUint32(data[0x260:], 32<<20)
	le.PutUint16(data[0x20e:], 0x100)
	copy(data[0x300:], "7.2.11-arch1-1 (builder)\x00")
	data[0x26c] = 0xf4 // Instruction after the setup header.
	copy(data[payloadAt:], "payload")
	image, err := OpenBZImage(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if image.Payload.Size() != 16 || image.InitSize != 32<<20 || image.PreferredAddress != 16<<20 || image.KernelAlignment != 2<<20 || !image.Relocatable {
		t.Fatalf("wrong bzImage layout: %+v", image)
	}
	if release, err := image.KernelRelease(); err != nil || release != "7.2.11-arch1-1" {
		t.Fatalf("kernel release = %q, %v", release, err)
	}
	for _, tc := range []struct {
		pointer uint16
		value   string
	}{
		{0, ""},
		{payloadAt - 0x200, ""},
		{payloadAt - 0x200 - 1, "1"},
		{0x100, "../outside"},
	} {
		malformed := bytes.Clone(data)
		le.PutUint16(malformed[0x20e:], tc.pointer)
		copy(malformed[0x200+int(tc.pointer):], tc.value)
		image, err := OpenBZImage(bytes.NewReader(malformed))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := image.KernelRelease(); err == nil {
			t.Fatalf("accepted invalid version at %#x", tc.pointer)
		}
	}

	var payload [7]byte
	if _, err := image.Payload.ReadAt(payload[:], 0); err != nil || string(payload[:]) != "payload" {
		t.Fatalf("payload = %q, %v", payload, err)
	}
	embedded, err := image.KernelPayload()
	if err != nil || embedded.Size() != 6 {
		t.Fatalf("embedded kernel length: %v, %v", embedded, err)
	}
	if _, err := embedded.ReadAt(payload[:6], 0); err != nil || string(payload[:6]) != "ayload" {
		t.Fatalf("embedded kernel bytes: %q, %v", payload[:6], err)
	}
	badExtent := bytes.Clone(data)
	le.PutUint32(badExtent[0x24c:], 16)
	outside, err := OpenBZImage(bytes.NewReader(badExtent))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := outside.KernelPayload(); err == nil {
		t.Fatal("accepted embedded payload which exceeded its parent extent")
	}
	var zeroPage [4096]byte
	image.CopySetup(&zeroPage)
	if !bytes.Equal(zeroPage[0x1f1:0x26c], data[0x1f1:0x26c]) || zeroPage[0x26c] != 0 {
		t.Fatal("wrong bytes copied into the boot parameters")
	}

	for _, tc := range []struct {
		name   string
		offset int
		value  byte
	}{
		{"short header", 0x201, 0x40},
		{"backward setup jump", 0x201, 0x80},
		{"setup outside file", 0x1f1, 0xff},
		{"empty payload", 0x1f4, 0},
		{"truncated payload", 0x1f4, 2},
		{"zImage", 0x211, 0},
		{"32-bit kernel", 0x236, 0},
		{"non-power-of-two alignment", 0x230, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			malformed := bytes.Clone(data)
			malformed[tc.offset] = tc.value
			if _, err := OpenBZImage(bytes.NewReader(malformed)); err == nil {
				t.Fatal("accepted invalid boot image")
			}
		})
	}
}

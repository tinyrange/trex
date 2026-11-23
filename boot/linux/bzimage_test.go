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
	le.PutUint64(data[0x258:], 16<<20)
	le.PutUint32(data[0x260:], 32<<20)
	data[0x26c] = 0xf4 // Instruction after the setup header.
	copy(data[payloadAt:], "payload")
	image, err := OpenBZImage(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if image.Payload.Size() != 16 || image.InitSize != 32<<20 || image.PreferredAddress != 16<<20 || image.KernelAlignment != 2<<20 || !image.Relocatable {
		t.Fatalf("wrong bzImage layout: %+v", image)
	}
	var payload [7]byte
	if _, err := image.Payload.ReadAt(payload[:], 0); err != nil || string(payload[:]) != "payload" {
		t.Fatalf("payload = %q, %v", payload, err)
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

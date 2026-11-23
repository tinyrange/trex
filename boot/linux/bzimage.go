// Package linux handles native Linux boot formats.
package linux

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/tinyrange/trex/storage"
)

// BZImage is the setup header and protected-mode payload of an x86-64
// bzImage using Linux boot protocol 2.12 or later. The payload borrows the
// original immutable source.
type BZImage struct {
	Payload          storage.Reader
	PreferredAddress uint64
	KernelAlignment  uint32
	InitSize         uint32
	InitrdAddressMax uint32
	CommandLineMax   uint32
	Relocatable      bool
	setup            []byte
}

// OpenBZImage reads the bounded setup header without touching the payload.
func OpenBZImage(source storage.Reader) (*BZImage, error) {
	const setupStart = 0x1f1
	// The jump at 0x200 skips the remainder of the header with an int8
	// displacement, limiting its end to 0x281 even in newer kernels.
	var header [0x281]byte
	if source == nil || source.Size() < int64(len(header)) {
		return nil, fmt.Errorf("bzImage is missing its setup header")
	}
	if _, err := io.ReadFull(io.NewSectionReader(source, 0, int64(len(header))), header[:]); err != nil {
		return nil, fmt.Errorf("read bzImage setup header: %w", err)
	}
	u16, u32, u64 := binary.LittleEndian.Uint16, binary.LittleEndian.Uint32, binary.LittleEndian.Uint64
	if u16(header[0x1fe:]) != 0xaa55 || header[0x200] != 0xeb || string(header[0x202:0x206]) != "HdrS" {
		return nil, fmt.Errorf("invalid bzImage setup signature")
	}
	end := 0x202 + int(header[0x201])
	if end < 0x264 || end > len(header) {
		return nil, fmt.Errorf("invalid bzImage setup header length")
	}
	if u16(header[0x206:]) < 0x20c || header[0x211]&1 == 0 || u16(header[0x236:])&1 == 0 {
		return nil, fmt.Errorf("bzImage requires x86-64 boot protocol 2.12 or later")
	}
	setupSectors := int64(header[setupStart])
	if setupSectors == 0 {
		setupSectors = 4
	}
	offset := (1 + setupSectors) * 512
	size := int64(u32(header[0x1f4:])) * 16
	if size == 0 || size > source.Size()-offset {
		return nil, fmt.Errorf("bzImage protected-mode payload is empty or truncated")
	}
	image := &BZImage{
		Payload:          io.NewSectionReader(source, offset, size),
		PreferredAddress: u64(header[0x258:]),
		KernelAlignment:  u32(header[0x230:]),
		InitSize:         u32(header[0x260:]),
		InitrdAddressMax: u32(header[0x22c:]),
		CommandLineMax:   u32(header[0x238:]),
		Relocatable:      header[0x234] != 0,
		setup:            header[setupStart:end],
	}
	if image.InitSize == 0 || image.CommandLineMax == 0 || (image.Relocatable && (image.KernelAlignment == 0 || image.KernelAlignment&(image.KernelAlignment-1) != 0)) {
		return nil, fmt.Errorf("invalid bzImage initialization size, command line size, or kernel alignment")
	}
	return image, nil
}

// CopySetup copies the image's setup header into a Linux boot_params zero page.
func (i *BZImage) CopySetup(zeroPage *[4096]byte) {
	copy(zeroPage[0x1f1:], i.setup)
}

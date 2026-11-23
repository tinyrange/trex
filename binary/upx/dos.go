// Package upx reads supported UPX payloads without running their loader stubs.
package upx

import (
	"encoding/binary"
	"fmt"
	"hash/adler32"
	"io"

	"github.com/tinyrange/trex/storage"
)

// DOSImage decodes a DOS EXE load image with a v13 UPX PackHeader, NRV2B_8,
// no filter, and no relocation table. headerOffset points to the PackHeader,
// which can also be embedded in an EXE flattened for a DOS boot loader.
func DOSImage(source storage.Reader, headerOffset int64) ([]byte, error) {
	const headerSize = 27
	if source == nil || headerOffset < 0 || source.Size() < headerSize || headerOffset > source.Size()-headerSize {
		return nil, fmt.Errorf("UPX DOS header outside source")
	}
	var header [headerSize]byte
	if _, err := io.ReadFull(io.NewSectionReader(source, headerOffset, headerSize), header[:]); err != nil {
		return nil, fmt.Errorf("read UPX DOS header: %w", err)
	}
	if string(header[:4]) != "UPX!" || header[4] != 13 || header[5] != 3 || header[6] != 3 || header[25] != 0 {
		return nil, fmt.Errorf("unsupported UPX DOS pack header")
	}
	var headerSum int
	for _, b := range header[4 : headerSize-1] {
		headerSum += int(b)
	}
	if byte(headerSum%251) != header[headerSize-1] {
		return nil, fmt.Errorf("UPX DOS header checksum mismatch")
	}
	imageSize, payloadSize, exeSize := u24(header[16:]), u24(header[19:]), u24(header[22:])
	if exeSize != imageSize+32 {
		return nil, fmt.Errorf("unsupported UPX DOS original EXE layout")
	}
	payloadOffset := headerOffset + headerSize
	if payloadSize == 0 || payloadSize >= imageSize || int64(payloadSize) > source.Size()-payloadOffset {
		return nil, fmt.Errorf("invalid UPX DOS payload size")
	}
	payload := make([]byte, payloadSize)
	if _, err := io.ReadFull(io.NewSectionReader(source, payloadOffset, int64(payloadSize)), payload); err != nil {
		return nil, fmt.Errorf("read UPX DOS payload: %w", err)
	}
	if adler32.Checksum(payload) != binary.LittleEndian.Uint32(header[12:]) {
		return nil, fmt.Errorf("UPX DOS payload checksum mismatch")
	}
	image, err := decodeNRV2B8(payload, imageSize)
	if err != nil {
		return nil, err
	}
	if adler32.Checksum(image) != binary.LittleEndian.Uint32(header[8:]) {
		return nil, fmt.Errorf("UPX DOS image checksum mismatch")
	}
	return image, nil
}

func u24(b []byte) int { return int(b[0]) | int(b[1])<<8 | int(b[2])<<16 }

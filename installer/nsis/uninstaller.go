package nsis

import (
	"bytes"
	"encoding/binary"
	"fmt"
	starfile "github.com/tinyrange/trex/storage/star"
	"hash/crc32"
)

func (a *Archive) readBlock(offset, maximum int64) ([]byte, int64, error) {
	end := a.Listing.HeaderOffset + a.Listing.ContainerSize
	if offset < a.Listing.DataOffset || offset > end-4 {
		return nil, 0, fmt.Errorf("nsis: data block offset out of bounds")
	}
	var word [4]byte
	if err := readAt(a.source, word[:], offset); err != nil {
		return nil, 0, err
	}
	size := int64(binary.LittleEndian.Uint32(word[:]) & 0x7fffffff)
	if size > end-offset-4 || size > a.maximum {
		return nil, 0, ErrLimit
	}
	packed := make([]byte, int(size))
	if err := readAt(a.source, packed, offset+4); err != nil {
		return nil, 0, err
	}
	next := offset + 4 + size
	if word[3]&0x80 != 0 {
		data, err := inflateNSIS(packed, maximum)
		return data, next, err
	}
	if size > maximum {
		return nil, 0, ErrLimit
	}
	return packed, next, nil
}

// applyStubPatch reads size, file-offset, data tuples terminated by a zero size.
// It never changes the stub size or permits writes into the appended container.
func applyStubPatch(stub, patch []byte) error {
	for {
		if len(patch) < 4 {
			return fmt.Errorf("nsis: truncated uninstaller patch")
		}
		size := int64(binary.LittleEndian.Uint32(patch))
		patch = patch[4:]
		if size == 0 {
			if len(patch) != 0 {
				return fmt.Errorf("nsis: trailing uninstaller patch")
			}
			return nil
		}
		if len(patch) < 4 {
			return fmt.Errorf("nsis: missing uninstaller patch offset")
		}
		offset := int64(binary.LittleEndian.Uint32(patch))
		patch = patch[4:]
		if offset > int64(len(stub)) || size > int64(len(stub))-offset || size > int64(len(patch)) {
			return fmt.Errorf("nsis: uninstaller patch out of bounds")
		}
		copy(stub[offset:offset+size], patch[:size])
		patch = patch[size:]
	}
}

// Uninstaller reconstructs a WriteUninstaller instruction natively: original PE
// stub, bounded embedded icon patches, and embedded uninstall container. NSIS's
// CRC excludes the first 512 stub bytes and the checksum word itself.
func (a *Archive) Uninstaller(instruction int) (starfile.File, error) {
	if instruction < 0 || instruction >= len(a.Listing.Code) || a.Listing.Code[instruction].Opcode != 62 {
		return nil, fmt.Errorf("nsis: expected WriteUninstaller instruction")
	}
	p := a.Listing.Code[instruction].Operands
	if p[1] < 0 || p[2] < 0 || a.Listing.HeaderOffset < 512 {
		return nil, fmt.Errorf("nsis: invalid uninstaller operands or stub")
	}
	if a.Listing.HeaderOffset > a.maximum || int64(p[2]) > a.maximum {
		return nil, ErrLimit
	}
	stub := make([]byte, int(a.Listing.HeaderOffset))
	if err := readAt(a.source, stub, 0); err != nil {
		return nil, err
	}
	at := a.Listing.DataOffset + int64(p[1])
	if p[2] != 0 {
		patch, next, err := a.readBlock(at, int64(p[2]))
		if err != nil {
			return nil, err
		}
		if len(patch) != int(p[2]) {
			return nil, fmt.Errorf("nsis: uninstaller patch length mismatch")
		}
		if err := applyStubPatch(stub, patch); err != nil {
			return nil, err
		}
		at = next
	}
	body, _, err := a.readBlock(at, a.maximum-int64(len(stub)))
	if err != nil {
		return nil, err
	}
	if len(body) < 32 || !bytes.Equal(body[4:20], signature) || binary.LittleEndian.Uint32(body[24:28]) != uint32(len(body)) {
		return nil, fmt.Errorf("nsis: invalid uninstall container")
	}
	flags := binary.LittleEndian.Uint32(body)
	if flags&1 == 0 || flags & ^uint32(15) != 0 {
		return nil, fmt.Errorf("nsis: invalid uninstall flags")
	}
	output := append(stub, body...)
	if flags&4 == 0 {
		binary.LittleEndian.PutUint32(output[len(output)-4:], crc32.ChecksumIEEE(output[512:len(output)-4]))
	}
	return &starfile.Bytes{Name: fmt.Sprintf("/uninstallers/%06d", instruction), Data: output}, nil
}

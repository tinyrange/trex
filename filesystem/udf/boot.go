package udf

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
)

// BootDescriptor is ECMA-167 part 2's BOOT2 descriptor. Load/StartAddress and
// Flags are declarations, not a generic execution recipe for the architecture.
type BootDescriptor struct {
	DescriptorOffset   int64   `json:"descriptor_offset"`
	Architecture       string  `json:"architecture"`
	ArchitectureFlags  byte    `json:"architecture_flags"`
	ArchitectureSuffix [8]byte `json:"architecture_suffix"`
	Identifier         string  `json:"identifier"`
	IdentifierFlags    byte    `json:"identifier_flags"`
	IdentifierSuffix   [8]byte `json:"identifier_suffix"`
	ExtentSector       uint32  `json:"extent_sector"`
	ExtentOffset       int64   `json:"extent_offset"`
	ExtentBytes        uint32  `json:"extent_bytes"`
	LoadAddress        uint64  `json:"load_address"`
	StartAddress       uint64  `json:"start_address"`
	Flags              uint16  `json:"flags"`
}

// ReadBootDescriptors reads the bounded volume-recognition sequence, not file
// names or signatures carved from payloads. Extents use 2048-byte recognition
// sectors, independently of a later logical volume's block size.
func ReadBootDescriptors(source storage.Reader) ([]BootDescriptor, error) {
	var out []BootDescriptor
	began := false
	for sector := int64(16); sector < 272; sector++ {
		if !began && sector >= 32 {
			return out, nil
		}
		off := sector * udfBlockSize
		if off > source.Size() || udfBlockSize > source.Size()-off {
			if began {
				return nil, fmt.Errorf("udf boot: truncated recognition sequence")
			}
			return out, nil
		}
		var b [2048]byte
		if _, err := starfile.ReadFullAt(source, b[:], off); err != nil {
			return nil, err
		}
		id := string(b[1:6])
		if !began {
			if id != "BEA01" {
				continue
			}
			began = true
		}
		if id == "TEA01" {
			return out, nil
		}
		if id != "BOOT2" {
			continue
		}
		if b[0] != 0 || b[6] != 1 || b[7] != 0 || !bytes.Equal(b[110:142], make([]byte, 32)) {
			return nil, fmt.Errorf("udf boot: unsupported BOOT2 descriptor at %d", off)
		}
		le := binary.LittleEndian
		d := BootDescriptor{DescriptorOffset: off,
			Architecture: string(bytes.TrimRight(b[9:32], "\x00")), ArchitectureFlags: b[8],
			Identifier: string(bytes.TrimRight(b[41:64], "\x00")), IdentifierFlags: b[40],
			ExtentSector: le.Uint32(b[72:76]), ExtentBytes: le.Uint32(b[76:80]),
			LoadAddress: le.Uint64(b[80:88]), StartAddress: le.Uint64(b[88:96]), Flags: le.Uint16(b[108:110])}
		copy(d.ArchitectureSuffix[:], b[32:40])
		copy(d.IdentifierSuffix[:], b[64:72])
		d.ExtentOffset = int64(d.ExtentSector) * udfBlockSize
		if d.ExtentOffset > source.Size() || int64(d.ExtentBytes) > source.Size()-d.ExtentOffset {
			return nil, fmt.Errorf("udf boot: extent outside media at %d", off)
		}
		out = append(out, d)
	}
	return nil, fmt.Errorf("udf boot: recognition sequence limit")
}

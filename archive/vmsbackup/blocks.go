package vmsbackup

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/tinyrange/trex/storage"
)

// Record retains the original record header and a borrowed payload view.
// Interpreting a file record's attributes and joining its data records is a
// separate layer; unknown record kinds and flags remain available to callers.
type Record struct {
	Offset   int64
	Kind     uint16
	Flags    uint32
	Address  uint32
	Reserved uint32
	Data     storage.Reader
}

type Block struct {
	Offset   int64
	Header   [blockHeaderSize]byte
	Sequence uint32
	Parity   bool
	Records  []Record
}

type Limits struct {
	MaximumBlocks    int
	MaximumRecords   int
	MaximumBlockSize int
}

// ReadBlocks reads a complete, single-volume VMS BACKUP block stream. It checks
// both CRCs, sequence numbers, record boundaries, and each encountered XOR
// redundancy payload. It does not repair corruption, interpret file contents,
// or require a redundancy block for a final group (or a /GROUP_SIZE=0 stream).
// Payloads borrow the source, which must remain unchanged while views are used.
func ReadBlocks(source storage.Reader, limits Limits) ([]Block, error) {
	if limits.MaximumBlocks < 1 || limits.MaximumRecords < 1 || limits.MaximumBlockSize < blockHeaderSize {
		return nil, fmt.Errorf("vms backup: invalid block limits")
	}
	if source.Size() < blockHeaderSize {
		return nil, fmt.Errorf("vms backup: truncated first header")
	}
	var first [blockHeaderSize]byte
	if err := readExact(source, first[:], 0); err != nil {
		return nil, err
	}
	if err := ValidateHeaderChecksum(first[:]); err != nil {
		return nil, err
	}
	size := int64(binary.LittleEndian.Uint32(first[40:]))
	if size < blockHeaderSize || size > int64(limits.MaximumBlockSize) {
		return nil, fmt.Errorf("vms backup: invalid or excessive block size %d", size)
	}
	if source.Size()%size != 0 {
		return nil, fmt.Errorf("vms backup: truncated final block")
	}
	if source.Size()/size > int64(limits.MaximumBlocks) {
		return nil, fmt.Errorf("vms backup: block limit")
	}
	buffer := make([]byte, int(size))
	xor := make([]byte, int(size)-blockHeaderSize)
	result := []Block{}
	recordCount, groupBlocks := 0, 0
	for offset := int64(0); offset < source.Size(); offset += size {
		if err := readExact(source, buffer, offset); err != nil {
			return nil, err
		}
		if err := ValidateBlockChecksums(buffer); err != nil {
			return nil, fmt.Errorf("vms backup: block at %d: %w", offset, err)
		}
		if binary.LittleEndian.Uint16(buffer) != blockHeaderSize || binary.LittleEndian.Uint16(buffer[2:]) != 0x0400 || binary.LittleEndian.Uint16(buffer[4:]) != 1 {
			return nil, fmt.Errorf("vms backup: unsupported block header at %d", offset)
		}
		b := Block{Offset: offset, Sequence: binary.LittleEndian.Uint32(buffer[8:])}
		copy(b.Header[:], buffer[:blockHeaderSize])
		if uint64(b.Sequence) != uint64(len(result))+1 {
			return nil, fmt.Errorf("vms backup: block sequence at %d", offset)
		}
		switch kind := binary.LittleEndian.Uint16(buffer[6:]); kind {
		case 1:
			if int64(binary.LittleEndian.Uint32(buffer[40:])) != size {
				return nil, fmt.Errorf("vms backup: inconsistent block size at %d", offset)
			}
			for p := blockHeaderSize; p < len(buffer); {
				if len(buffer)-p < 16 {
					return nil, fmt.Errorf("vms backup: truncated record header at %d", offset+int64(p))
				}
				length := int(binary.LittleEndian.Uint16(buffer[p:]))
				if length > len(buffer)-p-16 {
					return nil, fmt.Errorf("vms backup: record crosses block at %d", offset+int64(p))
				}
				if recordCount >= limits.MaximumRecords {
					return nil, fmt.Errorf("vms backup: record limit")
				}
				b.Records = append(b.Records, Record{
					Offset: offset + int64(p), Kind: binary.LittleEndian.Uint16(buffer[p+2:]),
					Flags: binary.LittleEndian.Uint32(buffer[p+4:]), Address: binary.LittleEndian.Uint32(buffer[p+8:]),
					Reserved: binary.LittleEndian.Uint32(buffer[p+12:]),
					Data:     io.NewSectionReader(source, offset+int64(p)+16, int64(length)),
				})
				recordCount++
				p += 16 + length
			}
			for i, value := range buffer[blockHeaderSize:] {
				xor[i] ^= value
			}
			groupBlocks++
		case 2:
			b.Parity = true
			if groupBlocks == 0 || !bytes.Equal(xor, buffer[blockHeaderSize:]) {
				return nil, fmt.Errorf("vms backup: redundancy payload mismatch at %d", offset)
			}
			clear(xor)
			groupBlocks = 0
		default:
			return nil, fmt.Errorf("vms backup: unsupported block kind %d", kind)
		}
		result = append(result, b)
	}
	return result, nil
}

func readExact(source storage.Reader, data []byte, offset int64) error {
	n, err := source.ReadAt(data, offset)
	if n == len(data) && (err == nil || err == io.EOF) {
		return nil
	}
	if err == nil {
		err = io.ErrUnexpectedEOF
	}
	return fmt.Errorf("vms backup: read at %d: %w", offset, err)
}

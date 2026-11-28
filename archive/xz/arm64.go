package xz

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"hash/crc64"
	"io"

	rootxz "github.com/therootcompany/xz"
	"github.com/ulikunitz/xz/lzma"
)

// decodeARM64Block handles the ARM64 branch filter added in XZ format 1.1.
// The older stream decoder can read the other filter chains. Here the
// original block checksum is evaluated after reversing the branch filter.
func (f *File) decodeARM64Block(block indexedBlock) ([]byte, error) {
	var prefix [1]byte
	if _, err := f.base.ReadAt(prefix[:], block.physical); err != nil {
		return nil, err
	}
	headerSize := (int64(prefix[0]) + 1) * 4
	if prefix[0] == 0 || headerSize >= block.unpadded {
		return nil, fmt.Errorf("xz: invalid ARM64 block header size")
	}
	header := make([]byte, headerSize)
	if _, err := f.base.ReadAt(header, block.physical); err != nil {
		return nil, err
	}
	flags := header[1]
	if flags&0x3f != 1 {
		return nil, rootxz.ErrOptions
	}
	le := binary.LittleEndian
	attributes := header[2 : len(header)-4]
	if le.Uint32(header[len(header)-4:]) != crc32.ChecksumIEEE(header[:len(header)-4]) {
		return nil, fmt.Errorf("xz: invalid ARM64 block header CRC")
	}
	fields := bufio.NewReaderSize(bytes.NewReader(attributes), len(attributes))

	checkKind := block.header[7]
	checkSize, known := map[byte]int64{0: 0, 1: 4, 4: 8, 10: 32}[checkKind]
	if !known || block.header[6] != 0 {
		return nil, rootxz.ErrUnsupportedCheck
	}
	compressedSize := block.unpadded - headerSize - checkSize
	if compressedSize <= 0 {
		return nil, fmt.Errorf("xz: invalid ARM64 block lengths")
	}
	if flags&0x40 != 0 {
		length, err := readXZVLI(fields)
		if err != nil || length != uint64(compressedSize) {
			return nil, fmt.Errorf("xz: incorrect ARM64 compressed length")
		}
	}
	if flags&0x80 != 0 {
		length, err := readXZVLI(fields)
		if err != nil || length != uint64(block.decoded) {
			return nil, fmt.Errorf("xz: incorrect ARM64 decoded length")
		}
	}
	filter, err := fields.ReadByte()
	if err != nil || filter != 0x0a {
		return nil, rootxz.ErrOptions
	}
	properties, err := fields.ReadByte()
	if err != nil || properties != 0 && properties != 4 {
		return nil, fmt.Errorf("xz: invalid ARM64 filter properties")
	}
	var position uint32
	if properties == 4 {
		var offset [4]byte
		if _, err := io.ReadFull(fields, offset[:]); err != nil {
			return nil, err
		}
		position = le.Uint32(offset[:])
		if position%4 != 0 {
			return nil, fmt.Errorf("xz: unaligned ARM64 filter position")
		}
	}
	var lzmaProperties [3]byte
	if _, err := io.ReadFull(fields, lzmaProperties[:]); err != nil {
		return nil, err
	}
	if lzmaProperties[0] != 0x21 || lzmaProperties[1] != 1 || lzmaProperties[2] > 40 {
		return nil, rootxz.ErrOptions
	}
	dictionaryBits := lzmaProperties[2]
	dictionary := uint64(2|dictionaryBits&1) << (dictionaryBits/2 + 11)
	if dictionaryBits == 40 {
		dictionary = 1<<32 - 1
	}
	if dictionary > uint64(f.dictionary) || uint64(int(dictionary)) != dictionary {
		return nil, rootxz.ErrMemlimit
	}
	for padding, err := fields.ReadByte(); err != io.EOF; padding, err = fields.ReadByte() {
		if err != nil || padding != 0 {
			return nil, fmt.Errorf("xz: invalid ARM64 block header padding")
		}
	}

	compressed := io.NewSectionReader(f.base, block.physical+headerSize, compressedSize)
	reader, err := (lzma.Reader2Config{DictCap: int(dictionary)}).NewReader2(compressed)
	if err != nil {
		return nil, err
	}
	out := make([]byte, block.decoded)
	if _, err := io.ReadFull(reader, out); err != nil {
		return nil, err
	}
	if err := verifyXZEnd(reader); err != nil {
		return nil, err
	}
	if remaining, err := compressed.Seek(0, io.SeekCurrent); err != nil || remaining != compressedSize {
		return nil, fmt.Errorf("xz: unexpected data after ARM64 LZMA2 stream")
	}
	reverseARM64Branches(out, position)

	padding := -block.unpadded & 3
	tail := make([]byte, padding+checkSize)
	if len(tail) > 0 {
		if _, err := f.base.ReadAt(tail, block.physical+headerSize+compressedSize); err != nil {
			return nil, err
		}
		for _, b := range tail[:padding] {
			if b != 0 {
				return nil, fmt.Errorf("xz: invalid ARM64 block padding")
			}
		}
	}
	check := tail[padding:]
	valid := true
	switch checkKind {
	case 1:
		valid = le.Uint32(check) == crc32.ChecksumIEEE(out)
	case 4:
		valid = le.Uint64(check) == crc64.Checksum(out, crc64.MakeTable(crc64.ECMA))
	case 10:
		digest := sha256.Sum256(out)
		valid = bytes.Equal(digest[:], check)
	}
	if !valid {
		return nil, fmt.Errorf("xz: ARM64 block checksum mismatch")
	}
	return out, nil
}

func reverseARM64Branches(data []byte, start uint32) {
	le := binary.LittleEndian
	for i := 0; i+4 <= len(data); i += 4 {
		instruction := le.Uint32(data[i:])
		address := start + uint32(i)
		switch {
		case instruction&0xfc000000 == 0x94000000: // BL
			target := (instruction - address/4) & 0x03ffffff
			le.PutUint32(data[i:], 0x94000000|target)
		case instruction&0x9f000000 == 0x90000000: // ADRP
			target := instruction>>29&3 | instruction>>3&0x1ffffc
			if (target+0x20000)&0x1c0000 != 0 {
				continue
			}
			target -= address / 4096
			immediate := (target&3)<<29 | (target&0x3fffc)<<3
			if target&0x20000 != 0 {
				immediate |= 0xe00000
			}
			le.PutUint32(data[i:], instruction&0x9000001f|immediate)
		}
	}
}

package xz

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"sort"

	rootxz "github.com/therootcompany/xz"
	bytecache "github.com/tinyrange/trex/storage/cache"
)

const indexCacheBytes = 96 << 20

type indexedBlock struct {
	physical, logical, unpadded, decoded int64
	header                               [12]byte
}

func (f *File) readIndexed(p []byte, off int64) (int, error) {
	index := sort.Search(len(f.blocks), func(i int) bool {
		return f.blocks[i].logical+f.blocks[i].decoded > off
	})
	written := 0
	for index < len(f.blocks) && written < len(p) {
		block := f.blocks[index]
		index++
		if block.decoded == 0 {
			continue
		}
		within := off - block.logical
		length := min(int64(len(p)-written), block.decoded-within)
		if block.decoded > indexCacheBytes {
			n, err := f.readSequential(p[written:written+int(length)], off)
			if err != nil {
				return written + n, err
			}
		} else {
			b, err := f.cache.Get(bytecache.Key{Offset: block.physical}, func() ([]byte, error) {
				return f.decodeBlock(block)
			})
			if err != nil {
				return written, err
			}
			copy(p[written:], b[within:within+length])
		}
		written += int(length)
		off += length
	}
	if written < len(p) {
		return written, io.EOF
	}
	return written, nil
}

func (f *File) decodeBlock(block indexedBlock) ([]byte, error) {
	out, err := f.decodeStandardBlock(block)
	if errors.Is(err, rootxz.ErrOptions) {
		return f.decodeARM64Block(block)
	}
	return out, err
}

func (f *File) decodeStandardBlock(block indexedBlock) ([]byte, error) {
	// Borrow the original block and its checksum. The decoder reads an XZ
	// stream with one index record for just that block.
	index := []byte{0, 1}
	index = binary.AppendUvarint(index, uint64(block.unpadded))
	index = binary.AppendUvarint(index, uint64(block.decoded))
	for len(index)%4 != 0 {
		index = append(index, 0)
	}
	index = binary.LittleEndian.AppendUint32(index, crc32.ChecksumIEEE(index))
	var footer [12]byte
	binary.LittleEndian.PutUint32(footer[4:], uint32(len(index)/4-1))
	copy(footer[8:10], block.header[6:8])
	copy(footer[10:], "YZ")
	binary.LittleEndian.PutUint32(footer[:], crc32.ChecksumIEEE(footer[4:10]))
	padded := (block.unpadded + 3) &^ 3
	input := io.MultiReader(bytes.NewReader(block.header[:]), io.NewSectionReader(f.base, block.physical, padded), bytes.NewReader(index), bytes.NewReader(footer[:]))
	r, err := rootxz.NewReader(input, f.dictionary)
	if err != nil {
		return nil, err
	}
	out := make([]byte, int(block.decoded))
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, fmt.Errorf("xz: block at %d: %w", block.physical, err)
	}
	if err := verifyXZEnd(r); err != nil {
		return nil, err
	}
	return out, nil
}

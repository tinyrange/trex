// Package chd reads standalone uncompressed version-5 CHD disk images.
package chd

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math"

	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

const headerSize = 124

type Image struct {
	source storage.Reader
	size   int64
	hunk   int64
	index  []byte
}

func Open(source storage.Reader) (*Image, error) {
	if source == nil || source.Size() < headerSize {
		return nil, fmt.Errorf("chd: truncated header")
	}
	var header [headerSize]byte
	if _, err := starfile.ReadFullAt(source, header[:], 0); err != nil {
		return nil, err
	}
	be := binary.BigEndian
	if string(header[:8]) != "MComprHD" || be.Uint32(header[8:]) != headerSize || be.Uint32(header[12:]) != 5 {
		return nil, fmt.Errorf("chd: expected a version-5 CHD")
	}
	if !bytes.Equal(header[16:32], make([]byte, 16)) {
		return nil, fmt.Errorf("chd: compressed version-5 maps are unsupported")
	}
	if !bytes.Equal(header[104:124], make([]byte, 20)) {
		return nil, fmt.Errorf("chd: a parent image is required")
	}
	size := be.Uint64(header[32:])
	mapOffset, metadata := be.Uint64(header[40:]), be.Uint64(header[48:])
	hunk, unit := uint64(be.Uint32(header[56:])), uint64(be.Uint32(header[60:]))
	if size == 0 || size > math.MaxInt64 || unit == 0 || hunk == 0 || hunk%unit != 0 || size%unit != 0 {
		return nil, fmt.Errorf("chd: invalid logical disk geometry")
	}
	hunks := (size-1)/hunk + 1
	total := uint64(source.Size())
	if hunks > 16<<20 || mapOffset < headerSize || mapOffset > total || hunks*4 > total-mapOffset {
		return nil, fmt.Errorf("chd: invalid or oversized hunk map")
	}
	mapEnd := mapOffset + hunks*4
	if metadata != 0 && (metadata < headerSize || metadata > total-16 || (metadata < mapEnd && metadata+16 > mapOffset)) {
		return nil, fmt.Errorf("chd: invalid metadata offset")
	}
	index := make([]byte, hunks*4)
	if _, err := starfile.ReadFullAt(source, index, int64(mapOffset)); err != nil {
		return nil, err
	}
	for i := uint64(0); i < hunks; i++ {
		n := uint64(be.Uint32(index[i*4:]))
		if n == 0 {
			continue // Unallocated hunks in standalone images read as zeros.
		}
		off := n * hunk
		if off < headerSize || off > total || hunk > total-off ||
			(off < mapEnd && mapOffset < off+hunk) ||
			(metadata != 0 && off < metadata+16 && metadata < off+hunk) {
			return nil, fmt.Errorf("chd: hunk %d points outside data at %#x", i, off)
		}
	}
	return &Image{source: source, size: int64(size), hunk: int64(hunk), index: index}, nil
}

func (im *Image) Size() int64 { return im.size }

func (im *Image) ReadAt(out []byte, offset int64) (int, error) {
	if offset < 0 {
		return 0, fmt.Errorf("chd: negative disk offset")
	}
	if len(out) == 0 {
		return 0, nil
	}
	if offset >= im.size {
		return 0, io.EOF
	}
	available := int(min(im.size-offset, int64(len(out))))
	n := 0
	for n < available {
		hunk, inside := offset/im.hunk, offset%im.hunk
		physical := int64(binary.BigEndian.Uint32(im.index[hunk*4:]))
		part := int(min(int64(available-n), im.hunk-inside))
		if physical == 0 {
			clear(out[n : n+part])
			n += part
		} else {
			got, err := starfile.ReadFullAt(im.source, out[n:n+part], physical*im.hunk+inside)
			n += got
			if err != nil {
				return n, err
			}
		}
		offset += int64(part)
	}
	if n < len(out) {
		return n, io.EOF
	}
	return n, nil
}

func Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var file starfile.File
	if err := starlark.UnpackArgs("filesystem.chd", args, kwargs, "file", &file); err != nil {
		return nil, err
	}
	image, err := Open(file)
	if err != nil {
		return nil, err
	}
	return starfile.NewReader("CHD disk", image), nil
}

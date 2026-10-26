// Package omaha reads the LZMA/BCJ2 payload resource of Omaha metainstallers.
// Format: google/omaha, omaha/mi_exe_stub/mi.cc, DecompressBufferToFile.
// PE resource selection, the decoded tar, and installation policy are separate.
package omaha

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/tinyrange/trex/archive/compressed"
	"github.com/tinyrange/trex/archive/sevenzip"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

// Open authenticates neither publisher nor contents. Callers must verify the
// enclosing executable before decoding its resource. Both decoded stages are
// bounded by maximum; framing and BCJ2 stream completion are checked exactly.
func Open(source storage.Reader, maximum int64, dictionary int) (storage.Reader, error) {
	decoded, err := compressed.OpenLZMA(source, maximum, dictionary)
	if err != nil {
		return nil, err
	}
	return decodeBCJ2(decoded, maximum)
}

func decodeBCJ2(source storage.Reader, maximum int64) (storage.Reader, error) {
	if source.Size() < 20 || maximum <= 0 {
		return nil, fmt.Errorf("omaha: short BCJ2 header or invalid limit")
	}
	var header [20]byte
	if _, err := source.ReadAt(header[:], 0); err != nil {
		return nil, err
	}
	size := uint64(binary.LittleEndian.Uint32(header[:4]))
	if size > uint64(maximum) || size > uint64(^uint(0)>>1) {
		return nil, fmt.Errorf("omaha: decoded output exceeds limit")
	}
	sizes := make([]uint64, 4)
	inputs := make([]io.Reader, 4)
	offset := int64(20)
	for i := range sizes {
		sizes[i] = uint64(binary.LittleEndian.Uint32(header[4+i*4 : 8+i*4]))
		if sizes[i] > uint64(source.Size()-offset) {
			return nil, fmt.Errorf("omaha: BCJ2 stream %d exceeds payload", i)
		}
		inputs[i] = io.NewSectionReader(source, offset, int64(sizes[i]))
		offset += int64(sizes[i])
	}
	if offset != source.Size() {
		return nil, fmt.Errorf("omaha: trailing BCJ2 payload bytes")
	}
	reader, err := sevenzip.NewBCJ2Reader(inputs, sizes, size)
	if err != nil {
		return nil, err
	}
	data := make([]byte, int(size))
	if _, err := io.ReadFull(reader, data); err != nil {
		return nil, fmt.Errorf("omaha: BCJ2 decode: %w", err)
	}
	var tail [1]byte
	if n, err := reader.Read(tail[:]); n != 0 || err != io.EOF {
		return nil, fmt.Errorf("omaha: BCJ2 completion: count=%d error=%v", n, err)
	}
	return &starfile.Bytes{Data: data}, nil
}

func Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	maximum, dictionary := int64(512<<20), 64<<20
	if err := starlark.UnpackArgs("omaha_payload", args, kwargs, "file", &value, "maximum_bytes?", &maximum, "max_dictionary?", &dictionary); err != nil {
		return nil, err
	}
	source, ok := value.(storage.Reader)
	if !ok {
		return nil, fmt.Errorf("omaha_payload: expected file")
	}
	result, err := Open(source, maximum, dictionary)
	if err != nil {
		return nil, err
	}
	return result.(starlark.Value), nil
}

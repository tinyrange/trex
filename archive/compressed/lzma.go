package compressed

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"math"

	"github.com/tinyrange/trex/storage"
	"github.com/ulikunitz/xz/lzma"
	"go.starlark.net/starlark"
)

// OpenLZMA decodes one standalone LZMA stream, including its 13-byte header.
// Both allocation dimensions are bounded before creating the decoder. The
// enclosing package must authenticate the source: LZMA has no checksum.
func OpenLZMA(source storage.Reader, maximum int64, dictionary int) (*File, error) {
	if source.Size() < 13 || maximum <= 0 || dictionary < lzma.MinDictCap || int64(dictionary) > lzma.MaxDictCap {
		return nil, fmt.Errorf("lzma: invalid header size or decoding limits")
	}
	var header [13]byte
	if _, err := source.ReadAt(header[:], 0); err != nil {
		return nil, fmt.Errorf("lzma: header: %w", err)
	}
	if uint64(binary.LittleEndian.Uint32(header[1:5])) > uint64(dictionary) {
		return nil, fmt.Errorf("lzma: dictionary exceeds max_dictionary %d", dictionary)
	}
	size := binary.LittleEndian.Uint64(header[5:13])
	if size != math.MaxUint64 && size > uint64(maximum) {
		return nil, fmt.Errorf("lzma: declared size exceeds maximum_bytes %d", maximum)
	}
	input := bufio.NewReader(io.NewSectionReader(source, 0, source.Size()))
	decoder, err := (lzma.ReaderConfig{DictCap: dictionary}).NewReader(input)
	if err != nil {
		return nil, fmt.Errorf("lzma: %w", err)
	}
	file, err := decode(decoder, "lzma", maximum)
	if err != nil {
		return nil, err
	}
	if size != math.MaxUint64 && uint64(file.Size()) != size {
		return nil, fmt.Errorf("lzma: decoded size differs from header")
	}
	if _, err := input.Peek(1); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("lzma: trailing data")
		}
		return nil, fmt.Errorf("lzma: stream end: %w", err)
	}
	return file, nil
}

func LZMABuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var source starlark.Value
	maximum, dictionary := int64(512<<20), 64<<20
	if err := starlark.UnpackArgs("lzma", args, kwargs, "file", &source, "maximum_bytes?", &maximum, "max_dictionary?", &dictionary); err != nil {
		return nil, err
	}
	file, ok := source.(storage.Reader)
	if !ok {
		return nil, fmt.Errorf("lzma: expected file, got %s", source.Type())
	}
	return OpenLZMA(file, maximum, dictionary)
}

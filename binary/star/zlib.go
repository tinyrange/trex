package star

import (
	"bufio"
	"compress/zlib"
	"fmt"
	"io"

	"go.starlark.net/starlark"
)

// binaryZlibBuiltin decodes one complete RFC 1950 stream, with bounded output.
func binaryZlibBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var source starlark.Value
	maximum := int64(16 << 20)
	if err := starlark.UnpackArgs("zlib", args, kwargs, "source", &source, "maximum?", &maximum); err != nil {
		return nil, err
	}
	if maximum < 0 || maximum > 512<<20 {
		return nil, fmt.Errorf("zlib: maximum must be between 0 and 512 MiB")
	}
	view, err := newBinaryByteView(source)
	if err != nil {
		return nil, err
	}
	input := bufio.NewReader(io.NewSectionReader(view, 0, view.size))
	reader, err := zlib.NewReader(input)
	if err != nil {
		return nil, fmt.Errorf("zlib: %w", err)
	}
	defer reader.Close()
	data, err := io.ReadAll(io.LimitReader(reader, maximum+1))
	if err != nil {
		return nil, fmt.Errorf("zlib: %w", err)
	}
	if int64(len(data)) > maximum {
		return nil, fmt.Errorf("zlib: decoded data exceeds maximum %d", maximum)
	}
	if _, err := input.ReadByte(); err != io.EOF {
		if err != nil {
			return nil, fmt.Errorf("zlib: %w", err)
		}
		return nil, fmt.Errorf("zlib: trailing data")
	}
	return starlark.Bytes(data), nil
}

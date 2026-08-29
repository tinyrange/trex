package windows

import (
	"fmt"
	"io"
	"math"

	"github.com/tinyrange/trex/block"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

const defaultBinaryBuilderLimit = 512 << 20

type starlarkNumber float64

func (number *starlarkNumber) Unpack(value starlark.Value) error {
	decoded, ok := starlark.AsFloat(value)
	if !ok || math.IsNaN(decoded) || math.IsInf(decoded, 0) {
		return fmt.Errorf("got %s, want finite int or float", value.Type())
	}
	*number = starlarkNumber(decoded)
	return nil
}

func readFullAt(reader io.ReaderAt, buffer []byte, offset int64) (int, error) {
	return block.ReadFullAt(reader, buffer, offset)
}

func validateBlockRange(size, offset, length int64) error {
	return block.ValidateRange(size, offset, length)
}

func bytesForValue(value starlark.Value) ([]byte, error) {
	switch value := value.(type) {
	case starfile.File:
		return starfile.ReadAll(value)
	case starlark.String:
		return []byte(string(value)), nil
	case starlark.Bytes:
		return []byte(value), nil
	default:
		return nil, fmt.Errorf("got %s, want file, string, or bytes", value.Type())
	}
}

func bytesForBinaryValue(value starlark.Value) ([]byte, error) {
	return bytesForBinaryValueLimited(value, defaultBinaryBuilderLimit)
}

func bytesForBinaryValueLimited(value starlark.Value, maximum int64) ([]byte, error) {
	data, err := bytesForValue(value)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maximum {
		return nil, fmt.Errorf("input size %d exceeds limit %d", len(data), maximum)
	}
	return data, nil
}

func readBytesAt(file starfile.File, offset, size int64) ([]byte, error) {
	if offset < 0 || size < 0 || offset > file.Size() || size > file.Size()-offset {
		return nil, io.ErrUnexpectedEOF
	}
	data := make([]byte, size)
	_, err := starfile.ReadFullAt(file, data, offset)
	return data, err
}

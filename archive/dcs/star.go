// Package dcs exposes the bounded native CBS component-store decoder.
package dcs

import (
	"fmt"
	"io"

	"github.com/tinyrange/trex/compression/lzms"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

// Open expands a DCS v1 container in memory. Both stored and expanded sizes
// are bounded; no signature or manifest digest verification is implied.
func Open(file storage.Reader, maximum int64) (storage.Reader, error) {
	if file == nil {
		return nil, fmt.Errorf("dcs: expected file")
	}
	if maximum < 1 || maximum > 512<<20 {
		return nil, fmt.Errorf("dcs: maximum_bytes must be 1..512MiB")
	}
	if file.Size() < 12 || file.Size() > maximum {
		return nil, fmt.Errorf("dcs: stored size exceeds bounds")
	}
	data, err := io.ReadAll(io.NewSectionReader(file, 0, file.Size()))
	if err != nil {
		return nil, err
	}
	decoded, err := lzms.DecompressDCS(data, uint64(maximum))
	if err != nil {
		return nil, err
	}
	return &starfile.Bytes{Name: "expanded DCS", Data: decoded}, nil
}

func Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	maximum := int64(512 << 20)
	if err := starlark.UnpackArgs("dcs", args, kwargs, "file", &value, "maximum_bytes?", &maximum); err != nil {
		return nil, err
	}
	file, ok := value.(storage.Reader)
	if !ok {
		return nil, fmt.Errorf("dcs: expected file")
	}
	expanded, err := Open(file, maximum)
	if err != nil {
		return nil, err
	}
	return starfile.NewReader("expanded DCS", expanded), nil
}

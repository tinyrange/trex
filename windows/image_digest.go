package windows

import (
	"fmt"
	"io"

	"github.com/tinyrange/trex/storage"
	"github.com/tinyrange/trex/windows/pe"
	"go.starlark.net/starlark"
)

func imageDigestBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	algorithm := "sha1"
	maximum := int64(512 << 20)
	if err := starlark.UnpackArgs("image_digest", args, kwargs, "file", &value, "algorithm?", &algorithm, "maximum_bytes?", &maximum); err != nil {
		return nil, err
	}
	file, ok := value.(storage.Reader)
	if !ok {
		return nil, fmt.Errorf("image_digest: expected file")
	}
	if maximum < 1 || maximum > 512<<20 || file.Size() < 0 || file.Size() > maximum {
		return nil, fmt.Errorf("image_digest: invalid bound or excessive file")
	}
	h, err := authenticodeHasher(algorithm)
	if err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.NewSectionReader(file, 0, file.Size()))
	if err != nil {
		return nil, err
	}
	if err := pe.ImageDigest(data, h); err != nil {
		return nil, err
	}
	return starlark.Bytes(h.Sum(nil)), nil
}

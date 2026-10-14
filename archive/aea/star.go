package aea

import (
	"fmt"

	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func MetadataBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs("aea_metadata", args, kwargs, "file", &value); err != nil {
		return nil, err
	}
	source, ok := value.(storage.Reader)
	if !ok {
		return nil, fmt.Errorf("aea_metadata: expected file")
	}
	metadata, err := ReadMetadata(source)
	if err != nil {
		return nil, err
	}
	values := starlark.NewDict(len(metadata.Values))
	for key, value := range metadata.Values {
		if err := values.SetKey(starlark.String(key), starlark.Bytes(value)); err != nil {
			return nil, err
		}
	}
	return starfile.NewRecord(starlark.StringDict{
		"profile":         starlark.MakeUint64(uint64(metadata.Profile)),
		"scrypt_strength": starlark.MakeUint64(uint64(metadata.ScryptStrength)),
		"auth_data":       starfile.NewReader("aea-auth-data", metadata.AuthData), "values": values,
	}), nil
}

func Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	var keyValue starlark.Value = starlark.None
	maximum := int64(4 << 30)
	if err := starlark.UnpackArgs("aea", args, kwargs, "file", &value, "key?", &keyValue, "maximum_bytes?", &maximum); err != nil {
		return nil, err
	}
	source, ok := value.(storage.Reader)
	if !ok {
		return nil, fmt.Errorf("aea: expected file")
	}
	var key []byte
	if keyValue != starlark.None {
		v, ok := keyValue.(starlark.Bytes)
		if !ok {
			return nil, fmt.Errorf("aea: key must be bytes")
		}
		key = []byte(v)
	}
	f, err := Open(source, key, maximum)
	if err != nil {
		return nil, err
	}
	verify := starlark.NewBuiltin("aea.verify", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		if err := starlark.UnpackArgs("verify", args, kwargs); err != nil {
			return nil, err
		}
		return starlark.None, f.Verify()
	})
	return starfile.NewRecord(starlark.StringDict{
		"file": starfile.NewReader("aea plaintext", f), "encrypted_size": starlark.MakeInt64(f.EncryptedSize),
		"segment_size": starlark.MakeUint64(uint64(f.SegmentSize)), "segments_per_cluster": starlark.MakeUint64(uint64(f.SegmentsPerCluster)),
		"compression": starlark.String(string([]byte{f.Compression})), "checksum": starlark.MakeInt(int(f.Checksum)), "verify": verify,
	}), nil
}

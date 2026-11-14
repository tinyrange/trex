package szdd

import (
	"bytes"
	"fmt"
	"strings"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

// InfoBuiltin retains the mode-A header's filename replacement character.
// SZDD stores only the replaced character, not a complete original filename;
// the caller must supply the compressed member's basename.
func InfoBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	var name string
	maximum := defaultSZDDLimit
	if err := starlark.UnpackArgs("szdd_info", args, kwargs, "file", &value, "name", &name, "maximum?", &maximum); err != nil {
		return nil, err
	}
	file, ok := value.(File)
	if !ok {
		return nil, fmt.Errorf("szdd_info: got %s, want file", value.Type())
	}
	if maximum <= 0 {
		return nil, fmt.Errorf("szdd_info: maximum must be positive")
	}
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\\:\x00") {
		return nil, fmt.Errorf("szdd_info: name must be a basename")
	}
	data, err := decodeSZDD(file, maximum)
	if err != nil {
		return nil, err
	}
	var header [10]byte
	if _, err := file.ReadAt(header[:], 0); err != nil {
		return nil, err
	}
	if bytes.Equal(header[:8], szddSignature) && header[9] != 0 && strings.HasSuffix(name, "_") {
		c := header[9]
		if c < 0x20 || c >= 0x7f || strings.ContainsRune(`/\:*?"<>|`, rune(c)) {
			return nil, fmt.Errorf("szdd_info: invalid filename replacement character %#x", c)
		}
		name = name[:len(name)-1] + string([]byte{c})
	}
	decoded := &starfile.Bytes{Name: name, Data: data}
	return starfile.NewRecord(starlark.StringDict{
		"file":            decoded,
		"name":            starlark.String(name),
		"decoded_size":    starlark.MakeInt64(decoded.Size()),
		"compressed_size": starlark.MakeInt64(file.Size()),
	}), nil
}

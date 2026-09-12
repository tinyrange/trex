package windows

import (
	"bytes"
	"github.com/tinyrange/trex/archive/kwaj"
	"github.com/tinyrange/trex/archive/szdd"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
	"path"
)

// Microsoft setup media mixes literal files and individually compressed DOS
// filenames. Detection uses the file signature, never the filename alone.
func decodeSetupFile(thread *starlark.Thread, file starfile.File) (starfile.File, error) {
	if file.Size() < 8 {
		return file, nil
	}
	magic := make([]byte, 8)
	if _, err := file.ReadAt(magic, 0); err != nil {
		return nil, err
	}
	var decoder func(*starlark.Thread, *starlark.Builtin, starlark.Tuple, []starlark.Tuple) (starlark.Value, error)
	if bytes.Equal(magic, []byte{'S', 'Z', 'D', 'D', 0x88, 0xf0, 0x27, 0x33}) || bytes.Equal(magic, []byte{'S', 'Z', ' ', 0x88, 0xf0, 0x27, 0x33, 0xd1}) {
		decoder = szdd.Builtin
	}
	if bytes.Equal(magic, []byte{'K', 'W', 'A', 'J', 0x88, 0xf0, 0x27, 0xd1}) {
		decoder = kwaj.Builtin
	}
	if decoder == nil {
		return file, nil
	}
	v, err := decoder(thread, nil, starlark.Tuple{file}, nil)
	if err != nil {
		return nil, err
	}
	return v.(starfile.File), nil
}

func setupCompressedName(name string) string {
	extension := path.Ext(name)
	if extension == "" {
		return name + "._"
	}
	if len(extension) < 4 {
		return name + "_"
	}
	return name[:len(name)-1] + "_"
}

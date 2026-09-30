package shell

import (
	"github.com/tinyrange/trex/channel"
	"io/fs"
)

type fullFile struct{ flags OpenFlags }

func (f *fullFile) Read(p []byte) (int, error) {
	if f.flags&Read == 0 {
		return 0, fs.ErrPermission
	}
	clear(p)
	return len(p), nil
}
func (f *fullFile) Write(p []byte) (int, error) {
	if f.flags&Write == 0 {
		return 0, fs.ErrPermission
	}
	return 0, channel.ErrNoSpace
}
func (*fullFile) Close() error         { return nil }
func (*fullFile) SetAppend(bool) error { return nil }

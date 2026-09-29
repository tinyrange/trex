package buildenv

import (
	"github.com/tinyrange/trex/channel"
	"github.com/tinyrange/trex/emulator/linux"
	"github.com/tinyrange/trex/emulator/shell"
	"io/fs"
)

type guestFiles struct{ fs *shell.MemoryFS }

func (g guestFiles) Open(name string, flags linux.OpenFlags, mode fs.FileMode) (channel.ByteChannel, error) {
	var f shell.OpenFlags
	for _, pair := range []struct {
		l linux.OpenFlags
		s shell.OpenFlags
	}{
		{linux.Read, shell.Read}, {linux.Write, shell.Write}, {linux.Create, shell.Create},
		{linux.Truncate, shell.Truncate}, {linux.Append, shell.Append}, {linux.Exclusive, shell.Exclusive},
	} {
		if flags&pair.l != 0 {
			f |= pair.s
		}
	}
	return g.fs.OpenMode(name, f, mode)
}

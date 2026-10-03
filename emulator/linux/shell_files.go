package linux

import (
	"io/fs"

	"github.com/tinyrange/trex/channel"
	"github.com/tinyrange/trex/emulator/shell"
)

type GuestFiles struct{ FS *shell.MemoryFS }

func (g GuestFiles) Open(name string, flags OpenFlags, mode fs.FileMode) (channel.ByteChannel, error) {
	var f shell.OpenFlags
	for _, pair := range []struct {
		l OpenFlags
		s shell.OpenFlags
	}{
		{Read, shell.Read}, {Write, shell.Write}, {Create, shell.Create},
		{Truncate, shell.Truncate}, {Append, shell.Append}, {Exclusive, shell.Exclusive},
	} {
		if flags&pair.l != 0 {
			f |= pair.s
		}
	}
	return g.FS.OpenMode(name, f, mode)
}

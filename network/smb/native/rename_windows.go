package native

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"strings"

	"github.com/tinyrange/trex/network/smb"
)

// NTFS refuses directory renames while descendants have native file handles,
// even with FILE_SHARE_DELETE. Root.mu already serializes SMB operations and
// the caller checked every descendant's delete sharing. Release only our own
// descendant handles, rename, then reopen them under the rooted directory.
// Check file identity before publishing each reopened handle: concurrent host
// replacement must fail the logical handle rather than access a different file.
func renameNative(f *file, target string) (bool, error) {
	var children []*file
	for h := range f.root.handles {
		if strings.HasPrefix(h.name, f.name+"/") {
			children = append(children, h)
		}
	}
	var closeErr error
	for _, h := range children {
		closeErr = errors.Join(closeErr, h.file.Close())
	}
	renamed := false
	err := closeErr
	if err == nil {
		err = f.root.root.Rename(f.name, target)
		renamed = err == nil
	}
	for _, h := range children {
		name := h.name
		if renamed {
			name = target + strings.TrimPrefix(name, f.name)
		}
		flags := os.O_RDONLY
		if h.options.Access&smb.AccessWrite != 0 && !h.options.Directory {
			flags = os.O_RDWR
		}
		reopened, e := f.root.root.OpenFile(name, flags, 0)
		if e == nil {
			info, statErr := reopened.Stat()
			e = statErr
			if e == nil && !os.SameFile(info, h.object.info) {
				e = fs.ErrNotExist
			}
			if e == nil && info.IsDir() {
				for remaining := h.directoryRead; remaining > 0; {
					entries, readErr := reopened.Readdir(min(remaining, 128))
					remaining -= len(entries)
					if readErr != nil {
						if readErr != io.EOF {
							e = readErr
						}
						break
					}
				}
			}
		}
		if e != nil {
			if reopened != nil {
				reopened.Close()
			}
			h.nativeErr = e
		} else {
			h.file = reopened
		}
		err = errors.Join(err, e)
	}
	return renamed, err
}

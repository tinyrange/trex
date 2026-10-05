package repo

import (
	"errors"
	"github.com/tinyrange/trex/storage"
	"io"
	"math"
)

// Positioned storage retains the original append/seek failure boundary while
// the public backend uses trex's portable random-access storage contract.
type fileSize interface{ Size() int64 }
type sizeValue int64

func (s sizeValue) Size() int64 { return int64(s) }

type repositoryFile interface {
	io.ReaderAt
	io.Writer
	io.Seeker
	io.Closer
	Stat() (fileSize, error)
	Sync() error
	Truncate(int64) error
	WriteAt([]byte, int64) (int, error)
}
type storeFile struct {
	storage.Store
	pos int64
}

func (f *storeFile) Stat() (fileSize, error) { n, e := f.Length(); return sizeValue(n), e }
func (f *storeFile) Write(p []byte) (int, error) {
	n, e := f.WriteAt(p, f.pos)
	f.pos += int64(n)
	return n, e
}
func (f *storeFile) Seek(off int64, whence int) (int64, error) {
	var base int64
	switch whence {
	case io.SeekStart:
	case io.SeekCurrent:
		base = f.pos
	case io.SeekEnd:
		n, e := f.Length()
		if e != nil {
			return 0, e
		}
		base = n
	default:
		return 0, errors.New("invalid seek origin")
	}
	if off < -base || off > math.MaxInt64-base {
		return 0, errors.New("invalid seek")
	}
	f.pos = base + off
	return f.pos, nil
}
func writePart(w io.Writer, p []byte) error {
	n, err := w.Write(p)
	if err == nil && n != len(p) {
		return io.ErrShortWrite
	}
	return err
}

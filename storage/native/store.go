package native

import (
	"errors"
	"github.com/tinyrange/trex/storage"
	"os"
	"path/filepath"
	"sync"
)

// OpenStore opens an exclusively locked native repository. create never
// overwrites existing data. The first successful Sync also persists the parent
// directory of a newly created file. This is final repository storage, not a
// temporary transport spool or exported working tree.
func OpenStore(name string, create bool) (storage.Store, error) {
	flags := os.O_RDWR
	if create {
		flags |= os.O_CREATE | os.O_EXCL
	}
	f, err := os.OpenFile(name, flags, 0600)
	if err != nil {
		return nil, err
	}
	if err = lockStore(f); err != nil {
		f.Close()
		if create {
			os.Remove(name)
		}
		return nil, err
	}
	s := &nativeStore{f: f}
	if create {
		s.parent, err = os.Open(filepath.Dir(name))
		if err != nil {
			f.Close()
			os.Remove(name)
			return nil, err
		}
	}
	return s, nil
}

type nativeStore struct {
	f        *os.File
	parent   *os.File
	once     sync.Once
	closeErr error
}

func (s *nativeStore) ReadAt(p []byte, off int64) (int, error)  { return s.f.ReadAt(p, off) }
func (s *nativeStore) WriteAt(p []byte, off int64) (int, error) { return s.f.WriteAt(p, off) }
func (s *nativeStore) Length() (int64, error) {
	st, e := s.f.Stat()
	if e != nil {
		return 0, e
	}
	return st.Size(), nil
}
func (s *nativeStore) Truncate(n int64) error { return s.f.Truncate(n) }
func (s *nativeStore) Sync() error {
	if err := s.f.Sync(); err != nil {
		return err
	}
	if s.parent != nil {
		if err := s.parent.Sync(); err != nil {
			return err
		}
		err := s.parent.Close()
		s.parent = nil
		return err
	}
	return nil
}
func (s *nativeStore) Close() error {
	s.once.Do(func() {
		s.closeErr = s.f.Close()
		if s.parent != nil {
			s.closeErr = errors.Join(s.closeErr, s.parent.Close())
			s.parent = nil
		}
	})
	return s.closeErr
}

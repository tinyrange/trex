package repo

import (
	"errors"
	"github.com/tinyrange/trex/storage"
)

// SnapshotFile returns an independently readable immutable repository artifact
// when the backend supports it (MemoryStore does). It seals/syncs records but
// does not publish live workspace edits. Native stores are already final files;
// close them before opening those files through the native reader API.
func (r *Repository) SnapshotFile() (storage.Reader, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.ready(); err != nil {
		return nil, err
	}
	file, ok := r.f.(*storeFile)
	if !ok {
		return nil, errors.New("backend cannot snapshot repository bytes")
	}
	source, ok := file.Store.(interface {
		Snapshot() (storage.Reader, error)
	})
	if !ok {
		return nil, errors.New("backend cannot snapshot repository bytes")
	}
	if err := r.sync(); err != nil {
		return nil, err
	}
	return source.Snapshot()
}

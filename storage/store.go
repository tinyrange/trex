package storage

import "io"

// Store is caller-supplied, exclusively owned, resizable repository storage.
// Unlike Reader, its length may change. Sync is an explicit durability barrier;
// memory implementations may provide volatile storage, but must say so.
// A repository takes ownership of a Store, including on construction failure.
// Native locking and pathname/directory durability belong to the backend.
type Store interface {
	io.ReaderAt
	io.WriterAt
	Length() (int64, error)
	Truncate(int64) error
	Sync() error
	io.Closer
}

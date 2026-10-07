package bzip2

import (
	"fmt"
	"github.com/tinyrange/trex/storage"
	"io"
)

// Materialize validates all concatenated streams and returns an immutable
// bounded RAM snapshot. Integrity failures never return a partial snapshot.
func Materialize(source storage.Reader, maximum int64) (storage.Reader, error) {
	if maximum <= 0 {
		return nil, fmt.Errorf("bzip2: materialize requires positive maximum_bytes")
	}
	decoded := NewReader(source, maximum)
	store := storage.NewMemoryStore(maximum)
	defer store.Close()
	var buf [64 << 10]byte
	var off int64
	for {
		n, err := decoded.ReadAt(buf[:], off)
		if err != nil && err != io.EOF {
			return nil, err
		}
		if n != 0 {
			if _, e := store.WriteAt(buf[:n], off); e != nil {
				return nil, e
			}
			off += int64(n)
		}
		if err == io.EOF {
			return store.Snapshot()
		}
		if n == 0 {
			return nil, io.ErrNoProgress
		}
	}
}

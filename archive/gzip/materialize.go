package gzip

import (
	"fmt"
	"io"

	"github.com/tinyrange/trex/storage"
)

// Materialize decodes and validates the entire stream into bounded volatile
// pages. Unlike Open's replaying window, the returned immutable reader supports
// arbitrary access without consulting the compressed source again. No result
// is returned after an integrity failure or limit overflow.
func Materialize(source storage.Reader, maximum int64) (storage.Reader, error) {
	if maximum <= 0 {
		return nil, fmt.Errorf("gzip: materialize requires positive maximum_bytes")
	}
	f, err := Open(source, maximum)
	if err != nil {
		return nil, err
	}
	defer f.decoder.Close()
	store := storage.NewMemoryStore(maximum)
	defer store.Close()
	var buf [64 << 10]byte
	var off int64
	for {
		n, err := f.read(buf[:])
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
	}
}

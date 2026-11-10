package wim

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/tinyrange/trex/storage"
	bytecache "github.com/tinyrange/trex/storage/cache"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

// Applied files already carry filesystem metadata in the destination tree.
// Retain only the content identity and reader, not another full directory entry
// and expanded resource descriptor for each file. Archive metadata remains
// immutable and is resolved lazily for source-specific introspection.
type contentFile struct {
	archive   *Archive
	reader    storage.Reader
	path      string
	size      int64
	offset    int64
	hash      [20]byte
	solidLZMS bool
}

func (w *Archive) newContentFile(e entry) *contentFile {
	f := &contentFile{}
	w.initContentFile(f, e)
	return f
}

func (w *Archive) initContentFile(f *contentFile, e entry) {
	*f = contentFile{archive: w, path: e.path, size: e.size, hash: e.hash}
	if w.legacyIDs != nil && e.hash == ([20]byte{}) && e.size == 0 {
		f.reader = &starfile.Bytes{Name: e.path}
	} else if indexed, ok := w.byHash[e.hash]; ok {
		location := w.expandIndexed(indexed)
		f.size = location.blobSize
		f.reader = location.wimResourceBacking
		f.offset = location.blobOffset
		f.solidLZMS = location.resource.flags&wimResourceSolid != 0 && location.resource.compression == 3
	}
}

func (f *contentFile) ReadAt(p []byte, off int64) (int, error) {
	if f.reader == nil {
		return 0, fmt.Errorf("wim: resource for %q not found", f.path)
	}
	if f.archive.blobCache == nil || !f.solidLZMS || f.size <= 0 || off < 0 || off >= f.size || len(p) == 0 {
		return f.readContentAt(p, off)
	}
	// Keep small files whole and large files in bounded segments. In particular,
	// a resource just above the segment size must not fall back to decoding a
	// whole solid chunk for each tiny paging read.
	n := 0
	for len(p) != 0 && off < f.size {
		start := off / solidBlobSegmentSize * solidBlobSegmentSize
		size := min(solidBlobSegmentSize, f.size-start)
		data, err := f.cachedBlobSegment(start, size)
		if err != nil {
			return n, err
		}
		copied := copy(p, data[off-start:])
		n += copied
		off += int64(copied)
		p = p[copied:]
	}
	if len(p) != 0 {
		return n, io.EOF
	}
	return n, nil
}

func (f *contentFile) cachedBlobSegment(start, size int64) ([]byte, error) {
	// WIM addresses blobs by their complete SHA-1. Preserve all 160 bits and
	// separately key the segment ordinal, without host paths or truncated hashes.
	key := bytecache.Key{Kind: 3, Offset: int64(binary.LittleEndian.Uint64(f.hash[:8])), Size: int64(binary.LittleEndian.Uint64(f.hash[8:16])), OriginalSize: int64(binary.LittleEndian.Uint32(f.hash[16:]))}
	if f.size > solidBlobSegmentSize {
		key.Kind = 5
		key.Source = uint64(start / solidBlobSegmentSize)
	}
	load := func() ([]byte, error) {
		var fresh []byte
		encoded, err := f.archive.blobCache.Get(key, func() ([]byte, error) {
			f.archive.noteBlobMiss(f.path)
			data := make([]byte, int(size))
			n, err := f.readContentAt(data, start)
			if err != nil {
				return nil, err
			}
			if n != len(data) {
				return nil, io.ErrUnexpectedEOF
			}
			encoded, err := encodeCachedBlob(data)
			if err == nil {
				// Only this loader owns the expanded source buffer. Keep the
				// encoded cache entry, but do not immediately decode our own
				// just-encoded bytes. Waiters/hits still use the stored encoding.
				fresh = data
			}
			return encoded, err
		})
		if err != nil {
			return nil, err
		}
		if fresh != nil {
			return fresh, nil
		}
		return decodeCachedBlob(encoded, size)
	}
	if f.archive.blobHotCache != nil {
		return f.archive.blobHotCache.Get(key, load)
	}
	return load()
}

func (f *contentFile) Size() int64 { return f.size }
func (f *contentFile) WriteAt([]byte, int64) (int, error) {
	return 0, fmt.Errorf("wim entry %q is read-only", f.path)
}
func (f *contentFile) String() string      { return fmt.Sprintf("<wim.file %q size=%d>", f.path, f.size) }
func (*contentFile) Type() string          { return "file" }
func (*contentFile) Freeze()               {}
func (*contentFile) Truth() starlark.Bool  { return starlark.True }
func (*contentFile) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: file") }
func (f *contentFile) AttrNames() []string { return (&File{}).AttrNames() }
func (f *contentFile) Attr(name string) (starlark.Value, error) {
	switch name {
	case "metadata", "streams", "resource", "verify", "verify_locations":
		e, err := f.archive.lookupPath(f.path)
		if err != nil {
			return nil, err
		}
		return f.archive.newFile(e).Attr(name)
	}
	return starfile.Attr(f, name), nil
}

func (f *contentFile) readContentAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("negative offset")
	}
	if f.offset < 0 || f.size < 0 || f.offset > f.reader.Size() || f.size > f.reader.Size()-f.offset {
		return 0, fmt.Errorf("wim resource %q: file range exceeds resource", f.path)
	}
	if off >= f.size {
		return 0, io.EOF
	}
	requested := len(p)
	if int64(len(p)) > f.size-off {
		p = p[:f.size-off]
	}
	n, err := f.reader.ReadAt(p, f.offset+off)
	if err == nil && n < requested {
		err = io.EOF
	}
	return n, err
}

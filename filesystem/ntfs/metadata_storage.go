package ntfs

import (
	"fmt"
	"io"

	starfile "github.com/tinyrange/trex/storage/star"
)

// ntfsMFTReader exists only while packing. The immutable returned file must not
// retain this reader, its node index, or the builder and source directory.
type ntfsMFTReader struct {
	build *ntfsBuild
	nodes []*ntfsNode
}

func (r *ntfsMFTReader) Size() int64 { return r.build.mftRecords * ntfsRecordSize }
func (r *ntfsMFTReader) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("ntfs: negative MFT offset")
	}
	if len(p) == 0 {
		return 0, nil
	}
	if off >= r.Size() {
		return 0, io.EOF
	}
	requested := len(p)
	p = p[:min(int64(len(p)), r.Size()-off)]
	n := 0
	for len(p) > 0 {
		id := off / ntfsRecordSize
		within := off % ntfsRecordSize
		count := min(int64(len(p)), ntfsRecordSize-within)
		if node := r.nodes[id]; node != nil {
			record, err := r.build.mftRecord(node)
			if err != nil {
				return n, err
			}
			copy(p[:count], record[within:within+count])
		} else {
			clear(p[:count])
		}
		p = p[count:]
		off += count
		n += int(count)
	}
	if n < requested {
		return n, io.EOF
	}
	return n, nil
}
func (b *ntfsBuild) packedMFT(store *starfile.PackedFileStore) (starfile.File, error) {
	if b.mftRecords < 0 || b.mftRecords > b.size/ntfsRecordSize {
		return nil, fmt.Errorf("ntfs: MFT capacity exceeds volume")
	}
	reader := &ntfsMFTReader{build: b, nodes: make([]*ntfsNode, b.mftRecords)}
	for _, node := range b.nodes {
		if node.id >= uint64(b.mftRecords) || reader.nodes[node.id] != nil {
			return nil, fmt.Errorf("ntfs: invalid or duplicate MFT record %d", node.id)
		}
		reader.nodes[node.id] = node
	}
	return store.Snapshot("$MFT", reader, reader.Size())
}

// An initial log consists of two restart pages (NTFS 1.x) or no prefix (3.x),
// followed by 0xff fill. The logical bytes and allocation remain unchanged.
type ntfsInitialLogReader struct {
	size   int64
	prefix []byte
}

func (r *ntfsInitialLogReader) Size() int64 { return r.size }
func (r *ntfsInitialLogReader) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("ntfs: negative logfile offset")
	}
	if len(p) == 0 {
		return 0, nil
	}
	if off >= r.size {
		return 0, io.EOF
	}
	requested := len(p)
	p = p[:min(int64(len(p)), r.size-off)]
	for i := range p {
		p[i] = 0xff
	}
	if off < int64(len(r.prefix)) {
		copy(p, r.prefix[off:])
	}
	if len(p) < requested {
		return len(p), io.EOF
	}
	return len(p), nil
}

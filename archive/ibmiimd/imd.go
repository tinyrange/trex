// Package ibmiimd reads observed IBM i LID directories and the IMD1 optical
// LIC boot container.
// It preserves stored component bytes. A separate bounded reader expands the
// observed packed profile; neither reader relocates, executes or authenticates LIC.
package ibmiimd

import (
	"bytes"
	"fmt"
	"io"
	"sort"

	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
)

var magic = []byte{0xc9, 0xd4, 0xc4, 0xf1}                                  // IMD1, invariant EBCDIC.
var directoryMagic = []byte{0xd3, 0xc9, 0xc4, 0xc4, 0xc9, 0xd9, 0x40, 0x40} // LIDDIR, then spaces.
var endMagic = []byte{0xc5, 0xd5, 0xc4, 0x40}

type Entry struct {
	ID      uint32 `json:"id"`
	Sector  uint32 `json:"sector"`
	Sectors uint32 `json:"sectors"`
	Flags   uint32 `json:"flags"`
	// DeclaredAddress preserves the +16 SLS address. It is not a physical
	// extent in the enclosing optical file or installed disk.
	DeclaredAddress uint64         `json:"declared_address"`
	OpaqueTail      [8]byte        `json:"opaque_tail"`
	Offset          int64          `json:"offset"`
	StoredBytes     int64          `json:"stored_bytes"`
	Data            storage.Reader `json:"-"`
}
type Image struct {
	Entries          []Entry        `json:"entries"`
	StoredBytes      int64          `json:"stored_component_bytes"`
	Header           storage.Reader `json:"-"`
	Directory        storage.Reader `json:"-"`
	DecodingComplete bool           `json:"decoding_complete"`
}

// Open qualifies the observed 512-byte addressed directory. No payload bytes
// are copied or signatures scanned to guess components; all extents originate
// in the active directory and must be distinct, bounded and nonoverlapping.
func Open(source storage.Reader, maximumEntries int, maximumBytes int64) (*Image, error) {
	if maximumEntries < 1 || maximumBytes < 0 || source.Size() < 4160 {
		return nil, fmt.Errorf("ibmi imd: invalid size or budget")
	}
	var h [4096]byte
	if _, err := starfile.ReadFullAt(source, h[:], 0); err != nil {
		return nil, err
	}
	if !bytes.Equal(h[:4], magic) {
		return nil, fmt.Errorf("ibmi imd: unsupported header")
	}
	entries, directoryBytes, err := ReadDirectory(source, 4096, maximumEntries)
	if err != nil {
		return nil, err
	}
	image := &Image{Header: io.NewSectionReader(source, 0, 4096), Directory: io.NewSectionReader(source, 4096, directoryBytes)}
	for _, e := range entries {
		e.Offset = int64(e.Sector) * 512
		e.StoredBytes = int64(e.Sectors) * 512
		if e.Sectors == 0 || e.Offset < 4096+directoryBytes || e.Offset > source.Size() || e.StoredBytes > source.Size()-e.Offset {
			return nil, fmt.Errorf("ibmi imd: duplicate, empty or invalid component %08x", e.ID)
		}
		if e.StoredBytes > maximumBytes-image.StoredBytes {
			return nil, fmt.Errorf("ibmi imd: stored-byte budget")
		}
		image.StoredBytes += e.StoredBytes
		e.Data = io.NewSectionReader(source, e.Offset, e.StoredBytes)
		image.Entries = append(image.Entries, e)
	}
	ordered := append([]Entry(nil), image.Entries...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Offset < ordered[j].Offset })
	for i := 1; i < len(ordered); i++ {
		if ordered[i].Offset < ordered[i-1].Offset+ordered[i-1].StoredBytes {
			return nil, fmt.Errorf("ibmi imd: overlapping components")
		}
	}
	return image, nil
}

package ods2

import (
	"fmt"
	"reflect"

	"github.com/tinyrange/trex/storage"
)

type Volume struct {
	Home  *Home
	Index *File
	base  storage.File
}

// Open bootstraps INDEXF.SYS using the home block's backup index header, then
// verifies the primary index header through that map. No physical adjacency
// between the bitmap and primary file headers is assumed.
func Open(base storage.File) (*Volume, error) {
	home, err := ReadHome(base, 1)
	if err != nil {
		return nil, err
	}
	raw, err := readBlock(base, home.AlternateIndex)
	if err != nil {
		return nil, err
	}
	backup, err := DecodeHeader(raw)
	if err != nil {
		return nil, err
	}
	if backup.ID != (FileID{Number: 1, Sequence: 1}) || backup.Segment != 0 || backup.Extension != (FileID{}) {
		return nil, fmt.Errorf("ods2: unsupported index identity or extension")
	}
	index, err := MapFile(base, backup.Extents, backup.Size)
	if err != nil {
		return nil, err
	}
	v := &Volume{Home: home, Index: index, base: base}
	primary, err := v.Header(backup.ID)
	if err != nil {
		return nil, err
	}
	if primary.Segment != 0 || primary.Extension != (FileID{}) || primary.Size != backup.Size || !reflect.DeepEqual(primary.Extents, backup.Extents) {
		return nil, fmt.Errorf("ods2: primary and backup index maps differ")
	}
	return v, nil
}

// Header locates a file ID by virtual block in INDEXF.SYS and verifies both
// its reuse sequence and volume. Cross-volume file IDs are not resolved.
func (v *Volume) Header(id FileID) (*Header, error) {
	if id.Number == 0 || id.Number > v.Home.MaximumFiles || id.Volume != 0 {
		return nil, fmt.Errorf("ods2: invalid or external file ID")
	}
	block := uint64(v.Home.BitmapVBN) + uint64(v.Home.BitmapBlocks) + uint64(id.Number) - 2
	if block*BlockSize+BlockSize > uint64(v.Index.Size()) {
		return nil, fmt.Errorf("ods2: file header outside index")
	}
	raw := make([]byte, BlockSize)
	if n, err := v.Index.ReadAt(raw, int64(block)*BlockSize); n != BlockSize || err != nil {
		return nil, fmt.Errorf("ods2: reading indexed header: %v", err)
	}
	h, err := DecodeHeader(raw)
	if err != nil {
		return nil, err
	}
	if h.ID != id {
		return nil, fmt.Errorf("ods2: file identity or sequence mismatch")
	}
	return h, nil
}

// File exposes logical bytes without converting RMS record formats. Extended
// allocations are rejected until their header chains can be fully validated.
func (v *Volume) File(id FileID) (*Header, *File, error) {
	h, err := v.Header(id)
	if err != nil {
		return nil, nil, err
	}
	if h.Segment != 0 || h.Extension != (FileID{}) {
		return nil, nil, fmt.Errorf("ods2: unsupported extension header chain")
	}
	var blocks uint64
	for _, e := range h.Extents {
		blocks += uint64(e.Blocks)
	}
	if blocks != uint64(h.AllocatedBlocks) {
		return nil, nil, fmt.Errorf("ods2: allocation count differs from extents")
	}
	f, err := MapFile(v.base, h.Extents, h.Size)
	return h, f, err
}

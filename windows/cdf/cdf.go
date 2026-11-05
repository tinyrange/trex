// Package cdf reads and writes the version-one compiled data containers used by
// Windows CSI FileMaps. It does not implement FileMap ownership policy.
package cdf

import (
	"encoding/binary"
	"fmt"
)

const (
	headerSize = 84
	// MaxSize bounds allocation and traversal of untrusted containers.
	MaxSize = 64 << 20
	NoBlob  = uint32(0xffffffff)
)

// Blob holds the native eight-bit kind and uninterpreted payload. References in
// payloads are not relocated: a blob's position in Document.Blobs is its ID.
type Blob struct {
	Kind uint8
	Data []byte
}

// Document preserves all four native indexes, both root IDs, and the format GUID.
// Strings, Identities and AppIDs contain blob IDs; GUIDs contain inline GUID bytes.
// Payload interpretation (including string encoding and nested tables) is separate.
type Document struct {
	Flags                       uint32
	Format                      [16]byte
	Root, AuxiliaryRoot         uint32
	Strings, Identities, AppIDs []uint32
	GUIDs                       [][16]byte
	Blobs                       []Blob
}

// Hash computes RtlIHA8HashLBlob with the header checksum field treated as zero.
// This detects corruption; it is not a cryptographic integrity or trust check.
func Hash(data []byte) uint64 {
	var h uint64
	i := 0
	for ; i+4 <= len(data); i += 4 {
		var v uint32
		if i != 12 && i != 16 {
			v = binary.LittleEndian.Uint32(data[i : i+4])
		}
		h = h*0x1fffffff7 + uint64(v)
	}
	for ; i < len(data); i++ {
		h = h*0x1fffffff7 + uint64(data[i])
	}
	return h
}

// Parse validates framing, checksum, extent bounds, and index references before
// returning independently owned payloads. Shared/overlapping payload extents are
// legal (including empty strings); they are not assumed to be disjoint.
func Parse(data []byte) (*Document, error) {
	if len(data) < headerSize || len(data) > MaxSize {
		return nil, fmt.Errorf("CDF: invalid size %d", len(data))
	}
	u32 := func(off int) uint32 { return binary.LittleEndian.Uint32(data[off : off+4]) }
	if string(data[:4]) != "PcmH" || u32(4) != 1 {
		return nil, fmt.Errorf("CDF: unsupported magic/version")
	}
	if u32(8)&^uint32(3) != 0 {
		return nil, fmt.Errorf("CDF: unsupported flags %#x", u32(8))
	}
	if binary.LittleEndian.Uint64(data[12:20]) != Hash(data) {
		return nil, fmt.Errorf("CDF: checksum mismatch")
	}
	extent := func(count, off uint32, width uint64) ([]byte, error) {
		n := uint64(count) * width
		if uint64(off) > uint64(len(data)) || n > uint64(len(data))-uint64(off) || (count != 0 && off < headerSize) {
			return nil, fmt.Errorf("CDF: invalid index extent offset=%d count=%d width=%d", off, count, width)
		}
		return data[uint64(off) : uint64(off)+n], nil
	}
	blobIndex, err := extent(u32(20), u32(24), 8)
	if err != nil {
		return nil, err
	}
	d := &Document{Flags: u32(8), Root: u32(60), AuxiliaryRoot: u32(64)}
	copy(d.Format[:], data[68:84])
	// A malicious directory can repeat large extents. Bound expanded payload size
	// as well as input size, before any payload copies or per-blob allocation.
	var expanded uint64
	for i := 0; i < len(blobIndex); i += 8 {
		n := binary.LittleEndian.Uint32(blobIndex[i:i+4]) & 0xffffff
		off := binary.LittleEndian.Uint32(blobIndex[i+4 : i+8])
		if uint64(off) > uint64(len(data)) || uint64(n) > uint64(len(data))-uint64(off) || off < headerSize {
			return nil, fmt.Errorf("CDF: invalid blob %d extent", i/8)
		}
		expanded += uint64(n)
		if expanded > MaxSize {
			return nil, fmt.Errorf("CDF: expanded blobs exceed limit")
		}
	}
	// Each blob costs more memory than its directory entry; bound record counts
	// independently so tiny/empty blobs cannot cause disproportionate allocation.
	if len(blobIndex)/8 > 1<<20 {
		return nil, fmt.Errorf("CDF: too many blobs")
	}
	d.Blobs = make([]Blob, len(blobIndex)/8)
	for i := range d.Blobs {
		word := binary.LittleEndian.Uint32(blobIndex[8*i : 8*i+4])
		off := binary.LittleEndian.Uint32(blobIndex[8*i+4 : 8*i+8])
		d.Blobs[i] = Blob{Kind: uint8(word >> 24), Data: append([]byte{}, data[off:off+(word&0xffffff)]...)}
	}
	readIDs := func(pos int) ([]uint32, error) {
		b, e := extent(u32(pos), u32(pos+4), 4)
		if e != nil {
			return nil, e
		}
		if len(b)/4 > 1<<20 {
			return nil, fmt.Errorf("CDF: too many index entries")
		}
		ids := make([]uint32, len(b)/4)
		for i := range ids {
			ids[i] = binary.LittleEndian.Uint32(b[4*i : 4*i+4])
			if uint64(ids[i]) >= uint64(len(d.Blobs)) {
				return nil, fmt.Errorf("CDF: index at %#x references missing blob %d", pos, ids[i])
			}
		}
		return ids, nil
	}
	if d.Strings, err = readIDs(28); err != nil {
		return nil, err
	}
	if d.Identities, err = readIDs(44); err != nil {
		return nil, err
	}
	if d.AppIDs, err = readIDs(52); err != nil {
		return nil, err
	}
	guids, err := extent(u32(36), u32(40), 16)
	if err != nil {
		return nil, err
	}
	if len(guids)/16 > 1<<20 {
		return nil, fmt.Errorf("CDF: too many GUIDs")
	}
	d.GUIDs = make([][16]byte, len(guids)/16)
	for i := range d.GUIDs {
		copy(d.GUIDs[i][:], guids[16*i:16*i+16])
	}
	for _, id := range []uint32{d.Root, d.AuxiliaryRoot} {
		if id != NoBlob && uint64(id) >= uint64(len(d.Blobs)) {
			return nil, fmt.Errorf("CDF: root references missing blob %d", id)
		}
	}
	return d, nil
}

// Marshal serializes a document with stable IDs, four-byte aligned payloads,
// and a fresh checksum. It preserves opaque blob kinds and payloads, but not
// original padding, payload sharing, or physical ordering. No ownership or
// trust decision is implied by successfully writing a container.
func (d *Document) Marshal() ([]byte, error) {
	if d == nil || d.Flags&^uint32(3) != 0 {
		return nil, fmt.Errorf("CDF: invalid document or flags")
	}
	for _, n := range []int{len(d.Blobs), len(d.Strings), len(d.Identities), len(d.AppIDs), len(d.GUIDs)} {
		if n > 1<<20 {
			return nil, fmt.Errorf("CDF: too many records")
		}
	}
	for _, ids := range [][]uint32{d.Strings, d.Identities, d.AppIDs} {
		for _, id := range ids {
			if uint64(id) >= uint64(len(d.Blobs)) {
				return nil, fmt.Errorf("CDF: invalid index reference %d", id)
			}
		}
	}
	for _, id := range []uint32{d.Root, d.AuxiliaryRoot} {
		if id != NoBlob && uint64(id) >= uint64(len(d.Blobs)) {
			return nil, fmt.Errorf("CDF: invalid root %d", id)
		}
	}
	size := uint64(headerSize) + uint64(len(d.Strings)+len(d.Identities)+len(d.AppIDs))*4 + uint64(len(d.GUIDs))*16 + uint64(len(d.Blobs))*8
	for _, b := range d.Blobs {
		if len(b.Data) > 0xffffff {
			return nil, fmt.Errorf("CDF: blob exceeds 24-bit length")
		}
		size += (uint64(len(b.Data)) + 3) &^ uint64(3)
	}
	if size > MaxSize {
		return nil, fmt.Errorf("CDF: serialized size exceeds limit")
	}
	out := make([]byte, int(size))
	put := func(off int, v uint32) { binary.LittleEndian.PutUint32(out[off:off+4], v) }
	copy(out, "PcmH")
	put(4, 1)
	put(8, d.Flags)
	put(60, d.Root)
	put(64, d.AuxiliaryRoot)
	copy(out[68:84], d.Format[:])
	off := headerSize
	ids := func(pos int, values []uint32) {
		if len(values) == 0 {
			return
		}
		put(pos, uint32(len(values)))
		put(pos+4, uint32(off))
		for _, v := range values {
			put(off, v)
			off += 4
		}
	}
	ids(28, d.Strings)
	if len(d.GUIDs) != 0 {
		put(36, uint32(len(d.GUIDs)))
		put(40, uint32(off))
		for _, v := range d.GUIDs {
			copy(out[off:off+16], v[:])
			off += 16
		}
	}
	ids(44, d.Identities)
	ids(52, d.AppIDs)
	put(20, uint32(len(d.Blobs)))
	put(24, uint32(off))
	directory := off
	off += 8 * len(d.Blobs)
	for i, b := range d.Blobs {
		put(directory+i*8, uint32(b.Kind)<<24|uint32(len(b.Data)))
		put(directory+i*8+4, uint32(off))
		copy(out[off:], b.Data)
		off += (len(b.Data) + 3) &^ 3
	}
	binary.LittleEndian.PutUint64(out[12:20], Hash(out))
	return out, nil
}

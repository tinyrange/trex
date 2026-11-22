// Package powerfirmware reads the UI version 3 firmware update directory and
// its 0222 version 3 LID records. Views preserve original bytes; opaque checksum
// words are compared between the two headers, not treated as authentication.
package powerfirmware

import (
	"encoding/binary"
	"fmt"
	"io"
	"sort"

	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
)

type LID struct {
	ID           uint32         `json:"id"`
	ChecksumWord uint32         `json:"checksum_word"`
	Offset       int64          `json:"offset"`
	StoredBytes  int64          `json:"stored_bytes"`
	Header       storage.Reader `json:"-"`
	Payload      storage.Reader `json:"-"`
}

type Image struct {
	Entries   []LID          `json:"entries"`
	Header    storage.Reader `json:"-"`
	Directory storage.Reader `json:"-"`
}

// MIKeyword returns the firmware level in a version-1 marker LID (80a00001).
// The first offset selects a length-prefixed keyword. The view excludes
// padding and subsequent fields.
func MIKeyword(source storage.Reader) (storage.Reader, error) {
	var header [12]byte
	if _, err := starfile.ReadFullAt(source, header[:], 0); err != nil {
		return nil, err
	}
	be := binary.BigEndian
	offset := int64(be.Uint32(header[4:]))
	if be.Uint32(header[:]) != 1 || offset < int64(len(header)) || offset > source.Size()-4 {
		return nil, fmt.Errorf("power firmware: invalid marker version or keyword offset")
	}
	var length [4]byte
	if _, err := starfile.ReadFullAt(source, length[:], offset); err != nil {
		return nil, err
	}
	n := int64(be.Uint32(length[:]))
	if n == 0 || n > source.Size()-offset-4 {
		return nil, fmt.Errorf("power firmware: invalid MI keyword length %d", n)
	}
	return io.NewSectionReader(source, offset+4, n), nil
}

// OpenLID bounds a record using its declared header and payload lengths. It
// does not interpret flags, execute code, apply relocations or verify signatures.
func OpenLID(source storage.Reader) (LID, error) {
	var h [108]byte
	if source.Size() < int64(len(h)) {
		return LID{}, fmt.Errorf("power firmware: short LID")
	}
	if _, err := starfile.ReadFullAt(source, h[:], 0); err != nil {
		return LID{}, err
	}
	be := binary.BigEndian
	if be.Uint16(h[:]) != 0x0222 || be.Uint16(h[2:]) != 3 {
		return LID{}, fmt.Errorf("power firmware: unsupported LID header")
	}
	header, payload := int64(be.Uint32(h[24:])), int64(be.Uint32(h[20:]))
	if header < int64(len(h)) || header > source.Size() || payload != source.Size()-header {
		return LID{}, fmt.Errorf("power firmware: invalid LID extent")
	}
	return LID{ID: be.Uint32(h[4:]), ChecksumWord: be.Uint32(h[16:]), StoredBytes: source.Size(), Header: io.NewSectionReader(source, 0, header), Payload: io.NewSectionReader(source, header, payload)}, nil
}

// Open validates every active directory extent and its corresponding LID
// header before exposing borrowed payload views. Budgets bound directory work
// and aggregate stored bytes; payloads are not copied during indexing.
func Open(source storage.Reader, maximumEntries int, maximumBytes int64) (*Image, error) {
	var h [128]byte
	if source.Size() < int64(len(h)) || maximumEntries < 1 || maximumBytes < 0 {
		return nil, fmt.Errorf("power firmware: invalid size or budget")
	}
	if _, err := starfile.ReadFullAt(source, h[:], 0); err != nil {
		return nil, err
	}
	be := binary.BigEndian
	if string(h[:2]) != "UI" || be.Uint16(h[2:]) != 3 || int64(be.Uint32(h[4:])) != source.Size() {
		return nil, fmt.Errorf("power firmware: unsupported UI header or size")
	}
	off, count := int64(be.Uint16(h[12:])), int(be.Uint16(h[14:]))
	end := off + int64(count)*16
	if off < 128 || count < 1 || count > maximumEntries || end > source.Size() {
		return nil, fmt.Errorf("power firmware: invalid directory or entry budget")
	}
	table := make([]byte, count*16)
	if _, err := starfile.ReadFullAt(source, table, off); err != nil {
		return nil, err
	}
	image := &Image{Header: io.NewSectionReader(source, 0, off), Directory: io.NewSectionReader(source, off, end-off)}
	seen := make(map[uint32]bool, count)
	var total int64
	for i := 0; i < count; i++ {
		row := table[i*16:]
		id, size, at, word := be.Uint32(row), int64(be.Uint32(row[4:])), int64(be.Uint32(row[8:])), be.Uint32(row[12:])
		if seen[id] || size < 108 || at < end || at > source.Size() || size > source.Size()-at {
			return nil, fmt.Errorf("power firmware: duplicate or invalid LID %08x", id)
		}
		if size > maximumBytes-total {
			return nil, fmt.Errorf("power firmware: stored-byte budget")
		}
		total += size
		lid, err := OpenLID(io.NewSectionReader(source, at, size))
		if err != nil {
			return nil, fmt.Errorf("power firmware: LID %08x: %w", id, err)
		}
		if lid.ID != id || lid.ChecksumWord != word {
			return nil, fmt.Errorf("power firmware: directory/LID mismatch %08x", id)
		}
		lid.Offset = at
		seen[id] = true
		image.Entries = append(image.Entries, lid)
	}
	ordered := append([]LID(nil), image.Entries...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Offset < ordered[j].Offset })
	for i := 1; i < len(ordered); i++ {
		if ordered[i].Offset < ordered[i-1].Offset+ordered[i-1].StoredBytes {
			return nil, fmt.Errorf("power firmware: overlapping LIDs")
		}
	}
	return image, nil
}

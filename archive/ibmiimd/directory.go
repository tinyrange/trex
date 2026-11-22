package ibmiimd

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
)

// ReadDirectory reads the counted LIDDIR table at offset without interpreting
// entry sector numbers as physical file locations. This also serves resident
// SLS directories, whose declared addresses identify virtual storage instead.
func ReadDirectory(source storage.Reader, offset int64, maximumEntries int) ([]Entry, int64, error) {
	if source == nil || offset < 0 || offset > source.Size() || source.Size()-offset < 32 || maximumEntries < 1 {
		return nil, 0, fmt.Errorf("ibmi imd: invalid directory range or budget")
	}
	var h [32]byte
	if _, err := starfile.ReadFullAt(source, h[:], offset); err != nil {
		return nil, 0, err
	}
	word := binary.BigEndian.Uint32(h[:])
	count := int(word & 0xffffff)
	if word&0xff000000 != 0x80000000 || !bytes.Equal(h[4:12], directoryMagic) || count < 1 || count > maximumEntries {
		return nil, 0, fmt.Errorf("ibmi imd: unsupported directory or entry budget")
	}
	size := int64(32) + int64(count)*32 + 4
	if size > source.Size()-offset {
		return nil, 0, fmt.Errorf("ibmi imd: directory outside image")
	}
	table := make([]byte, count*32+4)
	if _, err := starfile.ReadFullAt(source, table, offset+32); err != nil {
		return nil, 0, err
	}
	if !bytes.Equal(table[len(table)-4:], endMagic) {
		return nil, 0, fmt.Errorf("ibmi imd: missing directory end marker")
	}
	seen := make(map[uint32]bool, count)
	entries := make([]Entry, 0, count)
	for i := 0; i < count; i++ {
		row := table[i*32 : i*32+32]
		be := binary.BigEndian
		e := Entry{ID: be.Uint32(row), Sector: be.Uint32(row[4:]), Sectors: be.Uint32(row[8:]), Flags: be.Uint32(row[12:]), DeclaredAddress: be.Uint64(row[16:])}
		copy(e.OpaqueTail[:], row[24:])
		e.StoredBytes = int64(e.Sectors) * 512
		if seen[e.ID] {
			return nil, 0, fmt.Errorf("ibmi imd: duplicate component %08x", e.ID)
		}
		seen[e.ID] = true
		entries = append(entries, e)
	}
	return entries, size, nil
}

package ibmiimd

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"sort"

	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
)

var copyMagic = []byte{0xc3, 0xd6, 0xd7, 0xe8, 0xc4, 0xc9, 0xd9, 0x40}

const copyHeaderBytes = 16384

type CopySegment struct {
	Address       uint64         `json:"saved_base"`
	CopiedAddress uint64         `json:"saved_start"`
	Span          uint32         `json:"span"`
	Flags         uint32         `json:"flags"`
	Offset        int64          `json:"file_offset"`
	StoredBytes   uint32         `json:"stored_bytes"`
	Data          storage.Reader `json:"-"`
}
type CopyLID struct {
	ID                uint32         `json:"id"`
	DiskSector        uint32         `json:"disk_sector"`
	Sectors           uint32         `json:"sectors"`
	Flags             uint32         `json:"flags"`
	SavedAddress      uint64         `json:"saved_address"`
	OpaqueTail        [8]byte        `json:"opaque_tail"`
	UnavailableReason string         `json:"unavailable_reason,omitempty"`
	Data              storage.Reader `json:"-"`
}
type CopyDirectory struct {
	DeclaredRecords uint32         `json:"declared_records"`
	ReservedRecords uint32         `json:"reserved_records"`
	CopiedBytes     int64          `json:"copied_bytes"`
	Segments        []CopySegment  `json:"segments"`
	LIDs            []CopyLID      `json:"lids"`
	Header          storage.Reader `json:"-"`
	Directory       storage.Reader `json:"-"`
	ordered         []CopySegment
}

// OpenCopyDirectory indexes the observed COPYDIR profile without allocating its
// copied memory image. Each saved segment omits its first 4096-byte page. Disk
// sector numbers in LIDDIR are NOT source-file offsets or execution addresses.
// maximumBytes=0 permits unbounded borrowed payload length, never unbounded RAM.
func OpenCopyDirectory(source storage.Reader, maximumSegments, maximumLIDs int, maximumBytes int64) (*CopyDirectory, error) {
	if maximumSegments < 1 || maximumLIDs < 1 || maximumBytes < 0 || source.Size() < copyHeaderBytes+36 {
		return nil, fmt.Errorf("ibmi copydir: invalid source or budget")
	}
	header := make([]byte, copyHeaderBytes)
	if _, err := starfile.ReadFullAt(source, header, 0); err != nil {
		return nil, err
	}
	be := binary.BigEndian
	countWord := be.Uint32(header[24:])
	count := countWord & 0xffffff
	body := int64(be.Uint32(header[28:]))
	if !bytes.Equal(header[:8], copyMagic) || countWord&0xff000000 != 0x40000000 || count == 0 || uint64(count) > uint64(maximumSegments) || uint64(count)*64 > copyHeaderBytes-192 || body != source.Size()-copyHeaderBytes || (maximumBytes > 0 && body > maximumBytes) {
		return nil, fmt.Errorf("ibmi copydir: header, extent or budget")
	}
	c := &CopyDirectory{DeclaredRecords: count, CopiedBytes: body, Header: io.NewSectionReader(source, 0, copyHeaderBytes)}
	var cursor int64
	for i := uint32(0); i < count; i++ {
		row := header[192+int(i)*64 : 192+(int(i)+1)*64]
		address := be.Uint64(row[16:])
		span := be.Uint32(row[24:])
		stored := be.Uint32(row[48:])
		pos := be.Uint64(row[40:])
		if address == 0 {
			if span != 0 || stored != 0 || pos != 0 {
				return nil, fmt.Errorf("ibmi copydir: nonempty reserved record")
			}
			c.ReservedRecords++
			continue
		}
		if span < 4096 || stored != span-4096 || uint64(span) > math.MaxUint64-address || pos != uint64(cursor) || int64(stored) > body-cursor {
			return nil, fmt.Errorf("ibmi copydir: invalid segment %d", i)
		}
		s := CopySegment{Address: address, CopiedAddress: address + 4096, Span: span, Flags: be.Uint32(row[28:]), Offset: copyHeaderBytes + cursor, StoredBytes: stored}
		s.Data = io.NewSectionReader(source, s.Offset, int64(stored))
		c.Segments = append(c.Segments, s)
		cursor += int64(stored)
	}
	if cursor != body || len(c.Segments) == 0 {
		return nil, fmt.Errorf("ibmi copydir: aggregate mismatch")
	}
	c.ordered = append([]CopySegment(nil), c.Segments...)
	sort.Slice(c.ordered, func(i, j int) bool { return c.ordered[i].Address < c.ordered[j].Address })
	for i := 1; i < len(c.ordered); i++ {
		a, b := c.ordered[i-1], c.ordered[i]
		if uint64(a.Span) > b.Address-a.Address {
			return nil, fmt.Errorf("ibmi copydir: overlapping saved segments")
		}
	}
	// The observed directory is in the first copied segment, not a carved signature.
	var d [32]byte
	if c.Segments[0].StoredBytes < 36 {
		return nil, fmt.Errorf("ibmi copydir: missing directory segment")
	}
	if _, err := starfile.ReadFullAt(c.Segments[0].Data, d[:], 0); err != nil {
		return nil, err
	}
	word := be.Uint32(d[:])
	n := word & 0xffffff
	directoryBytes := int64(32) + int64(n)*32 + 4
	if word&0xff000000 != 0x80000000 || !bytes.Equal(d[4:12], directoryMagic) || n == 0 || uint64(n) > uint64(maximumLIDs) || directoryBytes > int64(c.Segments[0].StoredBytes) {
		return nil, fmt.Errorf("ibmi copydir: invalid LID directory")
	}
	table := make([]byte, int(n)*32+4)
	if _, err := starfile.ReadFullAt(c.Segments[0].Data, table, 32); err != nil {
		return nil, err
	}
	if !bytes.Equal(table[len(table)-4:], endMagic) {
		return nil, fmt.Errorf("ibmi copydir: directory end marker")
	}
	c.Directory = io.NewSectionReader(c.Segments[0].Data, 0, directoryBytes)
	seen := make(map[uint32]bool, int(n))
	for i := 0; i < int(n); i++ {
		row := table[i*32 : (i+1)*32]
		e := CopyLID{ID: be.Uint32(row), DiskSector: be.Uint32(row[4:]), Sectors: be.Uint32(row[8:]), Flags: be.Uint32(row[12:]), SavedAddress: be.Uint64(row[16:])}
		copy(e.OpaqueTail[:], row[24:])
		if seen[e.ID] || e.Sectors == 0 {
			return nil, fmt.Errorf("ibmi copydir: duplicate or empty LID")
		}
		seen[e.ID] = true
		data, err := c.SavedAt(e.SavedAddress, int64(e.Sectors)*512)
		if err != nil {
			e.UnavailableReason = err.Error()
		} else {
			e.Data = data
		}
		c.LIDs = append(c.LIDs, e)
	}
	return c, nil
}

// SavedAt borrows only actually copied bytes. It never fills omitted pages or
// reinterprets a saved address as a linked/physical executable address.
func (c *CopyDirectory) SavedAt(address uint64, size int64) (storage.Reader, error) {
	if size < 0 || uint64(size) > math.MaxUint64-address {
		return nil, fmt.Errorf("ibmi copydir: invalid saved range")
	}
	i := sort.Search(len(c.ordered), func(i int) bool { return c.ordered[i].Address > address }) - 1
	if i < 0 {
		return nil, fmt.Errorf("ibmi copydir: unmapped saved range")
	}
	s := c.ordered[i]
	if address < s.CopiedAddress || address-s.CopiedAddress > uint64(s.StoredBytes) || uint64(size) > uint64(s.StoredBytes)-(address-s.CopiedAddress) {
		return nil, fmt.Errorf("ibmi copydir: omitted page or unmapped saved range")
	}
	return io.NewSectionReader(s.Data, int64(address-s.CopiedAddress), size), nil
}

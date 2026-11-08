package ckd

import (
	"bytes"
	"fmt"
	"slices"
)

// CMS LIBPDS libraries (MACLIB and TXTLIB) are fixed-format files of 80-byte
// records. Record 1 is the header: "LIBPDS" in EBCDIC, two reserved bytes, the
// directory length in bytes at 8, the directory's first record at 12 and two
// further words preserved uninterpreted (zero in MACLIBs; in TXTLIBs a byte
// count that is sixteen times the following count). The directory occupies
// the final records; each 16-byte entry is an 8-byte name, a 4-byte flags
// word and the 1-based record where the member begins. Several entries (for
// example TXTLIB entry points) may name one member. A member ends before the
// first following record that begins with X'61FFFF61'. Decoded from z/VM 4.4
// ADCD media.

var (
	cmsLibraryMagic     = []byte{0xd3, 0xc9, 0xc2, 0xd7, 0xc4, 0xe2} // "LIBPDS"
	cmsLibraryDelimiter = []byte{0x61, 0xff, 0xff, 0x61}
	cmsOldLibraryMagic  = []byte{0xc4, 0xd4, 0xe2, 0xd3, 0xc9, 0xc2} // "DMSLIB"
)

type CMSLibraryEntry struct {
	Name    string
	RawName []byte
	Flags   uint32
	// Record is the member's first record; Records excludes the delimiter.
	Record, Records uint32
}

type CMSLibrary struct {
	Format                          string // "LIBPDS" or "DMSLIB"
	DirectoryBytes, DirectoryRecord uint32
	Reserved                        [2]uint32
	Entries                         []CMSLibraryEntry
	data                            []byte
}

// Member returns the bytes of entry i's member (Records*80 bytes, EBCDIC).
func (l *CMSLibrary) Member(i int) []byte {
	e := l.Entries[i]
	return l.data[int(e.Record-1)*80 : int(e.Record-1+e.Records)*80]
}

// ParseCMSLibrary decodes a LIBPDS library from its fixed-format content.
func ParseCMSLibrary(data []byte, maxEntries int) (*CMSLibrary, error) {
	const lrecl = 80
	if len(data) < 2*lrecl || len(data)%lrecl != 0 {
		return nil, fmt.Errorf("cms library: content is not whole 80-byte records")
	}
	if bytes.Equal(data[:6], cmsOldLibraryMagic) {
		return parseDMSLIB(data, maxEntries)
	}
	if !bytes.Equal(data[:6], cmsLibraryMagic) {
		return nil, fmt.Errorf("cms library: unsupported header %x", data[:8])
	}
	records := uint32(len(data) / lrecl)
	l := &CMSLibrary{Format: "LIBPDS", DirectoryBytes: be.Uint32(data[8:]), DirectoryRecord: be.Uint32(data[12:]),
		Reserved: [2]uint32{be.Uint32(data[16:]), be.Uint32(data[20:])}, data: data}
	if l.DirectoryBytes == 0 || l.DirectoryBytes%16 != 0 || l.DirectoryRecord < 2 || l.DirectoryRecord > records {
		return nil, fmt.Errorf("cms library: invalid directory %d bytes at record %d", l.DirectoryBytes, l.DirectoryRecord)
	}
	if l.DirectoryRecord+(l.DirectoryBytes+lrecl-1)/lrecl-1 != records {
		return nil, fmt.Errorf("cms library: directory does not end at the final record")
	}
	n := int(l.DirectoryBytes / 16)
	if n > maxEntries {
		return nil, fmt.Errorf("cms library: %d entries exceed limit %d", n, maxEntries)
	}
	dir := data[int(l.DirectoryRecord-1)*lrecl:]
	ends := map[uint32]uint32{}
	for i := 0; i < n; i++ {
		e := dir[16*i : 16*i+16]
		start := be.Uint32(e[12:])
		if start < 2 || start >= l.DirectoryRecord {
			return nil, fmt.Errorf("cms library: entry %d starts at record %d outside members", i, start)
		}
		end, ok := ends[start]
		if !ok {
			end = start
			for end < l.DirectoryRecord && !bytes.HasPrefix(data[int(end-1)*lrecl:], cmsLibraryDelimiter) {
				end++
			}
			if end == l.DirectoryRecord {
				return nil, fmt.Errorf("cms library: member at record %d has no delimiter", start)
			}
			ends[start] = end
		}
		l.Entries = append(l.Entries, CMSLibraryEntry{Name: Identifier(e[:8]), RawName: append([]byte(nil), e[:8]...), Flags: be.Uint32(e[8:]), Record: start, Records: end - start})
	}
	return l, nil
}

// parseDMSLIB reads the older TXTLIB format: "DMSLIB", the record count
// (halfword), the directory length in bytes at 8, the number of directory
// records at 12 and the entry size (12) at 16. The directory is the final
// records: entries of an 8-byte name, a halfword start record and a halfword
// of flags. A member runs to the next member's start record; the last ends
// before the X'61FFFF61' delimiter record.
func parseDMSLIB(data []byte, maxEntries int) (*CMSLibrary, error) {
	const lrecl = 80
	records := uint32(len(data) / lrecl)
	l := &CMSLibrary{Format: "DMSLIB", DirectoryBytes: be.Uint32(data[8:]), data: data}
	dirRecords, size := be.Uint32(data[12:]), be.Uint32(data[16:])
	if uint32(be.Uint16(data[6:])) != records || size != 12 || dirRecords == 0 || dirRecords >= records ||
		l.DirectoryBytes%12 != 0 || l.DirectoryBytes > dirRecords*lrecl {
		return nil, fmt.Errorf("cms library: invalid DMSLIB header")
	}
	l.DirectoryRecord = records - dirRecords + 1
	n := int(l.DirectoryBytes / 12)
	if n > maxEntries {
		return nil, fmt.Errorf("cms library: %d entries exceed limit %d", n, maxEntries)
	}
	// The delimiter record before the directory ends the last member.
	end := l.DirectoryRecord - 1
	if !bytes.HasPrefix(data[int(end-1)*lrecl:], cmsLibraryDelimiter) {
		return nil, fmt.Errorf("cms library: DMSLIB members do not end with a delimiter")
	}
	dir := data[int(l.DirectoryRecord-1)*lrecl:]
	starts := map[uint32]bool{}
	for i := 0; i < n; i++ {
		e := dir[12*i : 12*i+12]
		start := uint32(be.Uint16(e[8:]))
		if start < 2 || start >= end {
			return nil, fmt.Errorf("cms library: entry %d starts at record %d outside members", i, start)
		}
		starts[start] = true
		l.Entries = append(l.Entries, CMSLibraryEntry{Name: Identifier(e[:8]), RawName: append([]byte(nil), e[:8]...), Flags: uint32(be.Uint16(e[10:])), Record: start})
	}
	sorted := make([]uint32, 0, len(starts))
	for s := range starts {
		sorted = append(sorted, s)
	}
	slices.Sort(sorted)
	for i := range l.Entries {
		k, _ := slices.BinarySearch(sorted, l.Entries[i].Record)
		next := end
		if k+1 < len(sorted) {
			next = sorted[k+1]
		}
		l.Entries[i].Records = next - l.Entries[i].Record
	}
	return l, nil
}

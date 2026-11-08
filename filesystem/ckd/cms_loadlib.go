package ckd

import (
	"bytes"
	"fmt"
)

// CMS LOADLIB libraries are variable-format files simulating an OS PDS of
// load modules. Record 1 is a header: "LIBPDS", the directory length in bytes
// at 8, the directory's first record at 12, a word at 16 and a second
// block ("LIBPDS" or six zero bytes) holding the directory record, a halfword,
// the directory length and the directory record size, followed by a copy of the directory's beginning truncated at
// the record end, which is ignored. The directory occupies the final records
// from the directory record on. Entries do not span directory records; each
// record's entries end at a zero name or where no complete entry fits
// (records may omit trailing zeros or carry a few bytes beyond the declared
// directory record size, so the header length is not enforced). Each entry
// is an 8-byte name, three bytes and an OS PDS indicator byte (X'80' alias,
// low five bits the user-data halfword count), the member's first record and
// the user data (OS load module attributes), padded to a multiple of 16.
// Member records are OS load module records (CESD, IDR, control and text);
// a member ends before the next record beginning X'61FFFF61'. Decoded from
// z/VM 4.4 ADCD media.

type CMSLoadEntry struct {
	Name     string
	RawName  []byte
	Alias    bool
	Record   uint32
	UserData []byte
	// Records are the member's load module records, excluding the delimiter.
	Records [][]byte
}

type CMSLoadLibrary struct {
	DirectoryBytes, DirectoryRecord uint32
	Header                          []byte
	Entries                         []CMSLoadEntry
}

// ParseCMSLoadLibrary decodes Content() of a variable-format LOADLIB.
func ParseCMSLoadLibrary(data []byte, maxEntries int) (*CMSLoadLibrary, error) {
	var records [][]byte
	for p := 0; p < len(data); {
		if p+2 > len(data) || p+2+int(be.Uint16(data[p:])) > len(data) {
			return nil, fmt.Errorf("cms loadlib: truncated record")
		}
		n := int(be.Uint16(data[p:]))
		records = append(records, data[p+2:p+2+n])
		p += 2 + n
	}
	if len(records) < 2 || len(records[0]) < 36 || !bytes.Equal(records[0][:6], cmsLibraryMagic) || !(bytes.Equal(records[0][20:26], cmsLibraryMagic) || bytes.Equal(records[0][20:26], make([]byte, 6))) {
		return nil, fmt.Errorf("cms loadlib: missing LIBPDS header")
	}
	h := records[0]
	l := &CMSLoadLibrary{DirectoryBytes: be.Uint32(h[8:]), DirectoryRecord: be.Uint32(h[12:]), Header: h[:36]}
	if l.DirectoryRecord < 2 || int(l.DirectoryRecord) > len(records) || uint32(be.Uint16(h[26:])) != l.DirectoryRecord&0xffff {
		return nil, fmt.Errorf("cms loadlib: invalid directory record %d", l.DirectoryRecord)
	}
	ends := map[uint32]uint32{}
	for _, dir := range records[l.DirectoryRecord-1:] {
		// Entries do not span directory records; a record ends at a zero name
		// or where no complete entry fits.
		for e := 0; e+16 <= len(dir); {
			if bytes.Equal(dir[e:e+8], make([]byte, 8)) {
				break
			}
			c := dir[e+11]
			user := 2 * int(c&0x1f)
			size := (16 + user + 15) &^ 15
			if e+16+user > len(dir) || !symbolName(dir[e:e+8]) {
				return nil, fmt.Errorf("cms loadlib: invalid directory entry at %d", e)
			}
			if len(l.Entries) == maxEntries {
				return nil, fmt.Errorf("cms loadlib: entries exceed limit %d", maxEntries)
			}
			x := CMSLoadEntry{Name: Identifier(dir[e : e+8]), RawName: append([]byte(nil), dir[e:e+8]...), Alias: c&0x80 != 0,
				Record: be.Uint32(dir[e+12:]), UserData: append([]byte(nil), dir[e+16:e+16+user]...)}
			if x.Record < 2 || x.Record >= l.DirectoryRecord {
				return nil, fmt.Errorf("cms loadlib: %s starts at record %d outside members", x.Name, x.Record)
			}
			end, ok := ends[x.Record]
			if !ok {
				end = x.Record
				for end < l.DirectoryRecord && !bytes.HasPrefix(records[end-1], cmsLibraryDelimiter) {
					end++
				}
				if end == l.DirectoryRecord {
					return nil, fmt.Errorf("cms loadlib: member %s has no delimiter", x.Name)
				}
				ends[x.Record] = end
			}
			x.Records = records[x.Record-1 : end-1]
			l.Entries = append(l.Entries, x)
			e += size
		}
	}
	return l, nil
}

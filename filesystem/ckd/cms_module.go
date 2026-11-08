package ckd

import (
	"bytes"
	"fmt"
)

// CMS MODULE files (GENMOD output). A variable-format module is one or more
// segments. Each segment is an 80-byte header, core-image records whose
// lengths sum exactly to end-origin, then trailer records. Header words:
// entry point 0, origin 4, end 8, second end 12; halfword 0x28 counts loader
// table entries; byte 0x2D bit X'80' marks a relocation list and bit X'40'
// selects 5-byte entries (flags, 32-bit address) over 4-byte entries (flags,
// 24-bit address).
//
// The concatenated trailer holds the loader table, then the relocation list,
// then optional records such as service history text (Extra); trailer record
// boundaries are otherwise arbitrary. Loader entries are 24 bytes (name and
// four words) or 20 bytes (name and three words). No header bit selects the
// size reliably, so the size whose names and remainder validate is used and
// ambiguity is rejected. The relocation list runs while entries carry flag
// bits within X'83' including X'01' or X'02', and addresses from the origin's
// page (they may lie below a non-aligned origin) to the image end; Extra must
// begin on a record boundary.
//
// Nothing records a trailer's length: a following segment (as in CP's CPLOAD)
// is recognised only where an 80-byte trailer record's core records sum
// exactly and the bytes before it form a valid trailer. A trailer beginning
// "IEWPLMH" carries a binder program object and is kept raw. Fixed-format
// modules are bare core images with no header. Decoded from z/VM 4.4 ADCD
// media; one module (ICKSADSF) with an older header whose records fall short
// of its span is rejected.

var cmsProgramObject = []byte{0xc9, 0xc5, 0xe6, 0xd7, 0xd3, 0xd4, 0xc8} // "IEWPLMH"

type CMSLoaderEntry struct {
	Name    string
	RawName []byte
	Words   []uint32
}

type CMSRelocation struct {
	Flags   byte
	Address uint32
}

type CMSModuleSegment struct {
	// Header is nil for fixed-format modules.
	Header                   []byte
	Entry, Origin, End, End2 uint32
	Image                    []byte
	LoaderTable              []CMSLoaderEntry
	Relocations              []CMSRelocation
	RelocationWidth          int
	RelocationData           []byte // raw relocation entries
	Extra                    []byte // trailer bytes after the loader table and relocation list
	ProgramObject            []byte // raw IEWPLMH trailer, if any
	Trailer                  []byte // concatenated trailer records
	boundaries               map[int]bool
}

type CMSModule struct{ Segments []CMSModuleSegment }

// ParseCMSModule decodes Content() of a MODULE file. variable selects the
// record format; fixed content is returned as one headerless image.
func ParseCMSModule(data []byte, variable bool, maxEntries int) (*CMSModule, error) {
	if !variable {
		return &CMSModule{Segments: []CMSModuleSegment{{Image: data}}}, nil
	}
	var records [][]byte
	for p := 0; p < len(data); {
		if p+2 > len(data) {
			return nil, fmt.Errorf("cms module: truncated record length")
		}
		n := int(be.Uint16(data[p:]))
		if p+2+n > len(data) {
			return nil, fmt.Errorf("cms module: truncated record")
		}
		records = append(records, data[p+2:p+2+n])
		p += 2 + n
	}
	// One attempt per following segment, plus headroom for rejected candidates.
	budget, attempts := maxEntries, 4*len(records)+256
	segments, err := parseSegments(records, &budget, &attempts)
	if err != nil {
		return nil, err
	}
	return &CMSModule{Segments: segments}, nil
}

// coreEnd returns the index after the core-image records of the segment whose
// header is records[0], or -1 if the records do not sum exactly.
func coreEnd(records [][]byte) int {
	h := records[0]
	if len(h) != 80 || be.Uint32(h[8:]) < be.Uint32(h[4:]) {
		return -1
	}
	need := int64(be.Uint32(h[8:]) - be.Uint32(h[4:]))
	j := 1
	for ; j < len(records) && need > 0; j++ {
		need -= int64(len(records[j]))
	}
	if need != 0 {
		return -1
	}
	return j
}

// attempts bounds candidate segment splits so crafted trailers cannot force
// exponential backtracking.
func parseSegments(records [][]byte, budget, attempts *int) ([]CMSModuleSegment, error) {
	if len(records) == 0 || len(records[0]) != 80 {
		return nil, fmt.Errorf("cms module: first record is not an 80-byte header")
	}
	j := coreEnd(records)
	if j < 0 {
		h := records[0]
		return nil, fmt.Errorf("cms module: core-image records do not span origin %x to end %x", be.Uint32(h[4:]), be.Uint32(h[8:]))
	}
	// Prefer a following segment: an 80-byte trailer record whose core
	// records sum exactly, with both halves valid. Otherwise the whole
	// remainder is this segment's trailer.
	saved := *budget
	for k := j; k < len(records); k++ {
		if len(records[k]) != 80 || coreEnd(records[k:]) < 0 {
			continue
		}
		if *attempts <= 0 {
			return nil, fmt.Errorf("cms module: too many candidate segments")
		}
		*attempts--
		first, ferr := parseSegment(records[:j], records[j:k], budget)
		if ferr != nil {
			*budget = saved
			continue
		}
		rest, rerr := parseSegments(records[k:], budget, attempts)
		if rerr != nil {
			*budget = saved
			continue
		}
		return append([]CMSModuleSegment{first}, rest...), nil
	}
	s, err := parseSegment(records[:j], records[j:], budget)
	if err != nil {
		return nil, err
	}
	return []CMSModuleSegment{s}, nil
}

func parseSegment(core, trailer [][]byte, budget *int) (CMSModuleSegment, error) {
	h := core[0]
	m := CMSModuleSegment{Header: h, Entry: be.Uint32(h), Origin: be.Uint32(h[4:]), End: be.Uint32(h[8:]), End2: be.Uint32(h[12:])}
	m.Image = bytes.Join(core[1:], nil)
	m.Trailer = bytes.Join(trailer, nil)
	m.boundaries = map[int]bool{}
	for off, i := 0, 0; i < len(trailer); i++ {
		m.boundaries[off] = true
		off += len(trailer[i])
	}
	if m.Image == nil {
		m.Image = []byte{}
	}
	if bytes.HasPrefix(m.Trailer, cmsProgramObject) {
		m.ProgramObject = m.Trailer
		return m, nil
	}
	count := int(be.Uint16(h[0x28:]))
	if count == 0 {
		return m, decodeTrailer(&m, h, 0, 0, budget)
	}
	// No header bit reliably selects the loader entry size on observed media,
	// so accept the size whose entries all carry symbol names and whose
	// remainder is a valid relocation list; both fitting is ambiguous.
	var found []CMSModuleSegment
	var lastErr error
	saved := *budget
	for _, size := range []int{24, 20} {
		trial := m
		b := saved
		if err := decodeTrailer(&trial, h, count, size, &b); err != nil {
			lastErr = err
			continue
		}
		found = append(found, trial)
		*budget = b
	}
	switch len(found) {
	case 1:
		return found[0], nil
	case 0:
		*budget = saved
		return m, lastErr
	default:
		*budget = saved
		return m, fmt.Errorf("cms module: loader entry size is ambiguous")
	}
}

// symbolName accepts an 8-byte name of printable EBCDIC (X'40'-X'FE'),
// optionally padded with zeros; compiler-generated labels use punctuation
// such as '+', ':', '>', '?' and '='. A trailing zero run is allowed, but no
// zero may precede a printable byte.
func symbolName(b []byte) bool {
	zero := false
	for _, c := range b {
		switch {
		case c == 0x00:
			zero = true
		case c >= 0x40 && c != 0xff && !zero:
		default:
			return false
		}
	}
	return true
}

func decodeTrailer(m *CMSModuleSegment, h []byte, count, entrySize int, budget *int) error {
	if count*entrySize > len(m.Trailer) {
		return fmt.Errorf("cms module: %d loader entries exceed %d trailer bytes", count, len(m.Trailer))
	}
	rest := m.Trailer[count*entrySize:]
	if h[0x2d]&0x80 == 0 {
		// No relocation list; trailing records (such as service history
		// text) are kept as Extra and must begin on a record boundary.
		if len(rest) > 0 && !m.boundaries[count*entrySize] {
			return fmt.Errorf("cms module: trailer data after the loader table begins inside a record")
		}
		m.Extra = rest
		rest = nil
	}
	width := 4
	if h[0x2d]&0x40 != 0 {
		width = 5
	}
	if rest == nil {
		width = 0
	}
	n := count
	if width > 0 {
		n += len(rest) / width
	}
	if n > *budget {
		return fmt.Errorf("cms module: loader and relocation entries exceed limit")
	}
	*budget -= n
	m.RelocationWidth = width
	m.LoaderTable = nil
	for i := 0; i < count; i++ {
		e := m.Trailer[i*entrySize : (i+1)*entrySize]
		if !symbolName(e[:8]) {
			return fmt.Errorf("cms module: loader entry %d has no symbol name", i)
		}
		words := make([]uint32, (entrySize-8)/4)
		for k := range words {
			words[k] = be.Uint32(e[8+4*k:])
		}
		m.LoaderTable = append(m.LoaderTable, CMSLoaderEntry{Name: Identifier(e[:8]), RawName: append([]byte(nil), e[:8]...), Words: words})
	}
	if width == 0 {
		return nil
	}
	// The relocation list runs while entries are valid; any further bytes
	// (such as service history text) must begin on a trailer record boundary.
	m.Relocations = make([]CMSRelocation, 0, len(rest)/width)
	i := 0
	for ; i+width <= len(rest); i += width {
		r := CMSRelocation{Flags: rest[i]}
		if width == 4 {
			r.Address = be.Uint32(rest[i:]) & 0xffffff
		} else {
			r.Address = be.Uint32(rest[i+1:])
		}
		// Addresses precede the end of the image; they may lie below a
		// non-aligned origin.
		if r.Flags&0x7c != 0 || r.Flags&0x03 == 0 || r.Address < m.Origin&^0xfff || uint64(r.Address)+4 > uint64(m.End) {
			break
		}
		m.Relocations = append(m.Relocations, r)
	}
	m.RelocationData = rest[:i]
	if i < len(rest) {
		if !m.boundaries[len(m.Trailer)-len(rest)+i] {
			return fmt.Errorf("cms module: relocation list ends inside a trailer record at %d", i)
		}
		m.Extra = rest[i:]
	}
	return nil
}

// CMSCallableLibrary is a CSLLIB: a 56-byte header record (library name,
// MM/DD/YY date, HH:MM:SS time, two 8-byte identifiers and four words kept
// uninterpreted) followed by one module segment per routine. Each segment's
// Extra holds the routine's descriptor record; the final segment's Extra also
// holds the library index.
type CMSCallableLibrary struct {
	Name, Date, Time string
	Identifiers      [2]string
	Header           []byte
	Segments         []CMSModuleSegment
}

// ParseCMSCallableLibrary decodes Content() of a variable-format CSLLIB.
func ParseCMSCallableLibrary(data []byte, maxEntries int) (*CMSCallableLibrary, error) {
	if len(data) < 58 || be.Uint16(data) != 56 {
		return nil, fmt.Errorf("cms csllib: first record is not a 56-byte header")
	}
	h := data[2:58]
	m, err := ParseCMSModule(data[58:], true, maxEntries)
	if err != nil {
		return nil, fmt.Errorf("cms csllib: %w", err)
	}
	return &CMSCallableLibrary{Name: Identifier(h[:8]), Date: cmsDigits(h[8:16]), Time: cmsDigits(h[16:24]),
		Identifiers: [2]string{Identifier(h[24:32]), Identifier(h[32:40])}, Header: h, Segments: m.Segments}, nil
}

// cmsDigits decodes EBCDIC digits and the date/time separators '/', ':' and
// '.', escaping other bytes as Identifier does.
func cmsDigits(b []byte) string {
	var out []byte
	for _, c := range b {
		switch {
		case c >= 0xf0 && c <= 0xf9:
			out = append(out, '0'+c-0xf0)
		case c == 0x61:
			out = append(out, '/')
		case c == 0x7a:
			out = append(out, ':')
		case c == 0x4b:
			out = append(out, '.')
		case c == 0x40:
			out = append(out, ' ')
		default:
			out = append(out, fmt.Sprintf("%%%02X", c)...)
		}
	}
	return string(bytes.TrimRight(out, " "))
}

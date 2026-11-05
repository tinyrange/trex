package windows

// Windows 7 and later use 24-byte mapping entries and put the index root
// in the first mapping entry, not an XP admin page. Format descriptions:
// Mandiant FLARE WMI, python-cim/cim/cim.py (MappingWin7, EntryWin7,
// LogicalIndexStore and DataPage). This reader follows only live index links;
// unreferenced/deleted pages are not interpreted as live objects.
import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"strconv"
	"strings"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

const wmiModernUnmapped = uint32(0x3fffffff)

type wmiModernEntry struct{ page, crc, free, used, first, second uint32 }
type wmiModernSection struct {
	generation, first, second, physical uint32
	entries                             []wmiModernEntry
	free                                []uint32
}
type wmiModernMapping struct {
	objects, index wmiModernSection
	clean          uint32
}

func parseWMIModernMapping(data []byte) (wmiModernMapping, error) {
	offset := 0
	section := func() (wmiModernSection, error) {
		var s wmiModernSection
		if len(data)-offset < 24 {
			return s, fmt.Errorf("wmi repository: truncated modern mapping header")
		}
		h := data[offset : offset+24]
		offset += 24
		if binary.LittleEndian.Uint32(h) != wmiMappingStart {
			return s, fmt.Errorf("wmi repository: invalid modern mapping signature")
		}
		s.generation = binary.LittleEndian.Uint32(h[4:])
		s.first = binary.LittleEndian.Uint32(h[8:])
		s.second = binary.LittleEndian.Uint32(h[12:])
		s.physical = binary.LittleEndian.Uint32(h[16:])
		count := binary.LittleEndian.Uint32(h[20:])
		if uint64(count)*24+8 > uint64(len(data)-offset) {
			return s, fmt.Errorf("wmi repository: truncated modern mapping entries")
		}
		s.entries = make([]wmiModernEntry, count)
		seen := map[uint32]bool{}
		for i := range s.entries {
			p := data[offset : offset+24]
			offset += 24
			e := wmiModernEntry{binary.LittleEndian.Uint32(p), binary.LittleEndian.Uint32(p[4:]), binary.LittleEndian.Uint32(p[8:]), binary.LittleEndian.Uint32(p[12:]), binary.LittleEndian.Uint32(p[16:]), binary.LittleEndian.Uint32(p[20:])}
			physical := e.page & wmiModernUnmapped
			if physical != wmiModernUnmapped {
				if physical >= s.physical || seen[physical] {
					return s, fmt.Errorf("wmi repository: invalid or duplicate modern physical page %d", physical)
				}
				seen[physical] = true
			}
			s.entries[i] = e
		}
		freeCount := binary.LittleEndian.Uint32(data[offset:])
		offset += 4
		if uint64(freeCount)*4+4 > uint64(len(data)-offset) {
			return s, fmt.Errorf("wmi repository: truncated modern free table")
		}
		s.free = make([]uint32, freeCount)
		for i := range s.free {
			s.free[i] = binary.LittleEndian.Uint32(data[offset:])
			offset += 4
		}
		if binary.LittleEndian.Uint32(data[offset:]) != wmiMappingEnd {
			return s, fmt.Errorf("wmi repository: invalid modern mapping footer")
		}
		offset += 4
		return s, nil
	}
	objects, err := section()
	if err != nil {
		return wmiModernMapping{}, err
	}
	index, err := section()
	if err != nil {
		return wmiModernMapping{}, err
	}
	var clean uint32
	if len(data)-offset == 4 {
		clean = binary.LittleEndian.Uint32(data[offset:])
		offset += 4
	}
	if offset != len(data) || clean > 1 {
		return wmiModernMapping{}, fmt.Errorf("wmi repository: invalid mapping trailer")
	}
	if objects.generation != index.generation {
		return wmiModernMapping{}, fmt.Errorf("wmi repository: inconsistent modern mapping generations")
	}
	return wmiModernMapping{objects: objects, index: index, clean: clean}, nil
}

func (s wmiModernSection) page(data []byte, logical uint32) ([]byte, error) {
	if uint64(logical) >= uint64(len(s.entries)) {
		return nil, fmt.Errorf("wmi repository: logical page %d outside modern map", logical)
	}
	physical := s.entries[logical].page & wmiModernUnmapped
	offset := uint64(physical) * wmiRepositoryPageSize
	if physical == wmiModernUnmapped || offset+wmiRepositoryPageSize > uint64(len(data)) {
		return nil, fmt.Errorf("wmi repository: logical page %d unmapped or truncated", logical)
	}
	page := data[offset : offset+wmiRepositoryPageSize]
	if expected := s.entries[logical].crc; expected != 0 && wmiModernPageCRC(page) != expected {
		return nil, fmt.Errorf("wmi repository: page %d checksum %#x != %#x", logical, wmiModernPageCRC(page), expected)
	}
	return page, nil
}

func parseWMIModernIndex(s wmiModernSection, data []byte) ([]wmiRepositoryIndexPage, error) {
	if len(s.entries) == 0 {
		return nil, fmt.Errorf("wmi repository: empty modern index map")
	}
	pending := []uint32{s.entries[0].used}
	seen := map[uint32]bool{}
	var pages []wmiRepositoryIndexPage
	for len(pending) > 0 {
		id := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		if seen[id] {
			return nil, fmt.Errorf("wmi repository: duplicate/cyclic index child %d", id)
		}
		seen[id] = true
		raw, err := s.page(data, id)
		if err != nil {
			return nil, err
		}
		p, err := parseWMIRepositoryIndexPage(raw)
		if err != nil {
			return nil, fmt.Errorf("wmi repository: modern index page %d: %w", id, err)
		}
		if p.id != id {
			return nil, fmt.Errorf("wmi repository: index page identity %d != %d", p.id, id)
		}
		pages = append(pages, p)
		for _, child := range p.children {
			if child != 0xffffffff {
				pending = append(pending, child)
			}
		}
	}
	return pages, nil
}

func readWMIModernRecord(s wmiModernSection, data []byte, logical, id, size uint32) (wmiRepositoryRecord, error) {
	r := wmiRepositoryRecord{logicalPage: logical, id: id}
	page, err := s.page(data, logical)
	if err != nil {
		return r, err
	}
	// The descriptor table ends with a zero entry. Its first data offset is
	// not necessarily aligned and deleted records may leave holes.
	limit := len(page)
	var offset, stored uint32
	found, terminated := false, false
	for pos := 0; pos+16 <= limit; pos += 16 {
		p := page[pos : pos+16]
		rid := binary.LittleEndian.Uint32(p)
		off := binary.LittleEndian.Uint32(p[4:])
		n := binary.LittleEndian.Uint32(p[8:])
		crc := binary.LittleEndian.Uint32(p[12:])
		if rid == 0 && off == 0 && n == 0 && crc == 0 {
			terminated = true
			break
		}
		if off < uint32(pos+32) || off >= wmiRepositoryPageSize || n == 0 {
			return r, fmt.Errorf("wmi repository: invalid modern object descriptor on page %d", logical)
		}
		limit = min(limit, int(off))
		if rid == id {
			if found {
				return r, fmt.Errorf("wmi repository: duplicate record %d on page %d", id, logical)
			}
			offset, stored, found = off, n, true
		}
	}
	if !terminated || !found || size == 0 || size > stored {
		return r, fmt.Errorf("wmi repository: missing or invalid modern record %d.%d.%d", logical, id, size)
	}
	if uint64(logical)*wmiRepositoryPageSize+uint64(offset)+uint64(stored) > uint64(len(s.entries))*wmiRepositoryPageSize {
		return r, fmt.Errorf("wmi repository: modern record exceeds logical store")
	}
	r.data = make([]byte, stored)
	for copied := uint32(0); copied < stored; {
		position := uint64(offset) + uint64(copied)
		part, err := s.page(data, logical+uint32(position/wmiRepositoryPageSize))
		if err != nil {
			return r, err
		}
		within := uint32(position % wmiRepositoryPageSize)
		amount := min(stored-copied, uint32(wmiRepositoryPageSize)-within)
		copy(r.data[copied:copied+amount], part[within:within+amount])
		copied += amount
	}
	return r, nil
}

func readWMIModernRepository(files *starlark.Dict) (*wmiRepositoryFile, error) {
	sources := starlark.StringDict{}
	var mapping wmiModernMapping
	for _, name := range []string{"MAPPING1.MAP", "MAPPING2.MAP", "MAPPING3.MAP", "OBJECTS.DATA", "INDEX.BTR"} {
		file, err := wmiRepositorySource(files, name)
		if err != nil {
			return nil, err
		}
		sources[name] = file
		if strings.HasPrefix(name, "MAPPING") {
			data, err := readWMIRepositoryFile(file, name)
			if err != nil {
				return nil, err
			}
			m, err := parseWMIModernMapping(data)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", name, err)
			}
			if m.objects.generation > mapping.objects.generation {
				mapping = m
			}
		}
	}
	objects, err := readWMIRepositoryFile(sources["OBJECTS.DATA"].(starfile.File), "OBJECTS.DATA")
	if err != nil {
		return nil, err
	}
	index, err := readWMIRepositoryFile(sources["INDEX.BTR"].(starfile.File), "INDEX.BTR")
	if err != nil {
		return nil, err
	}
	if uint64(mapping.objects.physical)*wmiRepositoryPageSize != uint64(len(objects)) || uint64(mapping.index.physical)*wmiRepositoryPageSize != uint64(len(index)) {
		return nil, fmt.Errorf("wmi repository: modern physical store size mismatch")
	}
	pages, err := parseWMIModernIndex(mapping.index, index)
	if err != nil {
		return nil, err
	}
	var records []wmiRepositoryRecord
	seen := map[[2]uint32]uint32{}
	for _, page := range pages {
		for _, key := range page.keys {
			parts := strings.Split(key, ".")
			if len(parts) == 1 {
				continue
			}
			if len(parts) != 4 {
				return nil, fmt.Errorf("wmi repository: invalid record key %q", key)
			}
			var addr [3]uint32
			for i := range addr {
				v, err := strconv.ParseUint(parts[i+1], 10, 32)
				if err != nil {
					return nil, fmt.Errorf("wmi repository: invalid record address %q", key)
				}
				addr[i] = uint32(v)
			}
			pair := [2]uint32{addr[0], addr[1]}
			if size, ok := seen[pair]; ok {
				if size != addr[2] {
					return nil, fmt.Errorf("wmi repository: inconsistent record sizes")
				}
				continue
			}
			r, err := readWMIModernRecord(mapping.objects, objects, addr[0], addr[1], addr[2])
			if err != nil {
				return nil, err
			}
			records = append(records, r)
			seen[pair] = addr[2]
		}
	}
	return &wmiRepositoryFile{modern: &mapping, records: records, pages: pages, files: sources}, nil
}

// Repdrvfs CreateCRC32 samples the first byte of each 512-byte sector with
// reflected IEEE CRC. The stored mapping value complements its result. The
// skip size is initialized to 0x200 by the modern driver; it is not a CRC of
// the complete 8-KiB page. Verified against the inbox Windows 11 repository.
func wmiModernPageCRC(page []byte) uint32 {
	var sampled [wmiRepositoryPageSize / 512]byte
	for i := range sampled {
		sampled[i] = page[i*512]
	}
	return crc32.ChecksumIEEE(sampled[:])
}

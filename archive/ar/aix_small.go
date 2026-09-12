package ar

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"
	"strconv"
	"strings"

	starfile "github.com/tinyrange/trex/storage/star"
)

// AIX small indexed ar uses linked, not necessarily contiguous members.
// Format facts: IBM AIX Files Reference, ar File Format (Small).
// https://www.ibm.com/docs/en/aix/7.2.0?topic=formats-ar-file-format-small
// Independently checked against original AIX 4.1.5 liblpp.a member chains.
func openAIXSmall(file File, maximumEntries int, maximumMetadata int64) (*arArchive, error) {
	number := func(b []byte, base int) (int64, error) {
		s := strings.Trim(string(b), " ")
		if s == "" {
			return 0, fmt.Errorf("aix ar: empty numeric field")
		}
		for _, c := range s {
			if c < '0' || c >= rune('0'+base) {
				return 0, fmt.Errorf("aix ar: invalid numeric field %q", s)
			}
		}
		n, err := strconv.ParseInt(s, base, 64)
		if err != nil {
			return 0, fmt.Errorf("aix ar: numeric overflow: %w", err)
		}
		return n, nil
	}
	read := func(off, size int64) ([]byte, error) {
		if off < 0 || size < 0 || off > file.Size() || size > file.Size()-off {
			return nil, fmt.Errorf("aix ar: range outside input")
		}
		b := make([]byte, size)
		_, err := starfile.ReadFullAt(file, b, off)
		return b, err
	}
	h, err := read(0, 68)
	if err != nil {
		return nil, err
	}
	var offsets [5]int64
	for i := range offsets {
		offsets[i], err = number(h[8+i*12:20+i*12], 10)
		if err != nil {
			return nil, err
		}
	}
	table, symbols, first, last, free := offsets[0], offsets[1], offsets[2], offsets[3], offsets[4]
	if table == 0 || (first == 0) != (last == 0) {
		return nil, fmt.Errorf("aix ar: missing table or inconsistent first/last member")
	}
	type member struct {
		entry                arRawEntry
		off, next, prev, end int64
	}
	seen := map[int64]*member{}
	remaining := maximumMetadata
	memberAt := func(off int64) (*member, error) {
		if off < 68 || off%2 != 0 {
			return nil, fmt.Errorf("aix ar: invalid member offset %d", off)
		}
		if seen[off] != nil {
			return nil, fmt.Errorf("aix ar: repeated member offset %d", off)
		}
		if len(seen) >= maximumEntries+2 {
			return nil, fmt.Errorf("aix ar: member limit")
		}
		b, err := read(off, 88)
		if err != nil {
			return nil, err
		}
		var fields [8]int64
		for i := 0; i < 7; i++ {
			base := 10
			if i == 6 {
				base = 8
			}
			fields[i], err = number(b[i*12:i*12+12], base)
			if err != nil {
				return nil, err
			}
		}
		fields[7], err = number(b[84:88], 10)
		if err != nil {
			return nil, err
		}
		n := fields[7]
		if n > 255 || 90+n > remaining {
			return nil, fmt.Errorf("aix ar: name/metadata limit")
		}
		remaining -= 90 + n
		tail, err := read(off+88, (n+1)/2*2+2)
		if err != nil {
			return nil, err
		}
		if bytes.IndexByte(tail[:n], 0) >= 0 {
			return nil, fmt.Errorf("aix ar: NUL in member name")
		}
		// IBM calls the trailer cosmetic. It is not an integrity checksum.
		data := off + 88 + int64(len(tail))
		if fields[0] > file.Size()-data {
			return nil, fmt.Errorf("aix ar: payload outside input")
		}
		m := &member{off: off, next: fields[1], prev: fields[2], end: data + fields[0], entry: arRawEntry{name: string(tail[:n]), nameOffset: -1, dataOffset: data, size: fields[0], mtime: fields[3], uid: fields[4], gid: fields[5], mode: uint64(fields[6])}}
		seen[off] = m
		return m, nil
	}
	archive := &arArchive{index: map[string][]int{}}
	active := map[int64]*member{}
	off, prev := first, int64(0)
	for off != 0 {
		if off == table || off == symbols {
			return nil, fmt.Errorf("aix ar: table reached before last member")
		}
		if len(archive.entries) >= maximumEntries {
			return nil, fmt.Errorf("aix ar: entry limit")
		}
		m, err := memberAt(off)
		if err != nil {
			return nil, err
		}
		if m.prev != prev || m.entry.name == "" {
			return nil, fmt.Errorf("aix ar: invalid previous link/name at %d", off)
		}
		active[off] = m
		archive.index[m.entry.name] = append(archive.index[m.entry.name], len(archive.entries))
		archive.entries = append(archive.entries, &arEntryFile{archive: file, entry: m.entry})
		if off == last {
			if m.next != table {
				return nil, fmt.Errorf("aix ar: last member does not link to table")
			}
			break
		}
		prev, off = off, m.next
		if off == 0 {
			return nil, fmt.Errorf("aix ar: last member unreachable")
		}
	}
	index, err := memberAt(table)
	if err != nil {
		return nil, err
	}
	if index.entry.name != "" || index.prev != last || index.next != symbols {
		return nil, fmt.Errorf("aix ar: invalid member table links/name")
	}
	metadata := func(m *member) ([]byte, error) {
		if m.entry.size > remaining {
			return nil, fmt.Errorf("aix ar: metadata limit")
		}
		remaining -= m.entry.size
		return read(m.entry.dataOffset, m.entry.size)
	}
	b, err := metadata(index)
	if err != nil {
		return nil, err
	}
	if len(b) < 12 {
		return nil, fmt.Errorf("aix ar: truncated member table")
	}
	count, err := number(b[:12], 10)
	if err != nil {
		return nil, err
	}
	if count != int64(len(active)) || count > (int64(len(b))-12)/12 {
		return nil, fmt.Errorf("aix ar: inconsistent member count")
	}
	names := b[12+count*12:]
	indexed := map[int64]bool{}
	for i := int64(0); i < count; i++ {
		at, err := number(b[12+i*12:24+i*12], 10)
		if err != nil {
			return nil, err
		}
		end := bytes.IndexByte(names, 0)
		m := active[at]
		if m == nil || indexed[at] || end < 0 || string(names[:end]) != m.entry.name {
			return nil, fmt.Errorf("aix ar: member index disagrees with chain")
		}
		indexed[at] = true
		names = names[end+1:]
	}
	if len(names) != 0 {
		return nil, fmt.Errorf("aix ar: trailing member-table bytes")
	}
	if symbols != 0 {
		sym, err := memberAt(symbols)
		if err != nil {
			return nil, err
		}
		if sym.entry.name != "" || sym.prev != table || sym.next != 0 {
			return nil, fmt.Errorf("aix ar: invalid symbol table links/name")
		}
		b, err := metadata(sym)
		if err != nil {
			return nil, err
		}
		if len(b) < 4 {
			return nil, fmt.Errorf("aix ar: truncated symbol table")
		}
		count := int64(binary.BigEndian.Uint32(b))
		if count > int64(maximumEntries) || count > (int64(len(b))-4)/4 {
			return nil, fmt.Errorf("aix ar: symbol count outside limits")
		}
		names := b[4+4*count:]
		for i := int64(0); i < count; i++ {
			at := int64(binary.BigEndian.Uint32(b[4+4*i:]))
			end := bytes.IndexByte(names, 0)
			if active[at] == nil || end <= 0 {
				return nil, fmt.Errorf("aix ar: invalid symbol reference/name")
			}
			names = names[end+1:]
		}
		if len(names) != 0 {
			return nil, fmt.Errorf("aix ar: trailing symbol-table bytes")
		}
	}
	prev = 0
	for off := free; off != 0; {
		m, err := memberAt(off)
		if err != nil {
			return nil, err
		}
		if m.prev != prev {
			return nil, fmt.Errorf("aix ar: broken free-list link")
		}
		prev, off = off, m.next
	}
	spans := make([]*member, 0, len(seen))
	for _, m := range seen {
		spans = append(spans, m)
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].off < spans[j].off })
	for i := 1; i < len(spans); i++ {
		if spans[i].off < spans[i-1].end {
			return nil, fmt.Errorf("aix ar: overlapping members")
		}
	}
	return archive, nil
}

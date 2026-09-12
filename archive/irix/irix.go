// Package irix reads IRIX inst IDB indexes and indexed software images. It
// exposes original files and attributes, not installation choices or actions.
package irix

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/tinyrange/trex/archive/compressed"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

type Item struct {
	Kind, Owner, Group, Path, Source string
	Mode                             uint32
	Attributes                       []string
}

// words preserves whitespace within attribute parentheses and quoted strings.
// Backslashes quote the following character. Unbalanced input is rejected.
func words(line string) ([]string, error) {
	var result []string
	var current strings.Builder
	depth := 0
	var quote byte
	for i := 0; i < len(line); i++ {
		c := line[i]
		if c == '\\' {
			if i+1 == len(line) {
				return nil, fmt.Errorf("dangling escape")
			}
			i++
			current.WriteByte(line[i])
			continue
		}
		if quote != 0 {
			if c == quote {
				quote = 0
			} else {
				current.WriteByte(c)
			}
			continue
		}
		if c == '\'' || c == '"' {
			quote = c
			continue
		}
		if c == '(' {
			depth++
		}
		if c == ')' {
			depth--
			if depth < 0 {
				return nil, fmt.Errorf("unbalanced attribute")
			}
		}
		if (c == ' ' || c == '\t' || c == '\r') && depth == 0 {
			if current.Len() > 0 {
				result = append(result, current.String())
				current.Reset()
			}
			continue
		}
		current.WriteByte(c)
	}
	if depth != 0 || quote != 0 {
		return nil, fmt.Errorf("unterminated attribute or string")
	}
	if current.Len() > 0 {
		result = append(result, current.String())
	}
	return result, nil
}

func ReadIDB(file starfile.File, maximum int) ([]Item, error) {
	if maximum <= 0 || file.Size() > 64<<20 {
		return nil, fmt.Errorf("irix idb: invalid entry limit or oversized index")
	}
	data, err := starfile.ReadAll(file)
	if err != nil {
		return nil, err
	}
	// Tape distributions round indexes to complete blocks. NUL terminates
	// the text only when every remaining byte is padding, never hidden data.
	if end := bytes.IndexByte(data, 0); end >= 0 {
		if file.Size()%512 != 0 || !allZero(data[end:]) {
			return nil, fmt.Errorf("irix idb: invalid tape padding")
		}
		data = data[:end]
	}
	scan := bufio.NewScanner(bytes.NewReader(data))
	scan.Buffer(make([]byte, 4096), 1<<20)
	var items []Item
	line := 0
	for scan.Scan() {
		line++
		text := strings.TrimSpace(scan.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		tokens, err := words(text)
		if err != nil {
			return nil, fmt.Errorf("irix idb line %d: %w", line, err)
		}
		if len(tokens) < 6 || len(tokens[0]) != 1 {
			return nil, fmt.Errorf("irix idb line %d: missing fields", line)
		}
		mode, err := strconv.ParseUint(tokens[1], 8, 16)
		if err != nil {
			return nil, fmt.Errorf("irix idb line %d mode: %w", line, err)
		}
		if len(items) >= maximum {
			return nil, fmt.Errorf("irix idb: entry limit exceeded")
		}
		items = append(items, Item{Kind: tokens[0], Mode: uint32(mode), Owner: tokens[2], Group: tokens[3], Path: tokens[4], Source: tokens[5], Attributes: tokens[6:]})
	}
	if err := scan.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

func allZero(data []byte) bool {
	for _, b := range data {
		if b != 0 {
			return false
		}
	}
	return true
}

func checkPadding(file starfile.File, offset int64) error {
	if file.Size()%512 != 0 {
		return fmt.Errorf("irix: trailer is not block-aligned tape padding")
	}
	var buffer [32768]byte
	for offset < file.Size() {
		n := min(int64(len(buffer)), file.Size()-offset)
		if _, err := starfile.ReadFullAt(file, buffer[:n], offset); err != nil {
			return err
		}
		if !allZero(buffer[:n]) {
			return fmt.Errorf("irix: nonzero data after final indexed record at %d", offset)
		}
		offset += n
	}
	return nil
}

func (item Item) number(name string) (int64, bool, error) {
	var result int64
	found := false
	for _, a := range item.Attributes {
		if strings.HasPrefix(a, name+"(") && strings.HasSuffix(a, ")") {
			if found {
				return 0, false, fmt.Errorf("duplicate %s attribute for %s", name, item.Path)
			}
			n, err := strconv.ParseInt(a[len(name)+1:len(a)-1], 10, 64)
			if err != nil || n < 0 {
				return 0, false, fmt.Errorf("invalid %s attribute for %s", name, item.Path)
			}
			result = n
			found = true
		}
	}
	return result, found, nil
}

type Entry struct {
	Item
	Offset, StoredSize, DecodedSize int64
	stored                          starfile.File
	compressed                      bool
	checksum                        int64
	once                            sync.Once
	decoded                         starfile.File
	err                             error
}

func (e *Entry) prepare() {
	e.once.Do(func() {
		e.decoded = e.stored
		if e.compressed {
			e.decoded, e.err = compressed.Open(e.stored, "compress", max(e.DecodedSize, 1))
			if e.err != nil {
				return
			}
		}
		if e.decoded.Size() != e.DecodedSize {
			e.err = fmt.Errorf("irix: %s decoded size %d, expected %d", e.Path, e.decoded.Size(), e.DecodedSize)
			return
		}
		if e.checksum >= 0 {
			var sum uint16
			var buffer [32768]byte
			for off := int64(0); off < e.DecodedSize; {
				count := min(int64(len(buffer)), e.DecodedSize-off)
				if _, e.err = starfile.ReadFullAt(e.decoded, buffer[:count], off); e.err != nil {
					return
				}
				for _, b := range buffer[:count] {
					sum = (sum>>1 | sum<<15) + uint16(b)
				}
				off += count
			}
			if int64(sum) != e.checksum {
				e.err = fmt.Errorf("irix: %s checksum %d, expected %d", e.Path, sum, e.checksum)
			}
		}
	})
}
func (e *Entry) ReadAt(p []byte, off int64) (int, error) {
	e.prepare()
	if e.err != nil {
		return 0, e.err
	}
	return e.decoded.ReadAt(p, off)
}
func (*Entry) WriteAt([]byte, int64) (int, error) { return 0, fmt.Errorf("irix entry is read-only") }
func (e *Entry) Size() int64                      { return e.DecodedSize }
func (e *Entry) String() string                   { return fmt.Sprintf("<irix file %q size=%d>", e.Path, e.DecodedSize) }
func (*Entry) Type() string                       { return "file" }
func (*Entry) Freeze()                            {}
func (*Entry) Truth() starlark.Bool               { return true }
func (*Entry) Hash() (uint32, error)              { return 0, fmt.Errorf("unhashable: file") }
func (e *Entry) Attr(name string) (starlark.Value, error) {
	switch name {
	case "path":
		return starlark.String(e.Path), nil
	case "entry_type":
		return starlark.String("file"), nil
	case "stored_size":
		return starlark.MakeInt64(e.StoredSize), nil
	case "offset":
		return starlark.MakeInt64(e.Offset), nil
	case "mode":
		return starlark.MakeUint(uint(e.Mode)), nil
	case "owner":
		return starlark.String(e.Owner), nil
	case "group":
		return starlark.String(e.Group), nil
	case "source":
		return starlark.String(e.Source), nil
	case "attributes":
		values := make([]starlark.Value, len(e.Attributes))
		for i, value := range e.Attributes {
			values[i] = starlark.String(value)
		}
		return starlark.NewList(values), nil
	}
	return starfile.Attr(e, name), nil
}
func (*Entry) AttrNames() []string {
	return append(starfile.AttrNames(), "path", "entry_type", "stored_size", "offset", "mode", "owner", "group", "source", "attributes")
}

// OpenImage selects records belonging to imageName (for example "4Dwm.sw"),
// checks every indexed pathname and byte range, and rejects unindexed gaps or
// trailers. File reads validate decoded sizes and the IDB's BSD sum checksum.
func OpenImage(file starfile.File, items []Item, imageName string) ([]*Entry, error) {
	var header [13]byte
	if _, err := starfile.ReadFullAt(file, header[:min(file.Size(), int64(len(header)))], 0); err != nil {
		return nil, err
	}
	if imageName == "" {
		return nil, fmt.Errorf("irix: empty image name")
	}
	start := int64(0)
	if string(header[:5]) == "im001" {
		if file.Size() < 13 || header[5] != 'V' || header[9] != 'P' || header[12] != 0 {
			return nil, fmt.Errorf("irix: invalid image version header")
		}
		for _, i := range []int{6, 7, 8, 10, 11} {
			if header[i] < '0' || header[i] > '9' {
				return nil, fmt.Errorf("irix: invalid image version digits")
			}
		}
		start = 13
	}
	var entries []*Entry
	for _, item := range items {
		selected := false
		for _, a := range item.Attributes {
			if a == imageName || strings.HasPrefix(a, imageName+".") {
				selected = true
			}
		}
		if !selected || item.Kind != "f" {
			continue
		}
		offset, hasOffset, err := item.number("off")
		if err != nil {
			return nil, err
		}
		size, hasSize, err := item.number("size")
		if err != nil {
			return nil, err
		}
		if !hasSize {
			return nil, fmt.Errorf("irix: missing size for %s", item.Path)
		}
		if !hasOffset {
			// V620 indexes supply fingerprints but omit off(). The image's
			// sequential pathname records remain authoritative for location.
			offset = -1
		}
		stored, encoded, err := item.number("cmpsize")
		if err != nil {
			return nil, err
		}
		// inst uses cmpsize(0) for an uncompressed stored file, notably
		// payloads already compressed with UNIX pack.
		encoded = encoded && stored != 0
		if !encoded {
			stored = size
		}
		sum, hasSum, err := item.number("sum")
		if err != nil {
			return nil, err
		}
		if !hasSum {
			sum = -1
		}
		if sum > 65535 {
			return nil, fmt.Errorf("irix: invalid checksum")
		}
		if hasOffset && (offset < start || offset > file.Size()-2) {
			return nil, fmt.Errorf("irix: invalid offset for %s", item.Path)
		}
		entries = append(entries, &Entry{Item: item, Offset: offset, StoredSize: stored, DecodedSize: size, compressed: encoded, checksum: sum})
	}
	remaining := make(map[string][]*Entry, len(entries))
	for _, e := range entries {
		remaining[e.Path] = append(remaining[e.Path], e)
	}
	var ordered []*Entry
	for offset := start; offset < file.Size(); {
		if len(remaining) == 0 && len(ordered) != 0 {
			if err := checkPadding(file, offset); err != nil {
				return nil, err
			}
			break
		}
		var length [2]byte
		if _, err := starfile.ReadFullAt(file, length[:], offset); err != nil {
			return nil, err
		}
		n := int64(binary.BigEndian.Uint16(length[:]))
		if n == 0 || n > file.Size()-offset-2 {
			return nil, fmt.Errorf("irix: record outside image at %d", offset)
		}
		name := make([]byte, n)
		if _, err := starfile.ReadFullAt(file, name, offset+2); err != nil {
			return nil, err
		}
		candidates := remaining[string(name)]
		if len(candidates) == 0 {
			return nil, fmt.Errorf("irix: unindexed image pathname %q at %d", name, offset)
		}
		selected := -1
		for i, candidate := range candidates {
			if candidate.Offset == offset {
				if selected >= 0 {
					return nil, fmt.Errorf("irix: ambiguous index records for %q at %d", name, offset)
				}
				selected = i
			}
		}
		if selected < 0 {
			// Older tape indexes have no offsets. Repeated pathname records
			// follow their IDB occurrence order, including identical bytes for
			// different machine attributes. Preserve every occurrence; the
			// normal size/checksum validation still applies to each read.
			for i, candidate := range candidates {
				if candidate.Offset < 0 {
					selected = i
					break
				}
			}
		}
		if selected < 0 {
			return nil, fmt.Errorf("irix: no indexed offset matches %q at %d", name, offset)
		}
		e := candidates[selected]
		if e.Offset >= 0 && e.Offset != offset {
			return nil, fmt.Errorf("irix: indexed offset for %s is %d, image record is at %d", name, e.Offset, offset)
		}
		if e.StoredSize > file.Size()-offset-2-n {
			return nil, fmt.Errorf("irix: record data outside image for %s", name)
		}
		e.Offset = offset
		e.stored = &starfile.Slice{Name: e.Path, Base: file, Offset: offset + 2 + n, Length: e.StoredSize}
		// Generic readers do not call ReadAt on a zero-length file. Validate
		// empty declarations now so neither a bad checksum nor compressed
		// bytes decoding to nonempty content can bypass prepare.
		if e.DecodedSize == 0 {
			e.prepare()
			if e.err != nil {
				return nil, e.err
			}
		}
		ordered = append(ordered, e)
		candidates = append(candidates[:selected], candidates[selected+1:]...)
		if len(candidates) == 0 {
			delete(remaining, e.Path)
		} else {
			remaining[e.Path] = candidates
		}
		offset += 2 + n + e.StoredSize
	}
	if len(remaining) != 0 {
		return nil, fmt.Errorf("irix: %d indexed files missing from image", len(remaining))
	}
	return ordered, nil
}

func ImageBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var image, index starlark.Value
	var name string
	maximum := 1000000
	if err := starlark.UnpackArgs("irix_image", args, kwargs, "file", &image, "idb", &index, "image_name", &name, "maximum_entries?", &maximum); err != nil {
		return nil, err
	}
	f, ok := image.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("irix: expected image file")
	}
	idb, ok := index.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("irix: expected IDB file")
	}
	items, err := ReadIDB(idb, maximum)
	if err != nil {
		return nil, err
	}
	entries, err := OpenImage(f, items, name)
	if err != nil {
		return nil, err
	}
	values := make([]starlark.Value, len(entries))
	for i, e := range entries {
		values[i] = e
	}
	return starfile.NewRecord(starlark.StringDict{"entries": starlark.NewList(values)}), nil
}

// IDBBuiltin exposes parsed metadata separately from software-image payloads.
// This includes non-file records and logical subsystem names needed to inspect
// renamed overlay media without guessing from its physical filenames.
func IDBBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	maximum := 1000000
	if err := starlark.UnpackArgs("irix_idb", args, kwargs, "file", &value, "maximum_entries?", &maximum); err != nil {
		return nil, err
	}
	file, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("irix idb: expected file")
	}
	items, err := ReadIDB(file, maximum)
	if err != nil {
		return nil, err
	}
	values := make([]starlark.Value, len(items))
	for i, item := range items {
		attributes := make([]starlark.Value, len(item.Attributes))
		for j, a := range item.Attributes {
			attributes[j] = starlark.String(a)
		}
		values[i] = starfile.NewRecord(starlark.StringDict{
			"kind": starlark.String(item.Kind), "path": starlark.String(item.Path), "source": starlark.String(item.Source),
			"mode": starlark.MakeUint(uint(item.Mode)), "owner": starlark.String(item.Owner), "group": starlark.String(item.Group),
			"attributes": starlark.NewList(attributes),
		})
	}
	return starfile.NewRecord(starlark.StringDict{"items": starlark.NewList(values)}), nil
}

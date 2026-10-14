// Package applearchive indexes AA01 Apple Archive records without extraction.
// It supports the scalar, path, timestamp and blob field encodings observed
// in Apple's restore metadata archives. Unknown encodings fail explicitly.
package applearchive

import (
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"github.com/tinyrange/trex/storage"
)

type Timestamp struct {
	Seconds     int64
	Nanoseconds uint32
}
type Entry struct {
	Path, Kind string
	Fields     map[string]any
	Data       storage.Reader
}

func Read(source storage.Reader, maximum int) ([]Entry, error) {
	if source == nil || maximum <= 0 {
		return nil, fmt.Errorf("apple_archive: invalid source or entry bound")
	}
	entries := []Entry{}
	for off := int64(0); off < source.Size(); {
		if len(entries) == maximum || source.Size()-off < 6 {
			return nil, fmt.Errorf("apple_archive: truncated or excessive records")
		}
		var prefix [6]byte
		if _, err := source.ReadAt(prefix[:], off); err != nil {
			return nil, err
		}
		size := int(binary.LittleEndian.Uint16(prefix[4:]))
		if string(prefix[:4]) != "AA01" || size < 6 || int64(size) > source.Size()-off {
			return nil, fmt.Errorf("apple_archive: invalid record header")
		}
		h := make([]byte, size)
		if _, err := source.ReadAt(h, off); err != nil {
			return nil, err
		}
		e := Entry{Fields: map[string]any{}}
		blobOff := off + int64(size)
		for pos := 6; pos < size; {
			if size-pos < 4 {
				return nil, fmt.Errorf("apple_archive: truncated field")
			}
			key, kind := string(h[pos:pos+3]), h[pos+3]
			pos += 4
			if _, exists := e.Fields[key]; exists {
				return nil, fmt.Errorf("apple_archive: duplicate field %q", key)
			}
			var width int
			switch kind {
			case '1':
				width = 1
			case '2', 'A':
				width = 2
			case '4', 'B':
				width = 4
			case '8':
				width = 8
			case 'P':
				width = 2
			case 'T':
				width = 12
			default:
				return nil, fmt.Errorf("apple_archive: unsupported field %q encoding %q", key, kind)
			}
			if width > size-pos {
				return nil, fmt.Errorf("apple_archive: truncated field %q", key)
			}
			b := h[pos : pos+width]
			pos += width
			switch kind {
			case 'P':
				n := int(binary.LittleEndian.Uint16(b))
				if n > size-pos || strings.ContainsRune(string(h[pos:pos+n]), 0) {
					return nil, fmt.Errorf("apple_archive: invalid path field")
				}
				e.Fields[key] = string(h[pos : pos+n])
				pos += n
			case 'T':
				ns := binary.LittleEndian.Uint32(b[8:])
				if ns >= 1000000000 {
					return nil, fmt.Errorf("apple_archive: invalid timestamp")
				}
				e.Fields[key] = Timestamp{int64(binary.LittleEndian.Uint64(b)), ns}
			case 'A', 'B':
				var n int64
				if kind == 'A' {
					n = int64(binary.LittleEndian.Uint16(b))
				} else {
					n = int64(binary.LittleEndian.Uint32(b))
				}
				if n > source.Size()-blobOff {
					return nil, fmt.Errorf("apple_archive: truncated blob")
				}
				e.Fields[key] = io.NewSectionReader(source, blobOff, n)
				blobOff += n
			default:
				var n uint64
				for i, v := range b {
					n |= uint64(v) << uint(8*i)
				}
				e.Fields[key] = n
			}
		}
		path, hasPath := e.Fields["PAT"].(string)
		typ, hasType := e.Fields["TYP"].(uint64)
		if !hasPath || !hasType {
			return nil, fmt.Errorf("apple_archive: record lacks path/type")
		}
		e.Path = path
		switch typ {
		case 'D':
			e.Kind = "directory"
		case 'F':
			e.Kind = "file"
		case 'L':
			e.Kind = "symlink"
		default:
			return nil, fmt.Errorf("apple_archive: unsupported entry type %d", typ)
		}
		e.Data, _ = e.Fields["DAT"].(storage.Reader)
		entries = append(entries, e)
		off = blobOff
	}
	return entries, nil
}

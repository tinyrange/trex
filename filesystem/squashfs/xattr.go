package squashfs

import (
	"fmt"
	"strings"

	"github.com/tinyrange/trex/auto"
)

func (s *image) initXattrs(offset uint64) error {
	if offset == ^uint64(0) {
		return nil
	}
	header, err := s.read(offset, 16)
	if err != nil {
		return err
	}
	s.xattrStart = le.Uint64(header)
	s.xattrCount = le.Uint32(header[8:])
	s.xattrIndex = offset + 16
	pointers := ((uint64(s.xattrCount)*16 + 8191) / 8192) * 8
	if s.xattrCount == 0 || s.xattrStart < 96 || s.xattrStart >= offset || pointers > s.used-s.xattrIndex {
		return fmt.Errorf("squashfs: invalid extended attribute index")
	}
	return nil
}

func (s *image) xattrCursor(ref uint64) (cursor, error) {
	if ref>>16 >= s.xattrIndex-s.xattrStart {
		return cursor{}, fmt.Errorf("squashfs: extended attribute reference outside table")
	}
	return cursor{s: s, off: s.xattrStart + (ref >> 16), at: int(ref & 0xffff)}, nil
}

func (s *image) readXattrs(id uint32) (map[string][]byte, error) {
	if cached, ok := s.xattrs.Load(id); ok {
		return cached.(map[string][]byte), nil
	}
	if id >= s.xattrCount {
		return nil, fmt.Errorf("squashfs: invalid extended attribute ID")
	}
	record, err := s.table(s.xattrIndex, id, 16)
	if err != nil {
		return nil, err
	}
	count := le.Uint32(record[8:])
	if count == 0 || count > 4096 {
		return nil, auto.ErrLimit
	}
	data, err := s.xattrCursor(le.Uint64(record))
	if err != nil {
		return nil, err
	}
	prefixes := []string{"user.", "trusted.", "security."}
	attrs := make(map[string][]byte, count)
	total := 0
	for range count {
		entry, err := data.take(4)
		if err != nil {
			return nil, err
		}
		typ, size := le.Uint16(entry), int(le.Uint16(entry[2:]))
		prefix := int(typ & 0xff)
		if size == 0 || size > 255 || prefix >= len(prefixes) || typ&^uint16(0x1ff) != 0 {
			return nil, fmt.Errorf("squashfs: invalid extended attribute name type or size")
		}
		name, err := data.take(size)
		if err != nil {
			return nil, err
		}
		key := prefixes[prefix] + string(name)
		if _, exists := attrs[key]; exists || strings.IndexByte(key, 0) >= 0 {
			return nil, fmt.Errorf("squashfs: duplicate or invalid extended attribute %q", key)
		}
		length, err := data.take(4)
		if err != nil {
			return nil, err
		}
		valueSize := int(le.Uint32(length))
		source := &data
		if typ&0x100 != 0 {
			if valueSize != 8 {
				return nil, fmt.Errorf("squashfs: invalid extended attribute reference size")
			}
			ref, err := data.take(8)
			if err != nil {
				return nil, err
			}
			deref, err := s.xattrCursor(le.Uint64(ref))
			if err != nil {
				return nil, err
			}
			actual, err := deref.take(4)
			if err != nil {
				return nil, err
			}
			valueSize = int(le.Uint32(actual))
			source = &deref
		}
		if valueSize > 65536 || total+valueSize > 1<<20 {
			return nil, auto.ErrLimit
		}
		value, err := source.take(valueSize)
		if err != nil {
			return nil, err
		}
		total += valueSize
		attrs[key] = value
	}
	s.xattrs.Store(id, attrs)
	return attrs, nil
}

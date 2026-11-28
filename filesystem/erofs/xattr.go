package erofs

import (
	"fmt"
	"strings"
)

var xattrPrefixes = map[byte]string{
	1: "user.", 2: "system.posix_acl_access", 3: "system.posix_acl_default",
	4: "trusted.", 5: "lustre.", 6: "security.",
}

type xattr struct {
	name  string
	value []byte
}

func (n *inode) readXattrs() (map[string][]byte, error) {
	if n.xattrs == 0 {
		return nil, nil
	}
	size := uint64(12) + uint64(n.xattrs-1)*4
	body, err := n.fs.read(n.tail-size, size)
	if err != nil {
		return nil, err
	}
	shared := int(body[4])
	first := 12 + shared*4
	if first > len(body) {
		return nil, fmt.Errorf("invalid shared xattr count")
	}
	result := make(map[string][]byte, shared)
	for pos := 12; pos < first; pos += 4 {
		id := le.Uint32(body[pos:])
		entry, err := n.fs.readSharedXattr(id)
		if err != nil {
			return nil, err
		}
		if _, duplicate := result[entry.name]; duplicate {
			return nil, fmt.Errorf("duplicate extended attribute %q", entry.name)
		}
		result[entry.name] = entry.value
	}
	for pos := first; pos < len(body); {
		entry, consumed, err := decodeXattr(body[pos:])
		if err != nil {
			return nil, err
		}
		if _, duplicate := result[entry.name]; duplicate {
			return nil, fmt.Errorf("duplicate extended attribute %q", entry.name)
		}
		result[entry.name] = entry.value
		pos += consumed
	}
	return result, nil
}

func (s *image) readSharedXattr(id uint32) (xattr, error) {
	if value, ok := s.xattrs.Load(id); ok {
		return value.(xattr), nil
	}
	if s.sharedXattr == 0 {
		return xattr{}, fmt.Errorf("missing shared extended attribute area")
	}
	offset := s.sharedXattr + uint64(id)*4
	header, err := s.read(offset, 4)
	if err != nil {
		return xattr{}, err
	}
	length := (4 + uint64(header[0]) + uint64(le.Uint16(header[2:])) + 3) &^ 3
	data, err := s.read(offset, length)
	if err != nil {
		return xattr{}, err
	}
	attr, _, err := decodeXattr(data)
	if err == nil {
		s.xattrs.Store(id, attr)
	}
	return attr, err
}

func decodeXattr(data []byte) (xattr, int, error) {
	if len(data) < 4 {
		return xattr{}, 0, fmt.Errorf("truncated extended attribute")
	}
	nameSize := int(data[0])
	valueSize := int(le.Uint16(data[2:]))
	used := (4 + nameSize + valueSize + 3) &^ 3
	prefix := xattrPrefixes[data[1]]
	if used > len(data) || prefix == "" || strings.HasSuffix(prefix, ".") != (nameSize != 0) {
		return xattr{}, 0, fmt.Errorf("invalid extended attribute")
	}
	name := string(data[4 : 4+nameSize])
	if strings.IndexByte(name, 0) >= 0 {
		return xattr{}, 0, fmt.Errorf("invalid extended attribute name")
	}
	start := 4 + nameSize
	return xattr{prefix + name, data[start : start+valueSize]}, used, nil
}

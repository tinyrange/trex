package ext4

import (
	"fmt"
	"math/bits"
	"slices"
	"strings"
)

const xattrMagic = 0xea020000

var xattrPrefixes = map[uint8]string{
	1: "user.", 2: "system.posix_acl_access", 3: "system.posix_acl_default",
	4: "trusted.", 6: "security.", 7: "system.", 8: "system.richacl", 9: "gnu.",
}

type xattrEntry struct {
	index uint8
	name  string
	value []byte
}

func xattrName(name string) (uint8, string) {
	switch name {
	case "system.posix_acl_access":
		return 2, ""
	case "system.posix_acl_default":
		return 3, ""
	case "system.richacl":
		return 8, ""
	}
	for index, prefix := range xattrPrefixes {
		if !strings.HasSuffix(prefix, ".") {
			continue
		}
		if rest, ok := strings.CutPrefix(name, prefix); ok && rest != "" {
			return index, rest
		}
	}
	return 0, ""
}

func (v *Volume) readXattrs(node *inode) (map[string][]byte, error) {
	block := uint64(u32(node.raw, 104))
	if v.incompat&0x80 != 0 {
		block |= uint64(u16(node.raw, 118)) << 32
	}
	var attrs map[string][]byte
	if block != 0 {
		data, err := v.readBlock(block)
		if err != nil {
			return nil, err
		}
		if u32(data, 0) != xattrMagic || u32(data, 4) == 0 || u32(data, 8) != 1 {
			return nil, fmt.Errorf("ext4: invalid extended attribute block")
		}
		if v.ro&0x400 != 0 {
			var address [8]byte
			le.PutUint64(address[:], block)
			want := u32(data, 16)
			put32(data, 16, 0)
			if rawCRC(rawCRC(v.seed, address[:]), data) != want {
				return nil, fmt.Errorf("ext4: extended attribute checksum mismatch")
			}
		}
		attrs = make(map[string][]byte)
		if err := parseXattrs(attrs, data, 32, 0); err != nil {
			return nil, err
		}
	}
	if len(node.raw) > 131 {
		header := 128 + int(u16(node.raw, 128))
		if header <= len(node.raw)-8 && u32(node.raw, header) == xattrMagic {
			if attrs == nil {
				attrs = make(map[string][]byte)
			}
			first := header + 4
			if err := parseXattrs(attrs, node.raw, first, first); err != nil {
				return nil, err
			}
		}
	}
	return attrs, nil
}

func parseXattrs(attrs map[string][]byte, data []byte, first, valueOrigin int) error {
	valueFloor := len(data)
	for offset := first; offset+4 <= valueFloor; {
		if u32(data, offset) == 0 {
			return nil
		}
		length := int(data[offset])
		next := offset + 16 + ((length + 3) &^ 3)
		if next+4 > valueFloor {
			break
		}
		prefix := xattrPrefixes[data[offset+1]]
		suffix := string(data[offset+16 : offset+16+length])
		if prefix == "" || strings.IndexByte(suffix, 0) >= 0 || (length != 0) != strings.HasSuffix(prefix, ".") {
			return fmt.Errorf("ext4: invalid extended attribute name")
		}
		key := prefix + suffix
		if _, duplicate := attrs[key]; duplicate {
			return fmt.Errorf("ext4: duplicate extended attribute %q", key)
		}
		if u32(data, offset+4) != 0 {
			return fmt.Errorf("ext4: external value inode for extended attribute %q is unsupported", key)
		}
		size := int(u32(data, offset+8))
		attrs[key] = []byte{}
		if size != 0 {
			at := valueOrigin + int(u16(data, offset+2))
			if at < next+4 || at > len(data) || size > len(data)-at {
				return fmt.Errorf("ext4: extended attribute %q value outside block", key)
			}
			valueFloor = min(valueFloor, at)
			attrs[key] = slices.Clone(data[at : at+size])
		}
		offset = next
	}
	return fmt.Errorf("ext4: invalid or unterminated extended attribute table")
}

func buildXattrBlock(attrs map[string][]byte) ([]byte, error) {
	entries := make([]xattrEntry, 0, len(attrs))
	for fullName, value := range attrs {
		index, name := xattrName(fullName)
		if index == 0 || len(name) > 255 || strings.ContainsRune(name, 0) {
			return nil, fmt.Errorf("ext4: invalid extended attribute %q", fullName)
		}
		entries = append(entries, xattrEntry{index, name, value})
	}
	slices.SortFunc(entries, func(a, b xattrEntry) int {
		if a.index != b.index {
			return int(a.index) - int(b.index)
		}
		if len(a.name) != len(b.name) {
			return len(a.name) - len(b.name)
		}
		return strings.Compare(a.name, b.name)
	})
	block := make([]byte, blockSize)
	put32(block, 0, xattrMagic)
	put32(block, 4, 1) // refcount
	put32(block, 8, 1) // blocks
	entryAt, valueAt := 32, len(block)
	var blockHash uint32
	for _, entry := range entries {
		padding := (len(entry.value) + 3) &^ 3
		valueAt -= padding
		next := entryAt + 16 + ((len(entry.name) + 3) &^ 3)
		if next+4 > valueAt {
			return nil, fmt.Errorf("ext4: extended attributes exceed one block")
		}
		block[entryAt] = byte(len(entry.name))
		block[entryAt+1] = entry.index
		if len(entry.value) != 0 {
			put16(block, entryAt+2, uint16(valueAt))
		}
		put32(block, entryAt+8, uint32(len(entry.value)))
		copy(block[entryAt+16:], entry.name)
		copy(block[valueAt:], entry.value)
		var hash uint32
		for i := 0; i < len(entry.name); i++ {
			hash = bits.RotateLeft32(hash, 5) ^ uint32(entry.name[i])
		}
		for i := 0; i < padding; i += 4 {
			hash = bits.RotateLeft32(hash, 16) ^ u32(block, valueAt+i)
		}
		put32(block, entryAt+12, hash)
		blockHash = bits.RotateLeft32(blockHash, 16) ^ hash
		entryAt = next
	}
	put32(block, 12, blockHash)
	return block, nil
}

package hfs

import (
	"fmt"
	starfile "github.com/tinyrange/trex/storage/star"
	"strings"
)

type attrKey struct {
	id   uint32
	name string
}
type attrRecord struct {
	inline  starfile.File
	fork    []byte
	extents map[uint32][]plusExtent
}

// HFS+ attributes are an independent B-tree. Attribute forks use their own
// overflow records, not the ordinary data/resource extents-overflow tree.
func (r *plusReader) attributes(desc []byte, v *Volume, ids map[uint32]int, maximum int) error {
	tree, err := r.fork(8, 0, desc)
	if err != nil {
		return err
	}
	if tree.Size() == 0 {
		return nil
	}
	records := map[attrKey]*attrRecord{}
	err = leafRecords(tree, maximum, func(b []byte) error {
		if len(b) < 18 {
			return fmt.Errorf("hfs+: truncated attribute key")
		}
		keySize := int(be.Uint16(b))
		n := int(be.Uint16(b[12:]))
		off := 2 + keySize
		if keySize != 12+2*n || n == 0 || n > 127 || off+4 > len(b) {
			return fmt.Errorf("hfs+: invalid attribute key")
		}
		name, err := unicodeName(b[14:off])
		if err != nil {
			return err
		}
		key := attrKey{be.Uint32(b[4:]), string(name)}
		start := be.Uint32(b[8:])
		data := b[off:]
		record := records[key]
		if record == nil {
			record = &attrRecord{extents: map[uint32][]plusExtent{}}
			records[key] = record
		}
		switch be.Uint32(data) {
		case 0x10:
			if start != 0 || len(data) < 16 || record.inline != nil || record.fork != nil {
				return fmt.Errorf("hfs+: invalid/duplicate inline attribute")
			}
			size := be.Uint32(data[12:])
			if uint64(size) > uint64(len(data)-16) {
				return fmt.Errorf("hfs+: truncated inline attribute")
			}
			record.inline = &starfile.Bytes{Data: append([]byte(nil), data[16:16+int(size)]...)}
		case 0x20:
			if start != 0 || len(data) != 88 || record.fork != nil || record.inline != nil {
				return fmt.Errorf("hfs+: invalid/duplicate fork attribute")
			}
			record.fork = append([]byte(nil), data[8:]...)
		case 0x30:
			if start == 0 || len(data) != 72 || record.extents[start] != nil {
				return fmt.Errorf("hfs+: invalid attribute overflow")
			}
			record.extents[start] = plusExtents(data[8:])
		default:
			return fmt.Errorf("hfs+: unsupported attribute record")
		}
		return nil
	})
	if err != nil {
		return err
	}
	for key, record := range records {
		index, ok := ids[key.id]
		if !ok {
			return fmt.Errorf("hfs+: attribute for missing catalog ID %d", key.id)
		}
		value := record.inline
		if record.fork != nil {
			forkReader := *r
			forkReader.overflow = map[plusKey][]plusExtent{}
			for start, extents := range record.extents {
				forkReader.overflow[plusKey{key.id, 0, start}] = extents
			}
			value, err = forkReader.fork(key.id, 0, record.fork)
			if err != nil {
				return err
			}
		} else if len(record.extents) != 0 {
			return fmt.Errorf("hfs+: orphan attribute extents")
		}
		if value == nil {
			return fmt.Errorf("hfs+: missing attribute data")
		}
		entry := &v.Entries[index]
		if entry.Xattrs == nil {
			entry.Xattrs = map[string]starfile.File{}
		}
		entry.Xattrs[key.name] = value
	}
	return nil
}

// Resolve only the documented file-inode alias, never symbolic links. Keep
// both the original alias fork and inode path available for forensic access.
func plusLinks(v *Volume, raw ...bool) error {
	var private uint32
	for _, e := range v.Entries {
		if e.Parent == 2 && string(e.Name) == "\x00\x00\x00\x00HFS+ Private Data" && e.Kind == "directory" {
			private = e.ID
		}
	}
	inodes := map[string]int{}
	for i, e := range v.Entries {
		if private != 0 && e.Parent == private {
			inodes[string(e.Name)] = i
		}
	}
	for i := range v.Entries {
		e := &v.Entries[i]
		if e.Kind != "file" {
			continue
		}
		if len(e.FinderInfo) >= 8 && string(e.FinderInfo[:8]) == "hlnkhfs+" {
			index, ok := inodes[fmt.Sprintf("iNode%d", e.Special)]
			if !ok {
				return fmt.Errorf("hfs+: unresolved hardlink inode %d", e.Special)
			}
			inode := &v.Entries[index]
			if inode.Kind != "file" || len(inode.FinderInfo) >= 8 && string(inode.FinderInfo[:8]) == "hlnkhfs+" {
				return fmt.Errorf("hfs+: invalid hardlink target")
			}
			e.RawData = e.Data
			e.RawResource = e.Resource
			e.Data = inode.Data
			e.CompressionType = inode.CompressionType
			e.Resource = inode.Resource
			e.Xattrs = inode.Xattrs
			e.Target = inode.Path
		}
		if e.Mode&0170000 == 0120000 {
			if e.Data == nil || e.Data.Size() > 65536 {
				return fmt.Errorf("hfs+: invalid symlink size")
			}
			data, err := starfile.ReadAll(e.Data)
			if err != nil {
				return err
			}
			if len(data) == 0 || strings.ContainsRune(string(data), 0) {
				return fmt.Errorf("hfs+: invalid symlink target")
			}
			e.Kind = "symlink"
			e.Target = string(data)
		}
		// Unsupported compressed files must never look like empty regular files.
		if e.OwnerFlags&0x20 != 0 && e.CompressionType == 0 && (len(raw) == 0 || !raw[0]) {
			return fmt.Errorf("hfs+: decmpfs-compressed file unsupported: %s", e.Path)
		}
	}
	return nil
}

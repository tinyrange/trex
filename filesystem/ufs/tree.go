package ufs

import (
	"encoding/binary"
	"fmt"
	starfile "github.com/tinyrange/trex/storage/star"
	"strings"
)

// Walk reconstructs a historical UFS directory tree from portable inode views.
// Both on-disk UFS and BSD dump records use this directory layout.
// lookup must return an immutable inode view; symlinks are not followed.
func Walk(root Entry, order binary.ByteOrder, maximumEntries int, lookup func(uint32) (Entry, error)) ([]Entry, error) {
	if maximumEntries < 1 || root.Inode != 2 || root.Data == nil {
		return nil, fmt.Errorf("ufs: invalid tree root or limits")
	}
	if root.Kind != "directory" {
		return nil, fmt.Errorf("ufs: root is not a directory")
	}
	root.Path = "/"
	entries := []Entry{root}
	type work struct {
		entry  Entry
		parent uint32
	}
	queue := []work{{root, 2}}
	seenDirs := map[uint32]bool{2: true}
	for next := 0; next < len(queue); next++ {
		current := queue[next]
		children, err := directoryEntries(current.entry, current.parent, order, maximumEntries-len(entries), lookup)
		if err != nil {
			return nil, err
		}
		for _, entry := range children {
			entries = append(entries, entry)
			if entry.Kind == "directory" {
				if seenDirs[entry.Inode] {
					return nil, fmt.Errorf("ufs: directory cycle or hard link")
				}
				seenDirs[entry.Inode] = true
				queue = append(queue, work{entry, current.entry.Inode})
			}
		}
	}
	return entries, nil
}

// directoryEntries validates one directory without descending into children.
func directoryEntries(directory Entry, parent uint32, order binary.ByteOrder, maximumEntries int, lookup func(uint32) (Entry, error)) ([]Entry, error) {
	entries := []Entry{}
	file := directory.Data
	if file.Size()%512 != 0 {
		return nil, fmt.Errorf("ufs: directory length is not a multiple of 512")
	}
	seenNames := map[string]bool{}
	dots := 0
	for offset := int64(0); offset < file.Size(); offset += 512 {
		var block [512]byte
		if _, err := starfile.ReadFullAt(file, block[:], offset); err != nil {
			return nil, err
		}
		for pos := 0; pos < 512; {
			if 512-pos < 8 {
				return nil, fmt.Errorf("ufs: truncated directory header")
			}
			inode := order.Uint32(block[pos:])
			length := int(order.Uint16(block[pos+4:]))
			namesize := int(order.Uint16(block[pos+6:]))
			if length < 8 || length%4 != 0 || length > 512-pos {
				return nil, fmt.Errorf("ufs: invalid directory record length")
			}
			if inode != 0 {
				if namesize == 0 || namesize > 255 || namesize+9 > length || block[pos+8+namesize] != 0 {
					return nil, fmt.Errorf("ufs: invalid directory name length")
				}
				name := string(block[pos+8 : pos+8+namesize])
				if strings.ContainsAny(name, "/\x00") || seenNames[name] {
					return nil, fmt.Errorf("ufs: invalid or duplicate directory name")
				}
				seenNames[name] = true
				if name == "." || name == ".." {
					want := directory.Inode
					if name == ".." {
						want = parent
					}
					if inode != want {
						return nil, fmt.Errorf("ufs: invalid dot entry")
					}
					dots++
				} else {
					if len(entries) >= maximumEntries {
						return nil, fmt.Errorf("ufs: entry limit exceeded")
					}
					entry, err := lookup(inode)
					if err != nil {
						return nil, err
					}
					entry.Path = strings.TrimSuffix(directory.Path, "/") + "/" + name
					entries = append(entries, entry)

				}
			}
			pos += length
		}
	}
	if dots != 2 {
		return nil, fmt.Errorf("ufs: missing dot entries")
	}
	return entries, nil
}

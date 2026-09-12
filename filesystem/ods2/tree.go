package ods2

import "fmt"

type Entry struct {
	Path                     string
	Name                     []byte
	Version                  uint16
	Header                   *Header
	Data                     *File
	Directory, DirectoryLink bool
}

func component(name []byte) string {
	result := ""
	for _, b := range name {
		if b >= 33 && b <= 126 && b != '%' && b != '/' && b != '\\' && b != ';' {
			result += string(b)
		} else {
			result += fmt.Sprintf("%%%02X", b)
		}
	}
	return result
}

// Walk preserves versioned names and the master directory's self-reference.
// Files share identity-cached data views. Other directory cycles fail; no
// external volume, mount or logical-name resolution is attempted.
func (v *Volume) Walk(maximumEntries, maximumDepth int) ([]Entry, error) {
	if maximumEntries < 1 || maximumDepth < 0 {
		return nil, fmt.Errorf("ods2: invalid tree limits")
	}
	rootID := FileID{Number: 4, Sequence: 4}
	h, f, err := v.File(rootID)
	if err != nil {
		return nil, err
	}
	if h.Characteristics&0x2000 == 0 {
		return nil, fmt.Errorf("ods2: master file is not a directory")
	}
	entries := []Entry{{Path: "/", Header: h, Data: f, Directory: true}}
	type pending struct {
		index     int
		ancestors []FileID
	}
	queue := []pending{{index: 0, ancestors: []FileID{rootID}}}
	cache := map[FileID]Entry{rootID: entries[0]}
	paths := map[string]bool{"/": true}
	for q := 0; q < len(queue); q++ {
		item := queue[q]
		parent := entries[item.index]
		children, err := ReadDirectory(parent.Data, maximumEntries)
		if err != nil {
			return nil, fmt.Errorf("ods2 directory %s: %w", parent.Path, err)
		}
		for _, child := range children {
			if len(entries) >= maximumEntries {
				return nil, fmt.Errorf("ods2: tree entry limit")
			}
			e, ok := cache[child.ID]
			if !ok {
				h, f, err := v.File(child.ID)
				if err != nil {
					return nil, fmt.Errorf("ods2 child %s: %w", child.Name, err)
				}
				e = Entry{Header: h, Data: f, Directory: h.Characteristics&0x2000 != 0}
				cache[child.ID] = e
			}
			e.Name = append([]byte(nil), child.Name...)
			e.Version = child.Version
			prefix := parent.Path
			if prefix == "/" {
				prefix = ""
			}
			e.Path = prefix + "/" + component(child.Name) + fmt.Sprintf(";%d", child.Version)
			if paths[e.Path] {
				return nil, fmt.Errorf("ods2: duplicate path %s", e.Path)
			}
			paths[e.Path] = true
			if e.Directory {
				for _, ancestor := range item.ancestors {
					if ancestor == child.ID {
						if parent.Path == "/" && child.ID == rootID && string(child.Name) == "000000.DIR" {
							e.DirectoryLink = true
						} else {
							return nil, fmt.Errorf("ods2: directory cycle at %s", e.Path)
						}
					}
				}
				if !e.DirectoryLink {
					if len(item.ancestors) > maximumDepth {
						return nil, fmt.Errorf("ods2: tree depth limit")
					}
					ancestors := append(append([]FileID(nil), item.ancestors...), child.ID)
					queue = append(queue, pending{index: len(entries), ancestors: ancestors})
				}
			}
			entries = append(entries, e)
		}
	}
	return entries, nil
}

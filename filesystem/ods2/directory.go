package ods2

import (
	"fmt"
	"github.com/tinyrange/trex/storage"
)

type DirectoryEntry struct {
	Name                  []byte
	Version, VersionLimit uint16
	Flags                 byte
	ID                    FileID
	Offset                int64
}

// ReadDirectory preserves every version, including versions split across
// records. Names are raw ODS-2 bytes; no host-path conversion occurs here.
func ReadDirectory(f storage.File, maximumEntries int) ([]DirectoryEntry, error) {
	if maximumEntries < 1 {
		return nil, fmt.Errorf("ods2: invalid directory limit")
	}
	entries := []DirectoryEntry{}
	versions := map[string]uint16{}
	for block := int64(0); block < f.Size(); block += BlockSize {
		n := int64(BlockSize)
		if f.Size()-block < n {
			n = f.Size() - block
		}
		b := make([]byte, n)
		if got, err := f.ReadAt(b, block); got != len(b) {
			return nil, fmt.Errorf("ods2: short directory block: %v", err)
		}
		for p := 0; p < len(b); {
			if len(b)-p < 2 {
				return nil, fmt.Errorf("ods2: truncated directory count")
			}
			count := int(le.Uint16(b[p:]))
			if count == 65535 {
				break
			}
			end := p + count + 2
			if count < 4 || count%2 != 0 || end > len(b) {
				return nil, fmt.Errorf("ods2: directory record crosses block")
			}
			flags := b[p+4]
			if flags != 0 {
				return nil, fmt.Errorf("ods2: unsupported directory flags %#x", flags)
			}
			length := int(b[p+5])
			at := p + 6 + length + (length % 2)
			if length == 0 || length > 79 || at > end || (end-at)%8 != 0 || at == end {
				return nil, fmt.Errorf("ods2: invalid directory value layout")
			}
			name := b[p+6 : p+6+length]
			if length%2 != 0 && b[at-1] != 0 {
				return nil, fmt.Errorf("ods2: nonzero name padding")
			}
			for _, v := range name {
				if v == 0 || v == '/' || v == '\\' {
					return nil, fmt.Errorf("ods2: invalid directory name")
				}
			}
			for ; at < end; at += 8 {
				if len(entries) >= maximumEntries {
					return nil, fmt.Errorf("ods2: directory entry limit")
				}
				version := le.Uint16(b[at:])
				previous := versions[string(name)]
				if version == 0 || version > 32767 || previous != 0 && version >= previous {
					return nil, fmt.Errorf("ods2: invalid version ordering")
				}
				id := fileID(b[at+2 : at+8])
				if id.Number == 0 || id.Sequence == 0 {
					return nil, fmt.Errorf("ods2: invalid directory file identity")
				}
				versions[string(name)] = version
				entries = append(entries, DirectoryEntry{Name: append([]byte(nil), name...), Version: version, VersionLimit: le.Uint16(b[p+2:]), Flags: flags, ID: id, Offset: block + int64(p)})
			}
			p = end
		}
	}
	return entries, nil
}

package xfs

import (
	"fmt"
	starfile "github.com/tinyrange/trex/storage/star"
	"sort"
)

// Version-1 directories store 64-bit inode numbers even in shortform. The
// xfs_db manual documents their shortform, node and leaf organization; byte
// offsets are also checked against IRIX 6.5.9's original miniroot.
func shortDirectoryV1(data []byte) ([]dirent, error) {
	if len(data) < 9 {
		return nil, fmt.Errorf("xfs: truncated v1 short directory")
	}
	var entries []dirent
	pos := 9
	for i := 0; i < int(data[8]); i++ {
		if pos+9 > len(data) {
			return nil, fmt.Errorf("xfs: truncated v1 short entry")
		}
		id, n := be.Uint64(data[pos:]), int(data[pos+8])
		pos += 9
		if n == 0 || n > len(data)-pos {
			return nil, fmt.Errorf("xfs: invalid v1 short name")
		}
		entries = append(entries, dirent{string(data[pos : pos+n]), id})
		pos += n
	}
	if pos != len(data) {
		return nil, fmt.Errorf("xfs: trailing v1 short directory data")
	}
	return entries, nil
}

func leafDirectoryV1(b []byte) ([]dirent, error) {
	if len(b) < 32 || be.Uint16(b[8:]) != 0xfeeb {
		return nil, fmt.Errorf("xfs: invalid v1 directory leaf")
	}
	count := int(be.Uint16(b[12:]))
	end := 32 + count*8
	if end > len(b) {
		return nil, fmt.Errorf("xfs: v1 leaf count exceeds block")
	}
	type span struct{ start, end int }
	spans := make([]span, 0, count)
	entries := make([]dirent, 0, count)
	var previous uint32
	nameBytes := 0
	for i := 0; i < count; i++ {
		p := b[32+i*8:]
		hash, start, n := be.Uint32(p), int(be.Uint16(p[4:])), int(p[6])
		if i > 0 && hash < previous {
			return nil, fmt.Errorf("xfs: unordered v1 leaf hashes")
		}
		previous = hash
		if n == 0 || start < end || start > len(b)-8-n {
			return nil, fmt.Errorf("xfs: v1 leaf name outside data area")
		}
		entries = append(entries, dirent{string(b[start+8 : start+8+n]), be.Uint64(b[start:])})
		spans = append(spans, span{start, start + 8 + n})
		nameBytes += n
	}
	if nameBytes != int(be.Uint16(b[14:])) {
		return nil, fmt.Errorf("xfs: inconsistent v1 leaf name byte count")
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].start < spans[j].start })
	for i := 1; i < len(spans); i++ {
		if spans[i].start < spans[i-1].end {
			return nil, fmt.Errorf("xfs: overlapping v1 leaf names")
		}
	}
	return entries, nil
}

func (r *reader) directoryV1(dir Entry, maximum int) ([]dirent, error) {
	if dir.local {
		data, err := starfile.ReadAll(dir.Data)
		if err != nil {
			return nil, err
		}
		return shortDirectoryV1(data)
	}
	if dir.Data.Size() == 0 || uint64(dir.Data.Size())%r.block != 0 {
		return nil, fmt.Errorf("xfs: invalid v1 directory size")
	}
	blocks := uint64(dir.Data.Size()) / r.block
	type pending struct {
		block uint32
		level int
	}
	queue := []pending{{0, -1}}
	seen := map[uint32]bool{0: true}
	var result []dirent
	b := make([]byte, r.block)
	for index := 0; index < len(queue); index++ {
		item := queue[index]
		if _, err := starfile.ReadFullAt(dir.Data, b, int64(uint64(item.block)*r.block)); err != nil {
			return nil, err
		}
		switch be.Uint16(b[8:]) {
		case 0xfeeb:
			if item.level > 0 {
				return nil, fmt.Errorf("xfs: premature v1 directory leaf")
			}
			entries, err := leafDirectoryV1(b)
			if err != nil {
				return nil, err
			}
			if len(entries) > maximum-len(result) {
				return nil, fmt.Errorf("xfs: v1 directory entry limit exceeded")
			}
			result = append(result, entries...)
		case 0xfebe:
			count, level := int(be.Uint16(b[12:])), int(be.Uint16(b[14:]))
			if count == 0 || 16+count*8 > len(b) || level < 1 || level > 32 || (item.level >= 0 && item.level != level) {
				return nil, fmt.Errorf("xfs: invalid v1 directory node")
			}
			var previous uint32
			for i := 0; i < count; i++ {
				p := b[16+i*8:]
				hash, child := be.Uint32(p), be.Uint32(p[4:])
				if i > 0 && hash < previous {
					return nil, fmt.Errorf("xfs: unordered v1 node hashes")
				}
				previous = hash
				if uint64(child) >= blocks || seen[child] || len(queue) >= maximum {
					return nil, fmt.Errorf("xfs: invalid v1 child, cycle or block limit")
				}
				seen[child] = true
				queue = append(queue, pending{child, level - 1})
			}
		default:
			return nil, fmt.Errorf("xfs: unknown v1 directory block magic")
		}
	}
	return result, nil
}

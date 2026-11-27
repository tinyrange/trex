package xfs

import (
	"math/bits"
	"slices"
)

const (
	dirDataHeader = 16
	dirLeafOffset = uint64(32<<30) / xfsBlock
	dirFreeOffset = 2 * dirLeafOffset
	dirIndexSlots = (xfsBlock - 16) / 8
)

func directoryEntrySize(name string) int {
	return (11 + len(name) + 7) &^ 7
}

func shortDirectoryImage(n *buildNode, capacity int) []byte {
	size := 6
	for _, entry := range n.children {
		size += 7 + len(entry.name)
	}
	if size > capacity {
		return nil
	}
	b := make([]byte, size)
	b[0] = byte(len(n.children))
	be.PutUint32(b[2:], n.parent)
	pos := 6
	offset := dirDataHeader + directoryEntrySize(".") + directoryEntrySize("..")
	for _, entry := range n.children {
		size := len(entry.name)
		b[pos] = byte(size)
		be.PutUint16(b[pos+1:], uint16(offset))
		copy(b[pos+3:], entry.name)
		be.PutUint32(b[pos+3+size:], uint32(entry.inode))
		pos += 7 + size
		offset += directoryEntrySize(entry.name)
	}
	return b
}

type directoryIndex struct{ hash, address uint32 }

func indexDirectoryEntry(b []byte, num, pos int, e dirent) directoryIndex {
	be.PutUint64(b[pos:], e.inode)
	b[pos+8] = byte(len(e.name))
	copy(b[pos+9:], e.name)
	be.PutUint16(b[pos+directoryEntrySize(e.name)-2:], uint16(pos))
	var hash uint32
	for i := 0; i < len(e.name); i++ {
		hash = bits.RotateLeft32(hash, 7) ^ uint32(e.name[i])
	}
	return directoryIndex{hash, uint32((num*xfsBlock + pos) / 8)}
}

func directoryFreeSpace(b []byte, pos, end int) uint16 {
	if pos == end {
		return 0
	}
	free := uint16(end - pos)
	be.PutUint16(b[4:], uint16(pos))
	be.PutUint16(b[6:], free)
	be.PutUint16(b[pos:], 0xffff)
	be.PutUint16(b[pos+2:], free)
	be.PutUint16(b[end-2:], uint16(pos))
	return free
}

func writeDirectoryIndex(block []byte, entries []directoryIndex) {
	for i, entry := range entries {
		be.PutUint32(block[8*i:], entry.hash)
		be.PutUint32(block[8*i+4:], entry.address)
	}
}

func (b *volumeBuilder) mapDirectory(n *buildNode) (int64, []extent, error) {
	entries := append([]dirent{{".", uint64(n.id)}, {"..", uint64(n.parent)}}, n.children...)
	index := make([]directoryIndex, 0, len(entries))
	block := make([]byte, xfsBlock)
	pos := dirDataHeader
	entryBytes := 0
	for _, entry := range entries {
		entryBytes += directoryEntrySize(entry.name)
	}
	leafAt := xfsBlock - 8 - len(entries)*8
	if pos+entryBytes <= leafAt {
		copy(block, "XD2B")
		for _, e := range entries {
			index = append(index, indexDirectoryEntry(block, 0, pos, e))
			pos += directoryEntrySize(e.name)
		}
		sortDirectoryIndex(index)
		directoryFreeSpace(block, pos, leafAt)
		writeDirectoryIndex(block[leafAt:], index)
		be.PutUint32(block[xfsBlock-8:], uint32(len(index)))
		start, err := b.reserve(1)
		if err != nil {
			return 0, nil, err
		}
		b.put(start, block)
		return xfsBlock, []extent{{physical: uint64(start), length: 1}}, nil
	}

	dataStart := b.next
	var bests []uint16
	for len(entries) > 0 {
		copy(block, "XD2D")
		pos = dirDataHeader
		for len(entries) > 0 {
			e := entries[0]
			size := directoryEntrySize(e.name)
			if pos+size > xfsBlock {
				break
			}
			index = append(index, indexDirectoryEntry(block, len(bests), pos, e))
			pos += size
			entries = entries[1:]
		}
		bests = append(bests, directoryFreeSpace(block, pos, xfsBlock))
		start, err := b.reserve(1)
		if err != nil {
			return 0, nil, err
		}
		b.put(start, block)
		block = make([]byte, xfsBlock)
	}
	sortDirectoryIndex(index)
	records := []extent{{physical: uint64(dataStart), length: uint64(len(bests))}}
	dataSize := int64(len(bests)) * xfsBlock
	if 16+len(index)*8+len(bests)*2+4 <= xfsBlock {
		be.PutUint16(block[8:], 0xd2f1) // leaf with integrated free space index
		be.PutUint16(block[12:], uint16(len(index)))
		writeDirectoryIndex(block[16:], index)
		writeDirectoryBests(block[xfsBlock-4-len(bests)*2:], bests)
		be.PutUint32(block[xfsBlock-4:], uint32(len(bests)))
		start, err := b.reserve(1)
		if err != nil {
			return 0, nil, err
		}
		b.put(start, block)
		return dataSize, append(records, extent{logical: dirLeafOffset, physical: uint64(start), length: 1}), nil
	}

	tree := directoryTree(index)
	start, err := b.reserve(uint32(len(tree)))
	if err != nil {
		return 0, nil, err
	}
	for i, block := range tree {
		b.put(start+uint32(i), block)
	}
	records = append(records, extent{logical: dirLeafOffset, physical: uint64(start), length: uint64(len(tree))})

	const bestSlots = (xfsBlock - 16) / 2
	freeCount := (len(bests) + bestSlots - 1) / bestSlots
	start, err = b.reserve(uint32(freeCount))
	if err != nil {
		return 0, nil, err
	}
	for i := range freeCount {
		from := i * bestSlots
		values := bests[from:min(from+bestSlots, len(bests))]
		block := make([]byte, xfsBlock)
		copy(block, "XD2F")
		be.PutUint32(block[4:], uint32(from))
		be.PutUint32(block[8:], uint32(len(values)))
		be.PutUint32(block[12:], uint32(len(values)))
		writeDirectoryBests(block[16:], values)
		b.put(start+uint32(i), block)
	}
	return dataSize, append(records, extent{logical: dirFreeOffset, physical: uint64(start), length: uint64(freeCount)}), nil
}

func sortDirectoryIndex(entries []directoryIndex) {
	slices.SortStableFunc(entries, func(a, b directoryIndex) int {
		if a.hash < b.hash {
			return -1
		}
		if a.hash > b.hash {
			return 1
		}
		return 0
	})
}

func writeDirectoryBests(block []byte, bests []uint16) {
	for i, size := range bests {
		be.PutUint16(block[i*2:], size)
	}
}

func directoryTree(index []directoryIndex) [][]byte {
	// Block zero in this slice maps to the first block of the leaf address
	// space. The remaining logical block numbers are fixed as they are added.
	blocks := [][]byte{nil}
	depth := uint16(0)
	for {
		if depth > 0 && len(index) <= dirIndexSlots {
			blocks[0] = directoryTreeBlock(depth, index, 0, 0)
			return blocks
		}
		count := (len(index) + dirIndexSlots - 1) / dirIndexSlots
		parents := make([]directoryIndex, count)
		for i := range count {
			from, to := i*len(index)/count, (i+1)*len(index)/count
			address := uint32(dirLeafOffset) + uint32(len(blocks))
			var prev, next uint32
			if i != 0 {
				prev = address - 1
			}
			if i != count-1 {
				next = address + 1
			}
			blocks = append(blocks, directoryTreeBlock(depth, index[from:to], prev, next))
			parents[i] = directoryIndex{index[to-1].hash, address}
		}
		index = parents
		depth++
	}
}

func directoryTreeBlock(depth uint16, entries []directoryIndex, prev, next uint32) []byte {
	block := make([]byte, xfsBlock)
	be.PutUint32(block, next)
	be.PutUint32(block[4:], prev)
	magic := uint16(0xfebe)
	if depth == 0 {
		magic = 0xd2ff
	}
	be.PutUint16(block[8:], magic)
	be.PutUint16(block[12:], uint16(len(entries)))
	be.PutUint16(block[14:], depth) // zero stale entries in a leaf
	writeDirectoryIndex(block[16:], entries)
	return block
}

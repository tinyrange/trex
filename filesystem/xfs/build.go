package xfs

import (
	"fmt"
	"math/bits"
	"path"
	"sort"
	"strings"

	"github.com/tinyrange/trex/filesystem"
	"github.com/tinyrange/trex/filesystem/unixfs"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

const (
	xfsBlock       = 4096
	xfsInode       = 256
	inodesPerBlock = xfsBlock / xfsInode
	inodesPerChunk = 64
	firstInode     = 8 * inodesPerBlock
	logBlocks      = 2048
	noAGBlock      = ^uint32(0)
	noInode        = ^uint64(0)
)

type buildNode struct {
	entry    unixfs.Entry
	id       uint32
	parent   uint32
	links    uint32
	children []dirent
}

type volumeBuilder struct {
	blocks, next uint32
	parts        []filesystem.ExtentSpec
}

// Build creates an IRIX-compatible XFS v4 volume with v2 directories and a
// clean internal v1 log. A single allocation group holds the inode chunks,
// file data and a contiguous free range that the filesystem driver can use.
// Payloads remain borrowed file views. The caller supplies the volume UUID.
func Build(input []unixfs.Entry, size int64, label string, uuid [16]byte) (starfile.File, error) {
	if size < 16<<20 || size > 1<<40 || size%xfsBlock != 0 {
		return nil, fmt.Errorf("xfs: volume must be 16 MiB to 1 TiB in 4 KiB blocks")
	}
	if len(label) > 12 || strings.ContainsRune(label, 0) || uuid == [16]byte{} {
		return nil, fmt.Errorf("xfs: invalid volume label or zero UUID")
	}
	entries, err := unixfs.Normalize(input)
	if err != nil {
		return nil, err
	}
	if len(entries) > 1000000 {
		return nil, fmt.Errorf("xfs: too many entries")
	}
	nodes := make([]buildNode, 0, len(entries))
	byPath := make(map[string]uint32, len(entries))
	for _, entry := range entries {
		if entry.Hardlink {
			continue
		}
		id := uint32(firstInode + len(nodes))
		byPath[entry.Path] = id
		nodes = append(nodes, buildNode{entry: entry, id: id})
	}
	for _, entry := range entries {
		id := byPath[entry.Path]
		if entry.Hardlink {
			id = byPath[entry.Target]
		}
		node := &nodes[id-firstInode]
		node.links++
		if entry.Path == "." {
			node.parent = id
		}
		if entry.Mode&0170000 == unixfs.Directory {
			node.links++ // the directory's own dot entry
		}
		if entry.Path == "." {
			continue
		}
		name := path.Base(entry.Path)
		if len(name) > 255 {
			return nil, fmt.Errorf("xfs: directory component exceeds 255 bytes in %q", entry.Path)
		}
		parent := &nodes[byPath[path.Dir(entry.Path)]-firstInode]
		parent.children = append(parent.children, dirent{name, uint64(id)})
		if entry.Mode&0170000 == unixfs.Directory {
			node.parent = parent.id
			parent.links++ // the child's dot-dot entry
		}
	}

	chunks := (len(nodes) + inodesPerChunk - 1) / inodesPerChunk
	inodeBlocks := uint32(chunks * inodesPerChunk / inodesPerBlock)
	b := volumeBuilder{blocks: uint32(size / xfsBlock), next: firstInode/inodesPerBlock + inodeBlocks}
	if b.next >= b.blocks {
		return nil, fmt.Errorf("xfs: inode tables exceed capacity")
	}
	logStart, err := b.reserve(logBlocks)
	if err != nil {
		return nil, err
	}
	inodeLevels, err := b.inodeTree(chunks, len(nodes))
	if err != nil {
		return nil, err
	}
	table := make([]byte, int(inodeBlocks)*xfsBlock)
	for i := range nodes {
		if err := b.writeInode(table[i*xfsInode:(i+1)*xfsInode], &nodes[i]); err != nil {
			return nil, fmt.Errorf("xfs: %s: %w", nodes[i].entry.Path, err)
		}
	}
	for i := len(nodes); i < chunks*inodesPerChunk; i++ {
		inode := table[i*xfsInode:]
		copy(inode, "IN")
		inode[4], inode[5] = 2, 2
		be.PutUint32(inode[96:], noAGBlock)
	}
	if b.next == b.blocks {
		return nil, fmt.Errorf("xfs: volume needs free blocks for transactions")
	}
	b.put(firstInode/inodesPerBlock, table)
	b.put(logStart, cleanLog(uuid))
	b.allocationHeaders(label, uuid, logStart, chunks, len(nodes), inodeLevels)
	sort.Slice(b.parts, func(i, j int) bool { return b.parts[i].Start < b.parts[j].Start })
	return filesystem.NewGeneratedImage("XFS volume", size, b.parts), nil
}

func (b *volumeBuilder) reserve(count uint32) (uint32, error) {
	if count > b.blocks-b.next {
		return 0, fmt.Errorf("volume capacity exceeded")
	}
	start := b.next
	b.next += count
	return start, nil
}

func (b *volumeBuilder) put(start uint32, data []byte) {
	b.parts = append(b.parts, filesystem.ExtentSpec{Start: int64(start) * xfsBlock, Size: int64(len(data)), Data: data})
}

func (b *volumeBuilder) mapFile(file storage.Reader) ([]extent, error) {
	if file.Size() == 0 {
		return nil, nil
	}
	if file.Size() > int64(b.blocks-b.next)*xfsBlock {
		return nil, fmt.Errorf("file exceeds remaining capacity")
	}
	count := uint32((file.Size() + xfsBlock - 1) / xfsBlock)
	start, err := b.reserve(count)
	if err != nil {
		return nil, err
	}
	b.parts = append(b.parts, filesystem.ExtentSpec{Start: int64(start) * xfsBlock, Size: file.Size(), File: starfile.NewReader("XFS payload", file)})
	const extentLimit = (1 << 21) - 1
	var records []extent
	for block := uint32(0); block < count; {
		n := min(count-block, extentLimit)
		records = append(records, extent{logical: uint64(block), physical: uint64(start + block), length: uint64(n)})
		block += n
	}
	return records, nil
}

func (b *volumeBuilder) writeInode(inode []byte, n *buildNode) error {
	e := n.entry
	copy(inode, "IN")
	be.PutUint16(inode[2:], uint16(e.Mode))
	inode[4] = 2
	inode[5] = 2 // extents
	be.PutUint32(inode[8:], e.UID)
	be.PutUint32(inode[12:], e.GID)
	be.PutUint32(inode[16:], n.links)
	for _, off := range []int{32, 40, 48} {
		be.PutUint32(inode[off:], e.Mtime)
	}
	be.PutUint32(inode[96:], noAGBlock)
	fork := inode[100:]
	var size int64
	var records []extent
	var err error
	switch e.Mode & 0170000 {
	case unixfs.Regular:
		size = e.Data.Size()
		records, err = b.mapFile(e.Data)
	case unixfs.Directory:
		if local := shortDirectoryImage(n, len(fork)); local != nil {
			inode[5], size = 1, int64(len(local))
			copy(fork, local)
		} else {
			size, records, err = b.mapDirectory(n)
		}
	case unixfs.Symlink:
		size = int64(len(e.Target))
		if size <= int64(len(fork)) {
			inode[5] = 1
			copy(fork, e.Target)
		} else if size < 1024 {
			records, err = b.mapFile(&starfile.Bytes{Data: []byte(e.Target)})
		} else {
			return fmt.Errorf("symbolic link target exceeds XFS limit")
		}
	case unixfs.Character, unixfs.Block:
		if e.Major >= 1<<14 || e.Minor >= 1<<18 {
			return fmt.Errorf("device number exceeds on-disk limits")
		}
		be.PutUint32(fork, e.Major<<18|e.Minor)
		fallthrough
	case unixfs.FIFO, unixfs.Socket:
		inode[5] = 0 // device fork
	}
	if err != nil {
		return err
	}
	var blocks uint64
	for _, record := range records {
		blocks += record.length
	}
	if len(records) <= len(fork)/16 {
		writeExtentRecords(fork, records)
	} else {
		// A contiguous payload in a single allocation group can be split at
		// the extent length limit. Even at the maximum group size, all of
		// those records fit under one external leaf.
		leaf, err := b.reserve(1)
		if err != nil {
			return err
		}
		block := make([]byte, xfsBlock)
		copy(block, "BMAP")
		be.PutUint16(block[6:], uint16(len(records)))
		be.PutUint64(block[8:], noInode)
		be.PutUint64(block[16:], noInode)
		writeExtentRecords(block[24:], records)
		b.put(leaf, block)
		inode[5] = 3
		be.PutUint16(fork, 1) // root level
		be.PutUint16(fork[2:], 1)
		be.PutUint64(fork[4:], records[0].logical)
		be.PutUint64(fork[4+((len(fork)-4)/16)*8:], uint64(leaf))
		blocks++
	}
	be.PutUint64(inode[56:], uint64(size))
	be.PutUint64(inode[64:], blocks)
	be.PutUint32(inode[76:], uint32(len(records)))
	return nil
}

func writeExtentRecords(dst []byte, records []extent) {
	for i, record := range records {
		x := dst[i*16:]
		be.PutUint64(x, record.logical<<9|record.physical>>43)
		be.PutUint64(x[8:], record.physical<<21|record.length)
	}
}

func (b *volumeBuilder) allocationHeaders(label string, uuid [16]byte, log uint32, chunks, used, inodeLevels int) {
	const bnobt, cntbt, inobt, freeListCount = 1, 2, 3, 4
	free := b.blocks - b.next
	header := make([]byte, xfsBlock)
	sb, agf, agi, agfl := header[:512], header[512:1024], header[1024:1536], header[1536:2048]
	copy(sb, "XFSB")
	be.PutUint32(sb[4:], xfsBlock)
	be.PutUint64(sb[8:], uint64(b.blocks))
	copy(sb[32:], uuid[:])
	be.PutUint64(sb[48:], uint64(log))
	be.PutUint64(sb[56:], firstInode)
	be.PutUint64(sb[64:], noInode)
	be.PutUint64(sb[72:], noInode)
	be.PutUint32(sb[80:], 1) // realtime extent size, even without a realtime device
	be.PutUint32(sb[84:], b.blocks)
	be.PutUint32(sb[88:], 1)
	be.PutUint32(sb[96:], logBlocks)
	// Version 4 with v2 directories, extent state, inode alignment and v2 inodes.
	be.PutUint16(sb[100:], 0x30b4)
	be.PutUint16(sb[102:], 512)
	be.PutUint16(sb[104:], xfsInode)
	be.PutUint16(sb[106:], inodesPerBlock)
	copy(sb[108:], label)
	sb[120], sb[121], sb[122], sb[123] = 12, 9, 8, 4
	sb[124] = byte(bits.Len32(b.blocks - 1))
	sb[127] = 25 // maximum percentage of blocks for inode chunks
	be.PutUint64(sb[128:], uint64(chunks*inodesPerChunk))
	be.PutUint64(sb[136:], uint64(chunks*inodesPerChunk-used))
	be.PutUint64(sb[144:], uint64(free+freeListCount))
	be.PutUint32(sb[180:], inodesPerChunk/inodesPerBlock/2) // 8 KiB inode cluster alignment

	copy(agf, "XAGF")
	be.PutUint32(agf[4:], 1)
	be.PutUint32(agf[12:], b.blocks)
	be.PutUint32(agf[16:], bnobt)
	be.PutUint32(agf[20:], cntbt)
	be.PutUint32(agf[28:], 1)
	be.PutUint32(agf[32:], 1)
	be.PutUint32(agf[44:], freeListCount-1)
	be.PutUint32(agf[48:], freeListCount)
	be.PutUint32(agf[52:], free)
	be.PutUint32(agf[56:], free)

	copy(agi, "XAGI")
	be.PutUint32(agi[4:], 1)
	be.PutUint32(agi[12:], b.blocks)
	be.PutUint32(agi[16:], uint32(chunks*inodesPerChunk))
	be.PutUint32(agi[20:], inobt)
	be.PutUint32(agi[24:], uint32(inodeLevels))
	be.PutUint32(agi[28:], uint32(chunks*inodesPerChunk-used))
	be.PutUint32(agi[32:], uint32(firstInode+(chunks-1)*inodesPerChunk))
	for off := 36; off < 296; off += 4 {
		be.PutUint32(agi[off:], noAGBlock)
	}
	for off := 0; off < len(agfl); off += 4 {
		value := noAGBlock
		if off/4 < freeListCount {
			value = uint32(4 + off/4)
		}
		be.PutUint32(agfl[off:], value)
	}
	b.put(0, header)
	for i, magic := range []string{"ABTB", "ABTC"} {
		block := shortBtreeBlock(magic, 0, 1, noAGBlock, noAGBlock)
		be.PutUint32(block[16:], b.next)
		be.PutUint32(block[20:], free)
		b.put(uint32(i)+bnobt, block)
	}
}

func shortBtreeBlock(magic string, level, records int, left, right uint32) []byte {
	block := make([]byte, xfsBlock)
	copy(block, magic)
	be.PutUint16(block[4:], uint16(level))
	be.PutUint16(block[6:], uint16(records))
	be.PutUint32(block[8:], left)
	be.PutUint32(block[12:], right)
	return block
}

func (b *volumeBuilder) inodeTree(chunks, used int) (int, error) {
	const rootBlock, capacity = 3, (xfsBlock - 16) / 16
	writeLeaf := func(start uint32, first, count int, left, right uint32) {
		block := shortBtreeBlock("IABT", 0, count, left, right)
		for i := range count {
			chunk := first + i
			rec := block[16+i*16:]
			be.PutUint32(rec, uint32(firstInode+chunk*inodesPerChunk))
			occupied := min(inodesPerChunk, used-chunk*inodesPerChunk)
			be.PutUint32(rec[4:], uint32(inodesPerChunk-occupied))
			be.PutUint64(rec[8:], ^uint64(0)<<occupied)
		}
		b.put(start, block)
	}
	if chunks <= capacity {
		writeLeaf(rootBlock, 0, chunks, noAGBlock, noAGBlock)
		return 1, nil
	}
	leaves := (chunks + capacity - 1) / capacity
	start, err := b.reserve(uint32(leaves))
	if err != nil {
		return 0, err
	}
	root := shortBtreeBlock("IABT", 1, leaves, noAGBlock, noAGBlock)
	const pointers = 16 + ((xfsBlock-16)/8)*4
	for i := range leaves {
		block := start + uint32(i)
		left, right := block-1, block+1
		if i == 0 {
			left = noAGBlock
		}
		if i == leaves-1 {
			right = noAGBlock
		}
		first := i * chunks / leaves
		count := (i+1)*chunks/leaves - first
		writeLeaf(block, first, count, left, right)
		be.PutUint32(root[16+i*4:], uint32(firstInode+first*inodesPerChunk))
		be.PutUint32(root[pointers+i*4:], block)
	}
	b.put(rootBlock, root)
	return 2, nil
}

func cleanLog(uuid [16]byte) []byte {
	log := make([]byte, 1024)
	be.PutUint32(log, 0xfeedbabe)
	be.PutUint32(log[4:], 1) // cycle
	be.PutUint32(log[8:], 1) // log version
	be.PutUint32(log[12:], 20)
	be.PutUint64(log[16:], 1<<32)
	be.PutUint64(log[24:], 1<<32)
	be.PutUint32(log[36:], noAGBlock)
	be.PutUint32(log[40:], 1)  // one operation
	be.PutUint32(log[44:], 1)  // transaction ID replaced by cycle in the data sector
	be.PutUint32(log[300:], 3) // IRIX big endian
	copy(log[304:], uuid[:])
	be.PutUint32(log[320:], 32<<10)
	be.PutUint32(log[512:], 1)
	be.PutUint32(log[516:], 8)
	log[520], log[521] = 0xaa, 0x20 // log client, unmount operation
	be.PutUint16(log[524:], 0x556e)
	return log
}

func BuildBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var entries starlark.Value
	var size int64
	var rawUUID starlark.Bytes
	var label string
	if err := starlark.UnpackArgs("xfs_build", args, kwargs, "entries", &entries, "size", &size, "uuid", &rawUUID, "label?", &label); err != nil {
		return nil, err
	}
	if len(rawUUID) != 16 {
		return nil, fmt.Errorf("xfs_build: UUID must be 16 bytes")
	}
	var uuid [16]byte
	copy(uuid[:], rawUUID)
	rows, err := unixfs.ParseEntries(entries)
	if err != nil {
		return nil, err
	}
	return Build(rows, size, label, uuid)
}

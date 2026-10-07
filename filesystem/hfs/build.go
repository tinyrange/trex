package hfs

import (
	"bytes"
	"fmt"
	"io"
	"math"
	"path"
	"sort"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/tinyrange/trex/filesystem/unixfs"
	"github.com/tinyrange/trex/storage"
	"golang.org/x/text/unicode/norm"
)

// BuildEntry describes native Unix metadata, separate data/resource forks and
// extended attributes. Payload readers are borrowed, not extracted or copied.
type BuildEntry struct {
	unixfs.Entry
	FinderInfo             []byte
	Resource               storage.Reader
	Xattrs                 map[string]storage.Reader
	OwnerFlags, AdminFlags byte
}
type BuildOptions struct {
	Size  int64
	Label string
}

const allocationBlock = 4096
const treeNodeSize = 8192
const hfsEpoch = 2082844800

type hfsFragment struct {
	offset int64
	source storage.Reader
}
type hfsBuilder struct {
	next, total uint32
	fragments   []hfsFragment
}

func (b *hfsBuilder) allocate(r storage.Reader) ([]byte, error) {
	desc := make([]byte, 80)
	if r == nil || r.Size() == 0 {
		return desc, nil
	}
	if r.Size() < 0 || uint64(r.Size()) > uint64(b.total)*allocationBlock {
		return nil, fmt.Errorf("hfsx: invalid fork size")
	}
	blocks := uint32((r.Size() + allocationBlock - 1) / allocationBlock)
	if blocks > b.total-1-b.next {
		return nil, fmt.Errorf("hfsx: volume full")
	}
	be.PutUint64(desc, uint64(r.Size()))
	be.PutUint32(desc[12:], blocks)
	be.PutUint32(desc[16:], b.next)
	be.PutUint32(desc[20:], blocks)
	b.fragments = append(b.fragments, hfsFragment{int64(b.next) * allocationBlock, r})
	b.next += blocks
	return desc, nil
}

// hfsName uses canonical decomposition with the TN1150 excluded ranges. HFSX
// binary catalogs compare UTF-16 code units, not UTF-8 bytes or locale ordering.
func hfsName(name string, maximum int) ([]uint16, error) {
	if !utf8.ValidString(name) || strings.ContainsAny(name, "\x00/") {
		return nil, fmt.Errorf("hfsx: invalid name %q", name)
	}
	var decomposed, run strings.Builder
	flush := func() { decomposed.WriteString(norm.NFD.String(run.String())); run.Reset() }
	for _, r := range name {
		if r >= 0x2000 && r <= 0x2fff || r >= 0xf900 && r <= 0xfaff || r >= 0x2f800 && r <= 0x2faff {
			flush()
			decomposed.WriteRune(r)
		} else {
			run.WriteRune(r)
		}
	}
	flush()
	u := utf16.Encode([]rune(decomposed.String()))
	if len(u) > maximum {
		return nil, fmt.Errorf("hfsx: name exceeds %d UTF-16 units", maximum)
	}
	return u, nil
}
func catalogKey(id uint32, name []uint16) []byte {
	b := make([]byte, 8+2*len(name))
	be.PutUint16(b, uint16(len(b)-2))
	be.PutUint32(b[2:], id)
	be.PutUint16(b[6:], uint16(len(name)))
	for i, v := range name {
		be.PutUint16(b[8+i*2:], v)
	}
	return b
}

type treeRecord struct{ key, data []byte }
type buildTreeNode struct {
	records []treeRecord
	kind    byte
	height  byte
	id      uint32
}

// buildTree builds actual index levels and linked leaves, with free nodes for
// guest growth. All metadata allocations are bounded independently of disk size.
func buildTree(records []treeRecord, maxKey uint16, compare byte) ([]byte, error) {
	nodes := []buildTreeNode{{kind: 1}}
	pack := func(rows []treeRecord, kind, height byte) ([]buildTreeNode, error) {
		var out []buildTreeNode
		n := buildTreeNode{kind: kind, height: height}
		used := 14
		for _, r := range rows {
			need := len(r.key) + len(r.data)
			if need&1 != 0 {
				need++
			}
			if need+14+4 > treeNodeSize {
				return nil, fmt.Errorf("hfsx: B-tree record too large")
			}
			if used+need+2*(len(n.records)+2) > treeNodeSize {
				out = append(out, n)
				n = buildTreeNode{kind: kind, height: height}
				used = 14
			}
			n.records = append(n.records, r)
			used += need
		}
		if len(n.records) > 0 {
			out = append(out, n)
		}
		return out, nil
	}
	level, err := pack(records, 255, 1)
	if err != nil {
		return nil, err
	}
	first, last := uint32(0), uint32(0)
	depth := byte(0)
	root := uint32(0)
	for len(level) > 0 {
		for i := range level {
			level[i].id = uint32(len(nodes))
			nodes = append(nodes, level[i])
		}
		if depth == 0 {
			first = level[0].id
			last = level[len(level)-1].id
		}
		depth = level[0].height
		if len(level) == 1 {
			root = level[0].id
			break
		}
		var indices []treeRecord
		for _, n := range level {
			child := make([]byte, 4)
			be.PutUint32(child, n.id)
			indices = append(indices, treeRecord{n.records[0].key, child})
		}
		if depth >= 16 {
			return nil, fmt.Errorf("hfsx: B-tree depth exceeded")
		}
		level, err = pack(indices, 0, depth+1)
		if err != nil {
			return nil, err
		}
	}
	total := max(8, len(nodes)*2)
	// A single header map describes this deliberately bounded tree (no map nodes).
	mapSize := treeNodeSize - 14 - 106 - 128 - 8
	if total > mapSize*8 || total*treeNodeSize > 256<<20 {
		return nil, fmt.Errorf("hfsx: B-tree metadata limit")
	}
	out := make([]byte, total*treeNodeSize)
	write := func(id uint32, kind, height byte, rows [][]byte) {
		n := out[int(id)*treeNodeSize : (int(id)+1)*treeNodeSize]
		n[8], n[9] = kind, height
		be.PutUint16(n[10:], uint16(len(rows)))
		pos := 14
		for i, r := range rows {
			be.PutUint16(n[treeNodeSize-2*(i+1):], uint16(pos))
			copy(n[pos:], r)
			pos += (len(r) + 1) &^ 1
		}
		be.PutUint16(n[treeNodeSize-2*(len(rows)+1):], uint16(pos))
	}
	header := make([]byte, 106)
	be.PutUint16(header, uint16(depth))
	be.PutUint32(header[2:], root)
	be.PutUint32(header[6:], uint32(len(records)))
	be.PutUint32(header[10:], first)
	be.PutUint32(header[14:], last)
	be.PutUint16(header[18:], treeNodeSize)
	be.PutUint16(header[20:], maxKey)
	be.PutUint32(header[22:], uint32(total))
	be.PutUint32(header[26:], uint32(total-len(nodes)))
	be.PutUint32(header[32:], treeNodeSize*8)
	header[37] = compare
	be.PutUint32(header[38:], 6) // big keys, variable index keys.
	bitmap := make([]byte, mapSize)
	for i := range nodes {
		bitmap[i/8] |= 0x80 >> uint(i%8)
	}
	write(0, 1, 0, [][]byte{header, make([]byte, 128), bitmap})
	for _, n := range nodes[1:] {
		rows := make([][]byte, len(n.records))
		for i, r := range n.records {
			rows[i] = append(append([]byte(nil), r.key...), r.data...)
		}
		write(n.id, n.kind, n.height, rows)
		// Sibling links at every level; leaves are also traversable without indexes.
		if n.id > 1 && nodes[n.id-1].height == n.height {
			be.PutUint32(out[int(n.id)*treeNodeSize+4:], n.id-1)
		}
		if int(n.id)+1 < len(nodes) && nodes[n.id+1].height == n.height {
			be.PutUint32(out[int(n.id)*treeNodeSize:], n.id+1)
		}
	}
	return out, nil
}

// Build creates an unjournaled, case-sensitive HFSX volume (HFS+ generation 5).
// It does not create partitions, execute mkfs or modify borrowed payloads.
// Regular-file hardlinks use the TN1150 private inode directory and hlnk/hfs+
// catalog aliases; directory hardlinks and journaling are not constructed.
func Build(input []BuildEntry, options BuildOptions) (storage.Reader, error) {
	if options.Size < 16<<20 || options.Size%allocationBlock != 0 || options.Size/allocationBlock > math.MaxUint32 || len(input) > 1000000 {
		return nil, fmt.Errorf("hfsx: invalid volume geometry or entry limit")
	}
	label, err := hfsName(options.Label, 255)
	if err != nil || len(label) == 0 {
		return nil, fmt.Errorf("hfsx: invalid volume label")
	}
	originals := map[string]BuildEntry{}
	plain := make([]unixfs.Entry, 0, len(input))
	for _, e := range input {
		p, err := unixfs.Clean(e.Path)
		if err != nil {
			return nil, err
		}
		if _, ok := originals[p]; ok {
			return nil, fmt.Errorf("hfsx: duplicate path %q", p)
		}
		if len(e.FinderInfo) != 0 && len(e.FinderInfo) != 32 {
			return nil, fmt.Errorf("hfsx: Finder info must be 32 bytes")
		}
		e.Path = p
		originals[p] = e
		plain = append(plain, e.Entry)
	}
	entries, err := unixfs.Normalize(plain)
	if err != nil {
		return nil, err
	}
	// Normalize has resolved hardlink chains and validated shared Unix metadata.
	byPath := map[string]unixfs.Entry{}
	groups := map[string][]string{}
	for _, e := range entries {
		byPath[e.Path] = e
		if e.Hardlink {
			groups[e.Target] = append(groups[e.Target], e.Path)
		}
	}
	aliasTarget := map[string]string{}
	inodeLinks := map[string]uint32{}
	const privatePath = ".hfs-private-inodes"
	if len(groups) > 0 {
		if _, exists := byPath[privatePath]; exists {
			return nil, fmt.Errorf("hfsx: reserved private inode path")
		}
		dir := unixfs.Entry{Path: privatePath, Mode: unixfs.Directory | 0700, Mtime: entries[0].Mtime}
		entries = append(entries, dir)
		finder := make([]byte, 32)
		be.PutUint16(finder[8:], 0x4000)
		originals[privatePath] = BuildEntry{Entry: dir, FinderInfo: finder}
		targets := make([]string, 0, len(groups))
		for target := range groups {
			targets = append(targets, target)
		}
		sort.Strings(targets)
		for index, target := range targets {
			// Reference numbers are deterministic, nonzero and independent of
			// catalog IDs. Both the original path and every alias share the inode.
			ref := uint32(index + 16)
			inodePath := fmt.Sprintf("%s/iNode%d", privatePath, ref)
			inode := byPath[target]
			inode.Path = inodePath
			inode.Hardlink = false
			inode.Target = ""
			entries = append(entries, inode)
			metadata := originals[target]
			metadata.Entry = inode
			originals[inodePath] = metadata
			inodeLinks[inodePath] = uint32(len(groups[target]) + 1)
			aliasTarget[target] = inodePath
			for _, alias := range groups[target] {
				aliasTarget[alias] = inodePath
			}
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	}
	if uint64(options.Size/allocationBlock+7)/8 > 64<<20 {
		return nil, fmt.Errorf("hfsx: allocation bitmap limit")
	}
	b := &hfsBuilder{next: 1, total: uint32(options.Size / allocationBlock)}
	// Reserve the allocation bitmap early; its bits are populated after all forks.
	bitmap := make([]byte, (uint64(b.total)+7)/8)
	bitmapDesc, err := b.allocate(bytes.NewReader(bitmap))
	if err != nil {
		return nil, err
	}
	overflow, err := buildTree(nil, 10, 0)
	if err != nil {
		return nil, err
	}
	overflowDesc, err := b.allocate(bytes.NewReader(overflow))
	if err != nil {
		return nil, err
	}
	ids := map[string]uint32{".": 2}
	names := map[string][]uint16{".": label}
	valences := map[string]uint32{}
	nextID := uint32(16)
	for _, e := range entries {
		if e.Path == "." {
			continue
		}
		name, err := hfsName(path.Base(e.Path), 255)
		// The HFS catalog slash is the POSIX colon (TN1150 name translation).
		// Directory separators are already consumed by path.Base.
		for i, c := range name {
			if c == ':' {
				name[i] = '/'
			}
		}
		if e.Path == privatePath && len(groups) > 0 {
			name = utf16.Encode([]rune("\x00\x00\x00\x00HFS+ Private Data"))
			err = nil
		}
		if err != nil || len(name) == 0 {
			return nil, fmt.Errorf("hfsx: invalid catalog name %q", e.Path)
		}
		names[e.Path] = name
		ids[e.Path] = nextID
		nextID++
		valences[path.Dir(e.Path)]++
	}
	var catalog, attributes []treeRecord
	var files, folders uint32
	for _, e := range entries {
		metadata := originals[e.Path]
		name := names[e.Path]
		id := ids[e.Path]
		parent := uint32(1)
		if e.Path != "." {
			parent = ids[path.Dir(e.Path)]
		}
		directory := e.Mode&0170000 == unixfs.Directory
		kind := uint16(2)
		length := 248
		if directory {
			kind = 1
			length = 88
			if e.Path != "." {
				folders++
			}
		} else {
			files++
		}
		value := make([]byte, length)
		be.PutUint16(value, kind)
		be.PutUint16(value[2:], 2) // thread record exists.
		if directory {
			be.PutUint32(value[4:], valences[e.Path])
		}
		be.PutUint32(value[8:], id)
		if uint64(e.Mtime)+hfsEpoch > math.MaxUint32 {
			return nil, fmt.Errorf("hfsx: date outside HFS epoch")
		}
		date := e.Mtime + hfsEpoch
		for _, off := range []int{12, 16, 20, 24} {
			be.PutUint32(value[off:], date)
		}
		be.PutUint32(value[32:], e.UID)
		be.PutUint32(value[36:], e.GID)
		value[40], value[41] = metadata.AdminFlags, metadata.OwnerFlags
		be.PutUint16(value[42:], uint16(e.Mode))
		copy(value[48:80], metadata.FinderInfo)
		if !directory {
			var data storage.Reader
			switch e.Mode & 0170000 {
			case unixfs.Regular:
				data = e.Data
				be.PutUint32(value[44:], max(1, inodeLinks[e.Path]))
				if inode, alias := aliasTarget[e.Path]; alias {
					data = nil
					metadata.Resource = nil
					metadata.Xattrs = nil
					clear(value[48:80])
					copy(value[48:], "hlnkhfs+")
					be.PutUint16(value[56:], 0x100)
					var ref uint32
					if _, err := fmt.Sscanf(path.Base(inode), "iNode%d", &ref); err != nil {
						return nil, err
					}
					be.PutUint32(value[44:], ref)
					// Alias creation date is the volume/private-directory date.
					be.PutUint32(value[12:], entries[0].Mtime+hfsEpoch)
				}
			case unixfs.Symlink:
				data = bytes.NewReader([]byte(e.Target))
				copy(value[48:], "slnkrhap")
				be.PutUint32(value[44:], 1)
			case unixfs.Character, unixfs.Block:
				if e.Major > 255 || e.Minor > 0xffffff {
					return nil, fmt.Errorf("hfsx: device number out of range")
				}
				be.PutUint32(value[44:], e.Major<<24|e.Minor)
			case unixfs.FIFO, unixfs.Socket:
			default:
				return nil, fmt.Errorf("hfsx: unsupported file mode")
			}
			fork, err := b.allocate(data)
			if err != nil {
				return nil, fmt.Errorf("hfsx: %s: %w", e.Path, err)
			}
			copy(value[88:], fork)
			resource, err := b.allocate(metadata.Resource)
			if err != nil {
				return nil, err
			}
			copy(value[168:], resource)
		} else if metadata.Resource != nil && metadata.Resource.Size() != 0 {
			return nil, fmt.Errorf("hfsx: directory resource fork")
		}
		for key, r := range metadata.Xattrs {
			u, err := hfsName(key, 127)
			if err != nil || len(u) == 0 || r == nil || r.Size() < 0 {
				return nil, fmt.Errorf("hfsx: invalid extended attribute")
			}
			k := make([]byte, 14+len(u)*2)
			be.PutUint16(k, uint16(len(k)-2))
			be.PutUint32(k[4:], id)
			be.PutUint16(k[12:], uint16(len(u)))
			for i, v := range u {
				be.PutUint16(k[14+i*2:], v)
			}
			var v []byte
			if r.Size() <= 2048 {
				v = make([]byte, 16+r.Size())
				be.PutUint32(v, 0x10)
				be.PutUint32(v[12:], uint32(r.Size()))
				if _, err := io.ReadFull(io.NewSectionReader(r, 0, r.Size()), v[16:]); err != nil {
					return nil, err
				}
			} else {
				v = make([]byte, 88)
				be.PutUint32(v, 0x20)
				fork, err := b.allocate(r)
				if err != nil {
					return nil, err
				}
				copy(v[8:], fork)
			}
			attributes = append(attributes, treeRecord{k, v})
		}
		if len(metadata.Xattrs) > 0 {
			be.PutUint16(value[2:], be.Uint16(value[2:])|4)
		}
		catalog = append(catalog, treeRecord{catalogKey(parent, name), value})
		thread := make([]byte, 10+2*len(name))
		be.PutUint16(thread, kind+2)
		be.PutUint32(thread[4:], parent)
		be.PutUint16(thread[8:], uint16(len(name)))
		for i, v := range name {
			be.PutUint16(thread[10+i*2:], v)
		}
		catalog = append(catalog, treeRecord{catalogKey(id, nil), thread})
	}
	// Length fields must not participate in key comparison: parentID, then name
	// code units, ignoring the UTF-16 name length prefix.
	sort.Slice(catalog, func(i, j int) bool {
		a, c := catalog[i].key, catalog[j].key
		if be.Uint32(a[2:]) != be.Uint32(c[2:]) {
			return be.Uint32(a[2:]) < be.Uint32(c[2:])
		}
		return bytes.Compare(a[8:], c[8:]) < 0
	})
	for i := 1; i < len(catalog); i++ {
		if bytes.Equal(catalog[i].key, catalog[i-1].key) {
			return nil, fmt.Errorf("hfsx: duplicate decomposed catalog key")
		}
	}
	catData, err := buildTree(catalog, 516, 0xbc)
	if err != nil {
		return nil, err
	}
	catDesc, err := b.allocate(bytes.NewReader(catData))
	if err != nil {
		return nil, err
	}
	var attrDesc []byte
	if len(attributes) > 0 {
		sort.Slice(attributes, func(i, j int) bool {
			a, c := attributes[i].key, attributes[j].key
			if be.Uint32(a[4:]) != be.Uint32(c[4:]) {
				return be.Uint32(a[4:]) < be.Uint32(c[4:])
			}
			return bytes.Compare(a[14:], c[14:]) < 0
		})
		attrData, err := buildTree(attributes, 266, 0)
		if err != nil {
			return nil, err
		}
		attrDesc, err = b.allocate(bytes.NewReader(attrData))
		if err != nil {
			return nil, err
		}
	}
	// First and last allocation blocks reserve boot/volume-header sectors. The
	// bitmap uses MSB-first allocation bits and marks unused tail bits allocated.
	for i := uint32(0); i < b.next; i++ {
		bitmap[i/8] |= 0x80 >> uint(i%8)
	}
	for i := uint64(b.total) - 1; i < uint64(len(bitmap))*8; i++ {
		bitmap[i/8] |= 0x80 >> uint(i%8)
	}
	header := make([]byte, 512)
	be.PutUint16(header, 0x4858)
	be.PutUint16(header[2:], 5)
	be.PutUint32(header[4:], 1<<8) // cleanly unmounted, no journal.
	copy(header[8:], "10.0")
	be.PutUint32(header[32:], files)
	be.PutUint32(header[36:], folders)
	be.PutUint32(header[40:], allocationBlock)
	be.PutUint32(header[44:], b.total)
	be.PutUint32(header[48:], b.total-b.next-1)
	be.PutUint32(header[52:], b.next)
	be.PutUint32(header[56:], allocationBlock*16)
	be.PutUint32(header[60:], allocationBlock*16)
	be.PutUint32(header[64:], nextID)
	be.PutUint32(header[68:], 1)
	root := entries[0]
	date := root.Mtime + hfsEpoch
	for _, off := range []int{16, 20, 28} {
		be.PutUint32(header[off:], date)
	}
	copy(header[112:], bitmapDesc)
	copy(header[192:], overflowDesc)
	copy(header[272:], catDesc)
	copy(header[352:], attrDesc)
	b.fragments = append(b.fragments, hfsFragment{1024, bytes.NewReader(header)}, hfsFragment{options.Size - 1024, bytes.NewReader(header)})
	sort.Slice(b.fragments, func(i, j int) bool { return b.fragments[i].offset < b.fragments[j].offset })
	var ranges []storage.Range
	var position int64
	for _, f := range b.fragments {
		if f.offset < position {
			return nil, fmt.Errorf("hfsx: overlapping fragments")
		}
		if f.offset > position {
			ranges = append(ranges, storage.Range{Source: unixfs.Zero(f.offset - position), Length: f.offset - position})
		}
		ranges = append(ranges, storage.Range{Source: f.source, Length: f.source.Size()})
		position = f.offset + f.source.Size()
	}
	ranges = append(ranges, storage.Range{Source: unixfs.Zero(options.Size - position), Length: options.Size - position})
	return storage.Compose(ranges...)
}

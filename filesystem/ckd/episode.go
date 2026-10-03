package ckd

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math"
	"sort"

	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/storage"
)

// Episode reads the big-endian z/OS zFS aggregate layout. It is unrelated to
// Solaris ZFS. The input is an allocated-page stream, without CKD framing.
// Unsupported backing/copy-on-write addresses are rejected explicitly.
type Episode struct {
	source          storage.Reader
	block, fragment int64
	blocks          uint32
	limit           int
}
type episodeAnode struct {
	raw      []byte
	physical int64
	index    uint32
}
type EpisodeFileset struct {
	aggregate *Episode
	Name      string
	Index     uint32
	table     *Content
}
type EpisodeInode struct {
	Vnode, Generation, Links, Device uint32
	Kind                             string
	Size                             int64
	anode                            episodeAnode
}
type EpisodeName struct {
	Name              []byte
	Vnode, Generation uint32
}

func OpenEpisode(source storage.Reader, limit int) (*Episode, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("zFS: invalid entry limit")
	}
	b := make([]byte, 72)
	if _, err := source.ReadAt(b, 65536); err != nil {
		return nil, err
	}
	if be.Uint32(b[4:]) != 0x3198a2e0 || be.Uint32(b[8:]) != 1 || be.Uint32(b[12:]) != 0x8946f098 {
		return nil, fmt.Errorf("zFS: unsupported aggregate header")
	}
	block, fragment := int64(be.Uint32(b[20:])), int64(be.Uint32(b[24:]))
	if block != 8192 || fragment != 1024 {
		return nil, fmt.Errorf("zFS: unsupported block/fragment geometry")
	}
	blocks := be.Uint32(b[32:])
	if uint64(blocks)+1 > uint64(source.Size()/block) || blocks < 8 {
		return nil, fmt.Errorf("zFS: aggregate exceeds allocation")
	}
	return &Episode{source, block, fragment, blocks, limit}, nil
}
func (e *Episode) read(off, size int64) ([]byte, error) {
	if off < 0 || size < 0 || size > 1<<20 || off > e.source.Size() || size > e.source.Size()-off {
		return nil, fmt.Errorf("zFS: read outside aggregate")
	}
	b := make([]byte, int(size))
	_, err := e.source.ReadAt(b, off)
	return b, err
}
func (e *Episode) checkBlock(block uint32) error {
	if block&0x80000000 != 0 || block > e.blocks {
		return fmt.Errorf("zFS: invalid or backing block %x", block)
	}
	return nil
}
func (e *Episode) anodeAt(physical int64, index uint32) (episodeAnode, error) {
	b, err := e.read(physical, 252)
	if err != nil {
		return episodeAnode{}, err
	}
	a := episodeAnode{b, physical, index}
	if be.Uint32(b)>>24 != 0xb4 || be.Uint32(b[12:]) != index {
		return a, fmt.Errorf("zFS: invalid anode %d", index)
	}
	if be.Uint32(b[4:]) != 0 || be.Uint32(b[8:]) != 0 || be.Uint32(b[28:]) != 0 || be.Uint32(b[32:]) != 0 {
		return a, fmt.Errorf("zFS: unsupported backing anode")
	}
	return a, nil
}
func (e *Episode) content(a episodeAnode) (*Content, error) {
	b := a.raw
	size64 := be.Uint64(b[20:])
	if size64 > math.MaxInt64 {
		return nil, fmt.Errorf("zFS: file size overflow")
	}
	size := int64(size64)
	flags := be.Uint32(b)
	out := &Content{source: e.source, size: size}
	if flags&0x80000 != 0 { // Inline content precedes the status area.
		status := int64(flags & 255)
		if flags&0x100000 != 0 || status > 204 || size > 252-status-48 {
			return nil, fmt.Errorf("zFS: invalid inline content")
		}
		out.spans = []span{{a.physical + 48, size, 0}}
		return out, nil
	}
	if flags&0x100000 != 0 {
		block := be.Uint32(b[48:])
		first, count := int64(be.Uint16(b[52:])), int64(be.Uint16(b[54:]))
		if err := e.checkBlock(block); err != nil {
			return nil, err
		}
		if count == 0 || first+count > e.block/e.fragment || size > count*e.fragment {
			return nil, fmt.Errorf("zFS: invalid fragment range")
		}
		out.spans = []span{{int64(block)*e.block + first*e.fragment, size, 0}}
		return out, nil
	}
	// A bounded extent map permits sparse files without allocating their bytes.
	n := int64(0)
	if size > 0 {
		n = 1 + (size-1)/e.block
	}
	if n > 1<<20 {
		return nil, fmt.Errorf("zFS: block map limit exceeded")
	}
	add := func(block uint32, spanBlocks int64) error {
		start := int64(0)
		if len(out.spans) > 0 {
			s := out.spans[len(out.spans)-1]
			start = s.start + s.length
		}
		length := min(spanBlocks*e.block, size-start)
		if length <= 0 {
			return nil
		}
		offset := int64(-1)
		if block != 0xffffffff {
			if err := e.checkBlock(block); err != nil {
				return err
			}
			offset = int64(block) * e.block
		}
		out.spans = append(out.spans, span{offset, length, start})
		return nil
	}
	for i := int64(0); i < min(n, 8); i++ {
		if err := add(be.Uint32(b[48+4*i:]), 1); err != nil {
			return nil, err
		}
	}
	remaining := max(n-8, 0)
	fanout := (e.block - 32) / 4
	seen := map[uint32]bool{}
	var indirect func(uint32, int64, int64, int64, int64) error
	indirect = func(block uint32, depth, base, want, stride int64) error {
		if block == 0xffffffff {
			return add(block, want)
		}
		if seen[block] {
			return fmt.Errorf("zFS: indirect cycle or duplicate block")
		}
		seen[block] = true
		if err := e.checkBlock(block); err != nil {
			return err
		}
		page, err := e.read(int64(block)*e.block, e.block)
		if err != nil {
			return err
		}
		if be.Uint32(page[4:]) != 0x5a308d31 || be.Uint32(page) != be.Uint32(page[len(page)-4:]) || int64(be.Uint32(page[16:])) != base || int64(be.Uint32(page[20:])) != stride || int64(be.Uint32(page[24:])) != fanout {
			return fmt.Errorf("zFS: invalid indirect header")
		}
		for i := int64(0); want > 0 && i < fanout; i++ {
			child := be.Uint32(page[28+i*4:])
			take := min(want, stride)
			if depth == 1 {
				err = add(child, 1)
			} else {
				err = indirect(child, depth-1, base+i*stride, take, stride/fanout)
			}
			if err != nil {
				return err
			}
			want -= take
		}
		if want != 0 {
			return fmt.Errorf("zFS: indirect coverage mismatch")
		}
		return nil
	}
	capacity, base := fanout, int64(8)
	for depth := int64(1); depth <= 4 && remaining > 0; depth++ {
		take := min(remaining, capacity)
		if err := indirect(be.Uint32(b[80+4*(depth-1):]), depth, base, take, capacity/fanout); err != nil {
			return nil, err
		}
		remaining -= take
		base += capacity
		if depth < 4 {
			capacity *= fanout
		}
	}
	if remaining != 0 {
		return nil, fmt.Errorf("zFS: incomplete block map")
	}
	return out, nil
}
func (e *Episode) Filesets() ([]*EpisodeFileset, error) {
	a, err := e.anodeAt(65536+264, 1)
	if err != nil {
		return nil, err
	}
	avt, err := e.content(a)
	if err != nil {
		return nil, err
	}
	if avt.Size()%e.block != 0 || avt.Size()/e.block > int64(e.limit) {
		return nil, fmt.Errorf("zFS: invalid aggregate table length")
	}
	out := []*EpisodeFileset{}
	for block := int64(0); block < avt.Size()/e.block; block++ {
		physical, err := episodePhysical(avt, block*e.block)
		if err != nil {
			return nil, err
		}
		page, err := e.read(physical, e.block)
		if err != nil {
			return nil, err
		}
		if be.Uint32(page[4:]) != 0x3198a2e0 {
			return nil, fmt.Errorf("zFS: invalid aggregate table page")
		}
		for slot := uint32(0); slot < 32; slot++ {
			index := uint32(block)*32 + slot
			if index < 5 {
				continue
			}
			flags := be.Uint32(page[12+slot*252:])
			if flags == 0 {
				continue
			}
			if flags&0xf00 != 0x200 {
				continue
			} // Non-fileset aggregate objects.
			a, err := e.anodeAt(physical+12+int64(slot)*252, index)
			if err != nil {
				return nil, err
			}
			table, err := e.content(a)
			if err != nil {
				return nil, err
			}
			header := make([]byte, 256)
			if _, err := table.ReadAt(header, 0); err != nil {
				return nil, err
			}
			if be.Uint32(header[4:]) != 0xb7afc1db || be.Uint32(header[8:]) != index {
				return nil, fmt.Errorf("zFS: invalid fileset table")
			}
			name := bytes.TrimRight(header[24:88], "\x00")
			out = append(out, &EpisodeFileset{e, HFSDisplayName(name), index, table})
			if len(out) > e.limit {
				return nil, fmt.Errorf("zFS: fileset limit exceeded")
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("zFS: no filesets")
	}
	return out, nil
}
func episodePhysical(c *Content, off int64) (int64, error) {
	for _, s := range c.spans {
		if off >= s.start && off < s.start+s.length {
			if s.offset < 0 {
				break
			}
			return s.offset + off - s.start, nil
		}
	}
	return 0, fmt.Errorf("zFS: missing metadata page")
}
func (f *EpisodeFileset) Inode(vnode uint32) (*EpisodeInode, error) {
	if vnode == 0 || vnode >= 1<<30 {
		return nil, fmt.Errorf("zFS: invalid vnode")
	}
	// Alternate anode-table pages hold auxiliary objects, not vnodes.
	n := uint64(vnode) + 1
	index := uint32((n/32)*64 + n%32)
	off := int64(index/32)*f.aggregate.block + 12 + int64(index%32)*252
	if off > f.table.Size()-252 {
		return nil, fmt.Errorf("zFS: vnode outside fileset")
	}
	physical, err := episodePhysical(f.table, off)
	if err != nil {
		return nil, err
	}
	page, err := f.aggregate.read(physical-int64(index%32)*252-12, 12)
	if err != nil {
		return nil, err
	}
	if be.Uint32(page[4:]) != 0xb7afc1db || be.Uint32(page[8:]) != f.Index {
		return nil, fmt.Errorf("zFS: inode page identity mismatch")
	}
	a, err := f.aggregate.anodeAt(physical, index)
	if err != nil {
		return nil, err
	}
	b := a.raw
	if be.Uint32(b)&0xfff != 0xf98 || !bytes.Equal(b[100:104], []byte{0xc9, 0xc6, 0xe2, 0xd7}) || b[104] != 1 {
		return nil, fmt.Errorf("zFS: unsupported inode status")
	}
	kind := ""
	// The preceding three bytes are file-tag metadata, not part of the type.
	switch b[243] {
	case 1:
		kind = "directory"
	case 2:
		kind = "character-device"
	case 3:
		kind = "file"
	case 4:
		kind = "fifo"
	case 5:
		kind = "symlink"
	case 6:
		kind = "block-device"
	case 7:
		kind = "socket"
	default:
		return nil, fmt.Errorf("zFS: unsupported inode type %d at vnode %d", b[243], vnode)
	}
	size := be.Uint64(b[20:])
	if size > math.MaxInt64 {
		return nil, fmt.Errorf("zFS: inode size overflow")
	}
	return &EpisodeInode{vnode, be.Uint32(b[196:]), be.Uint32(b[228:]), be.Uint32(b[232:]), kind, int64(size), a}, nil
}
func (f *EpisodeFileset) Data(i *EpisodeInode) (storage.Reader, error) {
	if i.Kind != "file" && i.Kind != "directory" && i.Kind != "symlink" {
		return nil, fmt.Errorf("zFS: special inode has no readable data")
	}
	return f.aggregate.content(i.anode)
}
func (f *EpisodeFileset) Directory(vnode uint32) ([]EpisodeName, error) {
	inode, err := f.Inode(vnode)
	if err != nil {
		return nil, err
	}
	if inode.Kind != "directory" {
		return nil, fmt.Errorf("zFS: not a directory")
	}
	data, err := f.Data(inode)
	if err != nil {
		return nil, err
	}
	if data.Size() < 160 || data.Size()%32 != 0 || data.Size()/8192 > int64(f.aggregate.limit) {
		return nil, fmt.Errorf("zFS: invalid directory length")
	}
	out := []EpisodeName{}
	names := map[string]bool{}
	for off := int64(0); off < data.Size(); off += 8192 {
		b := make([]byte, int(min(8192, data.Size()-off)))
		if _, err := data.ReadAt(b, off); err != nil {
			return nil, err
		}
		magic := uint32(0xb63185f6)
		if off == 0 {
			magic = 0x2c70bf7f
		}
		if len(b) < 160 || be.Uint32(b) != magic {
			return nil, fmt.Errorf("zFS: invalid directory page")
		}
		used := map[int]bool{}
		for bucket := 0; bucket < 128; bucket++ {
			slot := int(b[32+bucket])
			for slot != 0 {
				pos := slot * 32
				if slot < 5 || pos+32 > len(b) || used[slot] || be.Uint32(b[pos:]) != 0x76e694c1 || b[pos+14] != 1 {
					return nil, fmt.Errorf("zFS: invalid directory hash chain")
				}
				count := int(b[pos+13])
				end := pos + count*32
				if count == 0 || end > len(b) {
					return nil, fmt.Errorf("zFS: invalid name slot count")
				}
				for s := slot; s < slot+count; s++ {
					if used[s] {
						return nil, fmt.Errorf("zFS: overlapping name slots")
					}
					used[s] = true
				}
				payload := b[pos+15 : end]
				zero := bytes.IndexByte(payload, 0)
				if zero < 1 || zero > 255 {
					return nil, fmt.Errorf("zFS: unterminated name")
				}
				name := payload[:zero]
				if names[string(name)] || bytes.IndexByte(name, 0x61) >= 0 {
					return nil, fmt.Errorf("zFS: duplicate or invalid name")
				}
				names[string(name)] = true
				child, generation := be.Uint32(b[pos+4:]), be.Uint32(b[pos+8:])
				if string(name) == "\x4b" {
					if child != vnode {
						return nil, fmt.Errorf("zFS: invalid self link")
					}
				} else if string(name) != "\x4b\x4b" {
					if len(out) >= f.aggregate.limit {
						return nil, fmt.Errorf("zFS: directory entry limit exceeded")
					}
					target, err := f.Inode(child)
					if err != nil {
						return nil, err
					}
					// Restored directory entries may omit the generation (zero).
					if generation != 0 && target.Generation != generation {
						return nil, fmt.Errorf("zFS: stale directory reference to %d", child)
					}
					out = append(out, EpisodeName{bytes.Clone(name), child, generation})
				}
				slot = int(b[pos+12])
			}
		}
	}
	if !names["\x4b"] || !names["\x4b\x4b"] {
		return nil, fmt.Errorf("zFS: missing dot entries")
	}
	sort.Slice(out, func(i, j int) bool { return bytes.Compare(out[i].Name, out[j].Name) < 0 })
	return out, nil
}
func (e *Episode) View() auto.View {
	return auto.ViewFunc(func() ([]auto.Entry, error) {
		fs, err := e.Filesets()
		if err != nil {
			return nil, err
		}
		out := []auto.Entry{}
		seen := map[string]bool{}
		for _, f := range fs {
			if seen[f.Name] || f.Name == "" || f.Name == "." || f.Name == ".." {
				return nil, fmt.Errorf("zFS: invalid fileset name")
			}
			seen[f.Name] = true
			out = append(out, dir(f.Name, f.view(1, nil)))
		}
		return out, nil
	})
}
func (f *EpisodeFileset) view(vnode uint32, ancestors []uint32) auto.View {
	return auto.ViewFunc(func() ([]auto.Entry, error) {
		if len(ancestors) >= 256 {
			return nil, fmt.Errorf("zFS: directory depth limit")
		}
		for _, v := range ancestors {
			if v == vnode {
				return nil, fmt.Errorf("zFS: directory cycle")
			}
		}
		chain := append(append([]uint32(nil), ancestors...), vnode)
		names, err := f.Directory(vnode)
		if err != nil {
			return nil, err
		}
		out := []auto.Entry{}
		for _, n := range names {
			i, err := f.Inode(n.Vnode)
			if err != nil {
				return nil, err
			}
			entry := auto.Entry{Name: HFSDisplayName(n.Name), Kind: i.Kind, Attributes: map[string]any{"vnode": i.Vnode, "generation": i.Generation, "links": i.Links, "device": i.Device, "name_ebcdic": hex.EncodeToString(n.Name)}}
			switch i.Kind {
			case "directory":
				entry.View = f.view(i.Vnode, chain)
			case "file":
				entry.Reader, err = f.Data(i)
			case "symlink":
				if i.Size > 65536 {
					return nil, fmt.Errorf("zFS: oversized link")
				}
				var data storage.Reader
				data, err = f.Data(i)
				if err == nil {
					b := make([]byte, int(i.Size))
					_, err = data.ReadAt(b, 0)
					if bytes.IndexByte(b, 0) >= 0 {
						return nil, fmt.Errorf("zFS: invalid link target")
					}
					entry.Attributes["link"] = HFSDisplayName(b)
					entry.Attributes["link_ebcdic"] = hex.EncodeToString(b)
				}
			}
			if err != nil {
				return nil, err
			}
			out = append(out, entry)
		}
		return out, nil
	})
}

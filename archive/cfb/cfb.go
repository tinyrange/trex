// Package cfb reads Microsoft Compound File Binary storage (MS-CFB) directly
// from portable files. Stream sectors remain lazy views of the original input.
package cfb

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode/utf16"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

const end = uint32(0xfffffffe)
const free = uint32(0xffffffff)

type Archive struct {
	file         starfile.File
	sector       int64
	fat, miniFAT []uint32
	mini         starfile.File
	streams      map[string]*Stream
	ClassID      [16]byte
}
type directory struct {
	name                      string
	kind                      byte
	left, right, child, start uint32
	size                      uint64
	clsid                     [16]byte
}
type Stream struct {
	base                  starfile.File
	blocks                []uint32
	blockSize, bias, size int64
	name                  string
}

func Open(file starfile.File) (*Archive, error) {
	h := make([]byte, 512)
	if _, err := io.ReadFull(io.NewSectionReader(file, 0, 512), h); err != nil {
		return nil, err
	}
	if !bytes.Equal(h[:8], []byte{0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1}) {
		return nil, fmt.Errorf("cfb: invalid signature")
	}
	u16 := binary.LittleEndian.Uint16
	u32 := binary.LittleEndian.Uint32
	version, shift := u16(h[26:]), u16(h[30:])
	if u16(h[28:]) != 0xfffe || (version != 3 || shift != 9) && (version != 4 || shift != 12) || u16(h[32:]) != 6 || u32(h[56:]) != 4096 {
		return nil, fmt.Errorf("cfb: unsupported sector geometry")
	}
	a := &Archive{file: file, sector: int64(1) << shift, streams: map[string]*Stream{}}
	sectors := file.Size()/a.sector - 1
	if sectors < 1 || file.Size()%a.sector != 0 {
		return nil, fmt.Errorf("cfb: truncated sector data")
	}
	readSector := func(id uint32) ([]byte, error) {
		if int64(id) >= sectors {
			return nil, fmt.Errorf("cfb: sector %d out of bounds", id)
		}
		b := make([]byte, a.sector)
		_, err := io.ReadFull(io.NewSectionReader(file, (int64(id)+1)*a.sector, a.sector), b)
		return b, err
	}
	fatCount, difatCount := u32(h[44:]), u32(h[72:])
	if int64(fatCount) > sectors || int64(fatCount)*a.sector > 256<<20 || int64(difatCount) > sectors {
		return nil, fmt.Errorf("cfb: FAT allocation exceeds bounds")
	}
	fatIDs := make([]uint32, 0, fatCount)
	for pos := 76; pos < 512; pos += 4 {
		id := u32(h[pos:])
		if id != free {
			fatIDs = append(fatIDs, id)
		}
	}
	seen := map[uint32]bool{}
	next := u32(h[68:])
	for n := uint32(0); n < difatCount; n++ {
		if seen[next] {
			return nil, fmt.Errorf("cfb: cyclic DIFAT")
		}
		seen[next] = true
		data, err := readSector(next)
		if err != nil {
			return nil, err
		}
		for pos := 0; pos < len(data)-4; pos += 4 {
			id := u32(data[pos:])
			if id != free {
				fatIDs = append(fatIDs, id)
			}
		}
		next = u32(data[len(data)-4:])
	}
	// The CE5 SDK MSI ends the final declared DIFAT sector with FREESECT.
	// Accept that terminator only after consuming the declared sector count
	// and requiring the exact declared number of FAT sector references.
	if len(fatIDs) != int(fatCount) || difatCount > 0 && next != end && next != free {
		return nil, fmt.Errorf("cfb: inconsistent DIFAT length: FAT entries %d, declared %d, terminator %#x", len(fatIDs), fatCount, next)
	}
	seen = map[uint32]bool{}
	for _, id := range fatIDs {
		if seen[id] {
			return nil, fmt.Errorf("cfb: duplicate FAT sector")
		}
		seen[id] = true
		data, err := readSector(id)
		if err != nil {
			return nil, err
		}
		for pos := 0; pos < len(data); pos += 4 {
			a.fat = append(a.fat, u32(data[pos:]))
		}
	}
	if int64(len(a.fat)) < sectors {
		return nil, fmt.Errorf("cfb: FAT does not cover input")
	}
	dirBlocks, err := chain(a.fat, u32(h[48:]), sectors)
	if err != nil {
		return nil, err
	}
	if int64(len(dirBlocks))*a.sector > 64<<20 {
		return nil, fmt.Errorf("cfb: directory exceeds 64 MiB")
	}
	dirs := []directory{}
	for _, id := range dirBlocks {
		data, err := readSector(id)
		if err != nil {
			return nil, err
		}
		for pos := 0; pos < len(data); pos += 128 {
			b := data[pos : pos+128]
			d := directory{kind: b[66], left: u32(b[68:]), right: u32(b[72:]), child: u32(b[76:]), start: u32(b[116:]), size: binary.LittleEndian.Uint64(b[120:])}
			if version == 3 {
				d.size = uint64(u32(b[120:]))
			}
			if d.kind != 0 {
				n := int(u16(b[64:]))
				if n < 2 || n > 64 || n%2 != 0 || u16(b[n-2:]) != 0 {
					return nil, fmt.Errorf("cfb: invalid directory name")
				}
				units := make([]uint16, n/2-1)
				for i := range units {
					units[i] = u16(b[i*2:])
				}
				d.name = string(utf16.Decode(units))
				copy(d.clsid[:], b[80:96])
			}
			dirs = append(dirs, d)
		}
	}
	if len(dirs) == 0 || dirs[0].kind != 5 {
		return nil, fmt.Errorf("cfb: missing root storage")
	}
	a.ClassID = dirs[0].clsid
	a.mini, err = a.normalStream(dirs[0].start, dirs[0].size, "mini stream")
	if err != nil {
		return nil, err
	}
	miniCount := u32(h[64:])
	miniBlocks, err := chain(a.fat, u32(h[60:]), sectors)
	if err != nil {
		return nil, err
	}
	if len(miniBlocks) != int(miniCount) || int64(miniCount)*a.sector > 64<<20 {
		return nil, fmt.Errorf("cfb: inconsistent mini FAT size")
	}
	for _, id := range miniBlocks {
		data, err := readSector(id)
		if err != nil {
			return nil, err
		}
		for pos := 0; pos < len(data); pos += 4 {
			a.miniFAT = append(a.miniFAT, u32(data[pos:]))
		}
	}
	type item struct {
		id     uint32
		parent string
	}
	pending := []item{{dirs[0].child, ""}}
	visited := map[uint32]bool{0: true}
	for len(pending) > 0 {
		current := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		if current.id == free {
			continue
		}
		if int(current.id) >= len(dirs) || visited[current.id] {
			return nil, fmt.Errorf("cfb: cyclic or invalid directory tree")
		}
		visited[current.id] = true
		d := dirs[current.id]
		if d.kind != 1 && d.kind != 2 {
			return nil, fmt.Errorf("cfb: invalid directory object type")
		}
		if strings.ContainsAny(d.name, "/\\\x00") || d.name == "." || d.name == ".." {
			return nil, fmt.Errorf("cfb: invalid path component")
		}
		name := current.parent + "/" + d.name
		pending = append(pending, item{d.left, current.parent}, item{d.right, current.parent})
		if d.kind == 1 {
			pending = append(pending, item{d.child, name})
			continue
		}
		var stream *Stream
		if d.size < 4096 {
			blocks, e := sizedChain(a.miniFAT, d.start, d.size, 64, a.mini.Size()/64)
			if e != nil {
				return nil, fmt.Errorf("cfb: %s: %w", name, e)
			}
			stream = &Stream{base: a.mini, blocks: blocks, blockSize: 64, size: int64(d.size), name: name}
		} else {
			stream, err = a.normalStream(d.start, d.size, name)
			if err != nil {
				return nil, err
			}
		}
		key := strings.ToUpper(name)
		if _, exists := a.streams[key]; exists {
			return nil, fmt.Errorf("cfb: duplicate stream %s", name)
		}
		a.streams[key] = stream
	}
	return a, nil
}

func chain(fat []uint32, start uint32, limit int64) ([]uint32, error) {
	out := []uint32{}
	seen := map[uint32]bool{}
	for start != end {
		if int64(start) >= limit || int64(start) >= int64(len(fat)) || seen[start] {
			return nil, fmt.Errorf("cfb: cyclic or invalid sector chain at %d", start)
		}
		seen[start] = true
		out = append(out, start)
		start = fat[start]
	}
	return out, nil
}
func sizedChain(fat []uint32, start uint32, size uint64, blockSize, limit int64) ([]uint32, error) {
	if size == 0 {
		return nil, nil
	}
	if size > uint64(limit)*uint64(blockSize) {
		return nil, fmt.Errorf("cfb: stream size exceeds storage")
	}
	blocks, err := chain(fat, start, limit)
	if err != nil {
		return nil, err
	}
	if uint64(len(blocks)) != (size+uint64(blockSize)-1)/uint64(blockSize) {
		return nil, fmt.Errorf("cfb: stream chain length disagrees with size")
	}
	return blocks, nil
}
func (a *Archive) normalStream(start uint32, size uint64, name string) (*Stream, error) {
	b, e := sizedChain(a.fat, start, size, a.sector, a.file.Size()/a.sector-1)
	if e != nil {
		return nil, e
	}
	return &Stream{base: a.file, blocks: b, blockSize: a.sector, bias: a.sector, size: int64(size), name: name}, nil
}
func (a *Archive) Files() []string {
	out := []string{}
	for _, s := range a.streams {
		out = append(out, s.name)
	}
	sort.Strings(out)
	return out
}
func (a *Archive) Lookup(name string) *Stream {
	return a.streams[strings.ToUpper("/"+strings.TrimPrefix(name, "/"))]
}
func (s *Stream) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("cfb: negative offset")
	}
	if len(p) == 0 {
		return 0, nil
	}
	if off >= s.size {
		return 0, io.EOF
	}
	wanted := len(p)
	if int64(len(p)) > s.size-off {
		p = p[:s.size-off]
	}
	total := 0
	for len(p) > 0 {
		index := off / s.blockSize
		within := off % s.blockSize
		n := min(int64(len(p)), s.blockSize-within)
		read, err := s.base.ReadAt(p[:n], s.bias+int64(s.blocks[index])*s.blockSize+within)
		total += read
		off += int64(read)
		p = p[read:]
		if err != nil {
			return total, err
		}
		if int64(read) != n {
			return total, io.ErrUnexpectedEOF
		}
	}
	if total < wanted {
		return total, io.EOF
	}
	return total, nil
}
func (s *Stream) Size() int64                           { return s.size }
func (*Stream) WriteAt([]byte, int64) (int, error)      { return 0, fmt.Errorf("cfb: read-only stream") }
func (s *Stream) String() string                        { return "<cfb stream " + s.name + ">" }
func (*Stream) Type() string                            { return "file" }
func (*Stream) Freeze()                                 {}
func (*Stream) Truth() starlark.Bool                    { return starlark.True }
func (*Stream) Hash() (uint32, error)                   { return 0, fmt.Errorf("unhashable: file") }
func (s *Stream) Attr(n string) (starlark.Value, error) { return starfile.Attr(s, n), nil }
func (*Stream) AttrNames() []string                     { return starfile.AttrNames() }

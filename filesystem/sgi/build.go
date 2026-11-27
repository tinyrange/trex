package sgi

import (
	"encoding/binary"
	"fmt"
	"math"
	"strings"

	"github.com/tinyrange/trex/filesystem"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

// DiskPartition assigns a sector-aligned payload to an ordinary SGI partition.
type DiskPartition struct {
	Index int
	Type  uint32
	Data  starfile.File
}

// Build lays out the supplied partitions in order alongside a volume header
// and a whole-volume partition. Optional boot files occupy the volume header.
// It borrows the payloads and represents holes as zero-filled ranges.
func Build(partitions []DiskPartition, root, swap int, bootfile string, headerBlocks uint32, files ...BootFile) (starfile.File, error) {
	if root < 0 || root >= 16 || swap < 0 || swap >= 16 || len(bootfile) > 16 || strings.IndexByte(bootfile, 0) != -1 {
		return nil, fmt.Errorf("sgi: invalid root, swap or boot filename")
	}
	if headerBlocks < 1 || len(partitions) == 0 || len(partitions) > 14 || len(files) > 15 {
		return nil, fmt.Errorf("sgi: invalid volume header or partition count")
	}

	header := make([]byte, 512)
	be := binary.BigEndian
	be.PutUint32(header, 0x0be5a941)
	be.PutUint16(header[4:], uint16(root))
	be.PutUint16(header[6:], uint16(swap))
	copy(header[8:24], bootfile)
	be.PutUint16(header[40:], 512) // Device parameter dp_secbytes.

	putPartition := func(index int, count, start, kind uint32) {
		entry := header[312+12*index:]
		be.PutUint32(entry, count)
		be.PutUint32(entry[4:], start)
		be.PutUint32(entry[8:], kind)
	}
	putPartition(8, headerBlocks, 0, 0)

	var used [16]bool
	used[8], used[10] = true, true
	next := uint64(headerBlocks)
	extents := []filesystem.ExtentSpec{{Start: 0, Size: 512, File: &starfile.Bytes{Name: "SGI volume header", Data: header}}}
	seenFiles := map[string]bool{}
	fileBlock := uint32(1)
	for i, file := range files {
		if len(file.Name) == 0 || len(file.Name) > 8 || strings.ContainsAny(file.Name, "\x00/") || seenFiles[file.Name] || file.Data == nil {
			return nil, fmt.Errorf("sgi: invalid or duplicate volume-header file %q", file.Name)
		}
		size := file.Data.Size()
		if size <= 0 || size > math.MaxUint32 || (size+511)/512 > int64(headerBlocks-fileBlock) {
			return nil, fmt.Errorf("sgi: volume-header file %q exceeds capacity", file.Name)
		}
		seenFiles[file.Name] = true
		dir := header[72+16*i:]
		copy(dir, file.Name)
		be.PutUint32(dir[8:], fileBlock)
		be.PutUint32(dir[12:], uint32(size))
		extents = append(extents, filesystem.ExtentSpec{Start: int64(fileBlock) * 512, Size: size, File: file.Data})
		fileBlock += uint32((size + 511) / 512)
	}
	for _, p := range partitions {
		if p.Index < 0 || p.Index >= len(used) || used[p.Index] || p.Type == 0 || p.Type == 6 || p.Data == nil {
			return nil, fmt.Errorf("sgi: invalid or duplicate partition %d", p.Index)
		}
		size := p.Data.Size()
		if size <= 0 || size%512 != 0 || uint64(size/512) > math.MaxUint32-next {
			return nil, fmt.Errorf("sgi: invalid size for partition %d", p.Index)
		}
		count := uint64(size / 512)
		putPartition(p.Index, uint32(count), uint32(next), p.Type)
		extents = append(extents, filesystem.ExtentSpec{Start: int64(next) * 512, Size: size, File: p.Data})
		used[p.Index] = true
		next += count
	}
	if !used[root] || !used[swap] || root == 8 || root == 10 || swap == 8 || swap == 10 {
		return nil, fmt.Errorf("sgi: root and swap must name supplied disk partitions")
	}

	putPartition(10, uint32(next), 0, 6)
	var sum uint32
	for i := 0; i < len(header); i += 4 {
		sum += be.Uint32(header[i:])
	}
	be.PutUint32(header[504:], -sum)
	return filesystem.NewGeneratedImage("SGI disk", int64(next)*512, extents), nil
}

func BuildBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var entries starlark.Iterable
	var bootfile string
	var bootFiles *starlark.Dict
	root, swap, headerBlocks := 0, 1, uint32(64)
	if err := starlark.UnpackArgs("sgi_build", args, kwargs, "partitions", &entries, "root?", &root, "swap?", &swap,
		"bootfile?", &bootfile, "header_blocks?", &headerBlocks, "volume_files?", &bootFiles); err != nil {
		return nil, err
	}
	var parts []DiskPartition
	for value := range starlark.Elements(entries) {
		tuple, ok := value.(starlark.Tuple)
		if !ok || len(tuple) != 3 || len(parts) >= 14 {
			return nil, fmt.Errorf("sgi_build: expected (index, type, file) partition tuples")
		}
		var p DiskPartition
		if err := starlark.AsInt(tuple[0], &p.Index); err != nil {
			return nil, err
		}
		if err := starlark.AsInt(tuple[1], &p.Type); err != nil {
			return nil, err
		}
		p.Data, ok = tuple[2].(starfile.File)
		if !ok {
			return nil, fmt.Errorf("sgi_build: expected a file for partition %d", p.Index)
		}
		parts = append(parts, p)
	}
	var files []BootFile
	if bootFiles != nil {
		if bootFiles.Len() > 15 {
			return nil, fmt.Errorf("sgi_build: too many volume-header files")
		}
		for _, pair := range bootFiles.Items() {
			name, ok := starlark.AsString(pair[0])
			data, isFile := pair[1].(starfile.File)
			if !ok || !isFile {
				return nil, fmt.Errorf("sgi_build: volume_files must map names to files")
			}
			files = append(files, BootFile{Name: name, Data: data})
		}
	}
	return Build(parts, root, swap, bootfile, headerBlocks, files...)
}

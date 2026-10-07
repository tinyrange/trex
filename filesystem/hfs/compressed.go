package hfs

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"github.com/tinyrange/trex/archive/macresource"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"io"
	"math"
	"sync"
)

const compressionBlock = 65536
const compressionBlocks = 1000000

type compressionChunk struct {
	source       storage.Reader
	offset, size int64
}
type compressedFork struct {
	size   int64
	chunks []compressionChunk
	mu     sync.Mutex
	cached int
	data   []byte
}

func (f *compressedFork) Size() int64 { return f.size }
func inflate(source storage.Reader, off, size, wanted int64) ([]byte, error) {
	if wanted < 0 || wanted > compressionBlock || size <= 0 || size > compressionBlock+1024 {
		return nil, fmt.Errorf("hfs+: invalid decmpfs chunk bounds")
	}
	b := make([]byte, size)
	if _, err := io.ReadFull(io.NewSectionReader(source, off, size), b); err != nil {
		return nil, err
	}
	if b[0] == 0xff {
		if int64(len(b)-1) != wanted {
			return nil, fmt.Errorf("hfs+: stored decmpfs size mismatch")
		}
		return b[1:], nil
	}
	input := bytes.NewReader(b)
	z, err := zlib.NewReader(input)
	if err != nil {
		return nil, err
	}
	decoded, err := io.ReadAll(io.LimitReader(z, wanted+1))
	closeErr := z.Close()
	if err != nil {
		return nil, err
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if int64(len(decoded)) != wanted || input.Len() != 0 {
		return nil, fmt.Errorf("hfs+: decmpfs length/trailing mismatch")
	}
	return decoded, nil
}
func (f *compressedFork) ReadAt(p []byte, off int64) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if off < 0 {
		return 0, fmt.Errorf("hfs+: negative compressed fork offset")
	}
	if len(p) == 0 {
		return 0, nil
	}
	if off >= f.size {
		return 0, io.EOF
	}
	wanted := len(p)
	done := 0
	for len(p) > 0 && off < f.size {
		index := int(off / compressionBlock)
		if f.cached != index || f.data == nil {
			c := f.chunks[index]
			data, err := inflate(c.source, c.offset, c.size, min(compressionBlock, f.size-int64(index)*compressionBlock))
			if err != nil {
				return done, fmt.Errorf("hfs+: decmpfs chunk %d: %w", index, err)
			}
			f.cached = index
			f.data = data
		}
		n := copy(p, f.data[off%compressionBlock:])
		done += n
		off += int64(n)
		p = p[n:]
	}
	if done != wanted {
		return done, io.EOF
	}
	return done, nil
}
func compressedData(attr, resource starfile.File) (starfile.File, uint32, error) {
	var header [16]byte
	if attr == nil || attr.Size() < 16 {
		return nil, 0, fmt.Errorf("hfs+: missing/truncated decmpfs attribute")
	}
	if _, err := attr.ReadAt(header[:], 0); err != nil {
		return nil, 0, err
	}
	le := binary.LittleEndian
	kind, size := le.Uint32(header[4:]), le.Uint64(header[8:])
	if string(header[:4]) != "fpmc" || size > math.MaxInt64 || size > compressionBlocks*compressionBlock {
		return nil, 0, fmt.Errorf("hfs+: invalid decmpfs header/size")
	}
	f := &compressedFork{size: int64(size), cached: -1}
	switch kind {
	case 3:
		if size > compressionBlock {
			return nil, 0, fmt.Errorf("hfs+: inline decmpfs size exceeds one block")
		}
		f.chunks = []compressionChunk{{source: attr, offset: 16, size: attr.Size() - 16}}
	case 4:
		if attr.Size() != 16 || resource == nil {
			return nil, 0, fmt.Errorf("hfs+: invalid resource decmpfs attribute")
		}
		fork, err := macresource.Open(resource, 1000)
		if err != nil {
			return nil, 0, err
		}
		var data starfile.File
		for _, e := range fork.Entries {
			if string(e.Type[:]) == "cmpf" {
				if data != nil {
					return nil, 0, fmt.Errorf("hfs+: duplicate cmpf resource")
				}
				data = e.Data
			}
		}
		if data == nil || data.Size() < 4 {
			return nil, 0, fmt.Errorf("hfs+: missing cmpf resource")
		}
		var countBytes [4]byte
		if _, err := data.ReadAt(countBytes[:], 0); err != nil {
			return nil, 0, err
		}
		count := int64(le.Uint32(countBytes[:]))
		if count != (int64(size)+compressionBlock-1)/compressionBlock || count > compressionBlocks || count > (data.Size()-4)/8 {
			return nil, 0, fmt.Errorf("hfs+: invalid decmpfs chunk count")
		}
		table := make([]byte, 8*count)
		if _, err := data.ReadAt(table, 4); err != nil {
			return nil, 0, err
		}
		previous := 4 + 8*count
		for i := int64(0); i < count; i++ {
			off, n := int64(le.Uint32(table[8*i:])), int64(le.Uint32(table[8*i+4:]))
			if off != previous || n <= 0 || n > compressionBlock+1024 || off > data.Size() || n > data.Size()-off {
				return nil, 0, fmt.Errorf("hfs+: invalid decmpfs chunk extent")
			}
			f.chunks = append(f.chunks, compressionChunk{data, off, n})
			previous = off + n
		}
		if previous != data.Size() {
			return nil, 0, fmt.Errorf("hfs+: trailing decmpfs resource bytes")
		}
	default:
		return nil, 0, fmt.Errorf("hfs+: unsupported decmpfs compression %d", kind)
	}
	if size == 0 {
		if kind != 3 {
			return nil, 0, fmt.Errorf("hfs+: empty resource decmpfs")
		}
		c := f.chunks[0]
		if _, err := inflate(c.source, c.offset, c.size, 0); err != nil {
			return nil, 0, err
		}
	}
	return starfile.NewReader("decmpfs", f), kind, nil
}
func decodeCompressed(v *Volume, raw bool) error {
	for i := range v.Entries {
		e := &v.Entries[i]
		if e.Kind != "file" || e.OwnerFlags&0x20 == 0 {
			continue
		}
		if len(e.FinderInfo) >= 8 && string(e.FinderInfo[:8]) == "hlnkhfs+" {
			continue
		}
		attr := e.Xattrs["com.apple.decmpfs"]
		if raw {
			continue
		}
		data, kind, err := compressedData(attr, e.Resource)
		if err != nil {
			return fmt.Errorf("hfs+: %s: %w", e.Path, err)
		}
		e.RawData = e.Data
		e.Data = data
		e.CompressionType = kind
	}
	return nil
}

// Package zfs reads single-vdev, unencrypted ZFS images without importing pools.
// Disk layout facts follow the published OpenZFS on-disk structure declarations.
// This is original Go code, not a translation of the OpenZFS implementation.
package zfs

import (
	"bytes"
	"compress/zlib"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"github.com/tinyrange/trex/storage"
	"io"
	"sync"
)

var le = binary.LittleEndian
var be = binary.BigEndian

const maxBlock = 32 << 20
const labelBias = 4 << 20

func order(little bool) binary.ByteOrder {
	if little {
		return le
	}
	return be
}

type pointer struct {
	b []byte
	o binary.ByteOrder
}
type pool struct {
	source         storage.Reader
	maximum, depth int
	mu             sync.Mutex
	cache          map[string][]byte
	cached         int
}

func read(r storage.Reader, at int64, n int) ([]byte, error) {
	if at < 0 || n < 0 || at > r.Size() || int64(n) > r.Size()-at {
		return nil, fmt.Errorf("zfs: read outside image")
	}
	b := make([]byte, n)
	_, err := io.ReadFull(io.NewSectionReader(r, at, int64(n)), b)
	return b, err
}
func (p *pool) block(bp pointer) ([]byte, binary.ByteOrder, error) {
	if len(bp.b) < 128 {
		return nil, nil, fmt.Errorf("zfs: short block pointer")
	}
	prop := bp.o.Uint64(bp.b[48:])
	o := order(prop>>63 != 0)
	if prop&(1<<61) != 0 {
		return nil, nil, fmt.Errorf("zfs: encrypted/authenticated block unsupported")
	}
	logical := int((prop&65535)+1) * 512
	physical := int((prop>>16&65535)+1) * 512
	codec := int(prop >> 32 & 127)
	if prop&(1<<39) != 0 {
		if prop>>40&255 != 0 {
			return nil, nil, fmt.Errorf("zfs: unsupported embedded block type")
		}
		logical = int(prop&((1<<25)-1)) + 1
		physical = int(prop>>25&127) + 1
		if physical > 112 {
			return nil, nil, fmt.Errorf("zfs: embedded length out of bounds")
		}
		var data []byte
		for i := 0; i < 16; i++ {
			if i == 6 || i == 10 {
				continue
			}
			var word [8]byte
			le.PutUint64(word[:], bp.o.Uint64(bp.b[i*8:]))
			data = append(data, word[:]...)
		}
		b, err := decompress(codec, data[:physical], logical)
		return b, o, err
	}
	if bytes.Equal(bp.b[:48], make([]byte, 48)) {
		return make([]byte, logical), o, nil
	}
	if logical > maxBlock || physical > maxBlock {
		return nil, nil, fmt.Errorf("zfs: block limit")
	}
	key := string(bp.b) + fmt.Sprint(bp.o)
	p.mu.Lock()
	cached := p.cache[key]
	p.mu.Unlock()
	if cached != nil {
		return cached, o, nil
	}
	var last error
	for i := 0; i < 3; i++ {
		a, b := bp.o.Uint64(bp.b[i*16:]), bp.o.Uint64(bp.b[i*16+8:])
		if a == 0 && b == 0 {
			continue
		}
		if a>>32 != 0 || b>>63 != 0 {
			last = fmt.Errorf("zfs: multiple-vdev or gang block unsupported")
			continue
		}
		sector := b & ((1 << 63) - 1)
		if sector > uint64(p.source.Size())/512 {
			last = fmt.Errorf("zfs: DVA outside image")
			continue
		}
		data, err := read(p.source, int64(sector)*512+labelBias, physical)
		if err != nil {
			last = err
			continue
		}
		if err = checksum(data, bp, int(prop>>40&255), o); err != nil {
			last = err
			continue
		}
		out, err := decompress(codec, data, logical)
		if err != nil {
			return nil, nil, err
		}
		p.mu.Lock()
		if p.cached+len(out) > 64<<20 {
			p.cache = map[string][]byte{}
			p.cached = 0
		}
		p.cache[key] = out
		p.cached += len(out)
		p.mu.Unlock()
		return out, o, nil
	}
	if last == nil {
		last = fmt.Errorf("zfs: missing DVA")
	}
	return nil, nil, last
}
func checksum(data []byte, bp pointer, kind int, o binary.ByteOrder) error {
	var got [4]uint64
	switch kind {
	case 2:
		return nil
	case 7:
		for i := 0; i+4 <= len(data); i += 4 {
			got[0] += uint64(o.Uint32(data[i:]))
			got[1] += got[0]
			got[2] += got[1]
			got[3] += got[2]
		}
	case 6:
		for i := 0; i+16 <= len(data); i += 16 {
			got[0] += o.Uint64(data[i:])
			got[1] += o.Uint64(data[i+8:])
			got[2] += got[0]
			got[3] += got[1]
		}
	case 8:
		h := sha256.Sum256(data)
		for i := range got {
			got[i] = be.Uint64(h[i*8:])
		}
	default:
		return fmt.Errorf("zfs: checksum %d unsupported", kind)
	}
	for i, g := range got {
		if g != bp.o.Uint64(bp.b[96+i*8:]) {
			return fmt.Errorf("zfs: block checksum mismatch (algorithm %d)", kind)
		}
	}
	return nil
}
func decompress(codec int, data []byte, size int) ([]byte, error) {
	if size < 0 || size > maxBlock {
		return nil, fmt.Errorf("zfs: expanded block limit")
	}
	out := make([]byte, 0, size)
	switch {
	case codec == 2:
		if len(data) < size {
			return nil, io.ErrUnexpectedEOF
		}
		return append(out, data[:size]...), nil
	case codec == 4:
		return make([]byte, size), nil
	case codec >= 5 && codec <= 13:
		r, err := zlib.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		defer r.Close()
		out, err = io.ReadAll(io.LimitReader(r, int64(size)+1))
		if err != nil {
			return nil, err
		}
	case codec == 15:
		if len(data) < 4 {
			return nil, io.ErrUnexpectedEOF
		}
		n := int(be.Uint32(data))
		if n > len(data)-4 {
			return nil, fmt.Errorf("zfs: invalid LZ4 size")
		}
		data = data[4 : 4+n]
		for len(data) > 0 {
			token := data[0]
			data = data[1:]
			literal := int(token >> 4)
			if literal == 15 {
				for {
					if len(data) == 0 {
						return nil, io.ErrUnexpectedEOF
					}
					x := int(data[0])
					data = data[1:]
					literal += x
					if x != 255 {
						break
					}
				}
			}
			if literal > len(data) || literal > size-len(out) {
				return nil, fmt.Errorf("zfs: LZ4 literal out of bounds")
			}
			out = append(out, data[:literal]...)
			data = data[literal:]
			if len(data) == 0 {
				break
			}
			if len(data) < 2 {
				return nil, io.ErrUnexpectedEOF
			}
			distance := int(le.Uint16(data))
			data = data[2:]
			length := int(token&15) + 4
			if token&15 == 15 {
				for {
					if len(data) == 0 {
						return nil, io.ErrUnexpectedEOF
					}
					x := int(data[0])
					data = data[1:]
					length += x
					if x != 255 {
						break
					}
				}
			}
			if distance == 0 || distance > len(out) || length > size-len(out) {
				return nil, fmt.Errorf("zfs: LZ4 match out of bounds")
			}
			for i := 0; i < length; i++ {
				out = append(out, out[len(out)-distance])
			}
		}
	case codec == 3:
		for len(out) < size {
			if len(data) == 0 {
				return nil, io.ErrUnexpectedEOF
			}
			mask := data[0]
			data = data[1:]
			for bit := byte(1); bit != 0 && len(out) < size; bit <<= 1 {
				if mask&bit == 0 {
					if len(data) == 0 {
						return nil, io.ErrUnexpectedEOF
					}
					out = append(out, data[0])
					data = data[1:]
				} else {
					if len(data) < 2 {
						return nil, io.ErrUnexpectedEOF
					}
					length := int(data[0]>>2) + 3
					distance := int(data[0]&3)<<8 | int(data[1])
					data = data[2:]
					if distance == 0 || distance > len(out) || length > size-len(out) {
						return nil, fmt.Errorf("zfs: LZJB match out of bounds")
					}
					for i := 0; i < length; i++ {
						out = append(out, out[len(out)-distance])
					}
				}
			}
		}
	default:
		return nil, fmt.Errorf("zfs: compression %d unsupported", codec)
	}
	if len(out) != size {
		return nil, fmt.Errorf("zfs: decompressed size mismatch %d != %d", len(out), size)
	}
	return out, nil
}

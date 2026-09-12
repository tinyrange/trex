package bzip2

import (
	"bytes"
	"fmt"
	"github.com/tinyrange/trex/archive/internal/bzip2"
	"io"
	"sort"
	"sync"

	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/storage"
)

const blockMagic uint64 = 0x314159265359
const endMagic uint64 = 0x177245385090
const cacheBytes = 2 << 20

type marker struct {
	bit   int64
	magic uint64
}
type block struct {
	start, end  int64
	size        int64
	crc         uint32
	data        []byte
	dataOffset  int64
	used        uint64
	level       byte
	streamEnd   bool
	expectedCRC uint32
}

// Reader indexes bzip2 block boundaries in the compressed source. Decoded block
// lengths are retained; data uses a bounded cache. No decoded host files are used.
type Reader struct {
	source  storage.Reader
	maximum int64
	mu      sync.Mutex
	once    sync.Once
	blocks  []block
	indexed int
	length  int64
	err     error
	cached  int64
	tick    uint64
	level   byte
}

func NewReader(source storage.Reader, maximum int64) *Reader {
	return &Reader{source: source, maximum: maximum}
}
func (r *Reader) KnownSize() (int64, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.length, r.indexed == len(r.blocks) && r.err == nil && len(r.blocks) > 0
}
func (r *Reader) Size() int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.init()
	r.ensure(int64(^uint64(0) >> 1))
	if r.err != nil {
		return -1
	}
	return r.length
}
func (r *Reader) init() { r.once.Do(func() { r.err = r.scan() }) }

func (r *Reader) scan() error {
	var header [4]byte
	if _, err := r.source.ReadAt(header[:], 0); err != nil {
		return err
	}
	if string(header[:3]) != "BZh" || header[3] < '1' || header[3] > '9' {
		return fmt.Errorf("bzip2: invalid header")
	}
	r.level = header[3]
	// Search all bit alignments using byte needles; retain overlap at chunk edges.
	var marks []marker
	const window = 4 << 20
	buf := make([]byte, window+16)
	for off := int64(0); off < r.source.Size(); off += window {
		count := min(int64(len(buf)), r.source.Size()-off)
		n, err := r.source.ReadAt(buf[:count], off)
		if err != nil && err != io.EOF {
			return err
		}
		data := buf[:n]
		for _, magic := range []uint64{blockMagic, endMagic} {
			for shift := 0; shift < 8; shift++ {
				// The five whole bytes following a possible partial first byte.
				var needle [5]byte
				value := magic
				skip := 0
				if shift > 0 {
					value = magic << (8 - shift)
					skip = 1
				}
				for j := 0; j < 5; j++ {
					needle[j] = byte(value >> uint(40-8*j))
				}
				for at := 0; at+5 <= len(data); {
					found := bytes.Index(data[at:], needle[:])
					if found < 0 {
						break
					}
					found += at
					at = found + 1
					bit := (off+int64(found-skip))*8 + int64(shift)
					if bit < 32 || bit >= min(off+window, r.source.Size())*8 {
						continue
					}
					if readBits(data, bit-off*8, 48) == magic {
						marks = append(marks, marker{bit, magic})
					}
				}
			}
		}
	}
	sort.Slice(marks, func(i, j int) bool { return marks[i].bit < marks[j].bit })
	next := int64(32)
	level := r.level
	first := 0
	for i, m := range marks {
		if i == 0 && m.bit != next {
			return fmt.Errorf("bzip2: missing first block")
		}
		if m.magic == blockMagic {
			if i+1 == len(marks) {
				return io.ErrUnexpectedEOF
			}
			r.blocks = append(r.blocks, block{start: m.bit, end: marks[i+1].bit, level: level})
			continue
		}
		var tail [11]byte
		n, err := r.source.ReadAt(tail[:], m.bit/8)
		if err != nil && err != io.EOF {
			return err
		}
		if m.bit%8+80 > int64(n*8) {
			return io.ErrUnexpectedEOF
		}
		crc := uint32(readBits(tail[:n], m.bit%8+48, 32))
		if len(r.blocks) == first {
			if crc != 0 {
				return fmt.Errorf("bzip2: empty stream checksum mismatch")
			}
		} else {
			last := &r.blocks[len(r.blocks)-1]
			last.streamEnd, last.expectedCRC = true, crc
		}
		first = len(r.blocks)
		nextByte := (m.bit + 80 + 7) / 8
		if nextByte == r.source.Size() {
			if i != len(marks)-1 {
				return fmt.Errorf("bzip2: unexpected trailing blocks")
			}
			return nil
		}
		if _, err := r.source.ReadAt(header[:], nextByte); err != nil {
			return err
		}
		if string(header[:3]) != "BZh" || header[3] < '1' || header[3] > '9' {
			return fmt.Errorf("bzip2: invalid concatenated stream")
		}
		level = header[3]
		next = nextByte*8 + 32
		if i+1 == len(marks) || marks[i+1].bit != next {
			return fmt.Errorf("bzip2: missing concatenated block")
		}
	}
	return io.ErrUnexpectedEOF
}
func readBits(data []byte, off int64, n int) uint64 {
	if off < 0 || off+int64(n) > int64(len(data))*8 {
		return 0
	}
	var result uint64
	for n > 0 {
		take := min(n, 8-int(off%8))
		result = result<<take | uint64(data[off/8]>>uint(8-int(off%8)-take)&byte((1<<take)-1))
		off += int64(take)
		n -= take
	}
	return result
}
func (r *Reader) decode(i int, keep bool) ([]byte, uint32, int64, error) {
	b := r.blocks[i]
	bits := b.end - b.start
	raw := make([]byte, (bits+b.start%8+7)/8)
	if _, err := r.source.ReadAt(raw, b.start/8); err != nil {
		return nil, 0, 0, err
	}
	// Reframe one block as a complete bzip2 stream, preserving its own CRC.
	encoded := make([]byte, 4+(bits+80+7)/8)
	copy(encoded, []byte{'B', 'Z', 'h', b.level})
	shift := uint(b.start % 8)
	for j := int64(0); j < (bits+7)/8; j++ {
		v := raw[j] << shift
		if shift != 0 && j+1 < int64(len(raw)) {
			v |= raw[j+1] >> (8 - shift)
		}
		encoded[4+j] = v
	}
	crc := uint32(readBits(raw, b.start%8+48, 32))
	for j := 0; j < 80; j++ {
		var v uint64
		if j < 48 {
			v = endMagic >> uint(47-j)
		} else {
			v = uint64(crc) >> uint(79-j)
		}
		pos := 32 + bits + int64(j)
		mask := byte(1 << uint(7-pos%8))
		encoded[pos/8] &= ^mask
		if v&1 != 0 {
			encoded[pos/8] |= mask
		}
	}
	decoder := io.LimitReader(bzip2.NewReader(bytes.NewReader(encoded)), r.maximum+1)
	if !keep {
		n, err := io.Copy(io.Discard, decoder)
		if n > r.maximum {
			return nil, 0, 0, auto.ErrLimit
		}
		return nil, crc, n, err
	}
	data, err := io.ReadAll(decoder)
	if int64(len(data)) > r.maximum {
		return nil, 0, 0, auto.ErrLimit
	}
	return data, crc, int64(len(data)), err
}
func (r *Reader) retain(i int, data []byte) {
	r.retainAt(i, data, 0)
}

// RLE can expand one bzip2 block beyond the cache budget. Retain a window
// around the requested offset instead of decoding that block for every tiny
// archive-header read. Copy the window so it does not retain the whole block.
func (r *Reader) retainAt(i int, data []byte, offset int64) {
	start := int64(0)
	if len(data) > cacheBytes {
		start = offset / cacheBytes * cacheBytes
		data = bytes.Clone(data[start:min(int64(len(data)), start+cacheBytes)])
	}
	r.tick++
	r.blocks[i].used = r.tick
	r.cached -= int64(len(r.blocks[i].data))
	r.blocks[i].data = data
	r.blocks[i].dataOffset = start
	r.cached += int64(len(data))
	for r.cached > cacheBytes {
		victim := -1
		for j := range r.blocks {
			if j != i && r.blocks[j].data != nil && (victim < 0 || r.blocks[j].used < r.blocks[victim].used) {
				victim = j
			}
		}
		if victim < 0 {
			break
		}
		r.cached -= int64(len(r.blocks[victim].data))
		r.blocks[victim].data = nil
	}
}
func (r *Reader) ensure(end int64) {
	for r.err == nil && r.length < end && r.indexed < len(r.blocks) {
		// Two independent blocks use both cores on small NAS systems. Keep the
		// initial prefix cheap; subsequent forward seeks use paired decoding.
		count := 1
		if r.indexed > 0 && end-r.length > int64(r.blocks[r.indexed].level-'0')*100000 {
			count = min(2, len(r.blocks)-r.indexed)
		}
		type result struct {
			data []byte
			crc  uint32
			err  error
			size int64
		}
		results := make([]result, count)
		var wg sync.WaitGroup
		for j := 0; j < count; j++ {
			wg.Add(1)
			go func(j int) {
				defer wg.Done()
				keep := r.indexed == 0 || end-r.length <= int64(r.blocks[r.indexed+j].level-'0')*100000*52
				results[j].data, results[j].crc, results[j].size, results[j].err = r.decode(r.indexed+j, keep)
			}(j)
		}
		wg.Wait()
		for _, result := range results {
			if result.err != nil {
				r.err = result.err
				return
			}
			if result.size > r.maximum-r.length {
				r.err = auto.ErrLimit
				return
			}
			i := r.indexed
			r.blocks[i].size = result.size
			r.blocks[i].crc = result.crc
			r.length += r.blocks[i].size
			if result.data != nil {
				r.retain(i, result.data)
			}
			r.indexed++
		}
	}
	if r.err == nil {
		var crc uint32
		for _, b := range r.blocks[:r.indexed] {
			crc = (crc<<1 | crc>>31) ^ b.crc
			if b.streamEnd {
				if crc != b.expectedCRC {
					r.err = fmt.Errorf("bzip2: stream checksum mismatch")
					return
				}
				crc = 0
			}
		}
	}
}
func (r *Reader) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off > int64(^uint64(0)>>1)-int64(len(p)) {
		return 0, fmt.Errorf("bzip2: invalid offset")
	}
	if len(p) == 0 {
		return 0, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.init()
	r.ensure(off + int64(len(p)))
	if r.err != nil {
		return 0, r.err
	}
	n := 0
	start := int64(0)
	for i := 0; i < r.indexed && n < len(p); i++ {
		b := &r.blocks[i]
		end := start + b.size
		if off < end {
			data := b.data
			local := off - start
			need := min(int64(len(p)-n), end-off)
			dataOffset := b.dataOffset
			if data == nil || local < dataOffset || local+need > dataOffset+int64(len(data)) {
				var err error
				data, _, _, err = r.decode(i, true)
				if err != nil {
					return n, err
				}
				r.retainAt(i, data, local)
				dataOffset = 0
			} else {
				r.tick++
				b.used = r.tick
			}
			copied := copy(p[n:n+int(need)], data[local-dataOffset:])
			n += copied
			off += int64(copied)
		}
		start = end
	}
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

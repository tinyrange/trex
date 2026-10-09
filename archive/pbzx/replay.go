package pbzx

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/klauspost/compress/s2"
	"github.com/tinyrange/trex/archive/xz"
	bytecache "github.com/tinyrange/trex/storage/cache"
)

// ReplayBlockSize is independent of the original PBZX/XZ chunk framing.
// A small read replays at most the intersecting blocks, not an entire chunk.
const ReplayBlockSize = 64 << 10

func (f *File) decodeChunk(c Chunk) ([]byte, error) {
	// Do not retain xz.File: it retains an LZMA dictionary after EOF.
	decoded, err := xz.Open(c.reader, MaxChunk)
	if err != nil {
		return nil, err
	}
	b := make([]byte, c.Size)
	// Do not use ReadFull: it suppresses trailing checksum errors when n==len.
	n, err := decoded.ReadAt(b, 0)
	if err != nil {
		return nil, err
	}
	if n != len(b) {
		return nil, io.ErrUnexpectedEOF
	}
	f.xzChunks.Add(1)
	f.xzBytes.Add(uint64(n))
	return b, nil
}

// encodeReplay is an internal, ephemeral index plus independent S2 blocks.
// One original chunk is admitted/evicted atomically; individual decoded pages
// have separate LRU keys, so replay does not pollute the cache with unused pages.
func encodeReplay(data []byte) []byte {
	blocks := (len(data) + ReplayBlockSize - 1) / ReplayBlockSize
	header := 4 * (blocks + 1)
	encoded := make([]byte, header, header+blocks*s2.MaxEncodedLen(ReplayBlockSize))
	scratch := make([]byte, 0, s2.MaxEncodedLen(ReplayBlockSize))
	for i := 0; i < blocks; i++ {
		binary.LittleEndian.PutUint32(encoded[4*i:], uint32(len(encoded)))
		start := i * ReplayBlockSize
		compressed := s2.Encode(scratch, data[start:min(start+ReplayBlockSize, len(data))])
		encoded = append(encoded, compressed...)
	}
	binary.LittleEndian.PutUint32(encoded[4*blocks:], uint32(len(encoded)))
	// Charge the entire retained backing array, not an encoded-length slice of
	// a worst-case-sized allocation. Includes the index and incompressible data.
	retained := make([]byte, len(encoded))
	copy(retained, encoded)
	return retained
}

func decodeReplayBlock(encoded []byte, size int64, page int64) ([]byte, error) {
	blocks := (size + ReplayBlockSize - 1) / ReplayBlockSize
	header := 4 * (blocks + 1)
	if size <= 0 || size > MaxChunk || page < 0 || page >= blocks || int64(len(encoded)) < header {
		return nil, fmt.Errorf("invalid PBZX replay block index")
	}
	start := int64(binary.LittleEndian.Uint32(encoded[page*4:]))
	end := int64(binary.LittleEndian.Uint32(encoded[(page+1)*4:]))
	if start < header || end <= start || end > int64(len(encoded)) {
		return nil, fmt.Errorf("invalid PBZX replay block bounds")
	}
	block := encoded[start:end]
	expected := min(int64(ReplayBlockSize), size-page*ReplayBlockSize)
	n, err := s2.DecodedLen(block)
	if err != nil || int64(n) != expected {
		return nil, fmt.Errorf("invalid PBZX replay block length")
	}
	return s2.Decode(nil, block)
}

func (f *File) readReplay(dst []byte, index int, c Chunk, off int64) (int, error) {
	// Retain at most one original chunk per ReadAt, even when the replay budget
	// is too small to admit it. Crossing pages must not repeat XZ in one call.
	var encoded, fresh []byte
	done := 0
	for done < len(dst) {
		page := off / ReplayBlockSize
		pageStart := page * ReplayBlockSize
		data, err := f.cache.Get(bytecache.Key{Index: index, Offset: pageStart}, func() ([]byte, error) {
			if encoded == nil {
				var err error
				encoded, err = f.replay.Get(bytecache.Key{Index: index}, func() ([]byte, error) {
					var err error
					fresh, err = f.decodeChunk(c)
					if err != nil {
						return nil, err
					}
					return encodeReplay(fresh), nil
				})
				if err != nil {
					return nil, err
				}
			}
			if fresh != nil {
				// Never retain a small subslice of a whole decoded chunk.
				b := make([]byte, min(int64(ReplayBlockSize), c.Size-pageStart))
				copy(b, fresh[pageStart:pageStart+int64(len(b))])
				return b, nil
			}
			b, err := decodeReplayBlock(encoded, c.Size, page)
			if err == nil {
				f.replayBlocks.Add(1)
				f.replayBytes.Add(uint64(len(b)))
			}
			return b, err
		})
		if err != nil {
			return done, err
		}
		skip := int(off - pageStart)
		n := copy(dst[done:], data[skip:])
		done += n
		off += int64(n)
	}
	return done, nil
}

// ReadStats separates original XZ work from fast replay. Counters are cumulative
// successful decodes; concurrent snapshots can straddle a completed operation.
// Cache bytes describe retention, not live/transient decoder allocations.
type ReadStats struct {
	XZChunks, XZBytes, ReplayBlocks, ReplayBytes uint64
	DecodedCache, ReplayCache                    bytecache.Stats
}

func (f *File) Stats() ReadStats {
	s := ReadStats{XZChunks: f.xzChunks.Load(), XZBytes: f.xzBytes.Load(), ReplayBlocks: f.replayBlocks.Load(), ReplayBytes: f.replayBytes.Load(), DecodedCache: f.cache.Stats()}
	if f.replay != nil {
		s.ReplayCache = f.replay.Stats()
	}
	return s
}

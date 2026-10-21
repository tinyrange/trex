package ibmisave

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/tinyrange/trex/auto/adapter"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"io"
	"sort"
	"sync"
)

var terseTag = []byte{0xd3, 0xc4, 0x6d, 0xe3, 0xd9, 0xe2, 0, 0}
var lzTag = []byte{0xd3, 0xc4, 0x6d, 0xd3, 0xe9, 0xf1, 0, 0}

type TransportRecord struct {
	Kind          string `json:"kind"`
	SourceOffset  int64  `json:"source_offset"`
	StoredSize    int64  `json:"stored_size"`
	LogicalOffset int64  `json:"logical_offset"`
	ExpandedSize  int64  `json:"expanded_size"`
}
type OpticalTransport struct {
	Records           []TransportRecord `json:"records"`
	LogicalBytes      int64             `json:"logical_bytes"`
	CompressedRecords int               `json:"compressed_records"`
	Complete          bool              `json:"complete"`
	UnknownTail       storage.Reader    `json:"-"`
	Data              storage.Reader    `json:"-"`
}

// OpenOpticalTransport follows explicit lengths, never signature-carves bodies.
// It borrows plain descriptors and lazily expands individual LD_TRS records.
// A terminal zero-expanded LD_LZ1 record is retained separately: its meaning is
// not inferred to be padding, nor are its bytes silently inserted or discarded.
func OpenOpticalTransport(source storage.Reader, maximum int, maximumBytes int64) (*OpticalTransport, error) {
	if maximum < 1 || maximumBytes < 0 {
		return nil, fmt.Errorf("ibmi transport: invalid budget")
	}
	t := &OpticalTransport{Complete: true}
	var h [pageSize]byte
	be := binary.BigEndian
	for off := int64(0); off < source.Size(); {
		if len(t.Records) >= maximum {
			return nil, fmt.Errorf("ibmi transport: record limit")
		}
		if source.Size()-off < 14 {
			return nil, fmt.Errorf("ibmi transport: truncated header at %d", off)
		}
		if _, err := starfile.ReadFullAt(source, h[:14], off); err != nil {
			return nil, err
		}
		r := TransportRecord{SourceOffset: off, LogicalOffset: t.LogicalBytes}
		switch {
		case bytes.Equal(h[:8], terseTag):
			r.Kind = "LD_TRS"
			r.StoredSize = 14 + int64(be.Uint16(h[12:]))
			r.ExpandedSize = int64(be.Uint16(h[8:]))
			if be.Uint16(h[10:]) != 0 || r.StoredSize < 26 || r.StoredSize > source.Size()-off || r.ExpandedSize == 0 || r.ExpandedSize%pageSize != 0 {
				return nil, fmt.Errorf("ibmi transport: invalid LD_TRS at %d", off)
			}
			if _, err := starfile.ReadFullAt(source, h[:12], off+14); err != nil {
				return nil, err
			}
			if be.Uint32(h[:]) != 0x02000080 || int64(be.Uint32(h[4:])) != r.StoredSize-14 || int64(be.Uint32(h[8:])) != r.ExpandedSize {
				return nil, fmt.Errorf("ibmi transport: inner/outer length mismatch at %d", off)
			}
			t.CompressedRecords++
		case bytes.Equal(h[:8], lzTag):
			r.Kind = "LD_LZ1-opaque"
			r.StoredSize = 14 + int64(be.Uint16(h[12:]))
			r.ExpandedSize = 0
			if be.Uint32(h[8:]) != 0 || r.StoredSize != source.Size()-off {
				return nil, fmt.Errorf("ibmi transport: unsupported nonterminal LD_LZ1 at %d", off)
			}
			t.Complete = false
			t.UnknownTail = &starfile.Slice{Base: adapter.File(source), Offset: off, Length: r.StoredSize}
		case h[0] == 0x40:
			r.Kind = "plain-padding"
			r.StoredSize = pageSize
			r.ExpandedSize = pageSize
			if r.StoredSize > source.Size()-off {
				return nil, fmt.Errorf("ibmi transport: partial padding")
			}
			if _, err := starfile.ReadFullAt(source, h[:], off); err != nil {
				return nil, err
			}
			for _, b := range h {
				if b != 0x40 {
					return nil, fmt.Errorf("ibmi transport: invalid padding at %d", off)
				}
			}
		case be.Uint32(h[:]) == 0xffffffff:
			r.Kind = "plain-object"
			if source.Size()-off < pageSize {
				return nil, fmt.Errorf("ibmi transport: truncated descriptor")
			}
			if _, err := starfile.ReadFullAt(source, h[:], off); err != nil {
				return nil, err
			}
			if !bytes.Equal(h[0x96:0xae], descriptor) {
				return nil, fmt.Errorf("ibmi transport: invalid plain descriptor at %d", off)
			}
			r.StoredSize = int64(be.Uint32(h[0xcc:])) * 512
			r.ExpandedSize = r.StoredSize
			if r.StoredSize < pageSize || r.StoredSize%pageSize != 0 || r.StoredSize > source.Size()-off {
				return nil, fmt.Errorf("ibmi transport: invalid plain extent at %d", off)
			}
		default:
			return nil, fmt.Errorf("ibmi transport: unsupported record at %d", off)
		}
		if r.ExpandedSize > maximumBytes-t.LogicalBytes {
			return nil, fmt.Errorf("ibmi transport: expanded byte limit")
		}
		t.Records = append(t.Records, r)
		t.LogicalBytes += r.ExpandedSize
		off += r.StoredSize
	}
	records := append([]TransportRecord(nil), t.Records...)
	if len(records) > 0 && records[len(records)-1].ExpandedSize == 0 {
		records = records[:len(records)-1]
	}
	t.Data = &transportReader{source: source, records: records, size: t.LogicalBytes, cached: -1}
	return t, nil
}

type transportReader struct {
	source  storage.Reader
	records []TransportRecord
	size    int64
	mu      sync.Mutex
	cached  int
	data    []byte
}

func (r *transportReader) Size() int64 { return r.size }
func (r *transportReader) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("ibmi transport: negative offset")
	}
	if len(p) == 0 {
		return 0, nil
	}
	if off >= r.size {
		return 0, io.EOF
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for n < len(p) && off < r.size {
		i := sort.Search(len(r.records), func(i int) bool { return r.records[i].LogicalOffset+r.records[i].ExpandedSize > off })
		rec := r.records[i]
		relative := off - rec.LogicalOffset
		size := min(int64(len(p)-n), rec.ExpandedSize-relative)
		if rec.Kind == "LD_TRS" {
			if r.cached != i {
				raw := make([]byte, int(rec.StoredSize-14))
				if _, err := starfile.ReadFullAt(r.source, raw, rec.SourceOffset+14); err != nil {
					return n, err
				}
				data, info, err := DecodeTerseWithInfo(raw)
				if err != nil {
					return n, fmt.Errorf("LD_TRS at %d: %w", rec.SourceOffset, err)
				}
				if !info.TerminationVerified {
					return n, fmt.Errorf("LD_TRS at %d: invalid end code/fill", rec.SourceOffset)
				}
				r.data = data
				r.cached = i
			}
			copy(p[n:n+int(size)], r.data[relative:relative+size])
		} else {
			if _, err := starfile.ReadFullAt(r.source, p[n:n+int(size)], rec.SourceOffset+relative); err != nil {
				return n, err
			}
		}
		n += int(size)
		off += size
	}
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

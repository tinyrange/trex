// Package memory provides read-only physical captures and translated address
// spaces over portable storage.Reader inputs. Sources must remain unchanged for
// the lifetime of a view; creating a view does not copy or freeze its source.
package memory

import (
	"fmt"
	"io"
	"math"
	"sort"

	"github.com/tinyrange/trex/storage"
)

// Range maps captured physical addresses to bytes in a source file. Holes
// between ranges are unavailable, not zero-filled. Offsets may be packed.
type Range struct{ Start, Offset, Size uint64 }

// Fault distinguishes absent translations from bytes missing from a capture.
// Address is in the requested address space; Physical identifies the failed
// physical read (including page-table reads), and Level names the paging stage.
type Fault struct {
	Kind              string
	Address, Physical uint64
	Level             string
	Cause             error
}

func (f *Fault) Error() string {
	return fmt.Sprintf("memory %s at %#x (physical %#x, %s): %v", f.Kind, f.Address, f.Physical, f.Level, f.Cause)
}
func (f *Fault) Unwrap() error { return f.Cause }

type Physical struct {
	source storage.Reader
	ranges []Range
	size   uint64
}

// NewPhysical validates and owns a copy of the mapping. A nil mapping means
// the entire source is a contiguous capture starting at physical address zero;
// a non-nil empty mapping describes a capture with no available ranges.
func NewPhysical(source storage.Reader, ranges []Range) (*Physical, error) {
	if source == nil || source.Size() < 0 {
		return nil, fmt.Errorf("invalid memory source")
	}
	if ranges == nil && source.Size() != 0 {
		ranges = []Range{{Size: uint64(source.Size())}}
	}
	if len(ranges) > 1<<20 {
		return nil, fmt.Errorf("too many physical ranges")
	}
	ranges = append([]Range(nil), ranges...)
	sort.Slice(ranges, func(i, j int) bool { return ranges[i].Start < ranges[j].Start })
	var end uint64
	for _, r := range ranges {
		if r.Size == 0 || r.Start > math.MaxInt64 || r.Size > math.MaxInt64-r.Start || r.Offset > uint64(source.Size()) || r.Size > uint64(source.Size())-r.Offset || r.Start < end {
			return nil, fmt.Errorf("invalid, overlapping, or out-of-source physical range")
		}
		end = r.Start + r.Size
	}
	return &Physical{source: source, ranges: ranges, size: end}, nil
}
func (p *Physical) Size() int64     { return int64(p.size) }
func (p *Physical) Ranges() []Range { return append([]Range(nil), p.ranges...) }
func (p *Physical) ReadAt(out []byte, offset int64) (int, error) {
	if offset < 0 {
		return 0, &Fault{Kind: "invalid-address", Level: "physical"}
	}
	if len(out) == 0 {
		return 0, nil
	}
	done := 0
	for done < len(out) {
		address := uint64(offset) + uint64(done)
		index := sort.Search(len(p.ranges), func(i int) bool { return p.ranges[i].Start+p.ranges[i].Size > address })
		if index == len(p.ranges) || address < p.ranges[index].Start {
			return done, &Fault{Kind: "not-captured", Address: address, Physical: address, Level: "physical"}
		}
		r := p.ranges[index]
		count := min(uint64(len(out)-done), r.Start+r.Size-address)
		n, err := p.source.ReadAt(out[done:done+int(count)], int64(r.Offset+address-r.Start))
		done += n
		if n != int(count) || (err != nil && err != io.EOF) {
			if err == nil {
				err = io.ErrUnexpectedEOF
			}
			return done, &Fault{Kind: "source-error", Address: address + uint64(n), Physical: address + uint64(n), Level: "physical", Cause: err}
		}
	}
	return done, nil
}

// Read bounds allocations for callers performing whole-range reads. ReadAt
// follows io.ReaderAt conventions and may return a valid prefix with an error.
func Read(source storage.Reader, address uint64, size int) ([]byte, error) {
	if size < 0 || size > 64<<20 || address > math.MaxInt64 || uint64(size) > uint64(math.MaxInt64)-address {
		return nil, fmt.Errorf("invalid or oversized memory read")
	}
	data := make([]byte, size)
	n, err := source.ReadAt(data, int64(address))
	if err == nil && n != len(data) {
		err = io.ErrUnexpectedEOF
	}
	return data[:n], err
}

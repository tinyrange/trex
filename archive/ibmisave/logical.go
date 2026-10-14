package ibmisave

import (
	"errors"
	"fmt"
	"github.com/tinyrange/trex/storage"
	"io"
	"math"
	"sort"
)

// ErrUnsaved distinguishes absent saved bytes from zero-filled or empty data.
var ErrUnsaved = errors.New("ibmi_save: requested logical bytes are not stored")

type logicalReader struct {
	source storage.Reader
	size   int64
}

func (r *logicalReader) Size() int64                 { return r.size }
func (r *logicalReader) ContiguousPrefixSize() int64 { return r.source.Size() }
func (r *logicalReader) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("ibmi_save: negative logical offset")
	}
	if len(p) == 0 {
		return 0, nil
	}
	if off >= r.size {
		return 0, io.EOF
	}
	if off >= r.source.Size() {
		return 0, ErrUnsaved
	}
	n := int(min(int64(len(p)), r.source.Size()-off))
	got, err := r.source.ReadAt(p[:n], off)
	if err != nil && !(err == io.EOF && got == n) {
		return got, err
	}
	if got != n {
		return got, io.ErrUnexpectedEOF
	}
	if n < len(p) {
		if off+int64(n) < r.size {
			return n, ErrUnsaved
		}
		return n, io.EOF
	}
	return n, nil
}

// LogicalReader keeps the declared logical size, but exposes only the stored
// prefix. Missing trailing pages fail explicitly; they are never zero-filled.
func (s Section) LogicalReader() (storage.Reader, error) {
	if s.Data == nil || s.Data.Size() < 0 || uint64(s.Data.Size()) > uint64(s.LogicalSize) {
		return nil, fmt.Errorf("ibmi_save: invalid section storage")
	}
	return &logicalReader{source: s.Data, size: int64(s.LogicalSize)}, nil
}

// StoredAt assembles a bounded saved-address range across adjacent stored
// sections. It rejects ambiguous logical spans and missing pages. Addresses
// remain opaque saved identities, not physical offsets or execution mappings.
func (o Object) StoredAt(address, length uint64) (storage.Reader, error) {
	if length > math.MaxInt64 || length > ^uint64(0)-address {
		return nil, fmt.Errorf("ibmi_save: saved range overflow")
	}
	sections := append([]Section(nil), o.Sections...)
	sort.Slice(sections, func(i, j int) bool { return sections[i].Address < sections[j].Address })
	var end uint64
	for i, s := range sections {
		if s.Data == nil || s.Data.Size() < 0 || uint64(s.Data.Size()) > uint64(s.LogicalSize) || uint64(s.LogicalSize) > ^uint64(0)-s.Address {
			return nil, fmt.Errorf("ibmi_save: invalid saved span")
		}
		if i != 0 && s.Address < end {
			return nil, fmt.Errorf("ibmi_save: overlapping saved spans")
		}
		end = s.Address + uint64(s.LogicalSize)
	}
	var ranges []storage.Range
	left := length
	for _, s := range sections {
		if left == 0 {
			break
		}
		if address < s.Address {
			return nil, ErrUnsaved
		}
		within := address - s.Address
		if within >= uint64(s.LogicalSize) {
			continue
		}
		if within >= uint64(s.Data.Size()) {
			return nil, ErrUnsaved
		}
		n := min(left, uint64(s.Data.Size())-within)
		ranges = append(ranges, storage.Range{Source: s.Data, Offset: int64(within), Length: int64(n)})
		address += n
		left -= n
	}
	if left != 0 {
		return nil, ErrUnsaved
	}
	return storage.Compose(ranges...)
}

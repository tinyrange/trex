package tararchive

import (
	"archive/tar"
	"fmt"
	"io"
	"io/fs"
	"math"
	"strconv"
	"sync"

	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/auto/adapter"
	"github.com/tinyrange/trex/storage"
)

// streamInput deliberately does not ask its backing stream for its total size.
// tar.Reader uses Seek to skip regular payloads, checking the last byte itself.
type streamInput struct {
	source storage.Reader
	offset int64
}

func (r *streamInput) Read(p []byte) (int, error) {
	n, err := r.source.ReadAt(p, r.offset)
	r.offset += int64(n)
	return n, err
}
func (r *streamInput) Seek(offset int64, whence int) (int64, error) {
	if whence != io.SeekCurrent || offset < 0 || offset > math.MaxInt64-r.offset {
		return 0, fmt.Errorf("tar: invalid forward seek")
	}
	r.offset += offset
	return r.offset, nil
}

// Streaming TARs expose their record sequence, not a prematurely complete path
// tree. Stable ordinal names preserve duplicates and file/directory collisions.
type streamView struct {
	mu      sync.Mutex
	input   *streamInput
	reader  *tar.Reader
	entries []auto.Entry
	maximum int
	done    bool
	err     error
	pending int64
}

func newStreamView(source storage.Reader, maximum int) *streamView {
	input := &streamInput{source: source}
	return &streamView{input: input, reader: tar.NewReader(input), maximum: maximum}
}
func (v *streamView) next() {
	h, err := v.reader.Next()
	if err == io.EOF {
		v.done = true
		return
	}
	if err != nil {
		v.err = fmt.Errorf("tar: record %d: %w", len(v.entries)+1, err)
		return
	}
	if len(v.entries) >= v.maximum {
		v.err = fmt.Errorf("%w: tar entries", auto.ErrLimit)
		return
	}
	if h.Typeflag == tar.TypeGNUSparse || h.PAXRecords["GNU.sparse.major"] != "" || h.PAXRecords["GNU.sparse.map"] != "" {
		v.err = fmt.Errorf("tar: sparse record %q unsupported", h.Name)
		return
	}
	e := &Entry{archive: adapter.File(v.input.source), dataOffset: v.input.offset, storedSize: h.Size, header: *h, path: storage.CleanPath(h.Name), kind: tarTypeName(h.Typeflag), regular: h.Typeflag == tar.TypeReg || h.Typeflag == tar.TypeRegA}
	item := auto.Entry{Name: strconv.Itoa(len(v.entries) + 1), Kind: e.kind, Attributes: map[string]any{"original_path": h.Name, "linkname": h.Linkname, "mode": h.Mode, "uid": h.Uid, "gid": h.Gid, "declared_size": h.Size}}
	if e.regular {
		item.Reader = e
	} else {
		item.Kind = "record"
	}
	v.entries = append(v.entries, item)
	v.pending = h.Size
}
func (v *streamView) Page(offset, limit int) (auto.EntryPage, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if offset < 0 || limit < 1 || offset > v.maximum {
		return auto.EntryPage{}, fmt.Errorf("%w: tar page", auto.ErrLimit)
	}
	// Reaching a later page is explicit work. A page stops before skipping a
	// large payload, even when fewer than limit records have been collected.
	for len(v.entries) < offset && !v.done && v.err == nil {
		v.next()
	}
	start := v.input.offset
	end := offset + min(limit, v.maximum-offset)
	if offset == v.maximum && !v.done && v.err == nil {
		v.next()
	}
	for len(v.entries) < end && !v.done && v.err == nil {
		if len(v.entries) > offset && (v.pending > 8<<20 || v.input.offset-start > 8<<20) {
			break
		}
		v.next()
	}
	if v.err != nil {
		return auto.EntryPage{}, v.err
	}
	lo := min(offset, len(v.entries))
	hi := min(end, len(v.entries))
	return auto.EntryPage{Entries: append([]auto.Entry(nil), v.entries[lo:hi]...), Next: hi, Complete: v.done && hi == len(v.entries), Total: len(v.entries)}, nil
}
func (v *streamView) Entries() ([]auto.Entry, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	for !v.done && v.err == nil {
		v.next()
	}
	return append([]auto.Entry(nil), v.entries...), v.err
}

func (v *streamView) Lookup(name string) (auto.Entry, error) {
	i, err := strconv.Atoi(name)
	if err != nil || i < 1 || strconv.Itoa(i) != name {
		return auto.Entry{}, fs.ErrNotExist
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	for len(v.entries) < i && !v.done && v.err == nil {
		v.next()
	}
	if i <= len(v.entries) {
		return v.entries[i-1], nil
	}
	if v.err != nil {
		return auto.Entry{}, v.err
	}
	return auto.Entry{}, fs.ErrNotExist
}

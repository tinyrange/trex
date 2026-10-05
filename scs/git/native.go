package gitstore

import (
	"bytes"
	"context"
	"crypto/sha1"
	"errors"
	"fmt"
	"github.com/tinyrange/trex/storage"
	"io"
	"runtime"
	"time"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/format/packfile"
	"github.com/go-git/go-git/v5/plumbing/storer"
	"github.com/tinyrange/trex/scs/repo"
)

type Report struct {
	Download      Download                     `json:"download"`
	Objects       uint64                       `json:"objects"`
	Types         map[string]repo.GitTypeStats `json:"types"`
	LogicalBytes  uint64                       `json:"logical_object_bytes"`
	Storage       repo.StorageStats            `json:"storage"`
	ImportSeconds float64                      `json:"import_seconds"`
	PeakHeapBytes uint64                       `json:"sampled_peak_heap_bytes"`
}

// Clone keeps verified transport bytes in bounded paged memory, never a host
// temporary file. The native repository retains decoded objects, not the pack.
// MaxPackBytes bounds scratch payload, not total memory or decoder allocations.
func Clone(ctx context.Context, r *repo.Repository, url string, opt Options) (Report, error) {
	if opt.MaxPackBytes == 0 {
		opt.MaxPackBytes = 256 << 20
	}
	f := storage.NewMemoryStore(opt.MaxPackBytes)
	defer f.Close()
	d, err := ReceivePack(ctx, url, io.NewOffsetWriter(f, 0), opt)
	if err != nil {
		return Report{}, err
	}
	view, err := f.Snapshot()
	if err != nil {
		return Report{}, err
	}
	return ImportPack(ctx, r, io.NewSectionReader(view, 0, view.Size()), d, opt)
}

// ImportPack accepts a complete caller-owned transport reader, not an archive to retain. It
// enables retrying the experiment without paying the network cost again.
func ImportPack(ctx context.Context, r *repo.Repository, input io.ReadSeeker, d Download, opt Options) (Report, error) {
	if opt.Name == "" {
		opt.Name = "git"
	}
	if opt.Progress == nil {
		opt.Progress = io.Discard
	}
	if opt.MaxNativeBytes == 0 {
		opt.MaxNativeBytes = 512 << 30
	}
	if opt.MaxNativeBytes < 1 {
		return Report{}, errors.New("invalid native storage limit")
	}
	if _, err := r.GitCatalog(opt.Name); err == nil {
		return Report{}, repo.ErrConflict
	}
	start := time.Now()
	if _, err := input.Seek(0, io.SeekStart); err != nil {
		return Report{}, err
	}
	// Independently verify the input before exposing any decoded Git refs.
	sum := &packDigest{h: sha1.New()}
	n, err := io.CopyBuffer(sum, contextReader{ctx, input}, make([]byte, 1<<20))
	if err != nil {
		return Report{}, err
	}
	if n != d.PackBytes || sum.n < 32 || !bytes.Equal(sum.tail, sum.h.Sum(nil)) || fmt.Sprintf("%x", sum.tail) != d.PackHash {
		return Report{}, errors.New("transport spool checksum/size mismatch")
	}
	if _, err := input.Seek(0, io.SeekStart); err != nil {
		return Report{}, err
	}
	native := &nativeStorer{r: r, ctx: ctx, required: map[repo.GitOID]byte{}, progress: opt.Progress, maxBytes: opt.MaxNativeBytes, start: start}
	fmt.Fprintf(opt.Progress, "decoding %d transport objects into native storage (no retained pack)\n", d.Objects)
	var got plumbing.Hash
	var decoded uint64
	if r.Optimized() {
		if at, ok := input.(io.ReaderAt); ok {
			got, decoded, err = importParallel(input, at, native, d.Objects)
		} else {
			got, decoded, err = importExtents(input, native, d.Objects)
		}
	} else {
		observed := &packObserver{ctx: ctx, expected: d.Objects}
		parser, e := packfile.NewParserWithStorage(packfile.NewScanner(&contextSeeker{ctx, input}), native, observed)
		if e != nil {
			return Report{}, e
		}
		got, err = parser.Parse()
		decoded = observed.count
	}
	if err != nil {
		return Report{}, err
	}
	if got.String() != d.PackHash || decoded != uint64(d.Objects) {
		return Report{}, errors.New("decoded pack identity/count mismatch")
	}
	if len(native.required) > 0 {
		for id, kind := range native.required {
			return Report{}, fmt.Errorf("incomplete Git graph: missing %s %s (%d unresolved)", repo.GitTypeName(kind), id.String(), len(native.required))
		}
	}
	stats := r.GitStatistics()
	if stats.Objects != uint64(d.Objects) {
		return Report{}, fmt.Errorf("native object count %d differs from transport count %d; duplicate IDs or objects from another import", stats.Objects, d.Objects)
	}
	c := repo.GitCatalog{Name: opt.Name, Remote: d.Remote, Head: d.Head, Refs: d.Refs, SymbolicRefs: d.SymbolicRefs, Peeled: d.Peeled, PackBytes: d.PackBytes, PackHash: d.PackHash, Objects: stats.Objects}
	for name, id := range c.Refs {
		if err := plumbing.ReferenceName(name).Validate(); err != nil {
			return Report{}, fmt.Errorf("invalid advertised ref %q: %w", name, err)
		}
		if _, err := repo.ParseGitOID(id); err != nil {
			return Report{}, err
		}
	}
	if err := ctx.Err(); err != nil {
		return Report{}, err
	}
	if err := r.PublishGit(c); err != nil {
		return Report{}, err
	}
	if r.Optimized() {
		if err := r.Checkpoint(); err != nil {
			return Report{}, err
		}
	}
	storage, err := r.StorageStats()
	if err != nil {
		return Report{}, err
	}
	fmt.Fprintf(opt.Progress, "native import complete: %d objects, %d logical bytes, %d stored bytes\n", stats.Objects, stats.Bytes, storage.FileBytes)
	return Report{d, stats.Objects, stats.Types, stats.Bytes, storage, time.Since(start).Seconds(), native.peakHeap}, nil
}

type contextSeeker struct {
	ctx context.Context
	io.ReadSeeker
}

func (s *contextSeeker) Read(b []byte) (int, error) {
	if err := s.ctx.Err(); err != nil {
		return 0, err
	}
	return s.ReadSeeker.Read(b)
}
func (s *contextSeeker) Seek(n int64, w int) (int64, error) {
	if err := s.ctx.Err(); err != nil {
		return 0, err
	}
	return s.ReadSeeker.Seek(n, w)
}

type edgeHint struct {
	ID   repo.GitOID
	Kind byte
}
type nativeStorer struct {
	edgeHints         []edgeHint
	r                 *repo.Repository
	ctx               context.Context
	required          map[repo.GitOID]byte
	progress          io.Writer
	maxBytes          int64
	start, last       time.Time
	inserted, logical uint64
	peakHeap          uint64
}

func (s *nativeStorer) NewEncodedObject() plumbing.EncodedObject { return &plumbing.MemoryObject{} }
func gitOID(h plumbing.Hash) repo.GitOID                         { id, _ := repo.GitOIDFromBytes(h[:]); return id }
func (s *nativeStorer) require(id repo.GitOID, kind byte) error {
	if s.edgeHints == nil {
		s.edgeHints = make([]edgeHint, 1<<16)
	}
	slot := int(id[0]) | int(id[1])<<8
	h := s.edgeHints[slot]
	if h.Kind != 0 && h.ID == id {
		if h.Kind != kind {
			return errors.New("conflicting Git edge types")
		}
		return nil
	}
	err := s.requireSlow(id, kind)
	if err == nil {
		s.edgeHints[slot] = edgeHint{id, kind}
	}
	return err
}
func (s *nativeStorer) requireSlow(id repo.GitOID, kind byte) error {
	if got, _, ok := s.r.GitObjectHeader(id); ok {
		if got != kind {
			return fmt.Errorf("Git edge type mismatch for %s", id.String())
		}
		return nil
	}
	if old, ok := s.required[id]; ok && old != kind {
		return errors.New("conflicting Git edge types")
	}
	s.required[id] = kind
	return nil
}
func (s *nativeStorer) SetEncodedObject(obj plumbing.EncodedObject) (plumbing.Hash, error) {
	if err := s.ctx.Err(); err != nil {
		return plumbing.ZeroHash, err
	}
	kind := byte(obj.Type())
	if kind < repo.GitCommit || kind > repo.GitTag {
		return plumbing.ZeroHash, errors.New("invalid reconstructed object type")
	}
	h := obj.Hash()
	id := gitOID(h)
	if want, ok := s.required[id]; ok && want != kind {
		return plumbing.ZeroHash, errors.New("Git object does not match referenced type")
	}
	if obj.Size() < 0 || obj.Size() > 1<<30 {
		return plumbing.ZeroHash, errors.New("Git object exceeds 1 GiB import limit")
	}
	reader, err := obj.Reader()
	if err != nil {
		return plumbing.ZeroHash, err
	}
	defer reader.Close()
	var input io.Reader = reader
	if kind != repo.GitBlob {
		data, err := io.ReadAll(io.LimitReader(reader, obj.Size()+1))
		if err != nil {
			return plumbing.ZeroHash, err
		}
		if int64(len(data)) != obj.Size() {
			return plumbing.ZeroHash, errors.New("Git metadata size mismatch")
		}
		if err := repo.GitLinks(kind, data, 20, s.require); err != nil {
			return plumbing.ZeroHash, fmt.Errorf("%s %s: %w", obj.Type(), id.String(), err)
		}
		input = bytes.NewReader(data)
	}
	_, _, exists := s.r.GitObjectHeader(id)
	if !exists {
		if _, err := s.r.PutGitObject(s.ctx, id, kind, obj.Size(), input); err != nil {
			return plumbing.ZeroHash, err
		}
		s.inserted++
		s.logical += uint64(obj.Size())
	}
	delete(s.required, id)
	if s.inserted%4096 == 0 || time.Since(s.last) > 10*time.Second {
		size, err := s.r.GitStorageBytes()
		if err != nil {
			return plumbing.ZeroHash, err
		}
		if size > s.maxBytes {
			return plumbing.ZeroHash, errors.New("native storage resource limit exceeded")
		}
		if time.Since(s.last) > 10*time.Second {
			var mem runtime.MemStats
			runtime.ReadMemStats(&mem)
			s.peakHeap = max(s.peakHeap, mem.HeapAlloc)
			fmt.Fprintf(s.progress, "native objects=%d logical=%d file=%d unresolved=%d heap=%d elapsed=%.1fs\n", s.inserted, s.logical, size, len(s.required), mem.HeapAlloc, time.Since(s.start).Seconds())
			s.last = time.Now()
		}
	}
	return h, nil
}
func (s *nativeStorer) EncodedObject(t plumbing.ObjectType, h plumbing.Hash) (plumbing.EncodedObject, error) {
	kind, size, ok := s.r.GitObjectHeader(gitOID(h))
	if !ok || (t != plumbing.AnyObject && t != plumbing.ObjectType(kind)) {
		return nil, plumbing.ErrObjectNotFound
	}
	return &nativeObject{s.r, h, plumbing.ObjectType(kind), size}, nil
}
func (s *nativeStorer) HasEncodedObject(h plumbing.Hash) error {
	_, _, ok := s.r.GitObjectHeader(gitOID(h))
	if !ok {
		return plumbing.ErrObjectNotFound
	}
	return nil
}
func (s *nativeStorer) EncodedObjectSize(h plumbing.Hash) (int64, error) {
	_, size, ok := s.r.GitObjectHeader(gitOID(h))
	if !ok {
		return 0, plumbing.ErrObjectNotFound
	}
	return size, nil
}
func (s *nativeStorer) AddAlternate(string) error {
	return errors.New("external object stores are not used")
}
func (s *nativeStorer) IterEncodedObjects(t plumbing.ObjectType) (storer.EncodedObjectIter, error) {
	ids := s.r.GitObjectIDs()
	hashes := make([]plumbing.Hash, 0, len(ids))
	for _, id := range ids {
		if id[32] != 20 {
			continue
		}
		kind, _, _ := s.r.GitObjectHeader(id)
		if t == plumbing.AnyObject || t == plumbing.ObjectType(kind) {
			var h plumbing.Hash
			copy(h[:], id[:20])
			hashes = append(hashes, h)
		}
	}
	return storer.NewEncodedObjectLookupIter(s, t, hashes), nil
}

type nativeObject struct {
	r    *repo.Repository
	h    plumbing.Hash
	t    plumbing.ObjectType
	size int64
}

func (o *nativeObject) Hash() plumbing.Hash             { return o.h }
func (o *nativeObject) Type() plumbing.ObjectType       { return o.t }
func (o *nativeObject) Size() int64                     { return o.size }
func (o *nativeObject) SetType(plumbing.ObjectType)     { panic("immutable native Git object") }
func (o *nativeObject) SetSize(int64)                   { panic("immutable native Git object") }
func (o *nativeObject) Reader() (io.ReadCloser, error)  { return o.r.OpenGitObject(gitOID(o.h)) }
func (o *nativeObject) Writer() (io.WriteCloser, error) { return nil, repo.ErrReadOnly }

type packObserver struct {
	ctx      context.Context
	expected uint32
	count    uint64
}

func (o *packObserver) OnHeader(count uint32) error {
	if count != o.expected {
		return errors.New("pack object count changed")
	}
	return o.ctx.Err()
}
func (o *packObserver) OnInflatedObjectHeader(t plumbing.ObjectType, size, pos int64) error {
	if byte(t) < repo.GitCommit || byte(t) > repo.GitTag {
		return errors.New("unresolved delta")
	}
	o.count++
	return o.ctx.Err()
}
func (o *packObserver) OnInflatedObjectContent(plumbing.Hash, int64, uint32, []byte) error {
	return o.ctx.Err()
}
func (o *packObserver) OnFooter(plumbing.Hash) error { return o.ctx.Err() }

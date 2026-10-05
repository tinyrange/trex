package gitstore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/format/packfile"
	"github.com/tinyrange/trex/scs/repo"
	"io"
	"runtime"
	"sync"
)

// Pointer-free dependency records keep the full-history scheduler cheap for GC.
// Links are one-based; zero is the end of a child/waiter list.
type deltaNode struct {
	offset      int64
	child, next uint32
	base        repo.GitOID
	done        bool
}
type deltaJob struct {
	index  uint32
	offset int64
	base   repo.GitOID
}
type deltaEdge struct {
	oid  repo.GitOID
	kind byte
}
type deltaResult struct {
	edges []deltaEdge
	size  int
	index uint32
	oid   repo.GitOID
	kind  byte
	err   error
}

// The scanner feeds bounded batches of headers while workers independently read
// runnable objects. Inflated payloads never queue behind unresolved dependencies.
type scanBatch struct {
	headers  []packfile.ObjectHeader
	checksum plumbing.Hash
	err      error
	done     bool
}

func importParallel(input io.ReadSeeker, at io.ReaderAt, s *nativeStorer, expected uint32) (plumbing.Hash, uint64, error) {
	ctx, cancel := context.WithCancel(s.ctx)
	var wg sync.WaitGroup
	defer func() { cancel(); wg.Wait() }()
	scanner := packfile.NewScanner(&contextSeeker{ctx, input})
	_, count, err := scanner.Header()
	if err != nil {
		return plumbing.ZeroHash, 0, err
	}
	if count != expected {
		return plumbing.ZeroHash, 0, errors.New("pack count mismatch")
	}
	nodes := make([]deltaNode, count)
	offsets := make(map[int64]uint32, count)
	waiting := make(map[repo.GitOID]uint32)
	var ready, roots []uint32
	rootPos := 0
	scans := make(chan scanBatch, 2)
	wg.Add(1)
	go func() {
		defer wg.Done()
		send := func(b scanBatch) bool {
			select {
			case scans <- b:
				return true
			case <-ctx.Done():
				return false
			}
		}
		batch := make([]packfile.ObjectHeader, 0, 1024)
		for i := uint32(0); i < count; i++ {
			h, e := scanner.NextObjectHeader()
			if e == nil && (h.Length < 0 || h.Length > 1<<30) {
				e = errors.New("inflated object limit")
			}
			if e == nil {
				var n int64
				n, _, e = scanner.NextObject(io.Discard)
				if e == nil && n != h.Length {
					e = errors.New("inflated length mismatch")
				}
			}
			if e != nil {
				send(scanBatch{err: e, done: true})
				return
			}
			batch = append(batch, *h)
			if len(batch) == cap(batch) {
				if !send(scanBatch{headers: batch}) {
					return
				}
				batch = make([]packfile.ObjectHeader, 0, 1024)
			}
		}
		if len(batch) > 0 && !send(scanBatch{headers: batch}) {
			return
		}
		checksum, e := scanner.Checksum()
		if e == io.EOF {
			e = nil
		}
		send(scanBatch{checksum: checksum, err: e, done: true})
	}()
	workers := min(6, max(1, runtime.GOMAXPROCS(0)))
	fmt.Fprintf(s.progress, "streaming dependency scan with %d import workers\n", workers)
	jobs := make(chan deltaJob)
	results := make(chan deltaResult, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w, err := s.r.NewGitIngester()
			if err != nil {
				select {
				case results <- deltaResult{err: err}:
				case <-ctx.Done():
				}
				return
			}
			defer w.Close()
			scan := packfile.NewScanner(&contextSeeker{ctx, io.NewSectionReader(at, 0, 1<<63-1)})
			var buf bytes.Buffer
			for {
				select {
				case <-ctx.Done():
					return
				case job := <-jobs:
					result := deltaResult{index: job.index}
					var body []byte
					result.oid, result.kind, body, result.err = ingestJob(ctx, scan, &buf, w, s.r, job)
					result.size = len(body)
					if result.err == nil && result.kind != repo.GitBlob {
						result.err = repo.GitLinks(result.kind, body, 20, func(oid repo.GitOID, kind byte) error {
							result.edges = append(result.edges, deltaEdge{oid, kind})
							return nil
						})
					}
					select {
					case results <- result:
					case <-ctx.Done():
						return
					}
					if result.err != nil {
						return
					}
				}
			}
		}()
	}
	active := 0
	scanned := uint32(0)
	scanDone := false
	var checksum plumbing.Hash
	for !scanDone || s.inserted < uint64(count) {
		if err := ctx.Err(); err != nil {
			return checksum, s.inserted, err
		}
		var send chan deltaJob
		var job deltaJob
		fromRoot := false
		if active < workers {
			var idx uint32
			available := true
			if len(ready) > 0 {
				idx = ready[len(ready)-1]
			} else if rootPos < len(roots) {
				idx = roots[rootPos]
				fromRoot = true
			} else {
				available = false
			}
			if available {
				job = deltaJob{idx, nodes[idx].offset, nodes[idx].base}
				send = jobs
			}
		}
		if scanDone && active == 0 && send == nil {
			return checksum, s.inserted, errors.New("missing or cyclic delta bases")
		}
		select {
		case <-ctx.Done():
			return checksum, s.inserted, ctx.Err()
		case batch := <-scans:
			if batch.err != nil {
				return checksum, s.inserted, batch.err
			}
			for _, h := range batch.headers {
				i := scanned
				scanned++
				node := &nodes[i]
				node.offset = h.Offset
				switch h.Type {
				case plumbing.OFSDeltaObject:
					parent, ok := offsets[h.OffsetReference]
					if !ok {
						return checksum, s.inserted, errors.New("missing offset delta base")
					}
					p := &nodes[parent-1]
					if p.done {
						node.base = p.base
						ready = append(ready, i)
					} else {
						node.next = p.child
						p.child = i + 1
					}
				case plumbing.REFDeltaObject:
					node.base = gitOID(h.Reference)
					if _, _, ok := s.r.GitObjectHeader(node.base); ok {
						ready = append(ready, i)
					} else {
						node.next = waiting[node.base]
						waiting[node.base] = i + 1
					}
				case plumbing.CommitObject, plumbing.TreeObject, plumbing.BlobObject, plumbing.TagObject:
					roots = append(roots, i)
				default:
					return checksum, s.inserted, errors.New("invalid pack object type")
				}
				offsets[h.Offset] = i + 1
			}
			if batch.done {
				if scanned != count {
					return checksum, s.inserted, errors.New("scanned object count mismatch")
				}
				checksum = batch.checksum
				scanDone = true
				scans = nil
				offsets = nil
				fmt.Fprintf(s.progress, "dependency scan complete: %d objects\n", count)
			}
		case send <- job:
			if fromRoot {
				rootPos++
			} else {
				ready = ready[:len(ready)-1]
			}
			active++
		case result := <-results:
			if result.err != nil {
				return checksum, s.inserted, result.err
			}
			active--
			if err := s.accountLinks(result.oid, result.kind, result.size, func() error {
				for _, edge := range result.edges {
					if err := s.require(edge.oid, edge.kind); err != nil {
						return err
					}
				}
				return nil
			}); err != nil {
				return checksum, s.inserted, err
			}
			node := &nodes[result.index]
			node.done = true
			node.base = result.oid
			for link := node.child; link != 0; link = nodes[link-1].next {
				nodes[link-1].base = result.oid
				ready = append(ready, link-1)
			}
			for link := waiting[result.oid]; link != 0; link = nodes[link-1].next {
				ready = append(ready, link-1)
			}
			delete(waiting, result.oid)
		}
	}
	return checksum, s.inserted, nil
}

func ingestJob(ctx context.Context, scan *packfile.Scanner, buf *bytes.Buffer, w *repo.GitIngester, r *repo.Repository, job deltaJob) (repo.GitOID, byte, []byte, error) {
	h, err := scan.SeekObjectHeader(job.offset)
	if err != nil {
		return repo.GitOID{}, 0, nil, err
	}
	if h.Length < 0 || h.Length > 1<<30 {
		return repo.GitOID{}, 0, nil, errors.New("inflated object limit")
	}
	kind := byte(h.Type)
	var baseSize int64
	if h.Type == plumbing.OFSDeltaObject || h.Type == plumbing.REFDeltaObject {
		var ok bool
		kind, baseSize, ok = r.GitObjectHeader(job.base)
		if !ok {
			return repo.GitOID{}, 0, nil, errors.New("scheduled delta base missing")
		}
	}
	// Do not permanently retain an unusually large object's allocation per worker.
	if buf.Cap() > 64<<20 {
		*buf = bytes.Buffer{}
	} else {
		buf.Reset()
	}
	n, _, err := scan.NextObject(buf)
	if err != nil {
		return repo.GitOID{}, 0, nil, err
	}
	if n != h.Length {
		return repo.GitOID{}, 0, nil, errors.New("inflated length mismatch")
	}
	full := buf.Bytes()
	var extents []repo.Extent
	size := uint64(n)
	if job.base.Valid() {
		extents, size, err = translateDelta(full, uint64(baseSize))
		if err != nil {
			return repo.GitOID{}, 0, nil, err
		}
		full = nil
	}
	oid, body, err := w.Ingest(ctx, kind, full, job.base, extents, size)
	return oid, kind, body, err
}

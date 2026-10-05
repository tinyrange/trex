package gitstore

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/format/packfile"
	"github.com/tinyrange/trex/scs/repo"
	"io"
	"runtime"
	"time"
)

// translateDelta converts Git's variable copy-bitmask instructions into native
// byte-range extents. Neither these wire instructions nor their compression is stored.
func translateDelta(data []byte, baseSize uint64) ([]repo.Extent, uint64, error) {
	read := func() (uint64, error) {
		n, k := binary.Uvarint(data)
		if k <= 0 {
			return 0, errors.New("invalid delta size")
		}
		data = data[k:]
		return n, nil
	}
	n, err := read()
	if err != nil || n != baseSize {
		return nil, 0, errors.New("delta base size mismatch")
	}
	size, err := read()
	if err != nil || size > 1<<30 {
		return nil, 0, errors.New("delta output size limit")
	}
	var out []repo.Extent
	var produced uint64
	for len(data) > 0 {
		op := data[0]
		data = data[1:]
		var e repo.Extent
		if op&128 == 0 {
			if op == 0 || int(op) > len(data) {
				return nil, 0, errors.New("invalid delta literal")
			}
			e.Data = data[:op]
			e.Length = uint64(op)
			data = data[op:]
		} else {
			for bit := uint(0); bit < 7; bit++ {
				if op&(1<<bit) == 0 {
					continue
				}
				if len(data) == 0 {
					return nil, 0, io.ErrUnexpectedEOF
				}
				if bit < 4 {
					e.Offset |= uint64(data[0]) << (8 * bit)
				} else {
					e.Length |= uint64(data[0]) << (8 * (bit - 4))
				}
				data = data[1:]
			}
			if e.Length == 0 {
				e.Length = 65536
			}
			if e.Offset > baseSize || e.Length > baseSize-e.Offset {
				return nil, 0, errors.New("delta copy outside base")
			}
		}
		if e.Length > size-produced {
			return nil, 0, errors.New("delta output overflow")
		}
		produced += e.Length
		if len(out) >= 1<<20 {
			return nil, 0, errors.New("delta extent count limit")
		}
		out = append(out, e)
	}
	if produced != size {
		return nil, 0, errors.New("delta output size mismatch")
	}
	return out, size, nil
}

func importExtents(input io.ReadSeeker, s *nativeStorer, expected uint32) (plumbing.Hash, uint64, error) {
	scanner := packfile.NewScanner(&contextSeeker{s.ctx, input})
	_, count, err := scanner.Header()
	if err != nil {
		return plumbing.ZeroHash, 0, err
	}
	if count != expected {
		return plumbing.ZeroHash, 0, errors.New("pack count mismatch")
	}
	offsets := make(map[int64]repo.GitOID)
	var pending []*packfile.ObjectHeader
	var buf bytes.Buffer
	process := func(h *packfile.ObjectHeader) (bool, error) {
		if err := s.ctx.Err(); err != nil {
			return false, err
		}
		if h.Length < 0 || h.Length > 1<<30 {
			return false, errors.New("inflated object limit")
		}
		var base repo.GitOID
		kind := byte(h.Type)
		var baseSize int64
		if h.Type == plumbing.OFSDeltaObject {
			base = offsets[h.OffsetReference]
		} else if h.Type == plumbing.REFDeltaObject {
			base = gitOID(h.Reference)
		}
		if h.Type == plumbing.OFSDeltaObject || h.Type == plumbing.REFDeltaObject {
			var ok bool
			kind, baseSize, ok = s.r.GitObjectHeader(base)
			if !ok {
				_, _, err := scanner.NextObject(io.Discard)
				return false, err
			}
		}
		buf.Reset()
		n, _, err := scanner.NextObject(&buf)
		if err != nil {
			return false, err
		}
		if n != h.Length {
			return false, errors.New("inflated length mismatch")
		}
		var extents []repo.Extent
		size := uint64(n)
		full := buf.Bytes()
		if base.Valid() {
			extents, size, err = translateDelta(full, uint64(baseSize))
			if err != nil {
				return false, err
			}
			full = nil
		}
		oid, body, err := s.r.IngestGitBody(s.ctx, kind, full, base, extents, size)
		if err != nil {
			return false, err
		}
		if err := s.accountBody(oid, kind, body); err != nil {
			return false, err
		}
		offsets[h.Offset] = oid
		return true, nil
	}
	for i := uint32(0); i < count; i++ {
		h, err := scanner.NextObjectHeader()
		if err != nil {
			return plumbing.ZeroHash, s.inserted, err
		}
		done, err := process(h)
		if err != nil {
			return plumbing.ZeroHash, s.inserted, err
		}
		if !done {
			pending = append(pending, h)
		}
	}
	checksum, err := scanner.Checksum()
	if err != nil && err != io.EOF {
		return checksum, s.inserted, err
	}
	for pass := 0; len(pending) > 0; pass++ {
		if pass >= 128 {
			return checksum, s.inserted, errors.New("delta dependency limit exceeded")
		}
		next := pending[:0]
		for _, old := range pending {
			h, err := scanner.SeekObjectHeader(old.Offset)
			if err != nil {
				return checksum, s.inserted, err
			}
			done, err := process(h)
			if err != nil {
				return checksum, s.inserted, err
			}
			if !done {
				next = append(next, h)
			}
		}
		if len(next) == len(pending) {
			return checksum, s.inserted, errors.New("missing or cyclic delta bases")
		}
		pending = next
	}
	return checksum, s.inserted, nil
}

func (s *nativeStorer) accountBody(oid repo.GitOID, kind byte, body []byte) error {
	return s.accountLinks(oid, kind, len(body), func() error { return repo.GitLinks(kind, body, 20, s.require) })
}
func (s *nativeStorer) accountLinks(oid repo.GitOID, kind byte, size int, links func() error) error {
	if want, ok := s.required[oid]; ok && want != kind {
		return errors.New("Git edge type mismatch")
	}
	if kind != repo.GitBlob {
		if err := links(); err != nil {
			return err
		}
	}
	delete(s.required, oid)
	s.inserted++
	s.logical += uint64(size)
	if time.Since(s.last) > 10*time.Second || s.inserted%4096 == 0 {
		file, err := s.r.GitStorageBytes()
		if err != nil {
			return err
		}
		if file > s.maxBytes {
			return errors.New("native storage resource limit exceeded")
		}
		if time.Since(s.last) > 10*time.Second {
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			s.peakHeap = max(s.peakHeap, m.HeapAlloc)
			fmt.Fprintf(s.progress, "native objects=%d logical=%d file=%d unresolved=%d heap=%d elapsed=%.1fs\n", s.inserted, s.logical, file, len(s.required), m.HeapAlloc, time.Since(s.start).Seconds())
			s.last = time.Now()
		}
	}
	return nil
}

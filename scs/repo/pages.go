package repo

import (
	"errors"
	"io"
)

// WritePages atomically installs a file made from an immutable base and full
// BlockSize overlay pages. baseLimit clips the original bytes after truncation;
// extensions read as zeros. Size is currently limited to 1 GiB. Page keys are block numbers. The caller must not
// mutate pages during this call. Failed writes leave the workspace unchanged.
// Unchanged native blocks are reused. Compressed bodies still require decoding
// their whole body; this API does not promise a bound on decompression memory.
func (w *Workspace) WritePages(p string, base *Reader, size, baseLimit int64, pages map[int64][]byte) error {
	w.s.mu.Lock()
	defer w.s.mu.Unlock()
	if w.readonly {
		return ErrReadOnly
	}
	if base == nil || base.r != w.r || size < 0 || size > 1<<30 || baseLimit < 0 || baseLimit > base.Size() {
		return errors.New("invalid page base or size")
	}
	for index, data := range pages {
		if index < 0 || index >= (size+BlockSize-1)/BlockSize || len(data) != BlockSize {
			return errors.New("invalid overlay page")
		}
	}
	p, err := clean(p)
	if err != nil {
		return err
	}
	if err = w.prepare(p, false); err != nil {
		return err
	}
	old, ok := w.s.get(p)
	if !ok || old.Kind != "file" {
		return errors.New("not a regular file")
	}
	base.mu.Lock()
	defer base.mu.Unlock()
	if base.closed {
		return errors.New("reader is closed")
	}
	w.r.mu.Lock()
	defer w.r.mu.Unlock()
	if err = w.r.ready(); err != nil {
		return err
	}
	var body []byte
	if base.entry.Body != "" && baseLimit > 0 {
		body, err = w.r.borrowBody(base.entry.Body)
		if err != nil {
			return err
		}
	}
	next := Entry{Kind: "file", Mode: old.Mode, Times: old.Times, Size: size}
	buf := make([]byte, BlockSize)
	for off := int64(0); off < size; off += BlockSize {
		index := off / BlockSize
		count := min(int64(BlockSize), size-off)
		page, dirty := pages[index]
		if !dirty && base.entry.Body == "" && off+count <= baseLimit && off+count <= base.entry.Size && (count == BlockSize || off+count == base.entry.Size) {
			next.Blocks = append(next.Blocks, base.entry.Blocks[index])
			continue
		}
		clear(buf)
		if dirty {
			copy(buf, page)
		} else if off < baseLimit {
			n := min(count, baseLimit-off)
			if body != nil {
				if off+n > int64(len(body)) {
					return io.ErrUnexpectedEOF
				}
				copy(buf, body[off:off+n])
			} else {
				b, e := w.r.get(base.entry.Blocks[index], blockKind)
				if e != nil {
					return e
				}
				if int64(len(b)) < n {
					return io.ErrUnexpectedEOF
				}
				copy(buf, b[:n])
			}
		}
		id, e := w.r.append(blockKind, buf[:count])
		if e != nil {
			return e
		}
		next.Blocks = append(next.Blocks, id)
	}
	w.s.set(p, &node{entry: next})
	return nil
}

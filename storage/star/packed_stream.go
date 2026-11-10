package star

import (
	"fmt"
	"io"
)

// PackStream consumes exactly size bytes synchronously from produce. The writer
// is valid only during that callback, must not be retained or used concurrently,
// and produce must not reenter this store. A failed or short producer returns no
// file. At most one input chunk is buffered, independently of the file size.
func (s *PackedFileStore) PackStream(name string, size int64, produce func(io.Writer) error) (File, error) {
	if size < 0 || produce == nil {
		return nil, fmt.Errorf("invalid packed stream size or producer")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.next++
	f := &PackedFile{name: name, length: size, cache: s.cache, id: s.next}
	w := &packedStreamWriter{store: s, file: f, buffer: make([]byte, 0, PackedChunkBytes)}
	if err := produce(w); err != nil {
		return nil, err
	}
	if w.err != nil {
		return nil, w.err
	}
	if w.written != size {
		return nil, io.ErrUnexpectedEOF
	}
	if len(w.buffer) != 0 {
		if err := w.flush(); err != nil {
			return nil, err
		}
	}
	return f, nil
}

type packedStreamWriter struct {
	store   *PackedFileStore
	file    *PackedFile
	buffer  []byte
	written int64
	err     error
}

func (w *packedStreamWriter) flush() error {
	chunk, err := w.store.packChunk(w.buffer)
	if err != nil {
		w.err = err
		return err
	}
	w.file.chunks = append(w.file.chunks, chunk)
	w.buffer = w.buffer[:0]
	return nil
}

func (w *packedStreamWriter) Write(p []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	if int64(len(p)) > w.file.length-w.written {
		w.err = fmt.Errorf("packed stream exceeds declared size %d", w.file.length)
		return 0, w.err
	}
	n := 0
	for len(p) != 0 {
		take := min(len(p), cap(w.buffer)-len(w.buffer))
		w.buffer = append(w.buffer, p[:take]...)
		p = p[take:]
		n += take
		w.written += int64(take)
		if len(w.buffer) == cap(w.buffer) {
			if err := w.flush(); err != nil {
				return n, err
			}
		}
	}
	return n, nil
}

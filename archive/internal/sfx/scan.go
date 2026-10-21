// Package sfx locates bounded archive signatures in executable envelopes.
package sfx

import (
	"bytes"
	"github.com/tinyrange/trex/storage"
	"io"
)

// Candidates scans a bounded prefix. Callers must validate candidate headers.
// Views retain the source; no payload is copied or extracted.
func Candidates(r storage.Reader, magic []byte, maximum int64) ([]storage.Reader, error) {
	end := min(r.Size(), maximum)
	if len(magic) == 0 || end < int64(len(magic)) {
		return nil, nil
	}
	var result []storage.Reader
	const chunk = 64 << 10
	buf := make([]byte, chunk+len(magic)-1)
	for off := int64(0); off < end; off += chunk {
		n, err := r.ReadAt(buf[:min(int64(len(buf)), end-off)], off)
		if err != nil && err != io.EOF {
			return nil, err
		}
		for pos := 0; pos < n; {
			i := bytes.Index(buf[pos:n], magic)
			if i < 0 {
				break
			}
			i += pos
			if i >= chunk {
				break
			}
			at := off + int64(i)
			result = append(result, io.NewSectionReader(r, at, r.Size()-at))
			if len(result) == 32 {
				return result, nil
			}
			pos = i + 1
		}
	}
	return result, nil
}

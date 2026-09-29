package sevenzip

import "io"

// NewLZMAStream decodes a raw LZMA stream terminated by an end marker. The
// five-byte properties are separate from input. Dictionary memory is bounded;
// callers must bound output reads independently. No bytes are staged on disk.
func NewLZMAStream(input io.Reader, properties []byte, maximumDictionary uint64) (io.Reader, error) {
	r, err := newLZMAReader(input, properties, ^uint64(0), maximumDictionary)
	if err != nil {
		return nil, err
	}
	r.endMarker = true
	return r, nil
}

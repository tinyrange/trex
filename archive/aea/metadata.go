// Package aea inspects Apple Encrypted Archive headers using portable readers.
package aea

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"unicode/utf8"

	"github.com/tinyrange/trex/storage"
)

// Metadata contains unauthenticated AEA1 header values. Reading it does not
// decrypt the archive, authenticate its contents, or contact a key service.
type Metadata struct {
	Profile        uint32
	ScryptStrength uint8
	AuthData       storage.Reader
	Values         map[string][]byte
}

// ReadMetadata reads a bounded key/value header, preserving binary values.
// Sources must remain unchanged while the borrowed AuthData view is used.
func ReadMetadata(source storage.Reader) (*Metadata, error) {
	if source == nil || source.Size() < 12 {
		return nil, fmt.Errorf("aea: truncated header")
	}
	var header [12]byte
	if _, err := source.ReadAt(header[:], 0); err != nil {
		return nil, err
	}
	if string(header[:4]) != "AEA1" {
		return nil, fmt.Errorf("aea: invalid signature")
	}
	profile := binary.LittleEndian.Uint32(header[4:])
	size := int64(binary.LittleEndian.Uint32(header[8:]))
	if size > 1<<20 || size > source.Size()-12 {
		return nil, fmt.Errorf("aea: metadata extent exceeds source or 1 MiB limit")
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(io.NewSectionReader(source, 12, size), data); err != nil {
		return nil, err
	}
	result := &Metadata{Profile: profile & 0xffffff, ScryptStrength: uint8(profile >> 24),
		AuthData: io.NewSectionReader(source, 12, size), Values: make(map[string][]byte)}
	for offset := 0; offset < len(data); {
		if len(result.Values) >= 1024 || len(data)-offset < 4 {
			return nil, fmt.Errorf("aea: truncated or excessive metadata records")
		}
		length := uint64(binary.LittleEndian.Uint32(data[offset:]))
		if length < 6 || length > uint64(len(data)-offset) {
			return nil, fmt.Errorf("aea: invalid metadata record extent")
		}
		record := data[offset+4 : offset+int(length)]
		key, value, found := bytes.Cut(record, []byte{0})
		if !found || len(key) == 0 || !utf8.Valid(key) {
			return nil, fmt.Errorf("aea: invalid metadata key")
		}
		if _, exists := result.Values[string(key)]; exists {
			return nil, fmt.Errorf("aea: duplicate metadata key %q", key)
		}
		result.Values[string(key)] = value
		offset += int(length)
	}
	return result, nil
}

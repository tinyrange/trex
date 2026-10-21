package im4p

import (
	"bytes"
	"fmt"
	"math"

	"github.com/tinyrange/trex/storage"
)

// Wrap constructs an IMG4 container, borrowing the complete IM4P and optional
// IM4M records. It does not manufacture a manifest or authenticate either input.
func Wrap(payload, manifest storage.Reader) (storage.Reader, error) {
	if _, err := Open(payload); err != nil {
		return nil, err
	}
	parts := []storage.Range{{Source: bytes.NewReader([]byte{0x16, 4, 'I', 'M', 'G', '4'}), Length: 6}, {Source: payload, Length: payload.Size()}}
	if manifest != nil {
		count := 0
		root, end, err := node(manifest, 0, manifest.Size(), 0, &count)
		if err != nil {
			return nil, err
		}
		if root.Tag != 0x30 || end != manifest.Size() || len(root.Children) == 0 {
			return nil, fmt.Errorf("img4: invalid manifest envelope")
		}
		magic, err := text(root.Children[0])
		if err != nil || magic != "IM4M" {
			return nil, fmt.Errorf("img4: expected IM4M manifest")
		}
		prefix := derHeader(0xa0, uint64(manifest.Size()))
		parts = append(parts, storage.Range{Source: bytes.NewReader(prefix), Length: int64(len(prefix))}, storage.Range{Source: manifest, Length: manifest.Size()})
	}
	body, err := storage.Compose(parts...)
	if err != nil || body.Size() > math.MaxInt64-10 {
		return nil, fmt.Errorf("img4: container size overflow")
	}
	prefix := derHeader(0x30, uint64(body.Size()))
	return storage.Compose(storage.Range{Source: bytes.NewReader(prefix), Length: int64(len(prefix))}, storage.Range{Source: body, Length: body.Size()})
}

func derHeader(tag byte, size uint64) []byte {
	if size < 128 {
		return []byte{tag, byte(size)}
	}
	var encoded [8]byte
	start := len(encoded)
	for size != 0 {
		start--
		encoded[start] = byte(size)
		size >>= 8
	}
	return append([]byte{tag, 0x80 | byte(len(encoded)-start)}, encoded[start:]...)
}

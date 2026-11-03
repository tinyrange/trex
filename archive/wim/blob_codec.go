package wim

import (
	"fmt"
	"sync"

	"github.com/klauspost/compress/zstd"
)

// These codecs only encode private, disposable in-memory cache entries. WIM
// source bytes and image file contents remain unchanged. EncodeAll/DecodeAll
// are safe for concurrent callers; single-worker codecs bound scratch memory.
var blobCodecs struct {
	sync.Once
	encoder *zstd.Encoder
	decoder *zstd.Decoder
	err     error
}

func initBlobCodecs() error {
	blobCodecs.Do(func() {
		blobCodecs.encoder, blobCodecs.err = zstd.NewWriter(nil, zstd.WithEncoderConcurrency(1), zstd.WithEncoderLevel(zstd.SpeedFastest), zstd.WithWindowSize(1<<20))
		if blobCodecs.err != nil {
			return
		}
		blobCodecs.decoder, blobCodecs.err = zstd.NewReader(nil, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(64<<20))
	})
	return blobCodecs.err
}

func encodeCachedBlob(data []byte) ([]byte, error) {
	if err := initBlobCodecs(); err != nil {
		return nil, err
	}
	encoded := blobCodecs.encoder.EncodeAll(data, []byte{1})
	if len(encoded) >= len(data)+1 {
		encoded = make([]byte, len(data)+1)
		copy(encoded[1:], data)
	}
	if cap(encoded) != len(encoded) {
		// EncodeAll may reserve its worst-case output capacity. Retain and
		// charge only the encoded bytes, not hidden plaintext-sized backing.
		tight := make([]byte, len(encoded))
		copy(tight, encoded)
		encoded = tight
	}
	return encoded, nil
}

func decodeCachedBlob(data []byte, size int64) ([]byte, error) {
	if size <= 0 || size > 32<<20 || len(data) == 0 {
		return nil, fmt.Errorf("wim: invalid cached blob bounds")
	}
	switch data[0] {
	case 0:
		if int64(len(data)-1) != size {
			return nil, fmt.Errorf("wim: invalid raw cached blob size")
		}
		return data[1:], nil
	case 1:
		if err := initBlobCodecs(); err != nil {
			return nil, err
		}
		decoded, err := blobCodecs.decoder.DecodeAll(data[1:], make([]byte, 0, int(size)))
		if err != nil {
			return nil, err
		}
		if int64(len(decoded)) != size {
			return nil, fmt.Errorf("wim: invalid expanded cached blob size")
		}
		return decoded, nil
	default:
		return nil, fmt.Errorf("wim: invalid cached blob encoding")
	}
}

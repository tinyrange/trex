package nsis

import (
	"bytes"
	"fmt"
	"github.com/tinyrange/trex/storage"
)

// Detect scans only the bounded aligned first-header signature. Once recognized,
// callers must propagate parsing errors rather than trying unrelated decoders.
func Detect(source storage.Reader, maximum int64) (int64, error) {
	if maximum <= 0 {
		return -1, fmt.Errorf("nsis: scan bound must be positive")
	}
	end := min(source.Size(), maximum)
	for base := int64(0); base < end; base += 64 << 10 {
		window := make([]byte, min(int64(64<<10), end-base))
		if err := readAt(source, window, base); err != nil {
			return -1, err
		}
		for at := 0; at+firstHeaderSize <= len(window); at += 512 {
			if bytes.Equal(window[at+4:at+20], signature) {
				return base + int64(at), nil
			}
		}
	}
	return -1, nil
}

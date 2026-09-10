package native

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// HTTPRangeDiskCache stores only immutable downloaded source bytes. It has no
// eviction limit: a successful range remains available to subsequent runs.
// Host paths and locking stay in the native backend. No parsed or constructed
// intermediate data is stored here.
type HTTPRangeDiskCache struct{ root string }

func NewHTTPRangeDiskCache(root string) (*HTTPRangeDiskCache, error) {
	if root == "" {
		return nil, fmt.Errorf("HTTP source cache directory must not be empty")
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	return &HTTPRangeDiskCache{root: absolute}, nil
}

func (c *HTTPRangeDiskCache) blockPath(digest [sha256.Size]byte, size, start, length int64) string {
	id := hex.EncodeToString(digest[:])
	return filepath.Join(c.root, "ranges-v1", id[:2], id, fmt.Sprint(size), fmt.Sprintf("%d-%d", start, length))
}

func (c *HTTPRangeDiskCache) get(ctx context.Context, digest [sha256.Size]byte, size, start, length int64, load func() ([]byte, error)) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	name := c.blockPath(digest, size, start, length)
	if err := os.MkdirAll(filepath.Dir(name), 0o700); err != nil {
		return nil, fmt.Errorf("create HTTP source cache: %w", err)
	}
	// OS locks are released on process exit, including interrupted downloads.
	// Recheck after locking: another process may have just fetched this range.
	lock, err := lockHTTPRangeCache(ctx, name+".lock")
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	data, err := readHTTPRangeCache(name, length)
	if err == nil {
		return data, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		// Never hide a damaged cache or a permissions error with more HTTP.
		return nil, fmt.Errorf("read HTTP source cache %q: %w", name, err)
	}
	data, err = load()
	if err != nil {
		return nil, err
	}
	if int64(len(data)) != length {
		return nil, fmt.Errorf("HTTP source cache loader returned %d bytes, want %d", len(data), length)
	}
	partial, err := os.CreateTemp(filepath.Dir(name), ".range-*")
	if err != nil {
		return nil, fmt.Errorf("create HTTP source cache range: %w", err)
	}
	defer func() { _ = partial.Close(); _ = os.Remove(partial.Name()) }()
	sum := sha256.Sum256(data)
	if _, err = partial.Write(sum[:]); err == nil {
		_, err = partial.Write(data)
	}
	if err == nil {
		err = partial.Sync()
	}
	if closeErr := partial.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(partial.Name(), name)
	}
	if err != nil {
		return nil, fmt.Errorf("publish HTTP source cache range: %w", err)
	}
	return data, nil
}

func readHTTPRangeCache(name string, length int64) ([]byte, error) {
	info, err := os.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() != length+sha256.Size {
		return nil, fmt.Errorf("invalid range file type or size")
	}
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var expected [sha256.Size]byte
	if _, err := io.ReadFull(f, expected[:]); err != nil {
		return nil, err
	}
	data := make([]byte, length)
	if _, err := io.ReadFull(f, data); err != nil {
		return nil, err
	}
	actual := sha256.Sum256(data)
	if !bytes.Equal(expected[:], actual[:]) {
		return nil, fmt.Errorf("range checksum mismatch")
	}
	return data, nil
}

package native

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/tinyrange/trex/storage"
)

// MirrorRequest identifies one immutable file available from interchangeable
// HTTP(S) mirrors. CacheKey is opaque and never used as a host path. Size is
// the exact expected size, or -1 when unknown. SHA256 is an optional lowercase
// or uppercase hexadecimal digest. MaximumBytes must be positive.
type MirrorRequest struct {
	URLs         []string
	CacheKey     string
	SHA256       string
	Size         int64
	MaximumBytes int64
}

// MirrorCache downloads immutable files into a configured local cache and
// returns random-access readers for verified cache objects.
type MirrorCache struct {
	root   string
	client *http.Client

	mu    sync.Mutex
	locks map[string]*sync.Mutex
}

// NewMirrorCache creates a cache backend. Directories are created lazily.
// A nil client uses http.DefaultClient.
func NewMirrorCache(root string, client *http.Client) (*MirrorCache, error) {
	if strings.TrimSpace(root) == "" {
		return nil, fmt.Errorf("mirror cache directory must not be empty")
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve mirror cache directory: %w", err)
	}
	if client == nil {
		client = http.DefaultClient
	}
	return &MirrorCache{root: absolute, client: client, locks: make(map[string]*sync.Mutex)}, nil
}

// CachedFile is a verified cache object. It implements storage.Reader and
// should be closed when the caller no longer needs it.
type CachedFile struct {
	name string
	file *os.File
	size int64
}

var _ storage.Reader = (*CachedFile)(nil)

func (f *CachedFile) ReadAt(p []byte, off int64) (int, error) { return f.file.ReadAt(p, off) }
func (f *CachedFile) Size() int64                             { return f.size }
func (f *CachedFile) Name() string                            { return f.name }
func (f *CachedFile) Close() error                            { return f.file.Close() }

// Open returns a verified cached file, downloading it when necessary. Partial
// files remain resumable after transport failures; only a fully verified file
// is atomically published as a cache object.
func (c *MirrorCache) Open(ctx context.Context, request MirrorRequest) (*CachedFile, error) {
	validated, digest, err := validateMirrorRequest(request)
	if err != nil {
		return nil, err
	}
	request = validated
	objectID := mirrorObjectID(request, digest)
	objectPath := filepath.Join(c.root, "objects", objectID[:2], objectID)
	lock := c.objectLock(objectPath)
	lock.Lock()
	defer lock.Unlock()

	if file, err := openVerifiedCacheFile(objectPath, request, digest); err == nil {
		return file, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		if removeErr := os.Remove(objectPath); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			return nil, fmt.Errorf("remove invalid mirror cache object: %w", removeErr)
		}
	}
	if err := os.MkdirAll(filepath.Dir(objectPath), 0o755); err != nil {
		return nil, fmt.Errorf("create mirror cache directory: %w", err)
	}
	partialPath := objectPath + ".partial"
	if info, err := os.Lstat(partialPath); err == nil && !info.Mode().IsRegular() {
		return nil, fmt.Errorf("mirror partial path is not a regular file")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect mirror partial path: %w", err)
	}
	partial, err := os.OpenFile(partialPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open mirror partial file: %w", err)
	}
	keepPartial := true
	defer func() {
		_ = partial.Close()
		if !keepPartial {
			_ = os.Remove(partialPath)
		}
	}()

	var failures []error
	for _, rawURL := range request.URLs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := c.downloadFrom(ctx, partial, rawURL, request, digest); err != nil {
			failures = append(failures, err)
			continue
		}
		if err := partial.Sync(); err != nil {
			return nil, fmt.Errorf("sync mirror partial file: %w", err)
		}
		if err := partial.Close(); err != nil {
			return nil, fmt.Errorf("close mirror partial file: %w", err)
		}
		if err := os.Rename(partialPath, objectPath); err != nil {
			return nil, fmt.Errorf("publish mirror cache object: %w", err)
		}
		keepPartial = false
		file, err := openVerifiedCacheFile(objectPath, request, digest)
		if err != nil {
			return nil, fmt.Errorf("open published mirror cache object: %w", err)
		}
		return file, nil
	}
	if len(failures) == 0 {
		return nil, fmt.Errorf("mirror request has no URLs")
	}
	return nil, fmt.Errorf("all mirrors failed: %w", errors.Join(failures...))
}

func validateMirrorRequest(request MirrorRequest) (MirrorRequest, []byte, error) {
	request.CacheKey = strings.TrimSpace(request.CacheKey)
	if request.CacheKey == "" {
		return request, nil, fmt.Errorf("mirror cache key must not be empty")
	}
	if request.Size < -1 {
		return request, nil, fmt.Errorf("mirror expected size must be -1 or non-negative")
	}
	if request.MaximumBytes <= 0 {
		return request, nil, fmt.Errorf("mirror maximum bytes must be positive")
	}
	if request.Size >= 0 && request.Size > request.MaximumBytes {
		return request, nil, fmt.Errorf("mirror expected size %d exceeds maximum %d", request.Size, request.MaximumBytes)
	}
	var digest []byte
	if request.SHA256 != "" {
		decoded, err := hex.DecodeString(strings.TrimSpace(request.SHA256))
		if err != nil || len(decoded) != sha256.Size {
			return request, nil, fmt.Errorf("mirror SHA-256 must contain 64 hexadecimal digits")
		}
		digest = decoded
		request.SHA256 = hex.EncodeToString(decoded)
	}
	for index, rawURL := range request.URLs {
		parsed, err := url.Parse(rawURL)
		if err != nil || parsed.Host == "" || parsed.Scheme != "http" && parsed.Scheme != "https" {
			return request, nil, fmt.Errorf("mirror URL %d must be absolute HTTP(S)", index)
		}
	}
	return request, digest, nil
}

func mirrorObjectID(request MirrorRequest, digest []byte) string {
	if len(digest) == sha256.Size {
		return hex.EncodeToString(digest)
	}
	value := sha256.Sum256([]byte(request.CacheKey))
	return hex.EncodeToString(value[:])
}

func (c *MirrorCache) objectLock(name string) *sync.Mutex {
	c.mu.Lock()
	defer c.mu.Unlock()
	lock := c.locks[name]
	if lock == nil {
		lock = &sync.Mutex{}
		c.locks[name] = lock
	}
	return lock
}

func openVerifiedCacheFile(name string, request MirrorRequest, digest []byte) (*CachedFile, error) {
	pathInfo, err := os.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !pathInfo.Mode().IsRegular() {
		return nil, fmt.Errorf("mirror cache object is not a regular file")
	}
	file, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, fmt.Errorf("mirror cache object is not a regular file")
	}
	if info.Size() > request.MaximumBytes || request.Size >= 0 && info.Size() != request.Size {
		_ = file.Close()
		return nil, fmt.Errorf("mirror cache object has size %d", info.Size())
	}
	if len(digest) != 0 {
		hasher := sha256.New()
		if _, err := io.Copy(hasher, file); err != nil {
			_ = file.Close()
			return nil, fmt.Errorf("hash mirror cache object: %w", err)
		}
		if !equalDigest(hasher.Sum(nil), digest) {
			_ = file.Close()
			return nil, fmt.Errorf("mirror cache object SHA-256 mismatch")
		}
	}
	return &CachedFile{name: name, file: file, size: info.Size()}, nil
}

func (c *MirrorCache) downloadFrom(ctx context.Context, partial *os.File, rawURL string, request MirrorRequest, digest []byte) error {
	parsed, _ := url.Parse(rawURL)
	displayURL := parsed.Redacted()
	info, err := partial.Stat()
	if err != nil {
		return fmt.Errorf("%s: inspect partial file: %w", displayURL, err)
	}
	offset := info.Size()
	if offset < 0 || offset > request.MaximumBytes || request.Size >= 0 && offset > request.Size {
		if err := partial.Truncate(0); err != nil {
			return fmt.Errorf("%s: reset oversized partial file: %w", displayURL, err)
		}
		offset = 0
	}
	hasher, err := hashFilePrefix(partial, offset)
	if err != nil {
		return fmt.Errorf("%s: hash partial file: %w", displayURL, err)
	}
	hasExisting := offset != 0
	requestHTTP, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return fmt.Errorf("%s: create request: %w", displayURL, err)
	}
	requestHTTP.Header.Set("Accept-Encoding", "identity")
	if hasExisting {
		requestHTTP.Header.Set("Range", fmt.Sprintf("bytes=%d-", offset))
	}
	response, err := c.client.Do(requestHTTP)
	if err != nil {
		return fmt.Errorf("%s: %w", displayURL, err)
	}
	defer response.Body.Close()

	switch response.StatusCode {
	case http.StatusOK:
		if err := partial.Truncate(0); err != nil {
			return fmt.Errorf("%s: restart partial file: %w", displayURL, err)
		}
		offset = 0
		hasher = sha256.New()
	case http.StatusPartialContent:
		start, err := contentRangeStart(response.Header.Get("Content-Range"))
		if err != nil || start != offset {
			return fmt.Errorf("%s: invalid Content-Range for offset %d", displayURL, offset)
		}
	default:
		return fmt.Errorf("%s: server returned %s", displayURL, response.Status)
	}
	if _, err := partial.Seek(offset, io.SeekStart); err != nil {
		return fmt.Errorf("%s: seek partial file: %w", displayURL, err)
	}
	remaining := request.MaximumBytes - offset
	if request.Size >= 0 {
		remaining = request.Size - offset
	}
	if response.ContentLength > remaining {
		return fmt.Errorf("%s: response exceeds remaining size %d", displayURL, remaining)
	}
	written, copyErr := io.Copy(io.MultiWriter(partial, hasher), io.LimitReader(response.Body, remaining+1))
	if copyErr != nil {
		return fmt.Errorf("%s: download after %d bytes: %w", displayURL, offset+written, copyErr)
	}
	actualSize := offset + written
	if written > remaining || actualSize > request.MaximumBytes {
		_ = partial.Truncate(0)
		return fmt.Errorf("%s: response exceeds maximum size", displayURL)
	}
	if request.Size >= 0 && actualSize != request.Size {
		return fmt.Errorf("%s: downloaded size %d, want %d", displayURL, actualSize, request.Size)
	}
	if len(digest) != 0 && !equalDigest(hasher.Sum(nil), digest) {
		_ = partial.Truncate(0)
		return fmt.Errorf("%s: SHA-256 mismatch", displayURL)
	}
	return nil
}

func hashFilePrefix(file *os.File, size int64) (hash.Hash, error) {
	hasher := sha256.New()
	if size == 0 {
		return hasher, nil
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	written, err := io.CopyN(hasher, file, size)
	if err != nil {
		return nil, err
	}
	if written != size {
		return nil, io.ErrUnexpectedEOF
	}
	return hasher, nil
}

func contentRangeStart(value string) (int64, error) {
	if !strings.HasPrefix(value, "bytes ") {
		return 0, fmt.Errorf("missing byte range")
	}
	value = strings.TrimPrefix(value, "bytes ")
	dash := strings.IndexByte(value, '-')
	slash := strings.IndexByte(value, '/')
	if dash <= 0 || slash <= dash+1 {
		return 0, fmt.Errorf("invalid byte range")
	}
	start, err := strconv.ParseInt(value[:dash], 10, 64)
	if err != nil || start < 0 {
		return 0, fmt.Errorf("invalid byte range start")
	}
	return start, nil
}

func equalDigest(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var different byte
	for index := range left {
		different |= left[index] ^ right[index]
	}
	return different == 0
}

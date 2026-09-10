package native

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tinyrange/trex/storage/cache"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

const (
	defaultHTTPRangeChunk = int64(4 << 20)
	defaultHTTPRangeCache = int64(256 << 20)
	httpRangeAttempts     = 3
	httpRangeAttemptLimit = 8 * time.Second
	httpRangeFetchLimit   = 25 * time.Second
)

var nextHTTPRangeSource atomic.Uint64

// HTTPRangeLocationResolver renews locations for the same immutable file.
// It must preserve the declared content identity and size. It is called only
// after a forbidden response, within the existing fetch deadline.
type HTTPRangeLocationResolver func(context.Context, string, int64, []string) ([]string, error)

// HTTPRangeFile is a read-only random-access HTTP file backed by a bounded
// in-memory chunk LRU. It never creates a host file or disk cache.
type HTTPRangeFile struct {
	context          context.Context
	name             string
	urls             []string
	locationMu       sync.RWMutex
	locationVersion  uint64
	resolveLocations HTTPRangeLocationResolver
	size, chunk      int64
	client           *http.Client
	cache            *bytecache.Cache
	cacheSourceID    uint64
	diskCache        *HTTPRangeDiskCache
	digest           [sha256.Size]byte
}

// HTTPRangePool owns the operation-wide byte cache shared by every file it
// opens. The bound therefore applies to the complete HTTP operation, not once
// per payload.
type HTTPRangePool struct {
	client           *http.Client
	chunk            int64
	cache            *bytecache.Cache
	resolveLocations HTTPRangeLocationResolver
	diskCache        *HTTPRangeDiskCache
}

// NewPersistentHTTPRangePool retains fetched source ranges across runs. The
// byte bound applies only to the RAM hot cache; the disk source cache does not
// evict successful downloads. Files must be opened with OpenSHA256.
func NewPersistentHTTPRangePool(chunkBytes, cacheBytes int64, client *http.Client, resolve HTTPRangeLocationResolver, disk *HTTPRangeDiskCache) (*HTTPRangePool, error) {
	if disk == nil {
		return nil, fmt.Errorf("persistent HTTP range pool requires a disk cache")
	}
	p, err := NewRefreshingHTTPRangePool(chunkBytes, cacheBytes, client, resolve)
	if err != nil {
		return nil, err
	}
	p.diskCache = disk
	return p, nil
}

// NewRefreshingHTTPRangePool adds bounded location renewal to a pool without
// changing its content cache or requiring callers to reopen existing files.
func NewRefreshingHTTPRangePool(chunkBytes, cacheBytes int64, client *http.Client, resolve HTTPRangeLocationResolver) (*HTTPRangePool, error) {
	p, err := NewHTTPRangePool(chunkBytes, cacheBytes, client)
	if err != nil {
		return nil, err
	}
	p.resolveLocations = resolve
	return p, nil
}

// NewHTTPRangePool creates a random-access HTTP source with a single bounded
// in-memory LRU. It never creates a host file or disk cache.
func NewHTTPRangePool(chunkBytes, cacheBytes int64, client *http.Client) (*HTTPRangePool, error) {
	if chunkBytes == 0 {
		chunkBytes = defaultHTTPRangeChunk
	}
	if cacheBytes == 0 {
		cacheBytes = defaultHTTPRangeCache
	}
	if chunkBytes <= 0 || cacheBytes < chunkBytes {
		return nil, fmt.Errorf("HTTP range chunk/cache bounds are invalid")
	}
	if client == nil {
		client = http.DefaultClient
	}
	return &HTTPRangePool{client: client, chunk: chunkBytes, cache: bytecache.New(cacheBytes)}, nil
}

// Open constructs a lazy read-only file using the pool's shared cache.
func (p *HTTPRangePool) Open(ctx context.Context, name string, urls []string, size int64) (*HTTPRangeFile, error) {
	if p != nil && p.diskCache != nil {
		return nil, fmt.Errorf("persistent HTTP source requires an immutable SHA-256 identity")
	}
	return p.open(ctx, name, urls, size)
}

// Discover opens a lazy file after a bounded HEAD request determines its size.
// It never downloads the body. Subsequent range reads validate the total size
// as usual; discovery does not replace format identity or content verification.
func (p *HTTPRangePool) Discover(ctx context.Context, name string, urls []string) (*HTTPRangeFile, error) {
	if p == nil || p.client == nil || p.cache == nil {
		return nil, fmt.Errorf("HTTP range pool is not initialized")
	}
	selected := validHTTPRangeLocations(urls)
	if len(selected) == 0 {
		return nil, fmt.Errorf("HTTP range file has no absolute HTTP(S) URL")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	requestCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodHead, selected[0], nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept-Encoding", "identity")
	response, err := p.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("HTTP range discovery: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.ContentLength <= 0 {
		return nil, fmt.Errorf("HTTP range discovery requires status 200 and positive Content-Length (status %d, size %d)", response.StatusCode, response.ContentLength)
	}
	if encoding := response.Header.Get("Content-Encoding"); encoding != "" && !strings.EqualFold(encoding, "identity") {
		return nil, fmt.Errorf("HTTP range discovery rejects encoded representation")
	}
	return p.Open(ctx, name, selected, response.ContentLength)
}

// OpenSHA256 keys persistent bytes by the declared content digest and size,
// never by expiring URLs or filenames. Range checksums detect cache damage;
// they do not replace the caller's complete payload/target hash verification.
func (p *HTTPRangePool) OpenSHA256(ctx context.Context, name string, urls []string, size int64, digest string) (*HTTPRangeFile, error) {
	decoded, err := hex.DecodeString(digest)
	if err != nil || len(decoded) != sha256.Size {
		return nil, fmt.Errorf("HTTP source SHA-256 must contain 64 hexadecimal digits")
	}
	f, err := p.open(ctx, name, urls, size)
	if err != nil {
		return nil, err
	}
	f.diskCache = p.diskCache
	copy(f.digest[:], decoded)
	return f, nil
}

func (p *HTTPRangePool) open(ctx context.Context, name string, urls []string, size int64) (*HTTPRangeFile, error) {
	if p == nil || p.client == nil || p.cache == nil {
		return nil, fmt.Errorf("HTTP range pool is not initialized")
	}
	if size <= 0 {
		return nil, fmt.Errorf("HTTP range file size must be positive")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	selected := validHTTPRangeLocations(urls)
	if len(selected) == 0 {
		return nil, fmt.Errorf("HTTP range file has no absolute HTTP(S) URL")
	}
	return &HTTPRangeFile{
		context: ctx, name: name, urls: selected, size: size, chunk: p.chunk,
		client: p.client, cache: p.cache, cacheSourceID: nextHTTPRangeSource.Add(1),
		resolveLocations: p.resolveLocations,
	}, nil
}

func validHTTPRangeLocations(urls []string) []string {
	selected := make([]string, 0, len(urls))
	for _, candidate := range urls {
		parsed, err := url.Parse(candidate)
		if err == nil && parsed.Host != "" && (parsed.Scheme == "http" || parsed.Scheme == "https") {
			selected = append(selected, candidate)
		}
	}
	return selected
}

func (f *HTTPRangeFile) locations() ([]string, uint64) {
	f.locationMu.RLock()
	defer f.locationMu.RUnlock()
	return append([]string(nil), f.urls...), f.locationVersion
}

func (f *HTTPRangeFile) refreshLocations(ctx context.Context, version uint64) error {
	f.locationMu.Lock()
	defer f.locationMu.Unlock()
	if f.locationVersion != version {
		return nil
	} // another chunk already renewed
	if err := ctx.Err(); err != nil {
		return err
	}
	urls, err := f.resolveLocations(ctx, f.name, f.size, append([]string(nil), f.urls...))
	if err != nil {
		return err
	}
	selected := validHTTPRangeLocations(urls)
	if len(selected) == 0 {
		return fmt.Errorf("resolver returned no absolute HTTP(S) URL")
	}
	f.urls = selected
	f.locationVersion++
	return nil
}

// NewHTTPRangeFile validates immutable HTTP location metadata and constructs
// a lazy random-access reader. Size must be exact and positive.
func NewHTTPRangeFile(name string, urls []string, size, chunkBytes, cacheBytes int64, client *http.Client) (*HTTPRangeFile, error) {
	pool, err := NewHTTPRangePool(chunkBytes, cacheBytes, client)
	if err != nil {
		return nil, err
	}
	return pool.Open(context.Background(), name, urls, size)
}

func (f *HTTPRangeFile) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off >= f.size {
		return 0, io.EOF
	}
	wanted := len(p)
	if int64(len(p)) > f.size-off {
		p = p[:f.size-off]
	}
	done := 0
	for len(p) != 0 {
		index := off / f.chunk
		start := index * f.chunk
		length := min(f.chunk, f.size-start)
		data, err := f.cache.Get(bytecache.Key{Source: f.cacheSourceID, Kind: 1, Offset: start, Size: length, Index: int(index)}, func() ([]byte, error) {
			if f.diskCache != nil {
				return f.diskCache.get(f.context, f.digest, f.size, start, length, func() ([]byte, error) { return f.fetch(start, length) })
			}
			return f.fetch(start, length)
		})
		if err != nil {
			return done, err
		}
		within := off - start
		count := copy(p, data[within:])
		done += count
		off += int64(count)
		p = p[count:]
	}
	if done != wanted {
		return done, io.EOF
	}
	return done, nil
}

func (f *HTTPRangeFile) fetch(start, length int64) ([]byte, error) {
	end := start + length - 1
	var lastErr error
	fetchContext, cancelFetch := context.WithTimeout(f.context, httpRangeFetchLimit)
	defer cancelFetch()
	refreshed := false
	locationCount := 0
attempts:
	for attempt := 0; attempt < httpRangeAttempts; attempt++ {
		urls, version := f.locations()
		locationCount = len(urls)
		for _, rawURL := range urls {
			requestContext, cancelRequest := context.WithTimeout(fetchContext, httpRangeAttemptLimit)
			request, err := http.NewRequestWithContext(requestContext, http.MethodGet, rawURL, nil)
			if err != nil {
				cancelRequest()
				lastErr = err
				continue
			}
			request.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", start, end))
			request.Header.Set("Accept-Encoding", "identity")
			response, err := f.client.Do(request)
			if err != nil {
				cancelRequest()
				lastErr = err
				continue
			}
			data, err := readHTTPRange(response, start, end, f.size)
			response.Body.Close()
			cancelRequest()
			if err == nil {
				return data, nil
			}
			lastErr = err
			if response.StatusCode == http.StatusForbidden && f.resolveLocations != nil && !refreshed && attempt+1 < httpRangeAttempts {
				refreshed = true
				if err := f.refreshLocations(fetchContext, version); err != nil {
					return nil, fmt.Errorf("refresh HTTP locations for %q: %w", f.name, err)
				}
				continue attempts
			}
		}
		if fetchContext.Err() != nil {
			break
		}
	}
	if lastErr == nil {
		lastErr = fetchContext.Err()
	}
	return nil, fmt.Errorf("fetch HTTP range %q [%d:%d] from %d location(s): %w", f.name, start, end+1, locationCount, lastErr)
}

func readHTTPRange(response *http.Response, start, end, size int64) ([]byte, error) {
	if response.StatusCode != http.StatusPartialContent {
		return nil, fmt.Errorf("returned status %d", response.StatusCode)
	}
	contentStart, contentEnd, contentSize, err := parseHTTPContentRange(response.Header.Get("Content-Range"))
	if err != nil || contentStart != start || contentEnd != end || contentSize != size {
		return nil, fmt.Errorf("invalid Content-Range %q", response.Header.Get("Content-Range"))
	}
	length := end - start + 1
	data := make([]byte, length)
	if _, err := io.ReadFull(response.Body, data); err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	var extra [1]byte
	if count, err := response.Body.Read(extra[:]); count != 0 || err != io.EOF {
		return nil, fmt.Errorf("response exceeds declared length")
	}
	return data, nil
}

func parseHTTPContentRange(value string) (int64, int64, int64, error) {
	if !strings.HasPrefix(value, "bytes ") {
		return 0, 0, 0, fmt.Errorf("invalid Content-Range")
	}
	parts := strings.Split(strings.TrimPrefix(value, "bytes "), "/")
	if len(parts) != 2 {
		return 0, 0, 0, fmt.Errorf("invalid Content-Range")
	}
	bounds := strings.Split(parts[0], "-")
	if len(bounds) != 2 {
		return 0, 0, 0, fmt.Errorf("invalid Content-Range")
	}
	start, err1 := strconv.ParseInt(bounds[0], 10, 64)
	end, err2 := strconv.ParseInt(bounds[1], 10, 64)
	size, err3 := strconv.ParseInt(parts[1], 10, 64)
	if err1 != nil || err2 != nil || err3 != nil || start < 0 || end < start || size <= end {
		return 0, 0, 0, fmt.Errorf("invalid Content-Range")
	}
	return start, end, size, nil
}

func (*HTTPRangeFile) WriteAt([]byte, int64) (int, error) {
	return 0, fmt.Errorf("HTTP range file is read-only")
}
func (f *HTTPRangeFile) Size() int64         { return f.size }
func (f *HTTPRangeFile) String() string      { return fmt.Sprintf("<HTTP file %s size=%d>", f.name, f.size) }
func (*HTTPRangeFile) Type() string          { return "file" }
func (*HTTPRangeFile) Freeze()               {}
func (*HTTPRangeFile) Truth() starlark.Bool  { return starlark.True }
func (*HTTPRangeFile) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: file") }
func (f *HTTPRangeFile) Attr(name string) (starlark.Value, error) {
	return starfile.Attr(f, name), nil
}
func (*HTTPRangeFile) AttrNames() []string { return starfile.AttrNames() }
func (*HTTPRangeFile) Close() error        { return nil }

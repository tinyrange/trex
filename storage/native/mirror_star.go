package native

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/tinyrange/trex/lifecycle"
	"go.starlark.net/starlark"
)

func mirrorFileBuiltin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var urlValues starlark.Iterable
	var cacheDirectory, cacheKey, digest string
	size := int64(-1)
	maximum := int64(64 << 30)
	timeout := 3600
	if err := starlark.UnpackArgs("mirror_file", args, kwargs,
		"urls", &urlValues, "cache", &cacheDirectory, "key", &cacheKey,
		"sha256?", &digest, "size?", &size, "maximum?", &maximum, "timeout?", &timeout); err != nil {
		return nil, err
	}
	if timeout <= 0 || timeout > 24*60*60 {
		return nil, fmt.Errorf("mirror_file: timeout must be between 1 and 86400 seconds")
	}
	var urls []string
	iterator := urlValues.Iterate()
	defer iterator.Done()
	var value starlark.Value
	for iterator.Next(&value) {
		text, ok := starlark.AsString(value)
		if !ok {
			return nil, fmt.Errorf("mirror_file: urls[%d] got %s, want string", len(urls), value.Type())
		}
		urls = append(urls, text)
	}
	cache, err := NewMirrorCache(cacheDirectory, &http.Client{Timeout: time.Duration(timeout) * time.Second})
	if err != nil {
		return nil, fmt.Errorf("mirror_file: %w", err)
	}
	ctx := context.Background()
	resources, resourceErr := lifecycle.ForThread(thread)
	if resourceErr == nil {
		ctx = resources.Context()
	}
	file, err := cache.Open(ctx, MirrorRequest{
		URLs: urls, CacheKey: cacheKey, SHA256: digest, Size: size, MaximumBytes: maximum,
	})
	if err != nil {
		return nil, fmt.Errorf("mirror_file: %w", err)
	}
	if resourceErr == nil {
		if _, err := resources.Add(file); err != nil {
			_ = file.Close()
			return nil, fmt.Errorf("mirror_file: register cached file: %w", err)
		}
	}
	return file, nil
}

func (f *CachedFile) WriteAt([]byte, int64) (int, error) {
	return 0, fmt.Errorf("mirror cache object %q is read-only", f.name)
}
func (f *CachedFile) String() string                           { return fmt.Sprintf("<file %q>", f.name) }
func (*CachedFile) Type() string                               { return "file" }
func (*CachedFile) Freeze()                                    {}
func (*CachedFile) Truth() starlark.Bool                       { return starlark.True }
func (*CachedFile) Hash() (uint32, error)                      { return 0, fmt.Errorf("unhashable: file") }
func (f *CachedFile) Attr(name string) (starlark.Value, error) { return fileAttr(f, name), nil }
func (*CachedFile) AttrNames() []string                        { return fileAttrNames() }

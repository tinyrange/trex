package native

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/tinyrange/trex/lifecycle"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func mirrorFileBuiltin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var urlValues starlark.Iterable
	var cacheDirectory, cacheKey, digest string
	var validateValue starlark.Value = starlark.None
	size := int64(-1)
	maximum := int64(64 << 30)
	timeout := 3600
	retries := 0
	if err := starlark.UnpackArgs("mirror_file", args, kwargs,
		"urls", &urlValues, "cache", &cacheDirectory, "key", &cacheKey,
		"sha256?", &digest, "size?", &size, "maximum?", &maximum, "timeout?", &timeout, "retries?", &retries,
		"validate?", &validateValue); err != nil {
		return nil, err
	}
	if timeout <= 0 || timeout > 24*60*60 {
		return nil, fmt.Errorf("mirror_file: timeout must be between 1 and 86400 seconds")
	}
	var validate func(storage.Reader) error
	if validateValue != starlark.None {
		callback, ok := validateValue.(starlark.Callable)
		if !ok {
			return nil, fmt.Errorf("mirror_file: validate must be callable or None")
		}
		validate = func(source storage.Reader) error {
			file := &validationFile{source: source, size: source.Size()}
			defer func() { file.source = nil }()
			result, err := starlark.Call(thread, callback, starlark.Tuple{file}, nil)
			if err != nil {
				return err
			}
			if result != starlark.None {
				return fmt.Errorf("mirror_file: validate must return None; raise an error to reject content")
			}
			return nil
		}
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
	if cacheDirectory == "" {
		root, err := os.UserCacheDir()
		if err != nil {
			return nil, fmt.Errorf("mirror_file: default cache directory: %w", err)
		}
		cacheDirectory = filepath.Join(root, "trex")
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
		URLs: urls, CacheKey: cacheKey, SHA256: digest, Size: size, MaximumBytes: maximum, Retries: retries, Validate: validate,
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

// validationFile borrows a reader only for the synchronous validation call.
// Invalidate it afterward so callbacks cannot retain a mutable partial file.
type validationFile struct {
	source storage.Reader
	size   int64
}

func (f *validationFile) ReadAt(p []byte, off int64) (int, error) {
	if f.source == nil {
		return 0, fmt.Errorf("validation file is no longer available")
	}
	return f.source.ReadAt(p, off)
}
func (*validationFile) WriteAt([]byte, int64) (int, error) {
	return 0, fmt.Errorf("validation file is read-only")
}
func (f *validationFile) Size() int64         { return f.size }
func (*validationFile) String() string        { return "<validation file>" }
func (*validationFile) Type() string          { return "file" }
func (*validationFile) Freeze()               {}
func (*validationFile) Truth() starlark.Bool  { return starlark.True }
func (*validationFile) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: file") }
func (f *validationFile) Attr(name string) (starlark.Value, error) {
	return starfile.Attr(f, name), nil
}
func (*validationFile) AttrNames() []string { return starfile.AttrNames() }

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

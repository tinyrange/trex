package windows

import (
	"fmt"

	"github.com/tinyrange/trex/lifecycle"
	starvalue "github.com/tinyrange/trex/storage/star"
	"github.com/tinyrange/trex/windows/uup"
	"go.starlark.net/starlark"
)

// cbsManifestValue owns an immutable parse, not a global file/name cache. Source
// readers are discarded after parsing, so a mutable input cannot stale the parse.
type cbsManifestValue struct {
	manifest *uup.AssemblyManifest
	size     int
}

func (m *cbsManifestValue) String() string        { return "<windows.cbs_manifest>" }
func (m *cbsManifestValue) Type() string          { return "cbs_manifest" }
func (m *cbsManifestValue) Freeze()               {}
func (m *cbsManifestValue) Truth() starlark.Bool  { return starlark.True }
func (m *cbsManifestValue) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: cbs_manifest") }

func cbsManifestForValue(value starlark.Value, limit int) (*uup.AssemblyManifest, int, error) {
	return cachedCBSManifestForValue(value, limit, nil)
}

func cachedCBSManifestForValue(value starlark.Value, limit int, cache *uup.ManifestCache) (*uup.AssemblyManifest, int, error) {
	if parsed, ok := value.(*cbsManifestValue); ok {
		if parsed.size > limit {
			return nil, 0, fmt.Errorf("CBS manifest bytes exceed bound")
		}
		return parsed.manifest, parsed.size, nil
	}
	// Metadata readers already validated the exact identity against the source
	// namespace. Reuse their owned snapshot, not a cache keyed by a file name.
	if file, ok := value.(*starvalue.ReaderValue); ok {
		if parsed, ok := file.StorageReader().(*uup.ParsedAssemblyFile); ok {
			if parsed.Size() > int64(limit) {
				return nil, 0, fmt.Errorf("CBS manifest bytes exceed bound")
			}
			return parsed.Manifest(), int(parsed.Size()), nil
		}
	}
	data, err := bytesForBinaryValueLimited(value, int64(limit))
	if err != nil {
		return nil, 0, err
	}
	if cache == nil {
		manifest, err := uup.ParseAssemblyManifestBytes(data)
		return manifest, len(data), err
	}
	manifest, err := cache.Parse(string(data))
	return manifest, len(data), err
}

func cbsManifestBuiltin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs("cbs_manifest", args, kwargs, "manifest", &value); err != nil {
		return nil, err
	}
	var cache *uup.ManifestCache
	if resources, err := lifecycle.ForThread(thread); err == nil {
		cache = uup.NewManifestCache(resources.Context(), resources.Derived)
	}
	manifest, size, err := cachedCBSManifestForValue(value, 32<<20, cache)
	if err != nil {
		return nil, err
	}
	return &cbsManifestValue{manifest: manifest, size: size}, nil
}

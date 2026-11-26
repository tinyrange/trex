package windows

import (
	"crypto/sha256"
	"fmt"
	"sync"

	"github.com/tinyrange/trex/lifecycle"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"github.com/tinyrange/trex/windows/catalog"
	"go.starlark.net/starlark"
)

// parsedCatalog owns the exact bytes whose CTL and cryptographic integrity are
// inspected. No pathname, mutable reader or trust-policy decision is cached.
// File operations remain ordinary read-only portable operations.
type parsedCatalog struct {
	content       starfile.Bytes
	entries       [][]byte
	signatureOnce sync.Once
	integrity     *verifiedPEIntegrity
	timestamp     *verifiedSignatureTimestamp
	signatureErr  error
}

func catalogBuiltin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs("catalog", args, kwargs, "file", &value); err != nil {
		return nil, err
	}
	if parsed, ok := value.(*parsedCatalog); ok {
		return parsed, nil
	}
	data, err := bytesForBinaryValueLimited(value, 64<<20)
	if err != nil {
		return nil, err
	}
	entries, err := cachedCatalogIndex(thread, data)
	if err != nil {
		return nil, fmt.Errorf("catalog: %w", err)
	}
	return &parsedCatalog{content: starfile.Bytes{Name: "catalog", Data: data}, entries: entries}, nil
}

// Only member digest records are reused. The CAT bytes still own the signature
// and every membership or trust decision is made by its normal consumer.
func cachedCatalogIndex(thread *starlark.Thread, data []byte) ([][]byte, error) {
	r, err := lifecycle.ForThread(thread)
	if err != nil || r.Derived == nil {
		return catalog.ParseIndex(data)
	}
	key := storage.DerivedKey("windows.catalog.member-digests/v1", sha256.Sum256(data))
	var entries [][]byte
	var parseErr error
	built := false
	packed, cacheErr := r.Derived.GetOrBuild(r.Context(), key, 64<<20, func() ([]byte, error) {
		built = true
		entries, parseErr = catalog.ParseIndex(data)
		if parseErr != nil {
			return nil, parseErr
		}
		var out []byte
		for _, entry := range entries {
			out = append(out, byte(len(entry)))
			out = append(out, entry...)
		}
		return out, nil
	})
	if built {
		return entries, parseErr
	}
	if cacheErr != nil {
		return catalog.ParseIndex(data)
	}
	for len(packed) > 0 {
		size := int(packed[0])
		packed = packed[1:]
		if (size != 20 && size != 32) || len(packed) < size {
			return catalog.ParseIndex(data)
		}
		entries = append(entries, packed[:size:size])
		packed = packed[size:]
	}
	return entries, nil
}
func (c *parsedCatalog) ReadAt(p []byte, off int64) (int, error) { return c.content.ReadAt(p, off) }
func (*parsedCatalog) WriteAt([]byte, int64) (int, error) {
	return 0, fmt.Errorf("catalog is read-only")
}
func (c *parsedCatalog) Size() int64                              { return c.content.Size() }
func (*parsedCatalog) String() string                             { return "<catalog file>" }
func (*parsedCatalog) Type() string                               { return "file" }
func (*parsedCatalog) Freeze()                                    {}
func (*parsedCatalog) Truth() starlark.Bool                       { return starlark.True }
func (*parsedCatalog) Hash() (uint32, error)                      { return 0, fmt.Errorf("unhashable: file") }
func (c *parsedCatalog) Attr(name string) (starlark.Value, error) { return starfile.Attr(c, name), nil }
func (*parsedCatalog) AttrNames() []string                        { return starfile.AttrNames() }
func (c *parsedCatalog) signature() (starlark.Value, error) {
	c.signatureOnce.Do(func() {
		c.integrity, c.signatureErr = verifyCatalogSignedContent(c.content.Data)
		if c.signatureErr == nil {
			c.timestamp, c.signatureErr = verifySignatureTimestamp(c.integrity)
		}
	})
	if c.signatureErr != nil {
		return nil, fmt.Errorf("catalog_signature: %w", c.signatureErr)
	}
	return signatureIntegrityProjection(c.integrity, c.timestamp), nil
}

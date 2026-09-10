package dmr

import "fmt"

// PackageResourceReferences contains already-resolved MRM reference blobs, not
// manifest strings. Callers must perform URI/PRI lookup (or establish the native
// literal branch) before supplying these values. A nil Description omits its
// optional record; an encoded empty literal is a present description.
type PackageResourceReferences struct {
	DisplayName, PublisherDisplayName, Description, Logo []byte
}

// EncodePackageResources builds the native package RESP section at index zero.
// Current internal references are literals or PRI indexes; unsupported forms
// fail rather than being copied as if their semantics had been established.
func EncodePackageResources(refs PackageResourceReferences) ([]byte, error) {
	r := Resources{Index: 0}
	for i, data := range [][]byte{refs.DisplayName, refs.PublisherDisplayName, refs.Description, refs.Logo} {
		if i == 2 && data == nil {
			continue
		}
		if _, err := ParseLiteralResourceReference(data); err != nil {
			if _, indexErr := ParseIndexResourceReference(data); indexErr != nil {
				return nil, fmt.Errorf("dmr: package resource %d requires a valid resolved reference", i+1)
			}
		}
		kind := uint16(0)
		if i == 3 {
			kind = 1
		}
		r.Entries = append(r.Entries, NamedResource{Value4: uint16(i + 1), Value6: kind, Data: data})
	}
	return EncodeResources(r)
}

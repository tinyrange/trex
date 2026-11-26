package storage

import (
	"context"
	"crypto/sha256"
)

// DerivedCache memoizes bounded, immutable records derived from exact inputs.
// Consumers version their record schemas in the key and retain responsibility
// for authenticating inputs and applying policy to the resulting records.
type DerivedCache interface {
	GetOrBuild(context.Context, [sha256.Size]byte, int64, func() ([]byte, error)) ([]byte, error)
}

// VerifiedContentCache returns random-access bytes tied to a digest obtained
// from the caller's admitted content declaration. A cold build must verify its
// input before publication. Cache hits do not authorize installing the content.
type VerifiedContentCache interface {
	GetOrBuildContent(context.Context, [sha256.Size]byte, int64, func() ([]byte, error)) (Reader, error)
}

// DerivedKey separates record types and schema versions for the same input.
func DerivedKey(schema string, input [sha256.Size]byte) [sha256.Size]byte {
	digest := sha256.New()
	_, _ = digest.Write([]byte(schema))
	_, _ = digest.Write(input[:])
	return [sha256.Size]byte(digest.Sum(nil))
}

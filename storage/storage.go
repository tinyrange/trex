// Package storage defines portable random-access byte sources and files.
package storage

import (
	"io"
	"path"
	"strings"
	"time"
)

// Reader is a random-access byte source whose size remains stable for its
// lifetime.
type Reader interface {
	io.ReaderAt
	Size() int64
}

// VerifiedSHA256Reader is an immutable, content-addressed reader that has
// already verified its entire logical payload. The returned identity is not
// merely declared metadata: false is required until byte verification succeeds.
// Every subsequent successful read must return that same content; reopening
// corrupted backing storage must fail, never expose different bytes. A cached
// digest describes content identity, not current backing-store availability.
// Implementations must be concurrency-safe.
type VerifiedSHA256Reader interface {
	VerifiedSHA256() ([32]byte, bool)
}

func Align(value, alignment int64) int64 {
	if alignment <= 0 {
		return value
	}
	return (value + alignment - 1) / alignment * alignment
}

func CeilDiv(value, divisor int64) int64 { return (value + divisor - 1) / divisor }

func WindowsFiletime(value time.Time) int64 {
	return value.UnixNano()/100 + 116444736000000000
}

// File is a writable Reader.
type File interface {
	Reader
	io.WriterAt
}

// CleanPath normalizes a path inside a virtual filesystem. It accepts either
// slash convention and always returns an absolute, slash-separated path.
func CleanPath(name string) string {
	name = strings.ReplaceAll(name, "\\", "/")
	return path.Clean("/" + strings.TrimPrefix(name, "/"))
}

package smb

import (
	"errors"
	"io"
	"io/fs"
	"strings"
	"time"
	"unicode/utf8"
)

var ErrSharingViolation = errors.New("SMB sharing violation")
var ErrDeletePending = errors.New("SMB delete pending")
var ErrNotDirectory = errors.New("SMB not a directory")
var ErrIsDirectory = errors.New("SMB is a directory")

// Access describes capabilities granted to an open handle, and, separately,
// capabilities that an opener permits other handles to acquire.
type Access uint8

const (
	AccessRead Access = 1 << iota
	AccessWrite
	AccessDelete
	AccessMetadataWrite
)
const (
	Supersede uint32 = iota
	OpenExisting
	CreateNew
	OpenIf
	Overwrite
	OverwriteIf
)

type OpenOptions struct {
	Access                                             Access
	Share                                              Access
	Disposition                                        uint32
	Directory, NonDirectory, DeleteOnClose, AppendOnly bool
}

// FileSystem owns the confinement boundary and open/share/delete semantics.
// Names are validated share-relative slash paths, with "." denoting the root.
// Implementations must enforce ReadOnly themselves, including metadata edits,
// and must not follow links outside their explicitly authorized root.
// Close prevents new opens and releases all handles.
type FileSystem interface {
	Open(name string, options OpenOptions) (File, uint32, error)
	ReadOnly() bool
	Close() error
}

// File exposes no OS path, file descriptor, socket, or process capability.
// ReadDir is bounded by count; Rewind resets directory enumeration.
type File interface {
	io.ReaderAt
	io.WriterAt
	io.Closer
	Stat() (fs.FileInfo, error)
	Sync() error
	Truncate(size int64) error
	ReadDir(count int) ([]fs.FileInfo, error)
	Rewind() error
	Rename(name string, replace bool) error
	SetDeletePending(pending bool) error
	SetTimes(access, modified time.Time) error
}

// SharePath rejects Windows device/stream namespaces as well as traversal.
// Do not clean an untrusted path: that can turn a forbidden name into an
// authorized one. This validation complements, never replaces, backend rooting.
func SharePath(name string) (string, error) {
	if len(name) > 4096 || !utf8.ValidString(name) {
		return "", fs.ErrInvalid
	}
	name = strings.ReplaceAll(name, "\\", "/")
	if name == "" {
		return ".", nil
	}
	if strings.HasPrefix(name, "/") || strings.ContainsAny(name, ":\x00<>|?*\"") {
		return "", fs.ErrInvalid
	}
	for _, part := range strings.Split(name, "/") {
		if part == "" || part == "." || part == ".." || strings.TrimRight(part, " .") != part || len(utf16Bytes(part)) > 510 {
			return "", fs.ErrInvalid
		}
		base := strings.ToUpper(strings.SplitN(part, ".", 2)[0])
		if base == "CON" || base == "PRN" || base == "AUX" || base == "NUL" || base == "CLOCK$" || (len(base) == 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) && base[3] >= '1' && base[3] <= '9') {
			return "", fs.ErrInvalid
		}
		for _, r := range part {
			if r < 32 {
				return "", fs.ErrInvalid
			}
		}
	}
	return name, nil
}

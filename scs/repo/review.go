package repo

import (
	"archive/tar"
	"context"
	"fmt"
	"io"
	"time"
)

// FileInfo describes review-relevant state. Timestamps are intentionally omitted
// from diffs, so a build touching a file without changing it is not a change.
type FileInfo struct {
	Kind   string `json:"kind"`
	Mode   uint32 `json:"mode"`
	Size   int64  `json:"size,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
	Target string `json:"target,omitempty"`
	GitOID string `json:"git_oid,omitempty"`
}
type Change struct {
	Path   string    `json:"path"`
	Status string    `json:"status"` // added, deleted, modified
	Before *FileInfo `json:"before,omitempty"`
	After  *FileInfo `json:"after,omitempty"`
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}

// Diff captures each live root independently, then compares those immutable
// views. It does not publish or mutate the inputs. Equal Merkle identities and
// equal content references are skipped; this is a review operation, NOT a scrub.
// Corruption inside skipped subtrees is intentionally not detected. Use
// OpenVerified/Scrub for integrity checking. Renames remain deletion/addition.
func Diff(ctx context.Context, before, after *Workspace) ([]Change, error) {
	return diffTrees(ctx, before, after)
}

// ExportTar writes a full tree, not a changes-only patch. PAX preserves modes,
// nanosecond mtime, symlinks (without following them), and empty directories.
// Ownership is normalized to 0. Gitlinks cannot be represented and are rejected.
// The caller must prevent mutation and discard output on any error. This does
// not extract files: untrusted archives, especially symlinks, need safe handling.
func ExportTar(ctx context.Context, w *Workspace, output io.Writer) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	paths, err := w.PathsWithError()
	if err != nil {
		return err
	}
	tw := tar.NewWriter(output)
	for _, p := range paths {
		if err = ctx.Err(); err != nil {
			return err
		}
		e, err := w.Stat(p)
		if err != nil {
			return err
		}
		h := &tar.Header{Name: p, Mode: int64(e.Mode), ModTime: time.Unix(0, e.Times.M), Format: tar.FormatPAX}
		switch e.Kind {
		case "dir":
			h.Typeflag = tar.TypeDir
			h.Name += "/"
		case "symlink":
			h.Typeflag = tar.TypeSymlink
			h.Linkname, err = w.Readlink(p)
			if err != nil {
				return err
			}
		case "file":
			h.Typeflag = tar.TypeReg
			h.Size = e.Size
		default:
			return fmt.Errorf("cannot export %s %q to tar", e.Kind, p)
		}
		if err = tw.WriteHeader(h); err != nil {
			return err
		}
		if e.Kind == "file" {
			r, err := w.OpenReader(p)
			if err != nil {
				return err
			}
			_, err = io.Copy(tw, contextReader{ctx, r})
			r.Close()
			if err != nil {
				return err
			}
		}
	}
	return tw.Close()
}

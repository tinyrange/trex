package repo

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/pjbgf/sha1cd"
	"hash"
	"io"
)

func (r *Repository) ReadGitObject(id GitOID) (byte, []byte, error) {
	kind, _, ok := r.GitObjectHeader(id)
	if !ok {
		return 0, nil, errors.New("Git object not found")
	}
	f, err := r.OpenGitObject(id)
	if err != nil {
		return 0, nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(f)
	return kind, b, err
}
func (r *Repository) ResolveGit(catalog, revision string) (GitOID, error) {
	c, err := r.GitCatalog(catalog)
	if err != nil {
		return GitOID{}, err
	}
	if revision == "" || revision == "HEAD" {
		revision = c.Head
	}
	for _, name := range []string{revision, "refs/heads/" + revision, "refs/tags/" + revision} {
		if id, ok := c.Refs[name]; ok {
			return ParseGitOID(id)
		}
	}
	id, err := ParseGitOID(revision)
	if err != nil {
		return id, err
	}
	if _, _, ok := r.GitObjectHeader(id); !ok {
		return id, errors.New("Git revision not found")
	}
	return id, nil
}
func (r *Repository) PeelGit(id GitOID) (GitOID, byte, error) {
	for range 64 {
		kind, _, ok := r.GitObjectHeader(id)
		if !ok {
			return id, 0, errors.New("Git object not found")
		}
		if kind != GitTag {
			return id, kind, nil
		}
		_, b, err := r.ReadGitObject(id)
		if err != nil {
			return id, 0, err
		}
		err = GitLinks(kind, b, int(id[32]), func(target GitOID, want byte) error {
			got, _, ok := r.GitObjectHeader(target)
			if !ok || got != want {
				return errors.New("invalid tag target")
			}
			id = target
			return nil
		})
		if err != nil {
			return id, 0, err
		}
	}
	return id, 0, errors.New("tag nesting limit exceeded")
}
func (r *Repository) GitCommitParents(id GitOID) ([]GitOID, error) {
	kind, b, err := r.ReadGitObject(id)
	if err != nil {
		return nil, err
	}
	if kind != GitCommit {
		return nil, errors.New("not a commit")
	}
	var parents []GitOID
	err = GitLinks(kind, b, int(id[32]), func(target GitOID, k byte) error {
		if k == GitCommit {
			parents = append(parents, target)
		}
		return nil
	})
	return parents, err
}

// VerifyGitObject rehashes the reconstructed canonical body, not its descriptor.
func (r *Repository) VerifyGitObject(id GitOID) error {
	kind, size, ok := r.GitObjectHeader(id)
	if !ok {
		return errors.New("Git object not found")
	}
	f, err := r.OpenGitObject(id)
	if err != nil {
		return err
	}
	defer f.Close()
	var h hash.Hash = sha256.New()
	if id[32] == 20 {
		h = sha1cd.New()
	}
	fmt.Fprintf(h, "%s %d\x00", GitTypeName(kind), size)
	n, err := io.Copy(h, f)
	if err != nil {
		return err
	}
	if n != size || !equalDigest(h.Sum(nil), id[:id[32]]) {
		return errors.New("Git object digest mismatch")
	}
	return nil
}

// LinkGitBlob shares native blocks; checkout does not ingest the body again.
func (w *Workspace) LinkGitBlob(p string, id GitOID, mode uint32) error {
	obj, err := w.r.GitObject(id)
	if err != nil {
		return err
	}
	if obj.Kind != GitBlob {
		return errors.New("not a blob")
	}
	kind := "file"
	perms := uint32(0644)
	switch mode {
	case 0100644:
	case 0100755:
		perms = 0755
	case 0120000:
		kind = "symlink"
		perms = 0777
	default:
		return errors.New("unsupported checkout mode")
	}
	return w.installGitEntry(p, Entry{Kind: kind, Mode: perms, Size: obj.Size, Blocks: obj.Blocks, Body: obj.Body})
}
func (w *Workspace) Gitlink(p string, id GitOID) error {
	if !id.Valid() {
		return errors.New("invalid gitlink ID")
	}
	return w.installGitEntry(p, Entry{Kind: "gitlink", GitOID: id.String()})
}
func (w *Workspace) installGitEntry(p string, e Entry) error {
	w.s.mu.Lock()
	defer w.s.mu.Unlock()
	if w.readonly {
		return ErrReadOnly
	}
	p, err := clean(p)
	if err != nil {
		return err
	}
	if err := w.prepare(p, false); err != nil {
		return err
	}
	if _, ok := w.s.get(p); ok {
		return errors.New("destination exists")
	}
	if err = w.parent(p); err != nil {
		return err
	}
	w.s.set(p, &node{entry: e})
	return nil
}

// CheckoutGit opens a lazy commit/tree view using existing native chunks.
// Only accessed directories and file descriptors are materialized. First native
// publication still serializes the complete tree; later publications share it.
// Names unrepresentable by the workspace remain losslessly stored in Git trees.
func (r *Repository) CheckoutGit(ctx context.Context, catalog, revision string) (*Workspace, error) {
	id, err := r.ResolveGit(catalog, revision)
	if err != nil {
		return nil, err
	}
	id, kind, err := r.PeelGit(id)
	if err != nil {
		return nil, err
	}
	w := r.Empty()
	if kind == GitCommit {
		w.s.source = id.String()
		_, b, e := r.ReadGitObject(id)
		if e != nil {
			return nil, e
		}
		err = GitLinks(kind, b, int(id[32]), func(target GitOID, k byte) error {
			if k == GitTree {
				id = target
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		kind = GitTree
	}
	if kind != GitTree {
		return nil, errors.New("checkout requires a commit or tree")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	w.s.root = &node{entry: Entry{Kind: "dir", Mode: 0755}, lazy: true, gitObject: id}
	return w, nil
}

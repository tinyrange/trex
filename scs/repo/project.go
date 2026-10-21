package repo

import (
	"errors"
	"github.com/tinyrange/trex/filesystem"
	"github.com/tinyrange/trex/storage"
	"io"
	"io/fs"
	"sort"
)

// View captures an independent, immutable live root without fsync or publication.
// Readonly instead follows subsequent mutations of the original workspace.
func (w *Workspace) View() *Workspace {
	w.s.mu.Lock()
	defer w.s.mu.Unlock()
	return &Workspace{r: w.r, readonly: true, s: &state{root: w.s.root, source: w.s.source, snapshot: w.s.snapshot, loadErr: w.s.loadErr}}
}
func (w *Workspace) SnapshotTree() (filesystem.Tree, error) { return &projectTree{w: w.View()}, nil }

type projectTree struct{ w *Workspace }

func (t *projectTree) Lookup(p string) (filesystem.TreeInfo, error) {
	e, err := t.w.Stat(p)
	return filesystem.TreeInfo{Kind: e.Kind, Mode: e.Mode, Size: e.Size}, err
}
func (t *projectTree) ReadDir(p string) ([]filesystem.TreeEntry, error) {
	w := t.w
	w.s.mu.Lock()
	defer w.s.mu.Unlock()
	p, err := clean(p)
	if err != nil {
		return nil, err
	}
	if err = w.prepare(p, false); err != nil {
		return nil, err
	}
	n := findNode(w.s.root, p)
	if n == nil {
		return nil, fs.ErrNotExist
	}
	if n.entry.Kind != "dir" {
		return nil, errors.New("not a directory")
	}
	out := make([]filesystem.TreeEntry, 0, count(n.children))
	err = eachChild(n.children, func(name string, child *node) error {
		out = append(out, filesystem.TreeEntry{Name: name, Kind: child.entry.Kind})
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, err
}
func (t *projectTree) OpenFile(p string) (storage.Reader, error) { return t.w.OpenReader(p) }

// WriteReader installs a trex file atomically. Same-repository immutable file
// versions reuse their descriptor's content directly, with no payload reads.
// Other portable readers use streaming ingestion and existing deduplication.
func (w *Workspace) WriteReader(p string, input storage.Reader) error {
	if input == nil || input.Size() < 0 {
		return errors.New("invalid source file")
	}
	if unwrap, ok := input.(interface{ StorageReader() storage.Reader }); ok {
		input = unwrap.StorageReader()
	}
	base, ok := input.(*Reader)
	if !ok || base.r != w.r {
		return w.WriteFrom(p, io.NewSectionReader(input, 0, input.Size()))
	}
	w.s.mu.Lock()
	defer w.s.mu.Unlock()
	if w.readonly {
		return ErrReadOnly
	}
	p, err := clean(p)
	if err != nil {
		return err
	}
	if p == "." {
		return errors.New("cannot replace root")
	}
	if err = w.prepare(p, false); err != nil {
		return err
	}
	if err = w.parent(p); err != nil {
		return err
	}
	base.mu.Lock()
	defer base.mu.Unlock()
	if base.closed {
		return errors.New("reader is closed")
	}
	next := base.entry
	next.Kind = "file"
	next.Mode = 0644
	next.Times = Times{}
	if old, exists := w.s.get(p); exists {
		if old.Kind != "file" {
			return errors.New("destination is not a regular file")
		}
		next.Mode = old.Mode
		next.Times = old.Times
	}
	w.r.mu.Lock()
	defer w.r.mu.Unlock()
	if err = w.r.ready(); err != nil {
		return err
	}
	w.s.set(p, &node{entry: next})
	return nil
}

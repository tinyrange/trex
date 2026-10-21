package repo

import (
	"io/fs"
	"strings"
	"syscall"
)

// SetTimes replaces timestamp metadata without changing content. It also supports
// the root and symlinks. Existing objects with no metadata remain readable.
func (w *Workspace) SetTimes(p string, times Times) error {
	w.s.mu.Lock()
	defer w.s.mu.Unlock()
	if w.readonly {
		return ErrReadOnly
	}
	p, err := clean(p)
	if err != nil {
		return err
	}
	if err = w.prepare(p, false); err != nil {
		return err
	}
	n := findNode(w.s.root, p)
	if n == nil {
		return fs.ErrNotExist
	}
	e := n.entry
	e.Times = times
	w.s.set(p, &node{entry: e, children: n.children})
	return nil
}

// RenameReplace atomically moves old over new using POSIX type/empty-directory
// checks. All validation precedes the root change. Existing Rename retains its
// no-replacement contract. noReplace implements RENAME_NOREPLACE.
func (w *Workspace) RenameReplace(old, new string, noReplace bool) error {
	w.s.mu.Lock()
	defer w.s.mu.Unlock()
	if w.readonly {
		return ErrReadOnly
	}
	var err error
	old, err = clean(old)
	if err != nil {
		return err
	}
	new, err = clean(new)
	if err != nil {
		return err
	}
	if old == "." || new == "." {
		return syscall.EBUSY
	}
	if err = w.prepare(old, true); err != nil {
		return err
	}
	if err = w.prepare(new, false); err != nil {
		return err
	}
	src := findNode(w.s.root, old)
	if src == nil {
		return fs.ErrNotExist
	}
	dst := findNode(w.s.root, new)
	if dst != nil && noReplace {
		return fs.ErrExist
	}
	if old == new {
		return nil
	}
	if strings.HasPrefix(new, old+"/") {
		return syscall.EINVAL
	}
	if err = w.parent(new); err != nil {
		return err
	}
	if dst != nil {
		if src.entry.Kind == "dir" && dst.entry.Kind != "dir" {
			return syscall.ENOTDIR
		}
		if src.entry.Kind != "dir" && dst.entry.Kind == "dir" {
			return syscall.EISDIR
		}
		if dst.entry.Kind == "dir" && count(dst.children) != 0 {
			return syscall.ENOTEMPTY
		}
	}
	if err = walkNodes(src, new, func(p string, _ *node) error { _, e := clean(p); return e }); err != nil {
		return err
	}
	root := replaceNode(w.s.root, old, nil)
	root = replaceNode(root, new, src)
	w.s.root = root
	w.s.snapshot = ""
	return nil
}

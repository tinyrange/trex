package repo

import (
	"fmt"
	"path"
	"strings"
)

// Match supports shell-style path segments and a whole-segment ** matching zero
// or more directories. Dotfiles are ordinary names; ignore files are not applied.
func Match(pattern, name string) (bool, error) {
	if pattern == "" {
		return false, fmt.Errorf("empty glob")
	}
	if _, err := clean(pattern); err != nil {
		return false, err
	}
	pattern = path.Clean(pattern)
	parts := strings.Split(pattern, "/")
	names := strings.Split(name, "/")
	for _, p := range parts {
		if p != "**" {
			if _, err := path.Match(p, ""); err != nil {
				return false, err
			}
		}
	}
	type key struct{ i, j int }
	seen := map[key]bool{}
	values := map[key]bool{}
	var visit func(int, int) bool
	visit = func(i, j int) bool {
		k := key{i, j}
		if seen[k] {
			return values[k]
		}
		seen[k] = true
		result := false
		if i == len(parts) {
			result = j == len(names)
		} else if parts[i] == "**" {
			result = visit(i+1, j) || (j < len(names) && visit(i, j+1))
		} else if j < len(names) {
			ok, _ := path.Match(parts[i], names[j])
			result = ok && visit(i+1, j+1)
		}
		values[k] = result
		return result
	}
	return visit(0, 0), nil
}
func (w *Workspace) Glob(pattern string) ([]string, error) {
	if _, err := Match(pattern, ""); err != nil {
		return nil, err
	}
	out := []string{}
	paths, err := w.PathsWithError()
	if err != nil {
		return nil, err
	}
	for _, p := range paths {
		ok, _ := Match(pattern, p)
		if ok {
			out = append(out, p)
		}
	}
	return out, nil
}

// Fork durably snapshots current state and shares its immutable root. A clean
// fork is O(1); its first mutation path-copies only the affected ancestors.
func (w *Workspace) Fork() (*Workspace, error) {
	w.s.mu.Lock()
	defer w.s.mu.Unlock()
	if w.readonly {
		return nil, ErrReadOnly
	}
	w.r.mu.Lock()
	defer w.r.mu.Unlock()
	id, err := w.snapshotLocked()
	if err != nil {
		return nil, err
	}
	return &Workspace{r: w.r, s: &state{root: w.s.root, source: w.s.source, snapshot: id}}, nil
}

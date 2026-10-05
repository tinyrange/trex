package repo

import "fmt"

// Drop removes a published name only if it still points to expected. Immutable
// snapshots and blocks remain recoverable by ID; this does not reclaim storage.
func (r *Repository) Drop(name string, expected ID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.ready(); err != nil {
		return err
	}
	current, ok := r.refs[name]
	if !ok {
		return fmt.Errorf("unknown workspace %q", name)
	}
	if current != expected {
		return ErrConflict
	}
	refs := map[string]ID{}
	for n, id := range r.refs {
		if n != name {
			refs[n] = id
		}
	}
	if _, err := r.putJSON(refsKind, catalog{refs}); err != nil {
		return err
	}
	if err := r.sync(); err != nil {
		return err
	}
	r.refs = refs
	return nil
}

package repo

import "fmt"

// EnableIndexedRefs explicitly opts into a persistent radix ref catalog. Older
// readers reject this catalog extension rather than silently losing roots.
// Migration is O(refs); subsequent promotions path-copy bounded index pages.
// Opening/enumerating refs still costs O(refs). This is not a distributed store.
func (r *Repository) EnableIndexedRefs() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.ready(); err != nil {
		return err
	}
	if r.indexedRefs {
		return nil
	}
	var root *childIndex
	for name, id := range r.refs {
		root = setChild(root, name, &node{entry: Entry{Kind: "file"}, id: id})
	}
	if err := r.writeRefIndex(root); err != nil {
		return err
	}
	r.refIndex, r.indexedRefs = root, true
	return nil
}

type refUpdate struct {
	Name           string
	Expected, Next ID
}

func (r *Repository) writeRefIndex(root *childIndex, updates ...*refUpdate) error {
	var update *refUpdate
	if len(updates) > 0 {
		update = updates[0]
	}
	id, err := r.saveIndex(root, ".", 0)
	if err != nil {
		return err
	}
	if _, err = r.putJSON(refsKind, catalog{Indexed: true, Index: id, Update: update}); err != nil {
		return err
	}
	return r.sync()
}
func (r *Repository) installCatalog(c catalog) error {
	if c.Update != nil {
		u := c.Update
		if !c.Indexed || c.Refs != nil || !r.indexedRefs || !validName(u.Name) || r.refs[u.Name] != u.Expected || u.Expected == "" && u.Next == "" {
			return fmt.Errorf("invalid indexed root transition")
		}
		var value *node
		if u.Next != "" {
			loc, ok := r.lookupObject(key(u.Next))
			if !validID(u.Next) || !ok || loc.kind != snapshotKind {
				return fmt.Errorf("invalid transition target")
			}
			value = &node{entry: Entry{Kind: "file"}, id: u.Next}
		}
		root := setChild(r.refIndex, u.Name, value)
		id, err := r.verifyRefTransition(root)
		if err != nil {
			return err
		}
		if id != c.Index {
			return fmt.Errorf("indexed root transition identity mismatch")
		}
		r.refIndex = root
		if u.Next == "" {
			delete(r.refs, u.Name)
		} else {
			r.refs[u.Name] = u.Next
		}
		return nil
	}
	if c.Indexed {
		if c.Refs != nil {
			return fmt.Errorf("indexed roots also contain a flat catalog")
		}
		refs := map[string]ID{}
		var root *childIndex
		var err error
		if c.Index != "" {
			root, err = r.loadIndex(c.Index, 0, [32]byte{}, func(c child) (*node, error) {
				loc, ok := r.lookupObject(key(c.ID))
				if !validName(c.Name) || c.Kind != "file" || c.Mode != 0 || !ok || loc.kind != snapshotKind || !r.earlier(c.ID, c.parent) {
					return nil, fmt.Errorf("invalid indexed root %q", c.Name)
				}
				refs[c.Name] = c.ID
				return &node{entry: Entry{Kind: "file"}, id: c.ID}, nil
			})
		}
		if err != nil {
			return err
		}
		r.refs, r.refIndex, r.indexedRefs = refs, root, true
		return nil
	}
	if c.Refs == nil || c.Index != "" {
		return fmt.Errorf("invalid flat roots")
	}
	for name, id := range c.Refs {
		loc, ok := r.lookupObject(key(id))
		if !validName(name) || !validID(id) || !ok || loc.kind != snapshotKind {
			return fmt.Errorf("invalid workspace root %q", name)
		}
	}
	r.refs, r.refIndex, r.indexedRefs = c.Refs, nil, false
	return nil
}

// Promote compare-and-swaps exactly one name to an already immutable snapshot
// or revision. Empty expected means create-only; empty next deletes the name.
// Authorization/review belongs to the caller, not this portable storage engine.
func (r *Repository) Promote(name string, expected, next ID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.promoteLocked(name, expected, next)
}
func (r *Repository) promoteLocked(name string, expected, next ID) error {
	if err := r.ready(); err != nil {
		return err
	}
	if !validName(name) {
		return fmt.Errorf("invalid workspace name")
	}
	if r.refs[name] != expected {
		return ErrConflict
	}
	if next != "" {
		if _, err := r.revisionLocked(next); err != nil {
			return err
		}
	}
	if expected == "" && next == "" {
		return fmt.Errorf("cannot delete absent name")
	}
	if r.indexedRefs {
		var value *node
		if next != "" {
			value = &node{entry: Entry{Kind: "file"}, id: next}
		}
		root := setChild(r.refIndex, name, value)
		if err := r.writeRefIndex(root, &refUpdate{Name: name, Expected: expected, Next: next}); err != nil {
			return err
		}
		r.refIndex = root
		if next == "" {
			delete(r.refs, name)
		} else {
			r.refs[name] = next
		}
		return nil
	}
	refs := make(map[string]ID, len(r.refs)+1)
	for n, id := range r.refs {
		refs[n] = id
	}
	if next == "" {
		delete(refs, name)
	} else {
		refs[name] = next
	}
	if _, err := r.putJSON(refsKind, catalog{Refs: refs}); err != nil {
		return err
	}
	if err := r.sync(); err != nil {
		return err
	}
	r.refs = refs
	return nil
}

// Drop removes a name only if it still points to expected. No storage reclamation.
func (r *Repository) Drop(name string, expected ID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.ready(); err != nil {
		return err
	}
	if _, ok := r.refs[name]; !ok {
		return fmt.Errorf("unknown workspace %q", name)
	}
	return r.promoteLocked(name, expected, "")
}

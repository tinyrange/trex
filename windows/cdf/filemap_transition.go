package cdf

import (
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// FileMapNode describes one immediate hierarchy child at the LUA phase, after
// any preliminary file pass. Name "." describes the directory itself. These
// are native reduced states, not manifest attributes or filesystem operations.
// BeforeIdentity is used only for the directory dot; files compare their
// existing owner with AfterIdentity, excluding version.
type FileMapNode struct {
	Name                                        string
	Operation, State, DirectoryFlags, FileFlags uint8
	BeforeIdentity, AfterIdentity               []IdentityAttribute
}

// FileMapDirectoryCollision reports a new directory owner that native insertion
// did not install because the old, unrelated dot record was retained. This is
// an observed diagnostic, not permission to ignore transaction-level checks.
type FileMapDirectoryCollision struct {
	RetainedIdentity, RequestedIdentity []IdentityAttribute
}

// FileMapTransition separates the resulting document from native diagnostics.
// Consumers must not interpret successful planning as successful servicing.
type FileMapTransition struct {
	Document            *FileMap
	DirectoryCollisions []FileMapDirectoryCollision
}

// fileMapFamily bounds native flags-1 identity comparison to ordinary ASCII
// component attributes. Native CAttributeValueCollection::CompareTo ignores
// version with this option, but still compares name and other attributes.
// Unknown namespaces/attributes fail instead of being silently discarded.
func fileMapFamily(attrs []IdentityAttribute) (map[string]string, error) {
	if len(attrs) == 0 || len(attrs) > 7 {
		return nil, fmt.Errorf("FileMap transition: unsupported owner attributes")
	}
	values := make(map[string]string, len(attrs))
	for _, a := range attrs {
		if a.Namespace != "" || len(a.Name) > 64 || len(a.Value) == 0 || len(a.Value) > 4096 {
			return nil, fmt.Errorf("FileMap transition: unsupported owner attribute")
		}
		for _, s := range []string{a.Name, a.Value} {
			for i := range s {
				if s[i] < 32 || s[i] > 126 {
					return nil, fmt.Errorf("FileMap transition: non-ASCII owner")
				}
			}
		}
		key := strings.ToLower(a.Name)
		switch key {
		case "name", "version", "culture", "publickeytoken", "processorarchitecture", "versionscope", "type":
		default:
			return nil, fmt.Errorf("FileMap transition: unsupported owner attribute %q", a.Name)
		}
		if _, exists := values[key]; exists {
			return nil, fmt.Errorf("FileMap transition: duplicate owner attribute %q", a.Name)
		}
		values[key] = strings.ToLower(a.Value)
	}
	if values["name"] == "" {
		return nil, fmt.Errorf("FileMap transition: missing owner name")
	}
	parts := strings.Split(values["version"], ".")
	if len(parts) != 4 {
		return nil, fmt.Errorf("FileMap transition: expected four-part owner version")
	}
	for _, part := range parts {
		if part == "" || strings.Trim(part, "0123456789") != "" {
			return nil, fmt.Errorf("FileMap transition: invalid owner version")
		}
		if _, err := strconv.ParseUint(part, 10, 16); err != nil {
			return nil, fmt.Errorf("FileMap transition: invalid owner version: %w", err)
		}
	}
	delete(values, "version")
	// Native parsed identities omit neutral culture from their attribute set.
	if values["culture"] == "neutral" {
		delete(values, "culture")
	}
	return values, nil
}

func sameFileMapFamily(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func validFileMapLeaf(name string) bool {
	if name == "" || name == ".." || strings.ContainsAny(name, `/\:`) {
		return false
	}
	for i := range name {
		if name[i] < 32 || name[i] > 126 {
			return false
		}
	}
	return true
}

// TransitionFileMap computes the supported no-hash ownership transition. It
// never mutates its inputs. Unmentioned records survive; addressed files are
// filtered before new immutable/link records are inserted. Directory ownership
// uses its old identity, not the new identity used for file-family admission.
//
// Unresolved file-family conflicts fail closed. A directory-dot collision
// retains the existing record and is returned explicitly as a diagnostic. The caller must select a dirty directory and provide
// post-first-pass states; this does not authorize filesystem/security effects,
// normalize root paths, or implement traversal, deletion or transaction commit.
// An empty result is intentional: it is not by itself permission to delete a
// map/directory, and Marshal continues to reject empty maps.
func TransitionFileMap(input *FileMap, nodes []FileMapNode) (*FileMapTransition, error) {
	if input == nil || input.RootSelector > 2 || len(nodes) > 1<<20 || len(input.Entries) > (1<<20)-len(nodes) {
		return nil, fmt.Errorf("FileMap transition: invalid input")
	}
	// Validate the full input before indexing references, including unchanged
	// entries. Empty input represents a new map; its unused identities are not
	// permitted. The writer performs the same bounded schema validation.
	if len(input.Entries) != 0 {
		if _, err := input.Marshal(); err != nil {
			return nil, err
		}
	} else if len(input.Identities) != 0 {
		return nil, fmt.Errorf("FileMap transition: identities on an empty input")
	}
	if len(input.Path) > MaxSize || !utf8.ValidString(input.Path) || strings.IndexByte(input.Path, 0) >= 0 {
		return nil, fmt.Errorf("FileMap transition: invalid path metadata")
	}
	budget := len(input.Path)
	for _, n := range nodes {
		if len(n.Name) > 4096 {
			return nil, fmt.Errorf("FileMap transition: name limit")
		}
		budget += len(n.Name)
		for _, attrs := range [][]IdentityAttribute{n.BeforeIdentity, n.AfterIdentity} {
			if len(attrs) > 7 {
				return nil, fmt.Errorf("FileMap transition: owner limit")
			}
			for _, a := range attrs {
				size := len(a.Namespace) + len(a.Name) + len(a.Value)
				if size > MaxSize-budget {
					return nil, fmt.Errorf("FileMap transition: input budget")
				}
				budget += size
			}
		}
		if budget > MaxSize {
			return nil, fmt.Errorf("FileMap transition: input budget")
		}
	}
	byName := make(map[string]FileMapNode, len(nodes))
	afterFamilies := make(map[string]map[string]string, len(nodes))
	var beforeDot map[string]string
	for _, n := range nodes {
		if !validFileMapLeaf(n.Name) || n.Operation > 3 {
			return nil, fmt.Errorf("FileMap transition: invalid node %q", n.Name)
		}
		key := strings.ToLower(n.Name)
		if _, exists := byName[key]; exists {
			return nil, fmt.Errorf("FileMap transition: duplicate node %q", n.Name)
		}
		if n.Name == "." {
			if n.State != 0 && n.State != 3 && n.State != 4 {
				return nil, fmt.Errorf("FileMap transition: unsupported directory state")
			}
		} else if n.Operation == 0 || (n.State != 0 && n.State != 1 && n.State != 2 && n.State != 5 && n.State != 6 && n.State != 7) {
			return nil, fmt.Errorf("FileMap transition: unsupported file state")
		}
		for i, attrs := range [][]IdentityAttribute{n.BeforeIdentity, n.AfterIdentity} {
			if attrs == nil {
				continue
			}
			family, err := fileMapFamily(attrs)
			if err != nil {
				return nil, err
			}
			if i == 1 {
				afterFamilies[key] = family
			} else if key == "." {
				beforeDot = family
			}
		}
		if (n.State == 4 || n.State == 2 || n.State == 6 || n.State == 7) && n.Operation != 2 && n.AfterIdentity == nil {
			return nil, fmt.Errorf("FileMap transition: missing new owner for %q", n.Name)
		}
		byName[key] = n
	}
	out := &FileMap{Path: input.Path, RootSelector: input.RootSelector}
	var collisions []FileMapDirectoryCollision
	present := make(map[string]bool, len(input.Entries))
	// Intern only byte-for-byte equal attributes. Family equality is NOT a
	// serialization identity: distinct versions must never share a record.
	interned := make(map[string]uint32)
	intern := func(attrs []IdentityAttribute) uint32 {
		var key strings.Builder
		for _, a := range attrs {
			for _, value := range []string{a.Namespace, a.Name, a.Value} {
				key.WriteString(strconv.Itoa(len(value)))
				key.WriteByte(':')
				key.WriteString(value)
			}
		}
		k := key.String()
		if id, ok := interned[k]; ok {
			return id
		}
		id := uint32(len(out.Identities))
		out.Identities = append(out.Identities, append([]IdentityAttribute(nil), attrs...))
		interned[k] = id
		return id
	}
	owners := make(map[uint32]uint32)
	retain := func(e FileMapEntry) {
		old := e.Identity
		id, ok := owners[old]
		if !ok {
			id = intern(input.Identities[old])
			owners[old] = id
		}
		e.Identity = id
		out.Entries = append(out.Entries, e)
		present[strings.ToLower(e.Name)] = true
	}
	for _, e := range input.Entries {
		if !validFileMapLeaf(e.Name) {
			return nil, fmt.Errorf("FileMap transition: invalid input leaf")
		}
		key := strings.ToLower(e.Name)
		n, found := byName[key]
		if !found {
			retain(e)
			continue
		}
		if key == "." {
			if beforeDot == nil {
				retain(e)
				continue
			}
			old, err := fileMapFamily(input.Identities[e.Identity])
			if err != nil {
				return nil, err
			}
			if !sameFileMapFamily(old, beforeDot) {
				retain(e)
			}
			continue
		}
		if n.Operation == 2 || n.State == 5 {
			continue
		}
		if n.AfterIdentity == nil {
			return nil, fmt.Errorf("FileMap transition: missing comparison owner for %q", n.Name)
		}
		old, err := fileMapFamily(input.Identities[e.Identity])
		if err != nil {
			return nil, err
		}
		if !sameFileMapFamily(old, afterFamilies[key]) && n.DirectoryFlags&8 == 0 {
			return nil, fmt.Errorf("FileMap transition: unresolved owner conflict for %q", n.Name)
		}
	}
	for _, n := range nodes {
		insert := n.State == 2 || n.State == 6 || n.State == 7
		if n.Name == "." {
			insert = n.State == 4 && n.Operation != 2
		} else {
			insert = insert && n.FileFlags&0x40 == 0
		}
		if !insert {
			continue
		}
		key := strings.ToLower(n.Name)
		if present[key] {
			if key != "." {
				return nil, fmt.Errorf("FileMap transition: unresolved record collision for %q", n.Name)
			}
			for _, existing := range out.Entries {
				if existing.Name == "." {
					collisions = append(collisions, FileMapDirectoryCollision{
						RetainedIdentity:  append([]IdentityAttribute(nil), out.Identities[existing.Identity]...),
						RequestedIdentity: append([]IdentityAttribute(nil), n.AfterIdentity...),
					})
					break
				}
			}
			continue
		}
		if n.AfterIdentity == nil {
			return nil, fmt.Errorf("FileMap transition: missing insertion owner")
		}
		id := intern(n.AfterIdentity)
		flags := uint32((n.DirectoryFlags>>3)&2 | (n.FileFlags&2)<<1)
		out.Entries = append(out.Entries, FileMapEntry{Name: n.Name, DisplayName: n.Name, Flags: flags, Identity: id})
		present[key] = true
	}
	if len(out.Entries) > 0 {
		if _, err := out.Marshal(); err != nil {
			return nil, err
		}
	}
	return &FileMapTransition{Document: out, DirectoryCollisions: collisions}, nil
}

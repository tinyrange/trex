package windows

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/tinyrange/trex/windows/registry"
	"go.starlark.net/starlark"
)

// Exclusions describe one source epoch, not an ordered stream of deletes.
// Resolve the union against private, still-unmodified bytes before retiring any
// cells. Ancestor exclusions subsume descendants, duplicates and absent paths
// are harmless, and a subsequent creation never inherits excluded contents.
// Unlike a full import this visits only selected branches and preserves all
// unrelated cells and their metadata verbatim.
func (h *mutableHive) excludeSource(keys, values *starlark.List) error {
	type selection struct {
		children map[string]*selection
		remove   bool
		values   map[string]bool
	}
	root := &selection{}
	budget := 1 << 20
	selectPath := func(parts []string) (*selection, error) {
		if len(parts) > 512 {
			return nil, fmt.Errorf("patch_hive: exclusion depth exceeds 512")
		}
		n := root
		for _, part := range parts {
			folded := strings.ToLower(part)
			if n.children == nil {
				n.children = make(map[string]*selection)
			}
			child := n.children[folded]
			if child == nil {
				if budget == 0 {
					return nil, fmt.Errorf("patch_hive: exclusion node bound exceeded")
				}
				budget--
				child = &selection{}
				n.children[folded] = child
			}
			n = child
		}
		return n, nil
	}
	if keys != nil {
		for value := range keys.Elements() {
			parts, err := hiveEditParts(value)
			if err != nil {
				return err
			}
			if len(parts) == 0 {
				return fmt.Errorf("patch_hive: cannot exclude the hive root")
			}
			n, err := selectPath(parts)
			if err != nil {
				return err
			}
			n.remove = true
		}
	}
	if values != nil {
		for value := range values.Elements() {
			record, ok := value.(*starlark.Dict)
			if !ok {
				return fmt.Errorf("patch_hive: excluded value must be a dict")
			}
			parts, err := hiveEditParts(record)
			if err != nil {
				return err
			}
			name, err := requiredPatchString(record, "name")
			if err != nil {
				return err
			}
			n, err := selectPath(parts)
			if err != nil {
				return err
			}
			if n.values == nil {
				n.values = make(map[string]bool)
			}
			if name == "" {
				name = "(default)"
			}
			n.values[strings.ToLower(name)] = true
		}
	}
	reader, err := registry.Open(bytes.NewReader(h.data))
	if err != nil {
		return err
	}
	first, err := reader.ReadKey(reader.RootCell())
	if err != nil {
		return err
	}
	var removed [][]string
	type valueRemoval struct {
		parts []string
		name  string
	}
	var deleted []valueRemoval
	seen := make(map[uint32]bool)
	var visit func(registry.Key, []string, *selection) error
	visit = func(key registry.Key, parts []string, n *selection) error {
		if seen[key.Cell] || len(seen) >= 1<<20 {
			return fmt.Errorf("patch_hive: cyclic or oversized exclusion traversal")
		}
		seen[key.Cell] = true
		if n.remove {
			removed = append(removed, parts)
			return nil
		}
		if len(n.values) != 0 {
			cells, err := reader.ValueCells(key)
			if err != nil {
				return err
			}
			for _, cell := range cells {
				value, err := reader.ReadValue(cell)
				if err != nil {
					return err
				}
				name := value.Name
				if name == "" {
					name = "(default)"
				}
				if n.values[strings.ToLower(name)] {
					deleted = append(deleted, valueRemoval{parts, value.Name})
				}
			}
		}
		if len(n.children) == 0 {
			return nil
		}
		children, err := reader.ReadSubkeys(key)
		if err != nil {
			return err
		}
		for _, child := range children {
			if next := n.children[strings.ToLower(child.Name)]; next != nil {
				if err := visit(child, appendRegistryPathPart(parts, child.Name), next); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := visit(first, nil, root); err != nil {
		return err
	}
	// No Starlark callbacks or source reads occur after this point. Publication
	// remains the caller's responsibility and an error discards the private copy.
	for _, value := range deleted {
		if err := h.deleteValueParts(value.parts, value.name); err != nil {
			return err
		}
	}
	for _, parts := range removed {
		if err := h.deleteKeyParts(parts); err != nil {
			return err
		}
	}
	return nil
}

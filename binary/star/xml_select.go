package star

import (
	"fmt"
	"go.starlark.net/starlark"
)

// One native traversal shares immutable nodes among multiple declaration
// consumers, without allocating child lists or interpreting policy per node.
func (n *binaryXMLNode) selectDescendantsBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var names *starlark.List
	namespace := ""
	includeSelf := false
	maximum := defaultBinaryXMLNodes
	if err := starlark.UnpackArgs("select_descendants", args, kwargs, "names", &names, "namespace?", &namespace, "include_self?", &includeSelf, "maximum?", &maximum); err != nil {
		return nil, err
	}
	if names.Len() > 64 || maximum < 1 || maximum > defaultBinaryXMLNodes {
		return nil, fmt.Errorf("select_descendants: requires at most 64 names and maximum in 1..%d", defaultBinaryXMLNodes)
	}
	selected := make(map[string]int, names.Len())
	results := make([]starlark.Tuple, names.Len())
	for i := 0; i < names.Len(); i++ {
		name, ok := starlark.AsString(names.Index(i))
		if !ok || name == "" {
			return nil, fmt.Errorf("select_descendants: names must be nonempty strings")
		}
		if _, ok := selected[name]; ok {
			return nil, fmt.Errorf("select_descendants: duplicate name %q", name)
		}
		selected[name] = i
	}
	visited := 0
	var visit func(*binaryXMLNode, int, bool) error
	visit = func(node *binaryXMLNode, depth int, admit bool) error {
		visited++
		if visited > maximum || depth > defaultBinaryXMLDepth {
			return fmt.Errorf("select_descendants: traversal limit exceeded")
		}
		if index, ok := selected[node.name]; ok && admit && node.namespace == namespace {
			results[index] = append(results[index], node)
		}
		for _, part := range node.content {
			if part.kind == binaryXMLChild {
				if err := visit(part.child, depth+1, true); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := visit(n, 1, includeSelf); err != nil {
		return nil, err
	}
	result := starlark.NewDict(names.Len())
	for i := 0; i < names.Len(); i++ {
		if err := result.SetKey(names.Index(i), results[i]); err != nil {
			return nil, err
		}
	}
	result.Freeze()
	return result, nil
}

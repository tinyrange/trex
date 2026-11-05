package windows

import (
	"fmt"
	"github.com/tinyrange/trex/windows/cdf"
	"go.starlark.net/starlark"
)

func cdfTransitionOwner(v starlark.Value) ([]cdf.IdentityAttribute, error) {
	if v == starlark.None {
		return nil, nil
	}
	list, ok := v.(*starlark.List)
	if !ok || list.Len() == 0 || list.Len() > 7 {
		return nil, fmt.Errorf("FileMap transition: owner must be None or 1..7 attribute tuples")
	}
	out := make([]cdf.IdentityAttribute, list.Len())
	for i := 0; i < list.Len(); i++ {
		a, ok := list.Index(i).(starlark.Tuple)
		if !ok || len(a) != 3 {
			return nil, fmt.Errorf("FileMap transition: owner attribute must be namespace/name/value tuple")
		}
		for j, p := range []*string{&out[i].Namespace, &out[i].Name, &out[i].Value} {
			s, ok := starlark.AsString(a[j])
			if !ok || len(s) > 4096 {
				return nil, fmt.Errorf("FileMap transition: invalid owner attribute field")
			}
			*p = s
		}
	}
	return out, nil
}

func cdfFileMapTransitionBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var doc *starlark.Dict
	var list *starlark.List
	if err := starlark.UnpackArgs("cdf_filemap_transition", args, kwargs, "document", &doc, "nodes", &list); err != nil {
		return nil, err
	}
	if list.Len() > 1<<20 {
		return nil, fmt.Errorf("FileMap transition: node limit")
	}
	input, err := cdfFileMapFromDict(doc)
	if err != nil {
		return nil, err
	}
	nodes := make([]cdf.FileMapNode, list.Len())
	budget := 0
	for i := 0; i < list.Len(); i++ {
		d, ok := list.Index(i).(*starlark.Dict)
		if !ok {
			return nil, fmt.Errorf("FileMap transition: node must be dict")
		}
		n := &nodes[i]
		var op, state, dirFlags, fileFlags starlark.Int
		var before, after starlark.Value = starlark.None, starlark.None
		if err := starlark.UnpackArgs("FileMap node", nil, d.Items(), "name", &n.Name, "operation", &op, "state", &state, "directory_flags", &dirFlags, "file_flags", &fileFlags, "before_identity", &before, "after_identity", &after); err != nil {
			return nil, err
		}
		for j, p := range []*uint8{&n.Operation, &n.State, &n.DirectoryFlags, &n.FileFlags} {
			v, ok := []starlark.Int{op, state, dirFlags, fileFlags}[j].Uint64()
			if !ok || v > 255 {
				return nil, fmt.Errorf("FileMap transition: state/flags outside byte range")
			}
			*p = uint8(v)
		}
		if len(n.Name) > 4096 {
			return nil, fmt.Errorf("FileMap transition: node name limit")
		}
		if n.BeforeIdentity, err = cdfTransitionOwner(before); err != nil {
			return nil, err
		}
		if n.AfterIdentity, err = cdfTransitionOwner(after); err != nil {
			return nil, err
		}
		budget += len(n.Name)
		for _, attrs := range [][]cdf.IdentityAttribute{n.BeforeIdentity, n.AfterIdentity} {
			for _, a := range attrs {
				budget += len(a.Namespace) + len(a.Name) + len(a.Value)
			}
		}
		if budget > cdf.MaxSize {
			return nil, fmt.Errorf("FileMap transition: input budget")
		}
	}
	result, err := cdf.TransitionFileMap(input, nodes)
	if err != nil {
		return nil, err
	}
	out := starlark.NewDict(2)
	_ = out.SetKey(starlark.String("document"), cdfFileMapToDict(result.Document))
	collisions := make([]starlark.Value, len(result.DirectoryCollisions))
	for i, c := range result.DirectoryCollisions {
		item := starlark.NewDict(2)
		_ = item.SetKey(starlark.String("retained_identity"), cdfOwnerToList(c.RetainedIdentity))
		_ = item.SetKey(starlark.String("requested_identity"), cdfOwnerToList(c.RequestedIdentity))
		collisions[i] = item
	}
	_ = out.SetKey(starlark.String("directory_collisions"), starlark.NewList(collisions))
	return out, nil
}

func cdfOwnerToList(owner []cdf.IdentityAttribute) *starlark.List {
	values := make([]starlark.Value, len(owner))
	for i, a := range owner {
		values[i] = starlark.Tuple{starlark.String(a.Namespace), starlark.String(a.Name), starlark.String(a.Value)}
	}
	return starlark.NewList(values)
}

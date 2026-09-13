package star

import (
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func PlanBuiltin(t *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	value, err := Builtin(t, b, args, kwargs)
	if err != nil {
		return nil, err
	}
	node, err := value.(*Value).Node.WithPlans()
	if err != nil {
		return nil, err
	}
	return &Value{node}, nil
}

func (v *Value) plans() (starlark.Value, error) {
	plans, err := v.Node.Plans()
	if err != nil {
		return nil, err
	}
	out := make([]starlark.Value, len(plans))
	for i, p := range plans {
		out[i] = starfile.NewRecord(starlark.StringDict{"id": starlark.String(p.ID), "title": starlark.String(p.Title), "description": starlark.String(p.Description), "path": starlark.String("$plans/" + p.ID)})
	}
	return starlark.NewList(out), nil
}

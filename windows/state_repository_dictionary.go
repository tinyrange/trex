package windows

import (
	"fmt"

	starfile "github.com/tinyrange/trex/storage/star"
	"github.com/tinyrange/trex/windows/srdictionary"
	"go.starlark.net/starlark"
)

func stateRepositoryDictionaryBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var properties *starlark.Dict
	if err := starlark.UnpackArgs("state_repository_dictionary", args, kwargs, "properties", &properties); err != nil {
		return nil, err
	}
	d, err := stateRepositoryDictionary(properties, 0)
	if err != nil {
		return nil, err
	}
	data, err := srdictionary.Encode(d)
	if err != nil {
		return nil, err
	}
	return &starfile.Bytes{Name: "StateRepository dictionary", Data: data}, nil
}

func stateRepositoryDictionary(properties *starlark.Dict, depth int) (srdictionary.Dictionary, error) {
	budget := 65536
	return stateRepositoryDictionaryBounded(properties, depth, &budget)
}

func stateRepositoryDictionaryBounded(properties *starlark.Dict, depth int, budget *int) (srdictionary.Dictionary, error) {
	if depth >= 32 || properties.Len() > 1024 {
		return nil, fmt.Errorf("state_repository_dictionary: depth or entry limit exceeded")
	}
	*budget -= properties.Len() + 1
	if *budget < 0 {
		return nil, fmt.Errorf("state_repository_dictionary: aggregate entry limit exceeded")
	}
	out := make(srdictionary.Dictionary, 0, properties.Len())
	for _, item := range properties.Items() {
		key, ok := starlark.AsString(item[0])
		if !ok {
			return nil, fmt.Errorf("state_repository_dictionary: keys must be strings")
		}
		var value any
		switch v := item[1].(type) {
		case starlark.String:
			value = string(v)
		case *starlark.Dict:
			child, err := stateRepositoryDictionaryBounded(v, depth+1, budget)
			if err != nil {
				return nil, err
			}
			value = child
		case *starlark.List:
			if v.Len() > 1024 {
				return nil, fmt.Errorf("state_repository_dictionary: map array exceeds entry limit")
			}
			children := make([]srdictionary.Dictionary, 0, v.Len())
			for i := 0; i < v.Len(); i++ {
				child, ok := v.Index(i).(*starlark.Dict)
				if !ok {
					return nil, fmt.Errorf("state_repository_dictionary: arrays must contain dictionaries")
				}
				d, err := stateRepositoryDictionaryBounded(child, depth+1, budget)
				if err != nil {
					return nil, err
				}
				children = append(children, d)
			}
			value = children
		default:
			return nil, fmt.Errorf("state_repository_dictionary: unsupported value type %s", item[1].Type())
		}
		out = append(out, srdictionary.Entry{Key: key, Value: value})
	}
	return out, nil
}

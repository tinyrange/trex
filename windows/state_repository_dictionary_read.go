package windows

import (
	"fmt"
	"github.com/tinyrange/trex/windows/srdictionary"
	"go.starlark.net/starlark"
)

// Expose the existing strict native decoder without interpreting property IDs.
func stateRepositoryDictionaryReadBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var source starlark.Value
	if err := starlark.UnpackArgs("state_repository_dictionary_read", args, kwargs, "source", &source); err != nil {
		return nil, err
	}
	data, err := bytesForBinaryValueLimited(source, 64<<20)
	if err != nil {
		return nil, err
	}
	decoded, err := srdictionary.Decode(data)
	if err != nil {
		return nil, err
	}
	return stateRepositoryDictionaryValue(decoded)
}

func stateRepositoryDictionaryValue(d srdictionary.Dictionary) (*starlark.Dict, error) {
	out := starlark.NewDict(len(d))
	for _, entry := range d {
		var value starlark.Value
		switch v := entry.Value.(type) {
		case bool:
			value = starlark.Bool(v)
		case string:
			value = starlark.String(v)
		case srdictionary.Dictionary:
			child, err := stateRepositoryDictionaryValue(v)
			if err != nil {
				return nil, err
			}
			value = child
		case []srdictionary.Dictionary:
			children := make([]starlark.Value, len(v))
			for i, d := range v {
				child, err := stateRepositoryDictionaryValue(d)
				if err != nil {
					return nil, err
				}
				children[i] = child
			}
			value = starlark.NewList(children)
		default:
			return nil, fmt.Errorf("unsupported decoded SRD1 value %T", v)
		}
		if err := out.SetKey(starlark.String(entry.Key), value); err != nil {
			return nil, err
		}
	}
	return out, nil
}

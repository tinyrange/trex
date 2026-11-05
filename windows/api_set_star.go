package windows

import (
	"fmt"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func apiSetNamespaceBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value, file starlark.Value
	if err := starlark.UnpackArgs("api_set_namespace", args, kwargs, "data?", &value, "file?", &file); err != nil {
		return nil, err
	}
	if (value == nil) == (file == nil) {
		return nil, fmt.Errorf("api_set_namespace: supply exactly one of data or file")
	}
	if file != nil {
		value = file
	}
	data, err := bytesForBinaryValueLimited(value, 16<<20)
	if err != nil {
		return nil, err
	}
	namespace, err := ParseAPISetNamespace(data)
	if err != nil {
		return nil, err
	}
	entries := make([]starlark.Value, 0, len(namespace.Entries))
	for _, entry := range namespace.Entries {
		values := make([]starlark.Value, 0, len(entry.Values))
		for _, item := range entry.Values {
			values = append(values, starfile.NewRecord(starlark.StringDict{"flags": starlark.MakeUint(uint(item.Flags)), "importer": starlark.String(item.Importer), "host": starlark.String(item.Host)}))
		}
		entries = append(entries, starfile.NewRecord(starlark.StringDict{"name": starlark.String(entry.Name), "flags": starlark.MakeUint(uint(entry.Flags)), "hashed_length": starlark.MakeUint(uint(entry.HashedLength)), "values": starlark.NewList(values)}))
	}
	resolve := starlark.NewBuiltin("resolve", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var contract, importer string
		if err := starlark.UnpackArgs("resolve", args, kwargs, "contract", &contract, "importer?", &importer); err != nil {
			return nil, err
		}
		for _, name := range []string{contract, importer} {
			for _, c := range name {
				if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
					return nil, fmt.Errorf("resolve: expected a module basename")
				}
			}
		}
		if contract == "" {
			return nil, fmt.Errorf("resolve: empty contract")
		}
		if host, ok := namespace.Resolve(contract, importer); ok {
			return starlark.String(host), nil
		}
		return starlark.None, nil
	})
	info, err := parseAPISetNamespace(data)
	if err != nil {
		return nil, err
	}
	legacy := info.(*starlark.Dict)
	contracts, _, _ := legacy.Get(starlark.String("contracts"))
	result := &apiSetNamespaceValue{Record: starfile.NewRecord(starlark.StringDict{"contracts": contracts, "version": starlark.MakeInt(6), "flags": starlark.MakeUint(uint(namespace.Flags)), "hash_factor": starlark.MakeUint(uint(namespace.HashFactor)), "entries": starlark.NewList(entries), "resolve": resolve}), info: legacy}
	result.Freeze()
	return result, nil
}

// Keep the counted inspection mapping alongside validated loader attributes.
// Both views own the same input snapshot and never load or invent a host DLL.
type apiSetNamespaceValue struct {
	*starfile.Record
	info *starlark.Dict
}

func (v *apiSetNamespaceValue) Get(key starlark.Value) (starlark.Value, bool, error) {
	return v.info.Get(key)
}
func (v *apiSetNamespaceValue) Iterate() starlark.Iterator { return v.info.Iterate() }
func (v *apiSetNamespaceValue) Len() int                   { return v.info.Len() }
func (v *apiSetNamespaceValue) Items() []starlark.Tuple    { return v.info.Items() }

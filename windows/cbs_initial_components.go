package windows

import (
	"fmt"
	"github.com/tinyrange/trex/windows/uup"
	"go.starlark.net/starlark"
	"sort"
)

func cbsInitialComponentsBuiltin(index *uup.CBSUpdateStateIndex) *starlark.Builtin {
	return starlark.NewBuiltin("cbs_update_index.initial_component_states", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var values *starlark.Dict
		var packages *starlark.List
		if err := starlark.UnpackArgs("initial_component_states", args, kwargs, "deployments", &values, "packages", &packages); err != nil {
			return nil, err
		}
		if values.Len() > 1<<20 || packages.Len() > uup.MaxCBSPackageContexts {
			return nil, fmt.Errorf("CBS initial component input bound exceeded")
		}
		names := make([]string, packages.Len())
		for i := range names {
			var ok bool
			names[i], ok = starlark.AsString(packages.Index(i))
			if !ok {
				return nil, fmt.Errorf("CBS initial package name must be string")
			}
		}
		deployments := make([]uup.CBSInitialDeployment, 0, values.Len())
		total, sources := 0, 0
		for _, item := range values.Items() {
			fields, ok := item[1].(*starlark.Dict)
			if !ok {
				return nil, fmt.Errorf("CBS initial deployment values must be dict")
			}
			identity, found, err := fields.Get(starlark.String("appid"))
			if err != nil {
				return nil, err
			}
			if !found {
				return nil, fmt.Errorf("CBS initial deployment lacks appid")
			}
			data, ok := identity.(starlark.Bytes)
			if !ok || len(data) > 64<<10 {
				return nil, fmt.Errorf("CBS initial appid requires bounded bytes")
			}
			id, err := uup.ParseCSIIdentity([]byte(data))
			if err != nil {
				return nil, err
			}
			total += len(data)
			if total > 256<<20 {
				return nil, fmt.Errorf("CBS initial source bytes exceed bound")
			}
			d := uup.CBSInitialDeployment{Identity: id, Sources: map[string]uint32{}}
			for _, pair := range fields.Items() {
				name, ok := starlark.AsString(pair[0])
				if !ok {
					return nil, fmt.Errorf("CBS initial source name must be string")
				}
				if len(name) < 2 {
					continue
				}
				var state uint32
				switch name[:2] {
				case "i!":
					state = 0x70
				case "s!":
					state = 0x40
				case "p!":
					state = 0x20
				default:
					continue
				}
				data, ok := pair[1].(starlark.Bytes)
				if !ok || len(data) > 64<<10 {
					return nil, fmt.Errorf("CBS initial source requires bounded bytes")
				}
				total += len(data)
				sources++
				if total > 256<<20 || sources > 1<<20 {
					return nil, fmt.Errorf("CBS initial source bytes/count exceed bound")
				}
				source, err := uup.ParseCBSDeploymentSource([]byte(data))
				if err != nil {
					return nil, err
				}
				if d.Sources[source.Primary] < state {
					d.Sources[source.Primary] = state
				}
			}
			deployments = append(deployments, d)
		}
		result, err := index.InitialComponentStates(names, deployments)
		if err != nil {
			return nil, err
		}
		out := starlark.NewDict(len(result))
		for _, name := range names {
			updates := result[name]
			keys := make([]string, 0, len(updates))
			for key := range updates {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			dict := starlark.NewDict(len(updates))
			for _, key := range keys {
				states := updates[key]
				vals := make([]starlark.Value, len(states))
				for i, state := range states {
					vals[i] = starlark.MakeUint64(uint64(state))
				}
				if err := dict.SetKey(starlark.String(key), starlark.NewList(vals)); err != nil {
					return nil, err
				}
			}
			if err := out.SetKey(starlark.String(name), dict); err != nil {
				return nil, err
			}
		}
		return out, nil
	})
}

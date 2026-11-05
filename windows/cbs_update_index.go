package windows

import (
	"fmt"
	"maps"
	"slices"

	starvalue "github.com/tinyrange/trex/storage/star"
	"github.com/tinyrange/trex/windows/uup"
	"go.starlark.net/starlark"
)

func cbsUpdateIndexBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var packages, editions *starlark.List
	if err := starlark.UnpackArgs("cbs_update_index", args, kwargs, "packages", &packages, "editions?", &editions); err != nil {
		return nil, err
	}
	inputs, err := cbsUpdateInputs(packages, editions)
	if err != nil {
		return nil, err
	}
	index, err := uup.NewCBSUpdateStateIndex(inputs)
	if err != nil {
		return nil, err
	}
	return cbsUpdateIndexRecord(index), nil
}

type cbsIndexValue struct{ index *uup.CBSUpdateStateIndex }

func (v *cbsIndexValue) String() string        { return "<cbs_update_index>" }
func (v *cbsIndexValue) Type() string          { return "cbs_update_index" }
func (v *cbsIndexValue) Freeze()               {}
func (v *cbsIndexValue) Truth() starlark.Bool  { return starlark.True }
func (v *cbsIndexValue) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: cbs_update_index") }
func cbsUpdateIndexRecord(index *uup.CBSUpdateStateIndex) starlark.Value {
	return &cbsIndexValue{index: index}
}
func (v *cbsIndexValue) AttrNames() []string {
	return []string{"ordinary_population", "package_state", "package_states", "with_components", "state", "applicable", "with_updates", "with_states", "package_state_vector"}
}
func (v *cbsIndexValue) Attr(name string) (starlark.Value, error) {
	index := v.index
	switch name {
	case "ordinary_population":
		return cbsPopulationBuiltin(index), nil
	case "package_state":
		return starlark.NewBuiltin("cbs_update_index.package_state", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var name string
			if err := starlark.UnpackArgs("cbs_update_index.package_state", args, kwargs, "package", &name); err != nil {
				return nil, err
			}
			state, err := index.PackageIntendedStateByName(name)
			if err != nil {
				return nil, err
			}
			return starlark.MakeUint64(uint64(state)), nil
		}), nil
	case "package_states":
		return starlark.NewBuiltin("cbs_update_index.package_states", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			if err := starlark.UnpackArgs("cbs_update_index.package_states", args, kwargs); err != nil {
				return nil, err
			}
			states := index.PackageIntendedStates()
			result := starlark.NewDict(len(states))
			for _, name := range slices.Sorted(maps.Keys(states)) {
				state := states[name]
				if err := result.SetKey(starlark.String(name), starlark.MakeUint64(uint64(state))); err != nil {
					return nil, err
				}
			}
			return result, nil
		}), nil
	case "with_components":
		return starlark.NewBuiltin("cbs_update_index.with_components", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var entries *starlark.List
			if err := starlark.UnpackArgs("cbs_update_index.with_components", args, kwargs, "components", &entries); err != nil {
				return nil, err
			}
			components, err := cbsComponentSnapshot(entries)
			if err != nil {
				return nil, err
			}
			next, err := index.WithComponentState(components)
			if err != nil {
				return nil, err
			}
			return cbsUpdateIndexRecord(next), nil
		}), nil
	case "state":
		return starlark.NewBuiltin("cbs_update_index.state", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var name, update string
			if err := starlark.UnpackArgs("cbs_update_index.state", args, kwargs, "package", &name, "update", &update); err != nil {
				return nil, err
			}
			id, err := index.PackageIdentity(name)
			if err != nil {
				return nil, err
			}
			state, err := index.UpdateState(id, update)
			if err != nil {
				return nil, err
			}
			return starvalue.NewRecord(starlark.StringDict{"raw_state": starlark.MakeUint64(uint64(state.RawState)), "intended_state": starlark.MakeUint64(uint64(state.IntendedState))}), nil
		}), nil
	case "applicable":
		return starlark.NewBuiltin("cbs_update_index.applicable", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var name, update string
			if err := starlark.UnpackArgs("cbs_update_index.applicable", args, kwargs, "package", &name, "update", &update); err != nil {
				return nil, err
			}
			id, err := index.PackageIdentity(name)
			if err != nil {
				return nil, err
			}
			state, err := index.ApplicableUpdateState(id, update)
			if err != nil {
				return nil, err
			}
			return starvalue.NewRecord(starlark.StringDict{"raw_state": starlark.MakeUint64(uint64(state.RawState)), "intended_state": starlark.MakeUint64(uint64(state.IntendedState))}), nil
		}), nil
	case "with_updates":
		return starlark.NewBuiltin("cbs_update_index.with_updates", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var name string
			var states *starlark.Dict
			if err := starlark.UnpackArgs("cbs_update_index.with_updates", args, kwargs, "package", &name, "states", &states); err != nil {
				return nil, err
			}
			id, err := index.PackageIdentity(name)
			if err != nil {
				return nil, err
			}
			if states.Len() > 1<<16 {
				return nil, fmt.Errorf("CBS published updates exceed bound")
			}
			updates := make(map[string]uint32, states.Len())
			for _, item := range states.Items() {
				name, ok := starlark.AsString(item[0])
				if !ok {
					return nil, fmt.Errorf("CBS published update name must be a string")
				}
				state, err := starlark.AsInt32(item[1])
				if err != nil || state < 0 {
					return nil, fmt.Errorf("invalid CBS published update state: %s", item[1])
				}
				updates[name] = uint32(state)
			}
			next, err := index.WithPublishedUpdates(id, updates)
			if err != nil {
				return nil, err
			}
			return cbsUpdateIndexRecord(next), nil
		}), nil
	case "with_states":
		return starlark.NewBuiltin("cbs_update_index.with_states", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var states *starlark.Dict
			if err := starlark.UnpackArgs("cbs_update_index.with_states", args, kwargs, "states", &states); err != nil {
				return nil, err
			}
			if states.Len() > 1<<16 {
				return nil, fmt.Errorf("CBS update state changes exceed bound")
			}
			changes := make([]uup.CBSUpdateIntentChange, 0, states.Len())
			for _, item := range states.Items() {
				name, ok := starlark.AsString(item[0])
				if !ok {
					return nil, fmt.Errorf("CBS update change identity must be a string")
				}
				state, err := starlark.AsInt32(item[1])
				if err != nil || state < 0 {
					return nil, fmt.Errorf("invalid CBS update change state: %s", item[1])
				}
				id, err := index.PackageIdentity(name)
				if err != nil {
					return nil, err
				}
				changes = append(changes, uup.CBSUpdateIntentChange{Identity: id, IntendedState: uint32(state)})
			}
			next, err := index.WithIntendedStates(changes)
			if err != nil {
				return nil, err
			}
			return cbsUpdateIndexRecord(next), nil
		}), nil
	case "package_state_vector":
		return starlark.NewBuiltin("cbs_update_index.package_state_vector", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var names *starlark.List
			if err := starlark.UnpackArgs("package_state_vector", args, kwargs, "packages", &names); err != nil {
				return nil, err
			}
			if names.Len() > 1<<16 {
				return nil, fmt.Errorf("CBS state vector exceeds bound")
			}
			result := make(starlark.Tuple, names.Len())
			for i := 0; i < names.Len(); i++ {
				name, ok := starlark.AsString(names.Index(i))
				if !ok {
					return nil, fmt.Errorf("CBS package name must be a string")
				}
				state, err := index.PackageIntendedStateByName(name)
				if err != nil {
					return nil, err
				}
				result[i] = starlark.MakeUint64(uint64(state))
			}
			return result, nil
		}), nil
	}
	return nil, nil
}

func cbsComponentSnapshot(entries *starlark.List) (*uup.CBSComponentStateIndex, error) {
	if entries.Len() > 1<<20 {
		return nil, fmt.Errorf("CBS component entries exceed bound")
	}
	values := make([]uup.CBSComponentInventoryEntry, 0, entries.Len())
	totalOwners, totalBytes := 0, 0
	for value := range entries.Elements() {
		entry, ok := value.(*starlark.Dict)
		if !ok {
			return nil, fmt.Errorf("CBS component entry must be a dict")
		}
		var identity starlark.Value
		var owners *starlark.List
		if err := starlark.UnpackArgs("CBS component entry", nil, entry.Items(), "identity", &identity, "owners", &owners); err != nil {
			return nil, err
		}
		data, ok := identity.(starlark.Bytes)
		if !ok {
			return nil, fmt.Errorf("CBS component identity must be canonical CSI bytes")
		}
		totalBytes += len(data)
		totalOwners += owners.Len()
		if len(data) > 64<<10 || totalBytes > 64<<20 || totalOwners > 1<<20 {
			return nil, fmt.Errorf("CBS component snapshot exceeds data bounds")
		}
		record := uup.CBSComponentInventoryEntry{Identity: []byte(data)}
		for v := range owners.Elements() {
			n, err := starlark.AsInt32(v)
			if err != nil || n < 0 {
				return nil, fmt.Errorf("invalid CBS component owner elevation")
			}
			record.Owners = append(record.Owners, uint32(n))
		}
		values = append(values, record)
	}
	return uup.NewCBSComponentStateIndex(values)
}

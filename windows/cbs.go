package windows

import (
	"fmt"

	starvalue "github.com/tinyrange/trex/storage/star"
	"github.com/tinyrange/trex/windows/uup"
	"go.starlark.net/starlark"
)

func cbsPackageNames(values *starlark.List) ([]uup.AssemblyIdentity, error) {
	if values == nil {
		return nil, nil
	}
	if values.Len() > 1<<16 {
		return nil, fmt.Errorf("CBS package list exceeds bound")
	}
	out := make([]uup.AssemblyIdentity, 0, values.Len())
	for i := 0; i < values.Len(); i++ {
		name, ok := starlark.AsString(values.Index(i))
		if !ok {
			return nil, fmt.Errorf("CBS package identity must be a string")
		}
		id, err := uup.ParsePackageManifestName(name + ".mum")
		if err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, nil
}

// cbsPackageOwnersBuiltin exposes pure planning, not a registry patch operation.
func cbsPackageOwnersBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var packages, targets *starlark.List
	var editionValues *starlark.List
	if err := starlark.UnpackArgs("cbs_package_owners", args, kwargs, "packages", &packages, "targets", &targets, "editions?", &editionValues); err != nil {
		return nil, err
	}
	selected, err := cbsPackageNames(targets)
	if err != nil {
		return nil, err
	}
	inputs, err := cbsUpdateInputs(packages, editionValues)
	if err != nil {
		return nil, err
	}
	owners, err := uup.PlanCBSPackageOwners(inputs, selected)
	if err != nil {
		return nil, fmt.Errorf("cbs_package_owners: %w", err)
	}
	out := make([]starlark.Value, 0, len(owners))
	for _, o := range owners {
		out = append(out, starvalue.NewRecord(starlark.StringDict{"package": starlark.String(o.Package), "owner": starlark.String(o.Owner), "integration": starlark.MakeUint64(uint64(o.Integration)), "state": starlark.MakeUint64(uint64(o.State)), "value": starlark.MakeUint64(uint64(o.Value()))}))
	}
	return starlark.NewList(out), nil
}

// cbsUpdateInputs decodes immutable inputs shared by owner projection and
// update snapshots. Each planner validates its own supported state subset.
func cbsUpdateInputs(packages, editionValues *starlark.List) ([]uup.CBSPackageIntent, error) {
	var editions []string
	if editionValues != nil {
		if editionValues.Len() > 2 {
			return nil, fmt.Errorf("CBS update context: at most two session edition names")
		}
		for i := 0; i < editionValues.Len(); i++ {
			name, ok := starlark.AsString(editionValues.Index(i))
			if !ok || name == "" {
				return nil, fmt.Errorf("CBS update context: edition names must be nonempty strings")
			}
			editions = append(editions, name)
		}
	}
	if packages.Len() > 1<<16 {
		return nil, fmt.Errorf("CBS update context: package count exceeds bound")
	}
	inputs := make([]uup.CBSPackageIntent, 0, packages.Len())
	totalBytes := 0
	for i := 0; i < packages.Len(); i++ {
		entry, ok := packages.Index(i).(*starlark.Dict)
		if !ok {
			return nil, fmt.Errorf("CBS update context: package %d must be a dict", i)
		}
		var manifest starlark.Value
		var state int
		var parents *starlark.List
		var choices *starlark.Dict
		if err := starlark.UnpackArgs("CBS package", nil, entry.Items(), "manifest", &manifest, "intended_state", &state, "parents?", &parents, "choices?", &choices); err != nil {
			return nil, err
		}
		if state < 0 || uint64(state) > 0xffffffff {
			return nil, fmt.Errorf("CBS update context: unsupported intended state %#x", state)
		}
		m, size, err := cbsManifestForValue(manifest, 32<<20)
		if err != nil {
			return nil, err
		}
		totalBytes += size
		if totalBytes > 256<<20 {
			return nil, fmt.Errorf("CBS update context: manifest bytes exceed bound")
		}
		resolved, err := cbsPackageNames(parents)
		if err != nil {
			return nil, err
		}
		input := uup.CBSPackageIntent{Manifest: m, IntendedState: uint32(state), Parents: resolved, SelectableChoices: map[string]bool{}, EditionNames: editions}
		if choices != nil {
			for _, item := range choices.Items() {
				name, nok := starlark.AsString(item[0])
				value, vok := item[1].(starlark.Bool)
				if !nok || !vok {
					return nil, fmt.Errorf("CBS update context: choices must map update names to booleans")
				}
				input.SelectableChoices[name] = bool(value)
			}
		}
		inputs = append(inputs, input)
	}
	return inputs, nil
}

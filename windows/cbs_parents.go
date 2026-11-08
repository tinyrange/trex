package windows

import (
	"fmt"

	"github.com/tinyrange/trex/windows/uup"
	"go.starlark.net/starlark"
)

// cbsParentStatesBuiltin is a bounded read-only observation of explicit
// transaction descriptors and effective state, not a servicing transaction.
func cbsParentStatesBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return cbsParentQuery(args, kwargs, "states")
}

func cbsParentUpdateScopesBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return cbsParentQuery(args, kwargs, "update_scopes")
}

func cbsParentRelationshipsBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return cbsParentQuery(args, kwargs, "relationships")
}

func cbsParentQuery(args starlark.Tuple, kwargs []starlark.Tuple, mode string) (starlark.Value, error) {
	name := "cbs_parent_" + mode
	scope := mode != "states"
	var packages, candidates *starlark.List
	if err := starlark.UnpackArgs(name, args, kwargs, "packages", &packages, "candidates", &candidates); err != nil {
		return nil, err
	}
	if packages.Len() > uup.MaxCBSPackageContexts || candidates.Len() > uup.MaxCBSPackageContexts {
		return nil, fmt.Errorf("CBS parent lists exceed bound")
	}
	states := make([]uup.CBSParentCandidate, 0, candidates.Len())
	candidateNames := make(map[string]string)
	for i := 0; i < candidates.Len(); i++ {
		if scope {
			name, ok := starlark.AsString(candidates.Index(i))
			if !ok {
				return nil, fmt.Errorf("CBS scope candidate must be a package name")
			}
			id, err := uup.ParsePackageManifestName(name + ".mum")
			if err != nil {
				return nil, err
			}
			candidateNames[id.ExactKey()] = name
			states = append(states, uup.CBSParentCandidate{Identity: id})
			continue
		}
		entry, ok := candidates.Index(i).(*starlark.Dict)
		if !ok {
			return nil, fmt.Errorf("CBS parent candidate must be a dict")
		}
		var name string
		var state int
		var baseline bool
		if err := starlark.UnpackArgs("CBS parent candidate", nil, entry.Items(), "package", &name, "intended_state", &state, "baseline", &baseline); err != nil {
			return nil, err
		}
		if state < 0 || uint64(state) > 0xffffffff {
			return nil, fmt.Errorf("CBS parent state exceeds DWORD")
		}
		id, err := uup.ParsePackageManifestName(name + ".mum")
		if err != nil {
			return nil, err
		}
		states = append(states, uup.CBSParentCandidate{Identity: id, IntendedState: uint32(state), Baseline: baseline})
	}
	index, err := uup.NewCBSParentStateIndex(states)
	if err != nil {
		return nil, err
	}
	out := make([]starlark.Value, 0, packages.Len())
	totalBytes := 0
	totalResults := 0
	for i := 0; i < packages.Len(); i++ {
		entry, ok := packages.Index(i).(*starlark.Dict)
		if !ok {
			return nil, fmt.Errorf("CBS parent package must be a dict")
		}
		var manifest starlark.Value
		var comparisons *starlark.List
		var standalone bool
		fields := []any{"manifest", &manifest, "comparisons", &comparisons}
		if !scope {
			fields = append(fields, "standalone_satisfied?", &standalone)
		}
		if err := starlark.UnpackArgs("CBS parent package", nil, entry.Items(), fields...); err != nil {
			return nil, err
		}
		m, size, err := cbsManifestForValue(manifest, 32<<20)
		if err != nil {
			return nil, err
		}
		totalBytes += size
		if totalBytes > 256<<20 {
			return nil, fmt.Errorf("CBS parent manifest bytes exceed bound")
		}
		if comparisons.Len() != len(m.PackageParents) {
			return nil, fmt.Errorf("CBS parent comparison count must equal parsed parent block count")
		}
		descriptors := make([]uup.CBSParentVersionComparison, comparisons.Len())
		for j := range descriptors {
			entry, ok := comparisons.Index(j).(*starlark.Dict)
			if !ok {
				return nil, fmt.Errorf("CBS parent comparison must be a dict")
			}
			d := &descriptors[j]
			if err := starlark.UnpackArgs("CBS parent comparison", nil, entry.Items(), "major_minor", &d.MajorMinor, "build", &d.Build, "revision", &d.Revision, "ignore_revision", &d.IgnoreRevision); err != nil {
				return nil, err
			}
		}
		if scope {
			var identities []uup.AssemblyIdentity
			if mode == "relationships" {
				identities, err = index.ParentRelationships(m, descriptors)
			} else {
				identities, err = index.ParentUpdateScope(m, descriptors)
			}
			if err != nil {
				return nil, fmt.Errorf("CBS parent package %d: %w", i, err)
			}
			totalResults += len(identities)
			if totalResults > 1<<20 {
				return nil, fmt.Errorf("CBS scope results exceed bound")
			}
			names := make([]starlark.Value, 0, len(identities))
			for _, id := range identities {
				names = append(names, starlark.String(candidateNames[id.ExactKey()]))
			}
			out = append(out, starlark.NewList(names))
			continue
		}
		state, err := uup.EvaluateCBSPackageParents(m, uup.CBSParentEvaluation{
			StandaloneSatisfied: standalone,
			Resolve: func(r uup.AssemblyReference) (uint32, error) {
				return index.Resolve(r.Identity, descriptors[r.ParentGroup-1])
			},
		})
		if err != nil {
			return nil, fmt.Errorf("CBS parent package %d: %w", i, err)
		}
		out = append(out, starlark.MakeUint64(uint64(state)))
	}
	return starlark.NewList(out), nil
}

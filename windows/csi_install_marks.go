package windows

import (
	"fmt"

	starvalue "github.com/tinyrange/trex/storage/star"
	"github.com/tinyrange/trex/windows/uup"
	"go.starlark.net/starlark"
)

// The actions remain tied to the immutable native population, not the mutable
// records returned by deployment_actions(). Only the evidence inventory is input.
func cbsInstallMarksBuiltin(population *uup.CBSOrdinaryPopulation) *starlark.Builtin {
	return cbsInstallMarksFromProvider(func() ([]uup.CBSDeploymentAction, error) { return uup.PlanCBSDeploymentActions(population) })
}

func cbsInstallMarksFromProvider(actionsForCall func() ([]uup.CBSDeploymentAction, error)) *starlark.Builtin {
	return starlark.NewBuiltin("cbs_population.install_marks", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var inventory *starlark.List
		if err := starlark.UnpackArgs("cbs_population.install_marks", args, kwargs, "inventory", &inventory); err != nil {
			return nil, err
		}
		if inventory.Len() > 1<<20 {
			return nil, fmt.Errorf("CSI install-mark inventory exceeds bound")
		}
		totalBytes, totalEntries := 0, 0
		boundedBytes := func(v starlark.Value) ([]byte, error) {
			b, ok := v.(starlark.Bytes)
			if !ok {
				return nil, fmt.Errorf("CSI install-mark identity/source requires bytes")
			}
			totalBytes += len(b)
			if len(b) > 64<<10 || totalBytes > 64<<20 {
				return nil, fmt.Errorf("CSI install-mark data exceeds bound")
			}
			return []byte(b), nil
		}
		input := make([]uup.CSIInstallMarkDeployment, 0, inventory.Len())
		for v := range inventory.Elements() {
			d, ok := v.(*starlark.Dict)
			if !ok {
				return nil, fmt.Errorf("CSI install-mark deployment requires a dict")
			}
			var identity starlark.Value
			var members, sources, persisted *starlark.List
			if err := starlark.UnpackArgs("CSI install-mark deployment", nil, d.Items(), "identity", &identity, "installed_sources", &sources, "composition?", &members, "persisted_members?", &persisted); err != nil {
				return nil, err
			}
			if (members == nil) == (persisted == nil) {
				return nil, fmt.Errorf("CSI inventory requires exactly one of composition or persisted_members")
			}
			totalEntries += sources.Len()
			if members != nil {
				totalEntries += members.Len()
			} else {
				totalEntries += persisted.Len()
			}
			if totalEntries > 1<<22 {
				return nil, fmt.Errorf("CSI install-mark entries exceed bound")
			}
			data, err := boundedBytes(identity)
			if err != nil {
				return nil, err
			}
			id, err := uup.ParseCSIIdentity(data)
			if err != nil {
				return nil, err
			}
			entry := uup.CSIInstallMarkDeployment{Identity: id}
			if persisted != nil {
				entry.PersistedMembers = make([]uup.AssemblyIdentity, 0, persisted.Len())
				for v := range persisted.Elements() {
					data, err := boundedBytes(v)
					if err != nil {
						return nil, err
					}
					id, err := uup.ParseCSIIdentity(data)
					if err != nil {
						return nil, err
					}
					entry.PersistedMembers = append(entry.PersistedMembers, id)
				}
				members = starlark.NewList(nil)
			}
			for value := range sources.Elements() {
				data, err := boundedBytes(value)
				if err != nil {
					return nil, err
				}
				entry.InstalledSources = append(entry.InstalledSources, data)
			}
			for value := range members.Elements() {
				r, ok := value.(starlark.HasAttrs)
				if !ok {
					return nil, fmt.Errorf("CSI composition member requires a record")
				}
				identity, err := r.Attr("identity")
				if err != nil {
					return nil, err
				}
				data, err := boundedBytes(identity)
				if err != nil {
					return nil, err
				}
				id, err := uup.ParseCSIIdentity(data)
				if err != nil {
					return nil, err
				}
				value, err := r.Attr("disposition")
				if err != nil {
					return nil, err
				}
				if value == nil {
					return nil, fmt.Errorf("CSI composition member lacks disposition")
				}
				var disposition uint32
				if err := starlark.AsInt(value, &disposition); err != nil {
					return nil, err
				}
				entry.Composition = append(entry.Composition, uup.CSICompositionMember{Identity: id, Disposition: disposition})
			}
			input = append(input, entry)
		}
		actions, err := actionsForCall()
		if err != nil {
			return nil, err
		}
		marks, err := uup.AnalyzeCSIInstallMarks(input, actions)
		if err != nil {
			return nil, err
		}
		values := make([]starlark.Value, 0, len(marks))
		for _, m := range marks {
			identity, err := uup.FormatCSIIdentity(m.Identity)
			if err != nil {
				return nil, err
			}
			values = append(values, starvalue.NewRecord(starlark.StringDict{
				"identity": starlark.Bytes(identity), "initial": starlark.MakeUint64(uint64(m.Initial)), "final": starlark.MakeUint64(uint64(m.Final)), "affected": starlark.Bool(m.Affected), "impactful_install": starlark.Bool(m.ImpactfulInstall),
			}))
		}
		return starlark.NewList(values), nil
	})
}

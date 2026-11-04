package windows

import (
	"fmt"

	starvalue "github.com/tinyrange/trex/storage/star"
	"github.com/tinyrange/trex/windows/uup"
	"go.starlark.net/starlark"
)

func unpackCSIWinnerInputs(name, membershipName string, args starlark.Tuple, kwargs []starlark.Tuple) ([]byte, string, []string, []uup.CSIWinnerVersionChange, error) {
	var identity starlark.Bytes
	var current string
	var installed, changes *starlark.List
	if err := starlark.UnpackArgs(name, args, kwargs, "identity", &identity, "current", &current, membershipName, &installed, "changes", &changes); err != nil {
		return nil, "", nil, nil, err
	}
	if len(identity) > 64<<10 || len(current) > 64 || installed.Len() > 1<<20 || changes.Len() > 1<<20 {
		return nil, "", nil, nil, fmt.Errorf("CSI winner input exceeds bound")
	}
	members := make([]string, 0, installed.Len())
	for v := range installed.Elements() {
		text, ok := starlark.AsString(v)
		if !ok || len(text) > 64 {
			return nil, "", nil, nil, fmt.Errorf("CSI installed version requires a bounded string")
		}
		members = append(members, text)
	}
	delta := make([]uup.CSIWinnerVersionChange, 0, changes.Len())
	for v := range changes.Elements() {
		d, ok := v.(*starlark.Dict)
		if !ok {
			return nil, "", nil, nil, fmt.Errorf("CSI winner version change requires a dict")
		}
		var change uup.CSIWinnerVersionChange
		if err := starlark.UnpackArgs("CSI winner version change", nil, d.Items(), "version", &change.Version, "installed", &change.Installed, "impactful_install", &change.ImpactfulInstall); err != nil {
			return nil, "", nil, nil, err
		}
		if len(change.Version) > 64 {
			return nil, "", nil, nil, fmt.Errorf("CSI changed version exceeds bound")
		}
		delta = append(delta, change)
	}
	return []byte(identity), current, members, delta, nil
}

func csiWinnerChangeBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	identity, current, members, delta, err := unpackCSIWinnerInputs("csi_winner_change", "installed", args, kwargs)
	if err != nil {
		return nil, err
	}
	result, err := uup.AnalyzeCSIWinnerChange([]byte(identity), current, members, delta)
	if err != nil {
		return nil, err
	}
	return starvalue.NewRecord(starlark.StringDict{"winner": starlark.String(result.Winner), "shadowed": starlark.String(result.Shadowed)}), nil
}

func csiWinnerPlanBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	identity, current, members, delta, err := unpackCSIWinnerInputs("csi_winner_plan", "before", args, kwargs)
	if err != nil {
		return nil, err
	}
	plan, err := uup.PlanCSIWinnerWrites(identity, current, members, delta)
	if err != nil {
		return nil, err
	}
	edits := make([]starlark.Value, 0, len(plan.Edits))
	for _, edit := range plan.Edits {
		edits = append(edits, starvalue.NewRecord(starlark.StringDict{
			"branch": starlark.String(edit.Branch), "name": starlark.String(edit.Value.Name),
			"delete": starlark.Bool(edit.Delete), "type": starlark.MakeUint64(uint64(edit.Value.Type)), "data": starlark.Bytes(edit.Value.Data),
		}))
	}
	return starvalue.NewRecord(starlark.StringDict{
		"family": starlark.String(plan.Family), "winner": starlark.String(plan.Change.Winner), "shadowed": starlark.String(plan.Change.Shadowed), "edits": starlark.NewList(edits),
	}), nil
}
